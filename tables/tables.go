// Serving: one parsed hive shared by seven tables, and the three things that
// stand between a SQL query and a process running as SYSTEM.
//
// A lock that can be abandoned, a deadline that can fire, and a recover that
// catches what nothing above us does. The last one is not defensive style: a
// panic that escapes Generate is not a failed query, it is a dead extension,
// because there is no recover() in thrift's TSimpleServer.innerAccept, in
// processRequests, in the generated Process, in ExtensionManagerServer.Call or
// in Plugin.Call -- and innerAccept runs us inside a bare `go func()`.
//
// The cache is load-bearing rather than an optimisation. osquery promotes every
// extension column to an index by default (extensions_default_index), and its
// own source records that an indexed column in a JOIN means xFilter is called
// five hundred times; without a shared snapshot that is five hundred raw-volume
// reads and five hundred parses for one query.

package tables

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/amcache/internal/hive"
	"github.com/karmine05/amcache/internal/inventory"
)

const (
	// Five minutes bounds how stale a row can be, and on a broken host it also
	// bounds raw-volume read attempts to twelve an hour, which is the reason
	// failures are remembered as well as successes.
	cacheTTL = 5 * time.Minute

	// The only cancellation that will ever fire in production. Thrift's
	// connectivity check under //go:build windows || wasm is a stub that returns
	// nil unconditionally, so the ticker that would cancel the request context
	// on a closed transport never sees one close: the context osquery hands us
	// has no deadline and a cancel that cannot happen.
	generateTimeout = 30 * time.Second

	// A constraint expression is attacker-adjacent -- anything that can run a
	// query against this host writes it -- so it is bounded before it is used.
	// Longer than this is not a hash, a path or a device id, and falls back to
	// the superset.
	maxExprLen = 4096
)

// snapshot is one parse and the equality indices built over it.
//
// idx is keyed "<table>\x00<column>" -> lowercased decoded cell -> the indices
// of the records carrying it, in the same slice the rows are built from.
type snapshot struct {
	inv *inventory.Snapshot
	idx map[string]map[string][]int32
}

// cache holds at most one snapshot, or the failure that produced none.
//
// read and stat are fields rather than direct calls into internal/hive because
// both are Windows-only in effect -- hive.Stat returns errors.ErrUnsupported on
// every other platform by construction -- so the reload, failure and freshness
// paths are otherwise unreachable anywhere they could be tested.
type cache struct {
	read func(context.Context) (hive.Result, error)
	stat func() (time.Time, int64, error)

	// A one-slot channel and not a sync.Mutex, and that difference is the only
	// thing that can end a queued call. Mutex.Lock cannot be abandoned: the
	// contract holds the lock across the load so a seven-table join parses once,
	// which means the second table can arrive behind a raw NTFS read of the
	// system volume plus a log replay plus a parse -- seconds -- and on Windows
	// nothing else would ever end its wait, because the incoming context has no
	// deadline and a cancel that cannot fire. Selected against ctx.Done, that
	// caller returns its own deadline instead of outliving it.
	sem chan struct{}

	// Read and written only while sem is held.
	snap  *snapshot
	err   error
	at    time.Time
	mtime time.Time
	size  int64
	timer *time.Timer
}

// hive.Stat is unavailable on every non-Windows build and can fail on a Windows
// one; neither is a reason to fail a query or to reload on every call.
var statWarned sync.Once

func warnStat(err error) {
	statWarned.Do(func() {
		logf("amcache: hive freshness check unavailable (%v); the snapshot is refreshed "+
			"on the %s timer alone; later occurrences are not logged", err, cacheTTL)
	})
}

// get returns the shared snapshot, parsing the hive if what is held is missing,
// expired or stale.
func (c *cache) get(ctx context.Context) (*snapshot, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()

	if mtime, size, err := c.stat(); err != nil {
		warnStat(err)
	} else if mtime != c.mtime || size != c.size {
		// The appraiser rewrites the hive while we are running, and a changed
		// (mtime, size) is the only cheap signal of it. os.Stat sees it through
		// GetFileAttributesEx, which takes no handle and so is not refused while
		// the appraiser holds the file open.
		c.drop()
		c.mtime, c.size = mtime, size
	}

	if (c.snap == nil && c.err == nil) || time.Since(c.at) > cacheTTL {
		if err := c.load(ctx); err != nil {
			return nil, err
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.snap, nil
}

// load replaces what is cached, and returns only the errors that must not be
// remembered.
func (c *cache) load(ctx context.Context) error {
	snap, err := c.parse(ctx)
	if err != nil && (ctx.Err() != nil ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		// One cancelled query would otherwise fail every query for five minutes.
		// Every other failure is remembered on purpose: it is what stops a host
		// whose hive cannot be read from attempting a raw volume read per query.
		return err
	}

	c.snap, c.err, c.at = snap, err, time.Now()
	if c.timer == nil {
		c.timer = time.AfterFunc(cacheTTL, c.expire)
	} else {
		c.timer.Reset(cacheTTL)
	}
	return nil
}

func (c *cache) parse(ctx context.Context) (*snapshot, error) {
	res, err := c.read(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := inventory.Parse(ctx, res.Data)
	if err != nil {
		return nil, err
	}
	// Two booleans, no path and no hive content. From outside the process this
	// is the only way to tell that the hive was locked and the raw volume read
	// ran, which is exactly what the cross-OS matrix has to record.
	logf("amcache: hive parsed (raw volume read: %t, transaction logs replayed: %t)", res.Raw, res.Replayed)

	// A legacy hive is not an error. It caches like any other and every table
	// serves zero rows, which is the parser's detect-and-do-not-parse behaviour
	// arriving at the table layer intact.
	return &snapshot{inv: inv, idx: index(inv)}, nil
}

// expire drops an idle snapshot rather than leaving a parsed hive in a SYSTEM
// process's RSS between investigations.
//
// ponytail: one global lock and one timer, fine for a five-minute cache; per
// table locks only if a single hive stops being the unit of work.
func (c *cache) expire() {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	// A reload between the timer firing and this acquiring the slot has already
	// re-armed the timer, so dropping here would throw away a fresh parse.
	if time.Since(c.at) < cacheTTL {
		return
	}
	c.drop()
}

func (c *cache) drop() { c.snap, c.err = nil, nil }

// index builds the equality indices, over the decoded cell rather than the raw
// value.
//
// The distinction decides whether the index is ever hit: an operator types the
// 40-hex sha1 the table displays, not the 44-character FileId the hive stores,
// and a backslashed device instance id, not the forward-slashed subkey name. An
// index over the source values would miss every query and cost a full scan to
// find that out.
func index(inv *inventory.Snapshot) map[string]map[string][]int32 {
	idx := make(map[string]map[string][]int32)
	for _, s := range specs {
		recs := inv.Keys[s.key]
		if len(recs) == 0 {
			continue
		}
		for _, c := range s.cols {
			if !c.push {
				continue
			}
			byVal := make(map[string][]int32)
			for i, rec := range recs {
				v, ok := cell(c, rec)
				if !ok || v == "" {
					// An empty cell is never looked up: an equality on the empty
					// string falls back to the superset in selected, because three
					// quarters of the file records on a Windows 11 host carry no
					// path and answering that query from an index would be a subset.
					continue
				}
				byVal[strings.ToLower(v)] = append(byVal[strings.ToLower(v)], int32(i))
			}
			idx[s.table+"\x00"+c.name] = byVal
		}
	}
	return idx
}
