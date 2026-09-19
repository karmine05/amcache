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
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/amcache/internal/hive"
	"github.com/karmine05/amcache/internal/inventory"
	"github.com/osquery/osquery-go/plugin/table"
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

// selected returns the record indices a query's constraints can narrow to, or
// nil for every record.
//
// A superset is always a correct answer because SQLite re-filters what we
// return; a subset never is. Every branch that cannot be sure returns more rows
// rather than fewer.
func selected(qc table.QueryContext, idx map[string]map[string][]int32, tbl string) []int32 {
	var out []int32
	narrowed := false

	for name, cl := range qc.Constraints {
		byVal, ok := idx[tbl+"\x00"+name]
		if !ok {
			// Constraints arrive for columns we never flagged: osquery promotes
			// every extension column with default options to INDEX, which is also
			// the only reason any constraint reaches us at all. An unflagged
			// column is one SQLite will filter itself, not one that cannot happen.
			continue
		}

		var hits []int32
		usable := false
		for _, cst := range cl.Constraints {
			if cst.Operator != table.OperatorEquals || cst.Expression == "" || len(cst.Expression) > maxExprLen {
				// LIKE, GLOB and the comparisons cannot be answered from an equality
				// index, and TEXT columns never receive the comparisons anyway.
				continue
			}
			usable = true
			// The whole exposure of a constraint in this extension: lowercased,
			// bounded above, and used as a map key. It reaches no filesystem call,
			// no format string and nothing regparser sees -- hive.Read takes no
			// parameter beyond a context, so there is no argument for it to become.
			hits = append(hits, byVal[strings.ToLower(cst.Expression)]...)
		}
		if !usable {
			continue
		}

		// Union within a column, never intersection. SQLite expands IN (a, b) into
		// one xFilter call per value today, but a future batched form would arrive
		// as two equalities in one list, and the union is the only reading correct
		// under both. Intersecting would return zero rows for every IN query --
		// an IOC sweep over two hundred hashes silently finding nothing, which is
		// the failure this table exists to prevent.
		hits = sortUnique(hits)
		if !narrowed {
			out, narrowed = hits, true
			continue
		}
		// Across columns is an AND.
		out = intersect(out, hits)
	}

	if !narrowed {
		return nil
	}
	if out == nil {
		// A usable constraint that matched nothing selects no records. Returning
		// nil here would mean every record instead, which is the difference
		// between an empty answer and a wrong one.
		out = []int32{}
	}
	return out
}

// sortUnique also dedupes, so a repeated value in an IN list cannot make the
// same record appear twice in the result.
func sortUnique(v []int32) []int32 {
	slices.Sort(v)
	return slices.Compact(v)
}

func intersect(a, b []int32) []int32 {
	out := make([]int32, 0, min(len(a), len(b)))
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// generator returns one table's Generate.
func (c *cache) generator(s spec) table.GenerateFunc {
	return func(ctx context.Context, qc table.QueryContext) (rows []map[string]string, err error) {
		// First statement, named returns, in fleet's own shape. A returned error
		// becomes Status{Code:1} and then SQLITE_ERROR: the query fails and the
		// process lives. An escaped panic ends a SYSTEM process serving every
		// other table, because nothing above this recovers.
		defer func() {
			if r := recover(); r != nil {
				logf("amcache: %s: recovered from panic: %v", s.table, r)
				rows, err = nil, fmt.Errorf("%s: recovered from panic: %v", s.table, r)
			}
		}()

		// Wraps the cache acquisition as well as the row build, which is what
		// makes the channel lock above worth having.
		ctx, cancel := context.WithTimeout(ctx, generateTimeout)
		defer cancel()

		snap, err := c.get(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.table, err)
		}
		recs := snap.inv.Keys[s.key]
		if len(recs) == 0 {
			// A key this host does not write, or a legacy hive. Zero rows.
			return nil, nil
		}
		return rowsFor(ctx, s, recs, selected(qc, snap.idx, s.table))
	}
}

// All returns the seven table plugins, reading the live hive.
func All() []*table.Plugin {
	return New(hive.Read, hive.Stat)
}

// New returns the seven table plugins over the given hive accessors, sharing
// one cache between them.
//
// Two closures rather than one because the freshness path is otherwise
// untestable: hive.Stat returns errors.ErrUnsupported on every platform a test
// can run on.
func New(read func(context.Context) (hive.Result, error), stat func() (time.Time, int64, error)) []*table.Plugin {
	c := &cache{read: read, stat: stat, sem: make(chan struct{}, 1)}
	out := make([]*table.Plugin, 0, len(specs))
	for _, s := range specs {
		out = append(out, table.NewPlugin(s.table, s.columnDefs(), c.generator(s)))
	}
	return out
}
