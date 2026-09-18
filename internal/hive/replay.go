// Package hive acquires the bytes of the Amcache hive and makes them parseable:
// a plain read where Windows allows one, a raw NTFS read where it does not, and
// an in-memory replay of the transaction logs when the hive is dirty.
package hive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"www.velocidex.com/golang/regparser"
)

// Result is declared here rather than in hive_windows.go / hive_other.go: those
// two are mutually exclusive, so a struct declared in both can drift apart
// without any build ever failing.
type Result struct {
	Data  []byte
	Raw   bool
	Dirty bool
}

// These bound every allocation this package drives from a file-declared size.
// The process runs as SYSTEM and the appraiser's output is influenceable by a
// local user.
const (
	MaxHiveBytes = 256 << 20
	MaxLogBytes  = 64 << 20
)

var ErrNotFound = errors.New("amcache: hive not found")

// Dirty reports whether the hive still needs its transaction logs applied.
//
// The regf specification also calls a base block dirty when its stored checksum
// is wrong. That half is deliberately left out: a bad checksum on a live hive
// means a torn read, which the logs cannot repair, and the snapshot retry
// already covers that case. Widening this would fire on hives replay cannot fix.
func Dirty(hive []byte) (bool, error) {
	reg, err := regparser.NewRegistry(bytes.NewReader(hive))
	if err != nil {
		return false, fmt.Errorf("amcache: base block: %w", err)
	}
	return reg.BaseBlock.Sequence1() != reg.BaseBlock.Sequence2(), nil
}

// Replay applies the dirty pages carried by Amcache.hve.LOG1/.LOG2 to a copy of
// the hive and returns the recovered bytes. The inputs are never mutated and no
// file is created: regparser's own recovery helper is never linked from product
// code because it writes to os.TempDir(), prints to stdout, and spins forever on
// a zero-size entry.
func Replay(hive []byte, logs ...[]byte) ([]byte, error) {
	if len(hive) > MaxHiveBytes {
		return nil, fmt.Errorf("amcache: hive is %d bytes, over the %d byte cap", len(hive), MaxHiveBytes)
	}
	for i, l := range logs {
		if len(l) > MaxLogBytes {
			return nil, fmt.Errorf("amcache: log %d is %d bytes, over the %d byte cap", i, len(l), MaxLogBytes)
		}
	}
	// A primary hive's base block is 4096 bytes. Anything shorter is not a hive,
	// and the header rewrite below indexes into it unconditionally.
	if len(hive) < 0x1000 {
		return nil, fmt.Errorf("amcache: hive is %d bytes, shorter than the 4096 byte base block", len(hive))
	}

	out := append([]byte(nil), hive...)

	base, err := regparser.NewRegistry(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("amcache: base block: %w", err)
	}
	baseSeq2 := base.BaseBlock.Sequence2()

	type applicable struct {
		buf []byte
		seq uint32
	}
	var ready []applicable
	for _, l := range logs {
		if len(l) == 0 {
			continue
		}
		lr, err := regparser.NewRegistry(bytes.NewReader(l))
		if err != nil {
			continue
		}
		// Types 1 and 2 are the pre-Windows-8.1 log formats, which carry no HvLE
		// entries at all.
		if t := lr.BaseBlock.Type(); t == 1 || t == 2 {
			continue
		}
		// The hive is already past everything this log holds. The spec's
		// precondition is >=, not ==, and the difference is load-bearing: a
		// primary file stays dirty on disk from the moment it goes dirty until
		// the next successful flush, while the circular logs run on and recycle
		// the entries in between, so a live hive is routinely hundreds of
		// sequences behind its logs. Requiring continuity between the two would
		// refuse to replay exactly the hives replay exists for.
		if lr.BaseBlock.Sequence1() < baseSeq2 {
			continue
		}
		ready = append(ready, applicable{buf: l, seq: lr.BaseBlock.Sequence1()})
	}
	if len(ready) > 2 {
		return nil, fmt.Errorf("amcache: %d applicable logs, a primary hive has at most 2", len(ready))
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].seq < ready[j].seq })

	profile := regparser.NewRegistryProfile()
	var (
		applied bool
		seq     uint32
		hbins   uint32
		flags   uint32
	)
	var expected uint32
	for i, lg := range ready {
		r := bytes.NewReader(lg.buf)
		// Recovery starts at the log base block's primary sequence number and the
		// regf spec ends it at the first gap: an entry numbered N must be followed
		// by N+1. regparser instead compares against the log's own Sequence2, which
		// stops on the first entry whenever the two happen to be equal.
		//
		// The chain continues across logs rather than restarting at each log's own
		// base. Restarting lets a second log whose range overlaps the first
		// re-apply entries the first already superseded, putting an older page
		// image on top of a newer one and recording the older sequence; both logs
		// pass the Sequence1 >= hive.Sequence2 gate, which is deliberately loose,
		// so overlapping ranges are ordinary. Moving forward to a later log's base
		// is still allowed, on the same grounds the hive-to-log gap is: the
		// circular logs recycle entries, and refusing the gap would refuse the
		// hives replay exists for. Because expected only ever increases, the last
		// entry applied is also the highest, which is what makes taking the header
		// fields from it correct.
		if i == 0 || lg.seq > expected {
			expected = lg.seq
		}
		// Log entries always start at 0x200 and are a multiple of 512 bytes; the
		// HvLE header is 40 bytes and carries 8 bytes per dirty page ref.
		for off := int64(0x200); off < int64(len(lg.buf)); {
			le := &regparser.HIVE_LOG_ENTRY{Reader: r, Offset: off, Profile: profile}
			if le.Signature() != 0x454C7648 { // "HvLE"
				break
			}
			size := int64(le.LogEntrySize())
			// A zero size never advances off; that is the loop regparser's own
			// recovery helper hangs in.
			if size < 40 || size%512 != 0 || off+size > int64(len(lg.buf)) {
				break
			}
			// GetDirtyPages and ParseArray_HIVE_DIRTY_PAGE_REF both pre-allocate
			// DirtyPagesCount() slots, so the count is bounded before either runs:
			// a declared 0xFFFFFFFF would otherwise reserve about 34 GB. The
			// weight is 8 bytes of ref plus the 4096-byte minimum page each ref
			// must carry inside the same entry. Weighing the 8 alone bounds the
			// ref array and nothing else, which still lets a 64 MiB log declare
			// 8.3M refs and drive ~740 MB of pre-allocation before a single page
			// is applied: an 11x amplification of the cap that is supposed to be
			// what this process will spend on a log.
			count := int64(le.DirtyPagesCount())
			if 40+count*(8+4096) > size {
				break
			}
			// The spec requires an entry's hive bins data size to be page-aligned.
			if le.HiveBinsDataSize()%4096 != 0 {
				break
			}
			if le.SequenceNumber() != expected {
				break
			}

			// The whole page list is validated before any of it is applied. A
			// half-applied entry cannot be undone, and the base block rewrite
			// below would then stamp a matching sequence pair and a valid
			// checksum over a hive that is half one generation and half another,
			// which no consumer can detect. A bad ref instead ends the chain at
			// the previous entry: the regf recovery rule stops at the first entry
			// that does not validate, and the hive is consistent at the last one
			// that did. The chain is truncated rather than the replay failed,
			// because a torn tail is the normal state of a log read out from
			// under the appraiser and a valid recovery point is worth keeping.
			pages := le.GetDirtyPages()
			torn := false
			for _, p := range pages {
				// Data() allocates PageSize bytes unconditionally, so both the size
				// and the source range are checked before it is called. A dirty page
				// is a whole number of 4096-byte hive bins pages; every page in
				// every captured fixture is.
				if p.PageSize == 0 || p.PageSize%4096 != 0 ||
					p.DataOffset+int64(p.PageSize) > off+size {
					torn = true
					break
				}
			}
			if torn {
				break
			}

			for _, p := range pages {
				data, err := p.Data()
				if err != nil {
					return nil, fmt.Errorf("amcache: dirty page at %#x: %w", p.DataOffset, err)
				}
				// Page offsets are relative to the start of hive bins data, which
				// always follows the base block at 0x1000 in a primary file.
				dst := int64(0x1000) + int64(p.PageOffset)
				if dst+int64(p.PageSize) > MaxHiveBytes {
					return nil, fmt.Errorf("amcache: dirty page at %#x would grow the hive past the %d byte cap", dst, MaxHiveBytes)
				}
				if need := dst + int64(p.PageSize); need > int64(len(out)) {
					out = append(out, make([]byte, need-int64(len(out)))...)
				}
				copy(out[dst:], data)
			}

			seq, hbins, flags = le.SequenceNumber(), le.HiveBinsDataSize(), le.Flags()
			applied = true
			expected++
			off += size
		}
	}

	if applied {
		// hbins comes verbatim from a log entry and is only known to be
		// page-aligned; nothing has tied it to the bytes actually recovered. A
		// consumer enumerates hive bins bounded by this field, so a value larger
		// than the buffer walks bin headers past the end of the reader, and one
		// smaller silently truncates the walk and drops inventory rows. len(out)
		// is final here, which is the only place the two can be compared.
		if int64(hbins) > int64(len(out))-0x1000 {
			return nil, fmt.Errorf("amcache: replayed hive declares %d bytes of hive bins data but holds %d",
				hbins, int64(len(out))-0x1000)
		}
		// Both sequence numbers, the hive bins data size, the flags and the
		// checksum together are what make Dirty(out) report false.
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], seq)
		copy(out[4:8], b[:])
		copy(out[8:12], b[:])
		binary.LittleEndian.PutUint32(b[:], hbins)
		copy(out[0x28:0x2c], b[:])
		binary.LittleEndian.PutUint32(b[:], flags)
		copy(out[0x90:0x94], b[:])
		binary.LittleEndian.PutUint32(b[:], checksum(out))
		copy(out[0x1fc:0x200], b[:])
	}

	return out, nil
}

// checksum is the regf base block checksum: XOR of every little-endian uint32 in
// the first 0x1fc bytes, with 0 and 0xFFFFFFFF reserved as invalid values.
func checksum(buf []byte) uint32 {
	var c uint32
	for i := 0; i < 0x1fc; i += 4 {
		c ^= binary.LittleEndian.Uint32(buf[i : i+4])
	}
	if c == 0 {
		return 1
	}
	if c == 0xFFFFFFFF {
		return 0xFFFFFFFE
	}
	return c
}
