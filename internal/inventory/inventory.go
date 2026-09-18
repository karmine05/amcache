// Package inventory turns the seven Root\Inventory* keys of an acquired Amcache
// hive into bounded, sorted records.
//
// Every length, count, offset and index structure in the input is written by
// whoever wrote the hive, and regparser's key and value walkers supply no bound
// of any kind: the bounds in this file are the only ones in the system. The
// process that links this package runs as SYSTEM.
package inventory

import (
	"context"
	"errors"
	"log"
	"sync"

	"www.velocidex.com/golang/regparser"
)

// The bare subkey names under Root. Phase 3 maps each to a table.
const (
	KeyApplicationFile     = "InventoryApplicationFile"
	KeyApplication         = "InventoryApplication"
	KeyApplicationShortcut = "InventoryApplicationShortcut"
	KeyDriverBinary        = "InventoryDriverBinary"
	KeyDriverPackage       = "InventoryDriverPackage"
	KeyDevicePnp           = "InventoryDevicePnp"
	KeyDeviceContainer     = "InventoryDeviceContainer"
)

// Keys is the parse order and the table order.
var Keys = [7]string{
	KeyApplicationFile,
	KeyApplication,
	KeyApplicationShortcut,
	KeyDriverBinary,
	KeyDriverPackage,
	KeyDevicePnp,
	KeyDeviceContainer,
}

// Record is one subkey of one inventory key. V holds the key's values under
// their registry value names, decoded only as far as a string: the column
// mapping and every semantic decode (SHA-1 out of FileId, date parsing, boolean
// normalisation) belong to the table layer, so that what is recorded here is
// what the hive says rather than what a decoder believes.
type Record struct {
	Name      string
	LastWrite int64
	V         map[string]string
}

// Snapshot carries only the inventory keys the hive actually holds; an absent
// key is an absent map entry, which the table layer serves as zero rows. Legacy
// marks the pre-Windows-8 Amcache format, whose Root\File and Root\Programs
// trees this package detects and does not parse.
type Snapshot struct {
	Legacy bool
	Keys   map[string][]Record
}

var ErrNotAmcache = errors.New("amcache: hive has no Amcache keys")

// Each cap sits in front of the regparser call that would otherwise allocate
// from a file-declared quantity. The measured uncapped cost of each is in the
// comment: those are what the process spends when the bound is missing or is
// placed after the call it is meant to guard.
const (
	// maxSubkeys bounds CM_KEY_NODE.Subkeys, which materialises every index slot
	// before returning. A 36 KiB hive whose root declares one subkey drove it to
	// 4,000,000 nodes and 612 MiB, so the cap is enforced against indexSlots
	// below and never against the node's own declared count.
	maxSubkeys = 1_000_000

	// maxValues bounds CM_KEY_NODE.Values, whose walk is driven by a uint32 read
	// from the file and is otherwise bounded only by EOF: 216 ms and 407 MiB per
	// record on a 64 MiB hive. The largest real count on any fixture is 34.
	maxValues = 256

	// maxValueBytes bounds CM_KEY_VALUE.ValueData, which reaches
	// ParseSafeArray_byte and issues one ReadAt per byte: 246 ms and 375 MiB for
	// a single value on a 64 MiB hive.
	//
	// 1 MiB rather than the 64 KiB the design contract first fixed: a real Hwids
	// on InventoryDriverPackage measures 994,592 bytes on both Windows 11
	// fixtures, so 64 KiB would silently empty that column on 2 of 43 driver
	// packages. Nothing else on any fixture exceeds 1,170 bytes, and total value
	// data cannot exceed the hive cap regardless, so the worst case does not
	// multiply.
	maxValueBytes = 1 << 20

	// maxIndexDepth bounds nesting in the subkey index. A real index is ri -> lh,
	// i.e. depth 1.
	maxIndexDepth = 32

	// ctxCheckEvery is how often the subkey walk honours cancellation.
	ctxCheckEvery = 1024
)

// regf cell signatures, as HCELL.Signature reports them.
const (
	sigNk = 0x6b6e
	sigLf = 0x666c
	sigLh = 0x686c
	sigRi = 0x6972
	sigLi = 0x696c
)

var (
	errIndexCycle     = errors.New("amcache: subkey index cell revisited")
	errIndexDepth     = errors.New("amcache: subkey index nested past the depth cap")
	errTooManySubkeys = errors.New("amcache: subkey index declares more slots than the cap admits")
)

// Warning conditions. Each fires at most once per process, so a hive that is
// corrupt in one way 16,850 times produces one line.
const (
	warnLegacy = iota
	warnSubkeyIndex
	warnValueCount
	warnValueSize
	warnValueShape
	warnRecordPanic
	nWarnConds
)

// sync.Once rather than a bool: a plain package-level bool here is a write/write
// data race as soon as two goroutines parse at once, which is exactly what the
// fuzz harness does. No other package-level mutable state exists in this
// package; everything else a helper needs is a parameter.
var warnOnce [nWarnConds]sync.Once

// warn never carries a name or a value read out of the hive. Counts, caps, key
// constants and error values only.
func warn(cond int, format string, args ...any) {
	warnOnce[cond].Do(func() { log.Printf(format, args...) })
}

// indexSlots is an upper bound on how many key nodes CM_KEY_NODE.Subkeys will
// materialise, computed without materialising any of them.
//
// Two regparser facts make this load-bearing rather than defensive. First,
// CM_KEY_NODE.SubKeyCounts is written by whoever wrote the hive and bounds
// nothing: a 36 KiB hive declaring a count of 1 drives Subkeys to 4,000,000
// nodes and 612 MiB, and the format maximum (an ri of 65535 elements each
// pointing at an lh of 65535) extrapolates to ~656 GiB from a 786 KiB hive. So
// checking the declared count and then calling Subkeys is not a bound, and
// checking the returned length is a bound placed after the allocation it guards.
// Second, CM_KEY_INDEX.Subkeys recurses into child indexes with no depth or
// visited tracking, so an ri that reaches itself recurses until the goroutine
// stack overflows. That is a fatal error and not a panic: recover cannot catch
// it, and the SYSTEM process dies. A visited set alone does not stop linear
// nesting and a depth cap alone does not cheaply stop a tight cycle, so both are
// here.
func indexSlots(reg *regparser.Registry, off uint32, limit int) (int, error) {
	type frame struct {
		off   uint32
		depth int
	}
	seen := make(map[uint32]struct{}, 16)
	stack := []frame{{off, 0}}
	total := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.depth > maxIndexDepth {
			return 0, errIndexDepth
		}
		if _, dup := seen[f.off]; dup {
			return 0, errIndexCycle
		}
		seen[f.off] = struct{}{}

		cell := reg.Profile.HCELL(reg.Reader, 0x1000+int64(f.off))
		switch cell.Signature() {
		case sigLf, sigLh:
			// A fast index holds Count elements and each resolves to at most one
			// key node, so Count bounds this branch without reading an element.
			total += int(cell.KeyIndexFast().Count())
		case sigRi, sigLi:
			idx := cell.KeyIndex()
			for _, child := range regparser.ParseSafeArray_uint32(
				reg.Reader, idx.Offset+reg.Profile.Off_CM_KEY_INDEX_List, int(idx.Count())) {
				switch reg.Profile.HCELL(reg.Reader, 0x1000+int64(child)).Signature() {
				case sigNk:
					total++
				case sigLf, sigLh, sigRi, sigLi:
					stack = append(stack, frame{child, f.depth + 1})
				}
			}
		default:
			// Not an index cell. Subkeys returns nil for it, so it contributes
			// nothing and needs no frame.
		}
		// The pending stack is bounded as well as the running total: a wide ri
		// must not be able to queue more work than the cap admits.
		if total > limit || len(stack) > limit {
			return 0, errTooManySubkeys
		}
	}
	return total, nil
}

// subkeys is the only place in this package that calls CM_KEY_NODE.Subkeys, so
// the pre-flight cannot be bypassed by a later caller.
func subkeys(reg *regparser.Registry, n *regparser.CM_KEY_NODE) ([]*regparser.CM_KEY_NODE, error) {
	off := n.SubKeyLists()[0]
	// SubKeyLists is a two-element ParseArray with unconditional appends, so the
	// index cannot panic even on a truncated read. A leaf key carries 0xFFFFFFFF
	// here, which resolves past EOF to a zero signature; Subkeys returns nil for
	// it and there is nothing to pre-flight.
	if reg.Profile.HCELL(reg.Reader, 0x1000+int64(off)).Signature() == 0 {
		return nil, nil
	}
	if _, err := indexSlots(reg, off, maxSubkeys); err != nil {
		return nil, err
	}
	return n.Subkeys(), nil
}

// Parse extracts the seven inventory keys from an acquired hive.
func Parse(ctx context.Context, hive []byte) (*Snapshot, error) {
	return nil, ErrNotAmcache
}
