// Package inventory turns the seven Root\Inventory* keys of an acquired Amcache
// hive into bounded, sorted records.
//
// Every length, count, offset and index structure in the input is written by
// whoever wrote the hive, and regparser's key and value walkers supply no bound
// of any kind: the bounds in this file are the only ones in the system. The
// process that links this package runs as SYSTEM.
package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

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
	sigDb = 0x6264
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
//
// The descent walks the base block to Root and classifies Root's children in one
// pass rather than opening each key by path: regparser's OpenKey calls Subkeys
// on every component, so seven OpenKey calls would perform fourteen walks, two
// of them on nodes nothing pre-flighted. This shape performs two guarded walks
// and makes the legacy classification fall out of the same pass.
func Parse(ctx context.Context, hive []byte) (*Snapshot, error) {
	reg, err := regparser.NewRegistry(bytes.NewReader(hive))
	if err != nil {
		return nil, fmt.Errorf("amcache: base block: %w", err)
	}
	// A local, threaded into the value guards. A package-level hive length is a
	// data race between two concurrent parses, and the bound it feeds is the one
	// standing between a corrupt cell offset and a panic.
	hiveLen := int64(len(hive))

	base := reg.Profile.HCELL(reg.Reader, 0x1000+int64(reg.BaseBlock.RootCell())).KeyNode()
	if base == nil {
		return nil, ErrNotAmcache
	}
	top, err := subkeys(reg, base)
	if err != nil {
		return nil, fmt.Errorf("amcache: base block subkey index: %w", err)
	}
	// EqualFold because the registry is case-insensitive; this is the comparison
	// OpenKey performs with a ToLower allocation per subkey per component.
	var root *regparser.CM_KEY_NODE
	for _, n := range top {
		if strings.EqualFold(nodeName(reg, n), "Root") {
			root = n
			break
		}
	}
	if root == nil {
		return nil, ErrNotAmcache
	}
	children, err := subkeys(reg, root)
	if err != nil {
		return nil, fmt.Errorf("amcache: Root subkey index: %w", err)
	}

	found := make(map[string]*regparser.CM_KEY_NODE, len(Keys))
	var legacy bool
	for _, n := range children {
		name := nodeName(reg, n)
		for _, k := range Keys {
			if strings.EqualFold(name, k) {
				found[k] = n
				break
			}
		}
		if strings.EqualFold(name, "File") || strings.EqualFold(name, "Programs") {
			legacy = true
		}
	}
	if len(found) == 0 {
		if legacy {
			warn(warnLegacy, "amcache: hive carries the pre-Windows-8 Amcache format; "+
				"the inventory tables serve zero rows because this build parses only the modern format")
			return &Snapshot{Legacy: true, Keys: map[string][]Record{}}, nil
		}
		return nil, ErrNotAmcache
	}

	snap := &Snapshot{Keys: make(map[string][]Record, len(found))}
	for _, k := range Keys {
		n, ok := found[k]
		if !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		subs, err := subkeys(reg, n)
		if err != nil {
			// A rejected index costs one key, never the parse. The key name is one
			// of our own constants and the error carries no hive content, so both
			// are safe to log.
			warn(warnSubkeyIndex, "amcache: %s: subkey index rejected (%v); that key serves zero rows", k, err)
			continue
		}
		recs := make([]Record, 0, len(subs))
		for i, s := range subs {
			if i%ctxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if r, ok := record(reg, s, hiveLen); ok {
				recs = append(recs, r)
			}
		}
		// The walk order is Windows' lh hash order, not lexical, so an unsorted
		// golden is unreadable and a cross-fixture diff is meaningless. It is not
		// here for -update idempotence: the walk is already deterministic per hive,
		// so that holds either way. Stable so that a hive carrying a duplicate
		// subkey name cannot make the order depend on the sort's internals.
		slices.SortStableFunc(recs, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
		snap.Keys[k] = recs
	}
	return snap, nil
}

// record builds one row from one subkey. A malformed record is skipped and its
// siblings survive.
//
// The recover is the only one in this package and it is a backstop for the
// unknown-unknowns, not the mitigation for anything tested: every failure mode
// this package knows about has an explicit guard in front of it below, because
// a guard is what a test can assert and a recover turns a bug into a silent row
// loss. It is also not a general corruption defence -- the fatal stack overflow
// an ri cycle produces is not a panic and reaches nothing here, which is why
// indexSlots exists. Record granularity rather than value granularity: the
// largest fixture holds 18,214 records against 102,975 values.
func record(reg *regparser.Registry, n *regparser.CM_KEY_NODE, hiveLen int64) (rec Record, ok bool) {
	defer func() {
		if p := recover(); p != nil {
			warn(warnRecordPanic, "amcache: a record was skipped after a parser panic (%v); "+
				"later panics are not logged", p)
			rec, ok = Record{}, false
		}
	}()

	rec = Record{Name: nodeName(reg, n), LastWrite: lastWrite(reg, n), V: map[string]string{}}

	// CHILD_LIST.Count is a uint32 read from the file and Values walks it bounded
	// only by EOF, so the cap goes in front of the call and not around its result.
	if count := n.ValueList().Count(); count > maxValues {
		warn(warnValueCount, "amcache: a record declares %d values, over the %d cap; "+
			"its values are dropped and the record is served with none", count, maxValues)
		return rec, true
	}
	vals := n.Values()
	rec.V = make(map[string]string, len(vals))
	for _, v := range vals {
		s, decoded := decode(reg, v, hiveLen)
		if !decoded {
			continue
		}
		// The unnamed default value four of the keys carry lands under "". This
		// layer records what the hive says; the column layer never looks it up.
		rec.V[valueName(reg, v)] = s
	}
	return rec, true
}

// valueName branches on VALUE_COMP_NAME for the reason nodeName branches on
// KEY_COMP_NAME. NameLength is checked first so the unnamed default value stays
// "" rather than decoding an empty buffer.
func valueName(reg *regparser.Registry, v *regparser.CM_KEY_VALUE) string {
	if v.NameLength() == 0 {
		return ""
	}
	if v.Flags()&0x0001 != 0 {
		return latin1(regparser.ParseSafeArray_byte(reg.Reader,
			v.Offset+reg.Profile.Off_CM_KEY_VALUE_Name, int(v.NameLength())))
	}
	return utf16le(regparser.ParseSafeArray_byte(reg.Reader,
		v.Offset+reg.Profile.Off_CM_KEY_VALUE_Name, int(v.NameLength())))
}

// decode renders one value as a string, or reports that it was skipped.
//
// Decoding stops at the string: no SHA-1 substring, no date parsing, no boolean
// normalisation, no separator rewriting. Those belong to the column layer, and
// keeping them out is what makes a golden record what the hive says.
func decode(reg *regparser.Registry, v *regparser.CM_KEY_VALUE, hiveLen int64) (string, bool) {
	raw := v.DataLength()
	size := raw & 0x7fffffff
	// ValueData reaches ParseSafeArray_byte, which issues one ReadAt per byte and
	// stops only at EOF, so a declared length drives the read whatever the hive
	// actually holds.
	if size > maxValueBytes {
		warn(warnValueSize, "amcache: a value declares %d bytes, over the %d byte cap; "+
			"the value is dropped", size, maxValueBytes)
		return "", false
	}
	inline := raw&0x80000000 != 0

	switch v.Type() {
	case regparser.REG_DWORD, regparser.REG_DWORD_BIG_ENDIAN, regparser.REG_QWORD:
		// ValueData checks only the DECLARED size and then indexes the bytes it
		// actually read with binary.LittleEndian.Uint32/Uint64. Three shapes make
		// that index run off the end and panic, and each is one bit flip from the
		// 8,020 real Size and Usn QWORDs on a Windows 11 hive: a size that does not
		// match the type, the inline bit set on an eight-byte type (the inline
		// branch returns exactly four bytes whatever the declaration says), and a
		// data cell outside the hive (which yields no bytes at all). A big-data
		// cell is rejected with them: an integer is never stored as big data, and
		// the segment walk can also produce a short buffer.
		want := int64(4)
		if v.Type() == regparser.REG_QWORD {
			want = 8
		}
		if int64(size) != want {
			warn(warnValueShape, "amcache: an integer value declares %d bytes for a %d byte type; "+
				"the value is dropped", size, want)
			return "", false
		}
		if inline {
			if want != 4 {
				warn(warnValueShape, "amcache: an %d byte integer value is marked inline, "+
					"which yields 4 bytes; the value is dropped", want)
				return "", false
			}
		} else {
			cell := reg.Profile.HCELL(reg.Reader, 0x1000+int64(v.Data()))
			if cell.Signature() == sigDb || cell.Payload()+want > hiveLen {
				warn(warnValueShape, "amcache: an integer value points at a data cell that cannot "+
					"hold its %d bytes; the value is dropped", want)
				return "", false
			}
		}
		return strconv.FormatUint(v.ValueData().Uint64, 10), true

	case regparser.REG_SZ, regparser.REG_EXPAND_SZ:
		// Decoded here rather than read from ValueData().String for the reason
		// utf16le exists: regparser's UTF16BytesToUTF8 has its BOM branches
		// inverted, so a value whose first code unit is U+FEFF comes back
		// byte-swapped end to end -- and byte-swapped UTF-16 is still valid
		// UTF-8, so ToValidUTF8 below cannot catch it. The appraiser copies PE
		// metadata into the hive verbatim, so that first code unit is attacker
		// controlled.
		s := utf16le(v.ValueData().Data)
		// The cut is load-bearing, not cosmetic: regparser over-reads every inline
		// value to four bytes, so 17,223 of 200,517 real string values carry data
		// after their first NUL, and none carries no NUL at all.
		if i := strings.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		// The trim is a behavioural choice, not a formality: it alters 182 real
		// values across the four fixtures, so a golden diff on a whitespace-bearing
		// value is that choice and not a regression.
		s = strings.TrimSpace(s)
		// Cheap insurance. It has never changed a real value -- utf16.Decode already
		// emits U+FFFD -- and it does not repair a name read with the wrong width.
		return strings.ToValidUTF8(s, "\uFFFD"), true

	case regparser.REG_MULTI_SZ:
		// No fixture carries one: Hwids, HWID and COMPID are all REG_SZ. The format
		// permits it, so the branch exists.
		// Split here rather than reading ValueData().MultiSz, which renders each
		// segment through the same inverted-BOM decode as REG_SZ above.
		data := v.ValueData().Data
		out := make([]string, 0, 4)
		for i := 0; i+1 < len(data); {
			j := i
			for j+1 < len(data) && !(data[j] == 0 && data[j+1] == 0) {
				j += 2
			}
			if p := utf16le(data[i:j]); p != "" {
				out = append(out, p)
			}
			i = j + 2
		}
		return strings.Join(out, ","), true
	}

	// REG_BINARY and every unknown type. Expected, not a failure, so no warning.
	return "", false
}

// nodeName branches on KEY_COMP_NAME because regparser never consults it: Name
// reads NameLength raw bytes whatever the flag says, so an uncompressed name
// otherwise comes back as UTF-16 reinterpreted as a Go string, which
// ToValidUTF8 does not repair because interleaved NULs are valid UTF-8. Every
// name on every fixture is compressed, so the uncompressed branch is reachable
// today only from corrupt input -- one bit clears 0x20 -- and from a future
// non-ASCII host.
func nodeName(reg *regparser.Registry, n *regparser.CM_KEY_NODE) string {
	if n.Flags()&0x20 != 0 {
		return latin1(regparser.ParseSafeArray_byte(reg.Reader,
			n.Offset+reg.Profile.Off_CM_KEY_NODE__Name, int(n.NameLength())))
	}
	return utf16le(regparser.ParseSafeArray_byte(reg.Reader,
		n.Offset+reg.Profile.Off_CM_KEY_NODE__Name, int(n.NameLength())))
}

// latin1 decodes a compressed name. The compressed form is one byte per
// character over the Latin-1 range, not ASCII: Windows sets the flag whenever
// every character is <= 0xFF, so an accented character is stored as a single
// byte >= 0x80 and a raw cast leaves it as invalid UTF-8 in Name, which is the
// identity column every table keys on. Reachable from any non-English host, not
// only from a hostile hive.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// utf16le decodes with unicode/utf16 rather than regparser's UTF16BytesToUTF8,
// whose BOM branches are inverted.
func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// FILETIME ticks (100 ns) from 1601-01-01 to 1970-01-01 and to 2100-01-01.
const (
	filetimeEpoch = 116444736000000000
	filetimeMax   = 157469184000000000
)

// lastWrite reads the raw FILETIME instead of calling LastWriteTime, whose
// conversion is an unsigned subtraction: a zero FILETIME comes back as the year
// 60056 and IsZero is never true, so neither a cast nor IsZero can produce the
// LastWrite == 0 this contract promises for a zero or pre-epoch stamp. The
// upper bound is here for the same reason -- a corrupt stamp must read as
// unknown, not as a date three centuries out.
func lastWrite(reg *regparser.Registry, n *regparser.CM_KEY_NODE) int64 {
	ft := regparser.ParseUint64(reg.Reader, n.Offset+reg.Profile.Off_CM_KEY_NODE_LastWriteTime)
	if ft < filetimeEpoch || ft >= filetimeMax {
		return 0
	}
	return int64(ft/10000000) - filetimeEpoch/10000000
}
