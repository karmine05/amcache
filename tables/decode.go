// Decoders and the row build: what a column means, as opposed to what the hive
// says.
//
// The parser already rendered every value as far as a string -- REG_SZ cut at
// the first NUL, trimmed and made valid UTF-8, every DWORD and QWORD through
// strconv.FormatUint, names UTF-16LE or Latin-1 decoded. None of that is redone
// here; doing it twice is a second place for the behaviour to drift. What is
// left is semantic, and it is where a mistake is invisible: a wrong date layout
// produces an empty bigint column that reads exactly like a value Windows never
// recorded.

package tables

import (
	"context"
	"encoding/hex"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/amcache/internal/inventory"
)

// The package logs through this one variable so a vendoring host can point it
// at its own sink by assigning once, before any goroutine exists.
var logf = log.Printf

// One decode-failure line per column per process.
//
// sync.Map rather than a map guarded by a bool: osquery calls Generate per
// table and the seven calls can overlap, so a plain map here is a write/write
// race. The key is the table and column name, both constants in columns.go.
var warned sync.Map

// warnDecode reports that a column rejected n non-empty values.
//
// Never the value, and never a cause the decoder did not test. The distinction
// is not pedantry: on a healthy Windows 11 host 526 of 4,010 LinkDate values
// are version strings the appraiser copied out of the PE header, so this line
// fires on hardware with nothing wrong with it. Worded as a defect in this
// extension it would train an operator to ignore the one signal that also
// catches a genuine ladder regression, so it is worded as an observation and
// the column is not exempted from it.
func warnDecode(tbl, col string, n int) {
	if _, dup := warned.LoadOrStore(tbl+"\x00"+col, struct{}{}); dup {
		return
	}
	logf("amcache: %s.%s: %d non-empty value(s) could not be decoded for this column "+
		"and are reported as empty; later occurrences are not logged", tbl, col, n)
}

// decodeInt accepts plain unsigned decimal and returns it unchanged.
//
// Unchanged and never narrowed. DriverTimeStamp exceeds 2^31-1 on 665 of the
// 1,581 values on every reference hive and the largest of them renders as a
// negative epoch through any 32-bit conversion, so whether the operator sees it
// intact is decided by the column's osquery type in columns.go and must not be
// pre-empted here.
//
// No 0x branch. The design contract specified one for pre-1709 hives; this
// extension claims Windows 10 1809 and later, no int column on any reference
// hive carries a 0x-prefixed value, and an unreachable branch is a branch
// nobody has watched work. Never signed either: ParseUint rejects a sign, and a
// negative here would be a corrupt value rather than a small number.
func decodeInt(s string) (string, bool) {
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return "", false
	}
	return s, true
}

// decodeBool normalises the two spellings Windows uses for these flags.
//
// Every observed value is exactly "0" or "1", so the true/false arm ships
// unexercised by any hive. Anything else is a failure rather than the design
// contract's "non-zero is true": none of these sources is a multi-bit field,
// and mapping a 2 to true would hide a column pointed at the wrong value.
func decodeBool(s string) (string, bool) {
	switch strings.ToLower(s) {
	case "1", "true":
		return "1", true
	case "0", "false":
		return "0", true
	}
	return "", false
}

// The date layouts, in the order they are tried. Each is the only form its own
// fields ever take, and no value on any reference hive matches two of them.
var timeLayouts = [...]string{
	"1/2/2006 15:04:05", // LinkDate, InstallDate (applications), MsiInstallDate, DriverLastWriteTime
	"1/2/2006",          // matched by nothing on any hive; Microsoft documents a date-only InstallDate
	"1-2-2006",          // every InventoryDevicePnp date
	"2006-1-2",          // InventoryDriverPackage.Date, year first, month and day unpadded
}

// Parsing is not evidence of a date. "1/1/1601 00:00:00" is a well-formed value
// of the first layout and converts to unix -11644473600, which reaches a
// forensic timeline as a 17th-century event rather than as the zero FILETIME it
// is; the parser hit the same class of bug from the other side and guards its
// own last-write conversion for the same reason.
//
// 1980 sits below the earliest plausible Windows file date and far above the
// FILETIME epoch, and a year of slack absorbs a host clock running ahead.
//
// The guard belongs to this ladder alone and must never be extended to kEpoch:
// DriverTimeStamp reaches 4,289,408,507 on real inbox drivers, which is the
// year 2105, and it is a PE header field rather than a wall-clock date.
var epochFloor = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func plausible(t time.Time) bool {
	return !t.Before(epochFloor) && t.Before(time.Now().AddDate(1, 0, 0))
}

// decodeTime converts an Amcache date string to unix seconds.
//
// The ladder is this file's reason to exist. The design contract specified the
// first two rungs only, which decode 0 of the 1,378 InventoryDevicePnp dates
// and 0 of the 92 InventoryDriverPackage dates: four bigint columns empty on
// every host, indistinguishable from a value Windows never wrote.
//
// Two counter-intuitive facts, recorded so nobody re-derives them wrongly. Go
// accepts an unpadded month, day and hour under these layouts but rejects an
// unpadded minute or second, so "1/2/2006 15:04:05" is not interchangeable with
// "1/2/2006 3:4:5" -- harmless only because every observed value is zero-padded
// in its time part. And "1-2-2006" cannot swallow a year-first value, because
// Go's numeric month accepts at most two digits.
//
// UTC is an assumption: Amcache records no zone. It is stated in every *_time
// description and is checked against file mtimes on a live host before the
// phase closes; a correction is this call plus a golden regeneration.
//
// LinkDate is where the empty return earns its place. It is attacker-influenced
// PE metadata the appraiser copies without validating, and roughly 13 percent
// of its values on a Windows 11 host are version strings rather than
// timestamps. This returns a timestamp only when it has one, whatever the
// reason a value is not one: every non-date observed so far happens to be a
// copy of the record's own ProductVersion, but that is a measured property of
// the hives in hand and is never this decoder's test.
func decodeTime(s string) (string, bool) {
	for _, layout := range timeLayouts {
		t, err := time.ParseInLocation(layout, s, time.UTC)
		if err != nil {
			continue
		}
		if !plausible(t) {
			return "", false
		}
		return strconv.FormatInt(t.Unix(), 10), true
	}
	return "", false
}

// decodeMulti normalises an already comma-joined list.
//
// A normalisation, never a re-parse. These columns are REG_SZ that the
// appraiser itself joined: REG_MULTI_SZ occurs nowhere in the seven keys, and a
// raw pass found no value holding more than one non-empty NUL-separated
// segment, so the parser's cut at the first NUL discarded nothing. 68 of 92
// Hwids values contain a comma inside an element, so element boundaries are not
// recoverable and nothing here may try to recover them. Measured effect on real
// data: 8 items on 4 of 38,203 records. It cannot fail.
func decodeMulti(s string) string {
	items := strings.Split(s, ",")
	out := items[:0]
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return strings.Join(out, ",")
}

// decodeSha1 returns the SHA-1 a FileId or a DriverId carries.
//
// The shape test is a guard on a column the spec already named, never a way to
// find a hash. ProgramId, ProgramInstanceId and ShortcutProgramId pass this
// identical test 32,617 times across the reference hives, and FileId never
// equals ProgramId on any of the 34,304 records carrying both -- so the
// widely-copied sha1 = ProgramId[4:] is wrong on every row it emits, and no
// shape check anywhere can detect that. Only columns.go decides what is hashed.
//
// Windows hashes the first 31,457,280 bytes of the file only; the schema says
// so, because the value is not a whole-file SHA-1 for anything larger. The
// 40-character arm is defence: all 29,790 non-empty FileId and DriverId values
// on the reference hives are 44 characters, so no hive exercises it.
func decodeSha1(s string) (string, bool) {
	switch {
	case len(s) == 44 && strings.HasPrefix(s, "0000"):
		s = s[4:]
	case len(s) != 40:
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return strings.ToLower(s), true
}

// cell decodes one column of one record. The second result is false only for a
// non-empty value the column rejected.
//
// The switch is on the column's kind and on nothing else, which is the whole
// defence against the defect described above decodeSha1: a decoder that
// inspected a value to decide what it was would read a ProgramId as a hash
// 31,265 times on one hive and pass its own test every time.
func cell(c col, rec inventory.Record) (string, bool) {
	switch c.kind {
	case kKey:
		return rec.Name, true
	case kKeyPath:
		// Unconditional, and it is the join rather than cosmetics: 121 of 146
		// Windows 11 parent_id values find another row's device_instance_id after
		// this rewrite and none before it. Exactly one subkey per hive is a braced
		// GUID and not a path at all, so any "does this look like a path" test
		// would drop that row out of the table.
		return strings.ReplaceAll(rec.Name, "/", `\`), true
	case kKeyLower:
		return strings.ToLower(rec.Name), true
	case kKeyTime:
		// 0 is the parser's "unknown", never the 1970 epoch.
		if rec.LastWrite == 0 {
			return "", true
		}
		return strconv.FormatInt(rec.LastWrite, 10), true
	}

	s := rec.V[c.src]
	if s == "" {
		// An absent value and a present-but-empty one are the same fact, and
		// neither is a decode failure: FileId is present on all 16,850 Windows 11
		// file records and empty on 3,217 of them, so warning here would fire the
		// sha1 line on a healthy host and teach the operator to ignore it.
		return "", true
	}

	switch c.kind {
	case kInt, kEpoch:
		// kEpoch is kInt's validation and nothing else: the value is already unix
		// seconds, so it must reach neither the date ladder nor the plausibility
		// guard, which would empty 665 of the 1,581 real DriverTimeStamp values.
		return decodeInt(s)
	case kBool:
		return decodeBool(s)
	case kTime:
		return decodeTime(s)
	case kMulti:
		return decodeMulti(s), true
	case kSha1:
		return decodeSha1(s)
	case kLower:
		// A GUID is case-insensitive, so this loses nothing, and it is what keeps
		// a join between device_pnp.container_id and device_containers.container_id
		// -- whose own side is lowercased from the subkey -- from depending on both
		// sides of a future hive happening to agree. No reference hive exercises
		// it: all 464 values are already lowercase.
		return strings.ToLower(s), true
	default: // kText
		return s, true
	}
}

// rowsFor builds one row per selected record. sel nil means every record.
//
// Every declared column is present in every row, with "" when the value is
// absent -- not usually, always. osquery renders a missing key as SQL NULL and
// logs a line per row while doing it, which on a 16,850-row table with several
// sparse columns is a verbose-log flood for nothing. What an empty cell looks
// like in SQL still depends on the column type: text renders the empty string,
// integer and bigint render NULL, which is why the schema notes and every
// numeric README predicate have to speak for their own type rather than quote
// one convention.
//
// No row cap and no truncation. A forensic table that silently drops rows fails
// the investigation with no way for the operator to know; the 1 MB Fleet
// log-line limit is documented instead of enforced.
func rowsFor(ctx context.Context, s spec, recs []inventory.Record, sel []int32) ([]map[string]string, error) {
	n := len(recs)
	if sel != nil {
		n = len(sel)
	}
	// Pre-sized because the allocation profile here is the opposite of the
	// obvious one: the widest row in the extension is in a 43-row table, one of
	// whose hwids values is 497,663 bytes on its own, and the 16,850-row table's
	// widest row is under 800.
	rows := make([]map[string]string, 0, n)
	var failed map[string]int

	for i := 0; i < n; i++ {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		rec := recs[i]
		if sel != nil {
			// The indices are built over this same slice by the caller. A stale one
			// panics here rather than silently serving the wrong rows, and Generate's
			// recover turns that into an error the operator sees.
			rec = recs[sel[i]]
		}
		row := make(map[string]string, len(s.cols))
		for _, c := range s.cols {
			v, ok := cell(c, rec)
			if !ok {
				if failed == nil {
					failed = make(map[string]int)
				}
				failed[c.name]++
			}
			row[c.name] = v
		}
		rows = append(rows, row)
	}

	for name, count := range failed {
		warnDecode(s.table, name, count)
	}
	return rows, nil
}
