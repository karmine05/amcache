//go:build windows

package hive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"www.velocidex.com/golang/go-ntfs/parser"
)

// Read acquires the Amcache hive and returns it ready to parse, replaying the
// transaction logs in memory when the hive is dirty. Result records which route
// produced the bytes and whether a replay was needed, because the caller is the
// only place that logs.
//
// Data returned with a nil error is always clean: a hive that is still dirty
// after replay comes back as an error instead, with whatever log reads failed
// joined to it. A torn hive parses into rows that look exactly as authoritative
// as correct ones, so there is no useful way for a caller to act on "here are
// the bytes, they may be from two generations at once".
func Read(ctx context.Context) (Result, error) {
	s, err := acquireHive(ctx)
	if err != nil {
		return Result{}, err
	}
	res := Result{Data: s.data, Raw: s.raw}

	dirty, err := Dirty(res.Data)
	if err != nil {
		return Result{}, err
	}
	if !dirty {
		// An idle host never touches the logs at all: reading them would be
		// pointless I/O and, on the raw route, a second privileged volume open.
		return res, nil
	}
	res.Replayed = true

	if cerr := ctx.Err(); cerr != nil {
		return Result{}, cerr
	}
	// One unreadable log is not fatal on its own: the other may carry the whole
	// chain, and partial recovery beats no data. What is fatal is ending up with
	// a hive the logs did not clean. This package has no logger, so the reads
	// that failed are carried until it is known whether they mattered.
	var logs [][]byte
	var logErrs []error
	for _, suffix := range []string{".LOG1", ".LOG2"} {
		b, lerr := s.readLog(suffix)
		if lerr != nil {
			logErrs = append(logErrs, fmt.Errorf("amcache: %s%s: %w", s.path, suffix, lerr))
			continue
		}
		logs = append(logs, b)
	}
	// ctx is not checked inside Replay: that is pure CPU over resident bytes.
	out, err := Replay(res.Data, logs...)
	if err != nil {
		return Result{}, err
	}
	stillDirty, err := Dirty(out)
	if err != nil {
		return Result{}, err
	}
	if stillDirty {
		return Result{}, errors.Join(append(logErrs,
			fmt.Errorf("amcache: %s is dirty and the transaction logs did not recover it", s.path))...)
	}
	res.Data = out
	return res, nil
}

// Files holds the hive and its two transaction logs as they are on disk,
// unreplayed.
type Files struct {
	Hive, Log1, Log2 []byte
	Raw              bool
}

// ReadFiles exists only so the Windows test binary can capture a fixture: the
// replay has to be re-runnable later, on another machine, against the exact
// bytes the host held at capture time. Read is the production entry point.
func ReadFiles(ctx context.Context) (Files, error) {
	s, err := acquireHive(ctx)
	if err != nil {
		return Files{}, err
	}
	if cerr := ctx.Err(); cerr != nil {
		return Files{}, cerr
	}
	// Both logs are read whether or not the hive is dirty, and a log that cannot
	// be read leaves its field nil.
	f := Files{Hive: s.data, Raw: s.raw}
	f.Log1, _ = s.readLog(".LOG1")
	f.Log2, _ = s.readLog(".LOG2")
	return f, nil
}

// source is an acquired hive plus what the log reads need to follow the same
// route. Read and ReadFiles share it so the classification below cannot drift
// between them.
type source struct {
	drive string
	path  string
	data  []byte
	raw   bool
}

func acquireHive(ctx context.Context) (source, error) {
	dir, path, err := hivePath()
	if err != nil {
		return source{}, err
	}
	s := source{drive: dir[:2], path: path}

	// The case order is the classification: absent first, then the two share
	// violations, then everything else unchanged. errors.Is separates all three
	// cleanly through the *fs.PathError, whichever stage inside readPlain
	// produced the failure.
	data, err := readPlain(path, MaxHiveBytes)
	switch {
	case err == nil:
		s.data = data
		return s, nil
	case errors.Is(err, fs.ErrNotExist):
		return source{}, ErrNotFound
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION),
		errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		// The appraiser has the hive open. A raw volume handle is privileged and
		// high-signal to any EDR, so it is opened for this one failure and for
		// nothing else; a violation raised mid-read is as much a trigger as one
		// raised at open.
		if cerr := ctx.Err(); cerr != nil {
			return source{}, cerr
		}
		raw, rerr := readRaw(s.drive, path, MaxHiveBytes)
		if rerr != nil {
			return source{}, rerr
		}
		s.data, s.raw = raw, true
		return s, nil
	default:
		return source{}, err
	}
}

// readLog reads one transaction log through whichever route produced the hive.
// On the raw route this opens a second volume handle rather than threading one
// NTFS context through both reads; it only fires when the hive is dirty and
// locked at the same time.
func (s source) readLog(suffix string) ([]byte, error) {
	if s.raw {
		return readRaw(s.drive, s.path+suffix, MaxLogBytes)
	}
	return readPlain(s.path+suffix, MaxLogBytes)
}

// hivePath returns the Windows directory and the hive path under it. The
// directory comes from the API and never from an environment variable: this
// process runs as SYSTEM and the environment is caller-controlled.
func hivePath() (dir, path string, err error) {
	dir, err = windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", "", fmt.Errorf("amcache: system windows directory: %w", err)
	}
	// GetSystemWindowsDirectoryW always returns a drive-qualified path, so a
	// value that is not X:\... means the API or the host is not what we think it
	// is, and dir[:2] is about to be concatenated into a \\.\ device path.
	if len(dir) < 3 || dir[2] != '\\' || dir[1] != ':' ||
		!(dir[0] >= 'A' && dir[0] <= 'Z' || dir[0] >= 'a' && dir[0] <= 'z') {
		return "", "", fmt.Errorf("amcache: unexpected windows directory %q", dir)
	}
	return dir, filepath.Join(dir, `AppCompat\Programs\Amcache.hve`), nil
}

// readPlain reads path through the filesystem, refusing anything over limit.
//
// os.Open is deliberately not replaced by a windows.CreateFile wrapper: stdlib
// already opens with GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
// OPEN_EXISTING and FILE_FLAG_BACKUP_SEMANTICS, which is exactly what is wanted,
// and it fails with an *fs.PathError whose syscall.Errno errors.Is can classify.
// Errors are returned unwrapped for that reason.
func readPlain(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed path under GetSystemWindowsDirectory
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("amcache: %s is not a regular file", path)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("amcache: %s is %d bytes, over the %d byte cap", path, st.Size(), limit)
	}
	// The +1 is what makes "nothing past the cap enters the process" provable:
	// at most limit+1 bytes are ever read, and the extra byte is the refusal
	// signal for a file that grew between the Stat and the read.
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("amcache: %s is over the %d byte cap", path, limit)
	}
	return buf, nil
}

// readRaw reads winPath out of the NTFS volume behind drive (`C:`), below the
// share-mode check the filesystem enforces. The handle is privileged and
// high-signal to any EDR, so callers reach here only for the one failure it
// fixes.
func readRaw(drive, winPath string, limit int64) ([]byte, error) {
	vol, err := os.Open(`\\.\` + drive) // #nosec G304 -- drive letter comes from GetSystemWindowsDirectory, not user input
	if err != nil {
		return nil, fmt.Errorf("amcache: open volume %s: %w", drive, err)
	}
	defer vol.Close()

	// cache_size is an LRU entry count, so this is 16 pages of 1 MiB. The 1 MiB
	// alignment is also what makes the reads legal: a raw volume handle rejects
	// unaligned and short reads, which is why the volume is never handed to
	// io.ReadAll.
	// ponytail: 16 MiB page cache, raise cache_size if raw reads on Server 2025 are slow
	pr, err := parser.NewPagedReader(vol, 1<<20, 16)
	if err != nil {
		return nil, fmt.Errorf("amcache: paged reader on %s: %w", drive, err)
	}
	ntfs, err := parser.GetNTFSContext(pr, 0)
	if err != nil {
		return nil, fmt.Errorf("amcache: ntfs context on %s: %w", drive, err)
	}
	defer ntfs.Close()

	// The drive letter has to go: GetDataForPath splits the path on its first
	// colon to detect an alternate data stream, so a drive-qualified path looks
	// for a file named C carrying a stream named /Windows/....
	rng, err := parser.GetDataForPath(ntfs, filepath.ToSlash(winPath[2:]))
	if err != nil {
		return nil, fmt.Errorf("amcache: raw lookup of %s: %w", winPath, err)
	}
	// RangeSize returns 0 for a file with no runs, so n <= 0 is a real case and
	// not defensive padding. Both bounds precede the allocation.
	n := parser.RangeSize(rng)
	if n <= 0 || n > limit {
		return nil, fmt.Errorf("amcache: raw %s is %d bytes, outside (0, %d]", winPath, n, limit)
	}
	buf := make([]byte, n)
	// A short read past the last run reports io.EOF with the bytes already
	// filled in, so EOF is an outcome here and not a failure.
	got, err := rng.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("amcache: raw read of %s: %w", winPath, err)
	}
	return buf[:got], nil
}
