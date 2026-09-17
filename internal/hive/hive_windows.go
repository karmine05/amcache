//go:build windows

package hive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"www.velocidex.com/golang/go-ntfs/parser"
)

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
	if len(dir) < 3 || dir[1] != ':' || dir[2] != '\\' {
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
