//go:build !windows

package hive

import (
	"context"
	"errors"
	"time"
)

// Read is the non-Windows half of the acquisition API. The extension only ever
// runs on Windows; this stub exists so that `go build ./...` and `go vet ./...`
// stay green on a macOS host and in fleet's linux CI, where every file behind
// //go:build windows is invisible.
func Read(ctx context.Context) (Result, error) {
	return Result{}, errors.ErrUnsupported
}

// Stat is the non-Windows half of the freshness API, and exists for the reason
// the Read stub above does: the hive path is derived from a Windows API, so
// every caller of it is invisible to a macOS or linux build without this.
func Stat() (time.Time, int64, error) {
	return time.Time{}, 0, errors.ErrUnsupported
}
