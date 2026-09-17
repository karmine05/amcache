//go:build !windows

package hive

import (
	"context"
	"errors"
)

// Read is the non-Windows half of the acquisition API. The extension only ever
// runs on Windows; this stub exists so that `go build ./...` and `go vet ./...`
// stay green on a macOS host and in fleet's linux CI, where every file behind
// //go:build windows is invisible.
func Read(ctx context.Context) (Result, error) {
	return Result{}, errors.ErrUnsupported
}
