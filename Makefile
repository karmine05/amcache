# amcache — Windows-only osquery extension build.
#
# `make dist` produces the two release binaries plus their checksums:
#
#   build/amcache_windows.ext.exe          (windows/amd64)
#   build/amcache_windows_arm64.ext.exe    (windows/arm64)
#
# `make check` is the gate that must be green before every commit.

BINARY  := amcache_windows
PKG     := ./cmd/amcache_windows
BUILD   := build
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

GO_TOOLCHAIN   := go1.27.1
GOSEC_VERSION  := v2.29.0
GOVULN_VERSION := v1.8.0
TOOLBIN        := $(CURDIR)/.tools

.PHONY: all check fmt fmtcheck vet test sec vuln build windows windows-arm64 \
        testbin dist osq-verify-windows clean

all: check build

## ---- quality gates (run before every commit) ----
check: fmtcheck vet sec vuln test

fmtcheck:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

fmt:
	gofmt -w .

# Host vet catches the tag-free code; the GOOS=windows pass is the only one that
# sees the //go:build windows files, which are most of the filesystem surface.
vet:
	go vet ./...
	GOOS=windows go vet ./...

# -race requires cgo and so cannot cross-compile; host-only by necessity.
# tests/ is gitignored and absent on a fresh clone, hence the guard. The guard is
# an if and not `test -d tests && go test ... || echo`: in that form the echo
# also runs when go test fails, which leaves the recipe exiting 0 on a red suite.
test:
	@if [ -d tests ]; then go test -race -count=1 ./...; else echo "tests/ absent (gitignored)"; fi

# GOTOOLCHAIN and the cleared GOOS/GOARCH are both load-bearing. A govulncheck
# built by a Go older than this module's `go 1.27.1` directive hard-fails with
# "package requires newer Go version", and a GOOS=windows install cross-compiles
# the tool itself into an .exe this host cannot execute.
$(TOOLBIN)/gosec:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(TOOLBIN) GOOS= GOARCH= go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

$(TOOLBIN)/govulncheck:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(TOOLBIN) GOOS= GOARCH= go install golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION)

# gosec runs under GOOS=windows only: on the host, //go:build windows hides every
# file that touches the filesystem, so a host run reports nothing and is noise.
sec: $(TOOLBIN)/gosec
	GOOS=windows $(TOOLBIN)/gosec -severity medium -quiet ./...

vuln: $(TOOLBIN)/govulncheck
	$(TOOLBIN)/govulncheck ./...
	GOOS=windows $(TOOLBIN)/govulncheck ./...

## ---- build ----
build: windows

windows:
	@mkdir -p $(BUILD)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD)/$(BINARY).ext.exe $(PKG)
	@echo "built $(BUILD)/$(BINARY).ext.exe"

windows-arm64:
	@mkdir -p $(BUILD)
	GOOS=windows GOARCH=arm64 $(GOBUILD) -o $(BUILD)/$(BINARY)_arm64.ext.exe $(PKG)
	@echo "built $(BUILD)/$(BINARY)_arm64.ext.exe"

# The Windows test binary the owner runs from elevated PowerShell. No -race here
# (see `test`); tests/ is gitignored, so this only works on a machine that has it.
testbin:
	@test -d tests || { echo "tests/ absent (gitignored) — nothing to compile"; exit 1; }
	@mkdir -p $(BUILD)
	GOOS=windows GOARCH=amd64 go test -c -o $(BUILD)/amcache_tests.exe ./tests
	@echo "built $(BUILD)/amcache_tests.exe"

## ---- release artifacts ----
# shasum -a 256 is the portable choice: it exists on macOS and emits the same
# "<hex>  <name>" format as coreutils sha256sum in CI.
dist: windows windows-arm64
	cd $(BUILD) && shasum -a 256 *.exe > SHA256SUMS
	@echo "checksums:" && cat $(BUILD)/SHA256SUMS

VERIFY_SQL := SELECT count(*) AS n FROM amcache_application_files

# Windows containers cannot run on a macOS/Linux Docker host, so there is no
# cross-host path: this target runs natively on a Windows host (GNU Make inherits
# OS=Windows_NT there) and otherwise prints guidance and fails.
osq-verify-windows: windows
ifeq ($(OS),Windows_NT)
	osqueryi.exe --allow_unsafe --extension "$(CURDIR)/$(BUILD)/$(BINARY).ext.exe" \
	  --extensions_require=amcache_windows --extensions_timeout=10 "$(VERIFY_SQL)"
else
	@echo "osq-verify-windows must run on a Windows host (osqueryi.exe loads the"
	@echo ".ext.exe build). Run it there, or on a windows-latest CI runner. The"
	@echo "binary still cross-builds here with 'make windows'."
	@exit 1
endif

clean:
	rm -rf $(BUILD) $(TOOLBIN)
