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
GOSEC          := $(TOOLBIN)/gosec-$(GOSEC_VERSION)
GOVULN         := $(TOOLBIN)/govulncheck-$(GOVULN_VERSION)

.PHONY: all check fmt fmtcheck vet test sec vuln build windows windows-arm64 \
        testbin dist osq-verify-windows clean

all: check build

## ---- quality gates (run before every commit) ----
check: fmtcheck modcheck vet buildcheck sec vuln test

fmtcheck:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# CI runs these two and `check` did not, so a green gate here could still push a
# red run there -- which breaks the only thing the pre-commit contract in
# CLAUDE.md rests on. Both are near-instant and need no network.
modcheck:
	go mod verify
	go mod tidy -diff

fmt:
	gofmt -w .

# Host vet catches the tag-free code; the GOOS=windows pass is the only one that
# sees the //go:build windows files, which are most of the filesystem surface.
vet:
	go vet ./...
	GOOS=windows GOARCH=amd64 go vet ./...
	GOOS=windows GOARCH=arm64 go vet ./...

# GOARCH is pinned above rather than inherited: this host is arm64, so a bare
# GOOS=windows pass never compiled the windows/amd64 target that actually ships.
#
# buildcheck compiles what CI cross-builds, without producing artifacts. `vet`
# type-checks but does not link, so a failure that only appears at link time
# (a missing symbol behind a build tag) reaches CI otherwise.
buildcheck:
	GOOS=windows GOARCH=amd64 go build -o /dev/null ./...
	GOOS=windows GOARCH=arm64 go build -o /dev/null ./...

# -race requires cgo and so cannot cross-compile; host-only by necessity.
# tests/ is gitignored and absent on a fresh clone, hence the guard. The guard is
# an if and not `test -d tests && go test ... || echo`: in that form the echo
# also runs when go test fails, which leaves the recipe exiting 0 on a red suite.
#
# Two invocations, and the split is deliberate. TestFuzzParse is sharded over
# NumCPU workers and runs 4,400 parses of each fixture: about 22 s unraced
# against 5 m 25 s under -race, which is the difference between a gate that runs
# before every commit and one that gets skipped. The parser spawns no goroutines
# of its own, so the only race that harness can find is package-level mutable
# state in internal/inventory -- which research finding F-13 already turns into a
# hard design rule (no package-level mutables, sync.Once for the warning dedupe).
#
# That left a hole worth naming: with the fuzz skipped, no remaining test parsed
# from two goroutines at once, so -race on the first invocation had nothing in
# this package to observe and the one test that did parse concurrently was the
# one deliberately built without the detector. TestParseIsRaceFree exists to
# close it -- it parses from NumCPU goroutines, runs in the raced invocation,
# and costs milliseconds.
#
# The two filters are one pair: the -skip and the -run must both keep matching
# the TestFuzz prefix in tests/inventory_fuzz_test.go, or the fuzz either runs
# twice (once raced) or not at all.
#
# && , never ; -- a failure in the first invocation must not be overwritten by a
# second that succeeds. That is CR-05's defect one command over.
test:
	@if [ -d tests ]; then \
	  go test -race -count=1 -skip 'TestFuzz' ./... && \
	  go test -count=1 -run 'TestFuzz' ./tests; \
	else echo "tests/ absent (gitignored)"; fi

# GOTOOLCHAIN and the cleared GOOS/GOARCH are both load-bearing. A govulncheck
# built by a Go older than this module's `go 1.27.1` directive hard-fails with
# "package requires newer Go version", and a GOOS=windows install cross-compiles
# the tool itself into an .exe this host cannot execute.
#
# The version is stamped into the target name because these are file targets with
# no prerequisites: with a bare $(TOOLBIN)/gosec, make considers an installed
# binary up to date whatever the version variable says, so bumping GOSEC_VERSION
# would silently keep enforcing SEC-02 with the previously installed build.
$(GOSEC):
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(TOOLBIN) GOOS= GOARCH= go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	mv $(TOOLBIN)/gosec $@

$(GOVULN):
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GOBIN=$(TOOLBIN) GOOS= GOARCH= go install golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION)
	mv $(TOOLBIN)/govulncheck $@

# gosec runs under GOOS=windows only: on the host, //go:build windows hides every
# file that touches the filesystem, so a host run reports nothing and is noise.
sec: $(GOSEC)
	GOOS=windows $(GOSEC) -severity medium -quiet ./...

vuln: $(GOVULN)
	$(GOVULN) ./...
	GOOS=windows $(GOVULN) ./...

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
# The artifacts are named, not globbed: `make testbin` writes
# build/amcache_tests.exe into the same directory and nothing cleans it, so a
# glob puts a test binary in the supply-chain root anyone deploying this reads.
dist: windows windows-arm64
	cd $(BUILD) && shasum -a 256 $(BINARY).ext.exe $(BINARY)_arm64.ext.exe > SHA256SUMS
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
