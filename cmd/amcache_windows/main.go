// Command amcache_windows is an osquery extension that exposes read-only
// tables over the Windows Amcache hive
// (C:\Windows\AppCompat\Programs\Amcache.hve): application files with their
// SHA-1s, installed applications and shortcuts, driver binaries and packages,
// and PnP device inventory.
//
// It speaks the osquery Thrift extension protocol over a named pipe. osquery
// autoloads it (--extensions_autoload) and passes --socket, --timeout and
// --interval; it can also be loaded by hand against osqueryi via
//
//	osqueryi.exe --extension .\amcache_windows.ext.exe
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/karmine05/amcache/tables"
	osquery "github.com/osquery/osquery-go"
)

// version is stamped at build time with -X main.version=$(VERSION).
var version = "dev"

func main() {
	socket := flag.String("socket", "", "path to the osquery extension socket (required)")
	interval := flag.Int("interval", 3, "seconds between extension health checks")
	flag.Int("timeout", 3, "seconds to wait for autoloaded extensions (accepted for osquery compatibility; ignored)")
	flag.Bool("verbose", false, "verbose mode (accepted for osquery compatibility; ignored)")
	flag.Parse()

	if *socket == "" {
		log.Fatalln("amcache_windows: --socket is required")
	}
	// osquery-go's health-check loop hands this straight to time.Sleep inside an
	// unconditional for, so a non-positive value returns immediately and spins a
	// goroutine pinging the extension socket as fast as the CPU allows.
	if *interval <= 0 {
		log.Fatalln("amcache_windows: --interval must be positive")
	}

	// regparser's init() has already read REGPARSER_DEBUG by the time any of
	// this runs, and an empty value enables it too, so unsetting the variable
	// cannot suppress anything. Its DebugPrint then writes hex signatures and
	// cell offsets through fmt.Printf, which reads os.Stdout at call time --
	// so replacing os.Stdout does suppress it.
	//
	// The exposure is information disclosure and log noise from a process
	// running as SYSTEM, not a broken protocol: the extension speaks thrift over
	// a Windows named pipe, and stdout is not the transport. Earlier notes in
	// this project said otherwise and were wrong.
	//
	// Here, before the server exists, and therefore before any goroutine exists:
	// assigning a package variable that other goroutines read is a data race.
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err != nil {
		// Serving tables matters more than silencing a debug path, so this is
		// reported and not fatal.
		log.Printf("amcache_windows: stdout not redirected to %s: %v", os.DevNull, err)
	} else {
		os.Stdout = null
	}

	// 60 s is the thrift socket timeout, not osquery's --timeout: a cold read of
	// the hive can need a raw NTFS read of the system volume plus transaction-log
	// replay plus a full parse, which takes seconds. Fleet allows 5 minutes for
	// the same reason in orbit/pkg/table/extension.go.
	server, err := osquery.NewExtensionManagerServer(
		"amcache_windows", *socket,
		osquery.ExtensionVersion(version),
		osquery.ServerTimeout(60*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("amcache_windows: creating extension server: %v", err)
	}

	for _, p := range tables.All() {
		server.RegisterPlugin(p)
	}

	if err := server.Run(); err != nil {
		log.Fatalf("amcache_windows: running extension server: %v", err)
	}
}
