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
	"time"

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

	if err := server.Run(); err != nil {
		log.Fatalf("amcache_windows: running extension server: %v", err)
	}
}
