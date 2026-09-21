# amcache

A Fleet and osquery extension that reads
`C:\Windows\AppCompat\Programs\Amcache.hve` on a live Windows host and serves it
as seven SQL tables.

It's built for [Fleet](https://fleetdm.com): the tables follow Fleet's schema
conventions, `schema/` ships the seven YAML files Fleet's documentation merger
consumes, and the package is laid out so Fleet can vendor it into
`fleetdm/fleet` as `orbit/pkg/table/amcache` (fleetdm/fleet#31103). It's a
plain osquery extension underneath, so it also loads under any osquery install
that is not managed by Fleet.

Amcache is the Microsoft Compatibility Appraiser's inventory of the machine:
SHA-1 and full path for executables it has seen, installed programs, driver
binaries and packages, and every PnP device ever attached. Unlike shimcache it
does not need a reboot to flush, so an investigator can query it mid-incident.

The extension reads the hive in place. When the appraiser holds it open, it
falls back to a raw NTFS read of the volume; when the hive is mid-write, it
replays `Amcache.hve.LOG1` and `.LOG2` in memory. It never writes, never shells
out, never opens a socket, and creates no temporary files.

## The gap this fills

osquery has had no Amcache table since the request was opened in 2020
(osquery/osquery#6639). Fleet users asked for one again in 2025
(fleetdm/fleet#31103). Until now the answer on Windows was `shimcache`, and
`shimcache` only flushes to disk on reboot.

That single sentence is the whole problem. Consider the shape of a real
incident.

A detection fires at 02:00: a hash your intel feed flagged an hour ago. You
need to know which machines in a fleet of twelve thousand have ever run it, and
you need to know before the operator at each desk wakes up and starts using
their laptop. `processes` only sees what is running right now, and the thing you
are hunting exited weeks ago. `shimcache` holds the answer but won't write it
to disk until the machine reboots, and rebooting twelve thousand endpoints to
answer a question destroys the volatile evidence you would want if any of them
comes back positive. The honest options were: wait for the next reboot cycle
and hope, or pick the hosts you can justify pulling offline, image them, and run
a forensics tool over the hive by hand. Both answer the question days late, and
the second answers it for a handful of machines rather than for the fleet.

Amcache already had the answer the entire time. The Microsoft Compatibility
Appraiser writes SHA-1, full path, publisher and PE metadata for binaries it has
seen, and it writes them continuously rather than at shutdown. The file simply
was not readable through osquery: it's a registry hive the appraiser usually
holds open, frequently mid-write, and osquery's registry table cannot open an
arbitrary hive file at all.

This extension makes that file queryable in place, while locked, without
a reboot and without taking the host offline. The 02:00 question becomes a live
query, sub-second per host once the hive is parsed and cached, and a few seconds
on the first query of a locked hive:

```sql
SELECT path, sha1, last_write_time FROM amcache_application_files
WHERE sha1 = '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12';
```

What that changes for an operator, concretely:

- **Fleet-wide retrospective hunting.** An IOC sweep now covers what machines
  have run historically, not just what they are running at the moment you ask.
- **Triage without acquisition.** Scoping an incident stops requiring a disk
  image per host. You answer "is this machine involved" with a query and reserve
  imaging for the hosts that come back positive.
- **Hardware history.** `amcache_device_pnp` remembers every device ever
  enumerated, including USB mass storage unplugged months ago, which is the
  question insider-threat and data-exfiltration investigations open with.
- **Driver provenance.** Non-inbox kernel drivers that are no longer installed
  still appear, which is exactly the residue a bring-your-own-vulnerable-driver
  attack leaves behind.
- **Correlation.** Because it is SQL, Amcache joins to `authenticode`, `hash`,
  `drivers`, `services` and `programs` in one query, so "unsigned, ran from a
  user directory, no installer behind it, still on disk" is one question rather
  than four tools.

The caveat that keeps this honest: Amcache records that the appraiser *saw* a
file, which is not proof of execution. It's an excellent lead and a poor
conclusion. See [Caveats](#caveats).

## Tables

| Table | Rows are | Key columns |
|---|---|---|
| `amcache_application_files` | executables the appraiser has inventoried | `path`, `sha1`, `program_id` |
| `amcache_applications` | installed programs | `program_id`, `name`, `publisher` |
| `amcache_application_shortcuts` | Start Menu shortcuts | `path`, `target_path`, `program_id` |
| `amcache_driver_binaries` | driver files | `path`, `sha1`, `service`, `inf` |
| `amcache_driver_packages` | DriverStore packages | `inf`, `provider`, `class` |
| `amcache_device_pnp` | devices ever enumerated | `device_instance_id`, `container_id`, `sha1` |
| `amcache_device_containers` | physical devices behind those interfaces | `container_id`, `friendly_name` |

`sha1` in `amcache_application_files` comes from the hive's `FileId` field and in
`amcache_driver_binaries` from `DriverId`. It's not derived from `ProgramId`,
which is a name/version/publisher digest and not a file hash.

Every column is `text`, `integer` or `bigint`. A value that is absent from the
record or cannot be decoded is never guessed at, but how that reaches SQL
depends on the type: a `text` column gives you an empty string, and an
`integer` or `bigint` column gives you `NULL`. Test numeric columns with
`IS NULL`, not `= ''`. All `*_time` columns are unix epoch seconds, decoded as
UTC.

Not every column is populated on every Windows version. Server builds in
particular leave parts of `amcache_application_shortcuts` empty, and a few
columns appear only on Windows 10. Each column's description in `schema/` says
where it was observed.

## Build

```sh
make windows          # build/amcache_windows.ext.exe
make windows-arm64    # build/amcache_windows_arm64.ext.exe
make dist             # amd64, plus SHA256SUMS
```

Releases carry amd64 only. arm64 cross-builds in CI and in `make check`, so it
cannot silently stop compiling, but it has never run on a host and is not
published beside a binary that has.

Both are built `CGO_ENABLED=0` with `-trimpath -ldflags "-s -w"`, so the
binaries are reproducible and carry no local paths. `make check` runs the full
gate: formatting, module verification, vet and a cross-compile for both Windows
architectures, gosec, govulncheck, and the test suite.

## Install

Under fleetd, ship it through TUF. fleetd rewrites
`C:\Program Files\Orbit\extensions.load` wholesale from the configuration Fleet
returns, and truncates it when Fleet returns no extensions, so a line appended
by hand survives only until the next config refresh:

```sh
fleetctl updates add --name extensions/amcache_windows --platform windows \
  --target ./amcache_windows.ext.exe --version 0.1.0
```

Under a plain osquery install, append the binary's absolute path to
osquery's own autoload file and restart the daemon:

```powershell
Add-Content "C:\Program Files\osquery\extensions.load" "C:\Program Files\amcache\amcache_windows.ext.exe"
Restart-Service osqueryd
```

osquery refuses to autoload a binary whose file or parent directory is
writable by a non-administrator, so place it somewhere Administrators own with
inheritance disabled. `--allow_unsafe` bypasses that check and is a development
shortcut, not a deployment flag.

Confirm it's up:

```sql
SELECT name, version FROM osquery_extensions WHERE name = 'amcache_windows';
```

Or run it against a local `osqueryi` without installing anything:

```powershell
osqueryi --allow_unsafe --extension .\build\amcache_windows.ext.exe --extensions_require=amcache_windows
```

Fleet Premium users can distribute it over TUF instead:

```sh
fleetctl updates add --name extensions/amcache_windows --platform windows \
  --version 0.1.0 --target build/amcache_windows.ext.exe
```

## Examples

The first few are ordinary lookups. The last few are the reason the tables exist.

### 1. What has this machine run

```sql
SELECT path, sha1, size, link_time FROM amcache_application_files LIMIT 25;
```

`link_time` is empty more often than you might expect; see
[Caveats](#caveats) before building anything on it.

### 2. Find one binary by path

```sql
SELECT sha1, publisher, product_name, link_time
FROM amcache_application_files
WHERE path = 'c:\windows\system32\notepad.exe';
```

`path` is stored lowercased, and equality on it is pushed down, so this reads
one record rather than scanning the table.

### 3. Sweep for known-bad hashes

```sql
SELECT path, sha1, last_write_time
FROM amcache_application_files
WHERE sha1 IN (
  'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'
);
```

`sha1` is an indexed column. SQLite expands an `IN` list into one lookup per
value, so a few thousand IOCs are a few thousand index probes against a single
cached parse of the hive, not a few thousand reads of it.

### 4. Executables running from user-writable directories

```sql
SELECT path, sha1, publisher, last_write_time
FROM amcache_application_files
WHERE path LIKE 'c:\users\%'
   OR path LIKE 'c:\programdata\%'
   OR path LIKE 'c:\windows\temp\%'
ORDER BY last_write_time DESC;
```

### 5. Binaries with no installer behind them

```sql
SELECT f.path, f.sha1, f.publisher
FROM amcache_application_files f
LEFT JOIN amcache_applications a ON f.program_id = a.program_id
WHERE a.program_id IS NULL
  AND f.path LIKE 'c:\users\%';
```

An executable the appraiser inventoried but that belongs to no installed
program. Portable tools, dropped payloads and things run once from a download
folder all land here.

### 6. Check what Amcache claims against what is on disk now

osquery's `hash` table needs a concrete path and won't hash the whole
filesystem for you. Constrain the left side first and keep the set small:

```sql
SELECT f.path, f.sha1 AS amcache_sha1, h.sha1 AS current_sha1
FROM amcache_application_files f
JOIN hash h ON h.path = f.path
WHERE f.path LIKE 'c:\users\%\appdata\local\temp\%'
  AND f.sha1 != ''
  AND h.sha1 IS NOT NULL
  AND f.sha1 != h.sha1;
```

A mismatch means the file at that path is not the file Amcache recorded: it was
replaced, or something is masquerading as it. Two things produce a false
positive. Windows hashes only the first 31,457,280 bytes of a file into
`FileId`, so anything larger legitimately differs; and an ordinary update
rewrites the file without anything being wrong.

### 7. Unsigned code that Amcache saw execute

```sql
SELECT f.path, f.sha1, a.result
FROM amcache_application_files f
JOIN authenticode a ON a.path = f.path
WHERE a.result != 'trusted'
  AND f.path NOT LIKE 'c:\windows\%';
```

osquery's `authenticode` table logs a warning and emits no row for a file it
cannot verify, so the join silently excludes those paths. The usual case is
Store apps under `C:\Program Files\WindowsApps`: the executables carry no
embedded Authenticode signature (trust is carried by the package signature),
so `CryptQueryObject` finds nothing and the table reports
`Failed to query the Authenticode signature information`. Those warnings are
harmless; the rows returned are the real untrusted hits.

### 8. Bring-your-own-vulnerable-driver

```sql
SELECT b.path, b.driver_name, b.sha1, b.driver_version, b.service
FROM amcache_driver_binaries b
WHERE b.inbox = 0 AND b.signed = 0 AND b.kernel_mode = 1;
```

A kernel-mode driver that did not ship with Windows and was not signed at
inventory time. Widen it by joining the live driver list:

```sql
SELECT b.path, b.sha1, d.image
FROM amcache_driver_binaries b
LEFT JOIN drivers d ON LOWER(d.image) = b.path
WHERE b.inbox = 0 AND b.kernel_mode = 1 AND d.image IS NULL;
```

The `LEFT JOIN ... IS NULL` half is the interesting one: a non-inbox kernel
driver Amcache remembers and the live driver list no longer reports.

### 9. Removable storage history, including devices long since unplugged

```sql
SELECT c.friendly_name, c.manufacturer, c.model_name,
       p.device_instance_id, p.first_install_time, p.install_time, c.connected
FROM amcache_device_pnp p
LEFT JOIN amcache_device_containers c ON p.container_id = c.container_id
WHERE UPPER(p.enumerator) = 'USBSTOR'
ORDER BY p.first_install_time DESC;
```

Devices persist in Amcache after removal, so this answers "what was ever plugged
into this machine," not just what is attached now. `first_install_time` is the
first time Windows enumerated that specific device.

### 10. Device-stack filter drivers, correlated to their binaries

```sql
SELECT p.description, p.class, p.lower_filters, p.upper_filters,
       b.path AS driver_path, b.signed, b.inbox
FROM amcache_device_pnp p
LEFT JOIN amcache_driver_binaries b ON p.sha1 = b.sha1
WHERE (p.lower_filters != '' OR p.upper_filters != '')
  AND (b.inbox = 0 OR b.inbox IS NULL);
```

A filter driver sits in the I/O path of every request to its device class, which
makes it a durable place to hide a keylogger or a storage interceptor. This
surfaces the non-inbox ones and resolves each to the driver binary Amcache has
for it.

Three tables in one query all parse the hive once, not three times.

## Performance

The extension parses the hive once and caches the result for five minutes,
reloading earlier if the hive's size or mtime changes. A join across seven
tables inside that window triggers one read and one parse; a repeat query
within the window does no I/O at all.

On a workstation-sized hive of a few tens of megabytes, the parse is well under
a second and peak memory stays to a small multiple of the hive size. A locked
hive costs a raw NTFS read instead, which is seconds rather than milliseconds,
and only happens while the appraiser is actually running. If a load ever
exceeds thirty seconds the query fails rather than hanging, and the failure is
remembered for the rest of the cache window instead of being retried per query.

`amcache_application_files` is the large one and can carry tens of thousands of
rows. A scheduled `SELECT *` against it produces log lines larger than
Fleet's 1 MB per-line limit; filter on `path`, `sha1` or `program_id` instead.
Those three are pushed down and evaluated before rows are built. An equality on
any other column, `last_write_time` included, still narrows the result but is
applied by SQLite after every row has been built.

## EDR note

When the hive is locked, the extension opens `\\.\C:` read-only and reads the
file through a raw NTFS parser. That is a privileged volume handle, and EDR
products reasonably treat it as suspicious. It happens only after a genuine
sharing violation on the ordinary open, it's read-only, and it touches exactly
one path. If your EDR alerts on it, allow-list the extension by its Authenticode
publisher or by the SHA-256 in the release's `SHA256SUMS`.

## Caveats

Amcache records that the appraiser *saw* a file. It's not proof of execution,
and the key's last-write time is when the appraiser wrote the record, not when
the program ran or the device was attached. Treat `last_write_time` as an
inventory timestamp.

`link_time` deserves its own warning. It's the PE header's `TimeDateStamp`,
copied out of the binary by the appraiser without being validated, and on the
hosts this was measured against it decodes to a timestamp for roughly seven in
ten of the records that carry it at all. The rest divide into two groups. Some
are not dates in any format -- they are a verbatim copy of the same record's
product version string, which the appraiser writes into the field. Others parse
as dates but fall outside any plausible range, which is what a reproducible
build looks like when the linker puts a content hash where the timestamp goes.
Both render empty rather than as a fabricated epoch. This is not specific to
one Windows version: it was observed on every host examined, client and server.

Treat a populated `link_time` as evidence and an empty one as absence of
evidence, never as a zero.

On Windows 11 a record in `amcache_application_files` usually carries a path or
a hash, not both. Roughly three in four rows are hash-only stubs with no path,
name, size or version metadata; of the rows that do carry a path, most carry no
hash; and fewer than one in ten rows carry both. Windows 10 and Windows Server
2022 populate both on every record. Three consequences worth knowing before you
rely on a result: a hash sweep like example 3 returns rows whose `path` is empty,
a path lookup like example 2 returns a row whose `sha1` is empty, and the hash
comparison in example 6 can only reach the small minority of rows carrying both.
None of this is a fault in the extension; it's what the appraiser wrote.

Only the modern hive format is parsed: Windows 10 1809 and later, Windows 11,
and Windows Server 2022 and later. A pre-Windows-8 hive carrying `Root\File`
and `Root\Programs` yields zero rows and one log line rather than an error.

Uninstalled programs disappear from `amcache_applications` while their files
often remain in `amcache_application_files`, which is why example 5 finds what
it finds.

Reading the hive requires administrative rights, and the raw fallback path
requires SYSTEM.

## License

MIT. See [LICENSE](LICENSE).
