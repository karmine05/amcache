// Package tables maps the parsed Amcache inventory onto seven osquery tables.
//
// This file is the contract the rest of the package is written against: which
// column reads which registry value, and how that value is decoded. Nothing
// here inspects a value to decide what it is. Deciding by shape is the defect
// Elastic's extension ships -- 31,265 ProgramId values on the four reference
// hives pass the same 44-character 0000-prefixed hex test that identifies a
// FileId, and FileId never equals ProgramId on any of the 34,304 records
// carrying both, so a shape-driven sha1 is wrong on every row and no shape
// check can detect it.
package tables

import (
	"github.com/karmine05/amcache/internal/inventory"
	"github.com/osquery/osquery-go/plugin/table"
)

// kind selects a decoder. A column names its decoder here, once, rather than
// the decoder deriving one from the value.
type kind uint8

const (
	kText  kind = iota // REG_SZ as the parser already rendered it
	kInt               // decimal as stored; every fixture value is decimal, none is 0x-prefixed
	kBool              // 1/0 out of either a REG_SZ "1"/"0" or a DWORD
	kTime              // a date string in one of four observed layouts, to unix seconds
	kEpoch             // a DWORD that is already unix seconds
	kMulti             // comma-separated list, re-joined after trimming
	kSha1              // the 40 hex characters after a 44-character value's 0000 prefix
	kLower             // a value lowercased, as opposed to kKeyLower's subkey name

	// The four key-derived kinds read the subkey name, not a value, so their
	// src is empty.
	kKey      // subkey name verbatim
	kKeyPath  // subkey name with '/' rewritten to '\'
	kKeyLower // subkey name lowercased
	kKeyTime  // Record.LastWrite
)

// col is one osquery column. src is the registry value name and is empty for
// the key-derived kinds. push marks a column the pushdown index is built over.
type col struct {
	name string
	typ  table.ColumnType
	src  string
	kind kind
	push bool
}

// spec is one table: its osquery name and the inventory key it reads.
type spec struct {
	table string
	key   string
	cols  []col
}

// The seven tables, in inventory.Keys order.
//
// Types follow one rule, measured rather than assumed: osquery renders an
// integer column through sqlite3_result_int, which is 32-bit signed, while the
// parser emits every DWORD through strconv.FormatUint, which is unsigned
// decimal. Any value at or above 2^31 therefore truncates silently. That is not
// hypothetical -- 665 of the 1,581 DriverTimeStamp values across the four
// reference hives exceed 2^31-1, and the largest renders as a negative epoch
// when narrowed. So: a flags word or bitmask is bigint whatever its observed
// range, anything that can exceed 2^31-1 is bigint, and only a bounded
// enumeration, an LCID or a boolean stays integer.
var specs = []spec{
	{
		table: "amcache_application_files",
		key:   inventory.KeyApplicationFile,
		cols: []col{
			{name: "path", typ: table.ColumnTypeText, src: "LowerCaseLongPath", kind: kText, push: true},
			// Not derived from the subkey. The subkey is <name>|<hash>, but its
			// pre-pipe segment differs from the Name value, even case-insensitively,
			// on 28 percent of Windows 11 records, so neither substitutes for the
			// other and the subkey is not exposed at all.
			{name: "name", typ: table.ColumnTypeText, src: "Name", kind: kText},
			{name: "sha1", typ: table.ColumnTypeText, src: "FileId", kind: kSha1, push: true},
			{name: "program_id", typ: table.ColumnTypeText, src: "ProgramId", kind: kText, push: true},
			{name: "publisher", typ: table.ColumnTypeText, src: "Publisher", kind: kText},
			{name: "original_file_name", typ: table.ColumnTypeText, src: "OriginalFileName", kind: kText},
			{name: "version", typ: table.ColumnTypeText, src: "Version", kind: kText},
			{name: "bin_file_version", typ: table.ColumnTypeText, src: "BinFileVersion", kind: kText},
			{name: "product_name", typ: table.ColumnTypeText, src: "ProductName", kind: kText},
			{name: "product_version", typ: table.ColumnTypeText, src: "ProductVersion", kind: kText},
			{name: "bin_product_version", typ: table.ColumnTypeText, src: "BinProductVersion", kind: kText},
			{name: "binary_type", typ: table.ColumnTypeText, src: "BinaryType", kind: kText},
			{name: "size", typ: table.ColumnTypeBigInt, src: "Size", kind: kInt},
			// Attacker-influenced PE metadata: on Windows 11, 526 of 4,010 non-empty
			// LinkDate values are a copy of the record's own ProductVersion rather
			// than a date, which decodes to an empty cell and is not a defect.
			{name: "link_time", typ: table.ColumnTypeBigInt, src: "LinkDate", kind: kTime},
			{name: "language", typ: table.ColumnTypeInteger, src: "Language", kind: kInt},
			{name: "os_component", typ: table.ColumnTypeInteger, src: "IsOsComponent", kind: kBool},
			{name: "usn", typ: table.ColumnTypeBigInt, src: "Usn", kind: kInt},
			// Windows 10 only: 395 of 395 records there, absent from every Windows 11
			// and Server 2022 record.
			{name: "long_path_hash", typ: table.ColumnTypeText, src: "LongPathHash", kind: kText},
			{name: "appx_package_full_name", typ: table.ColumnTypeText, src: "AppxPackageFullName", kind: kText},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_applications",
		key:   inventory.KeyApplication,
		cols: []col{
			// The subkey is the ProgramId on 723 of 723 records, so unlike the file
			// table this one does expose it.
			{name: "program_id", typ: table.ColumnTypeText, kind: kKey, push: true},
			{name: "name", typ: table.ColumnTypeText, src: "Name", kind: kText},
			{name: "version", typ: table.ColumnTypeText, src: "Version", kind: kText},
			{name: "publisher", typ: table.ColumnTypeText, src: "Publisher", kind: kText},
			// Windows 10 only: 98 of 98 records there, absent elsewhere.
			{name: "type", typ: table.ColumnTypeText, src: "Type", kind: kText},
			{name: "source", typ: table.ColumnTypeText, src: "Source", kind: kText},
			{name: "store_app_type", typ: table.ColumnTypeText, src: "StoreAppType", kind: kText},
			{name: "install_time", typ: table.ColumnTypeBigInt, src: "InstallDate", kind: kTime},
			// MsiInstallDate, not the InstallDateMsi the design contract named: that
			// value exists on no hive. Absent from Windows 10 entirely.
			{name: "msi_install_time", typ: table.ColumnTypeBigInt, src: "MsiInstallDate", kind: kTime},
			{name: "root_dir_path", typ: table.ColumnTypeText, src: "RootDirPath", kind: kText},
			{name: "uninstall_string", typ: table.ColumnTypeText, src: "UninstallString", kind: kText},
			{name: "registry_key_path", typ: table.ColumnTypeText, src: "RegistryKeyPath", kind: kText},
			{name: "msi_product_code", typ: table.ColumnTypeText, src: "MsiProductCode", kind: kText},
			{name: "msi_package_code", typ: table.ColumnTypeText, src: "MsiPackageCode", kind: kText},
			{name: "package_full_name", typ: table.ColumnTypeText, src: "PackageFullName", kind: kText},
			{name: "manifest_path", typ: table.ColumnTypeText, src: "ManifestPath", kind: kText},
			{name: "hidden_arp", typ: table.ColumnTypeInteger, src: "HiddenArp", kind: kBool},
			{name: "inbox_modern_app", typ: table.ColumnTypeInteger, src: "InboxModernApp", kind: kBool},
			{name: "language", typ: table.ColumnTypeInteger, src: "Language", kind: kInt},
			// A four-part Windows version quad on 98 of 98 values, never a date, so
			// it is deliberately not in the *_time namespace the schema reserves for
			// epochs. The registry value it reads is still OSVersionAtInstallTime.
			// Windows 10 only.
			{name: "os_version_at_install", typ: table.ColumnTypeText, src: "OSVersionAtInstallTime", kind: kText},
			{name: "program_instance_id", typ: table.ColumnTypeText, src: "ProgramInstanceId", kind: kText},
			{name: "user_sid", typ: table.ColumnTypeText, src: "UserSid", kind: kText},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_application_shortcuts",
		key:   inventory.KeyApplicationShortcut,
		cols: []col{
			{name: "path", typ: table.ColumnTypeText, src: "ShortcutPath", kind: kText, push: true},
			// The three columns below are absent from all 61 Server 2022 shortcut
			// records, which carry ShortcutPath and nothing else. They are real on
			// Windows 10 and Windows 11.
			{name: "target_path", typ: table.ColumnTypeText, src: "ShortcutTargetPath", kind: kText},
			{name: "aumid", typ: table.ColumnTypeText, src: "ShortcutAumid", kind: kText},
			{name: "program_id", typ: table.ColumnTypeText, src: "ShortcutProgramId", kind: kText, push: true},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_driver_binaries",
		key:   inventory.KeyDriverBinary,
		cols: []col{
			// Every one of the 1,581 subkey names is an 'X:'-prefixed lowercase path
			// written with '/' where a Windows path uses '\', and none contains a
			// backslash already, so the rewrite is unconditional and lossless.
			{name: "path", typ: table.ColumnTypeText, kind: kKeyPath, push: true},
			{name: "driver_name", typ: table.ColumnTypeText, src: "DriverName", kind: kText},
			{name: "sha1", typ: table.ColumnTypeText, src: "DriverId", kind: kSha1, push: true},
			{name: "signed", typ: table.ColumnTypeInteger, src: "DriverSigned", kind: kBool},
			{name: "inbox", typ: table.ColumnTypeInteger, src: "DriverInBox", kind: kBool},
			{name: "kernel_mode", typ: table.ColumnTypeInteger, src: "DriverIsKernelMode", kind: kBool},
			// A flags word: ten distinct bits are set across the reference hives,
			// including three the design contract's legend does not list.
			{name: "driver_type", typ: table.ColumnTypeBigInt, src: "DriverType", kind: kInt},
			{name: "driver_version", typ: table.ColumnTypeText, src: "DriverVersion", kind: kText},
			{name: "product", typ: table.ColumnTypeText, src: "Product", kind: kText},
			{name: "product_version", typ: table.ColumnTypeText, src: "ProductVersion", kind: kText},
			{name: "driver_company", typ: table.ColumnTypeText, src: "DriverCompany", kind: kText},
			{name: "service", typ: table.ColumnTypeText, src: "Service", kind: kText},
			{name: "inf", typ: table.ColumnTypeText, src: "Inf", kind: kText, push: true},
			{name: "driver_package_strong_name", typ: table.ColumnTypeText, src: "DriverPackageStrongName", kind: kText},
			{name: "image_size", typ: table.ColumnTypeBigInt, src: "ImageSize", kind: kInt},
			{name: "checksum", typ: table.ColumnTypeBigInt, src: "DriverCheckSum", kind: kInt},
			// Already unix seconds, so it never reaches the date ladder. This is the
			// column that proves the integer/bigint rule matters: 665 of 1,581 values
			// exceed 2^31-1.
			{name: "link_time", typ: table.ColumnTypeBigInt, src: "DriverTimeStamp", kind: kEpoch},
			{name: "modified_time", typ: table.ColumnTypeBigInt, src: "DriverLastWriteTime", kind: kTime},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_driver_packages",
		key:   inventory.KeyDriverPackage,
		cols: []col{
			// From the Inf value, present on every record. The subkey is opaque and
			// is not exposed.
			{name: "inf", typ: table.ColumnTypeText, src: "Inf", kind: kText, push: true},
			{name: "directory", typ: table.ColumnTypeText, src: "Directory", kind: kText},
			{name: "sys_file", typ: table.ColumnTypeText, src: "SYSFILE", kind: kText},
			{name: "class", typ: table.ColumnTypeText, src: "Class", kind: kText},
			{name: "class_guid", typ: table.ColumnTypeText, src: "ClassGuid", kind: kText},
			{name: "provider", typ: table.ColumnTypeText, src: "Provider", kind: kText},
			{name: "version", typ: table.ColumnTypeText, src: "Version", kind: kText},
			// Year-first with unpadded month and day on 92 of 92 values, which is a
			// different layout from every other date in the hive.
			{name: "driver_ver_time", typ: table.ColumnTypeBigInt, src: "Date", kind: kTime},
			{name: "inbox", typ: table.ColumnTypeInteger, src: "DriverInBox", kind: kBool},
			{name: "submission_id", typ: table.ColumnTypeText, src: "SubmissionId", kind: kText},
			// The widest column in the extension: one real row holds 11,295 comma
			// separated hardware ids and is roughly half a megabyte on its own.
			{name: "hwids", typ: table.ColumnTypeText, src: "Hwids", kind: kMulti},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_device_pnp",
		key:   inventory.KeyDevicePnp,
		cols: []col{
			// The rewrite is the join, not cosmetics: with it, 121 of 146 Windows 11
			// parent_id values match another row here; without it, none do. Exactly
			// one subkey per hive is a braced GUID rather than an instance id, so the
			// rewrite must stay a blind replacement and never a path validation, or
			// that row is dropped from the table.
			{name: "device_instance_id", typ: table.ColumnTypeText, kind: kKeyPath, push: true},
			{name: "description", typ: table.ColumnTypeText, src: "Description", kind: kText},
			{name: "bus_reported_description", typ: table.ColumnTypeText, src: "BusReportedDescription", kind: kText},
			{name: "class", typ: table.ColumnTypeText, src: "Class", kind: kText},
			{name: "class_guid", typ: table.ColumnTypeText, src: "ClassGuid", kind: kText},
			{name: "enumerator", typ: table.ColumnTypeText, src: "Enumerator", kind: kText},
			{name: "manufacturer", typ: table.ColumnTypeText, src: "Manufacturer", kind: kText},
			{name: "model", typ: table.ColumnTypeText, src: "Model", kind: kText},
			{name: "provider", typ: table.ColumnTypeText, src: "Provider", kind: kText},
			{name: "service", typ: table.ColumnTypeText, src: "Service", kind: kText},
			{name: "driver_name", typ: table.ColumnTypeText, src: "DriverName", kind: kText},
			{name: "sha1", typ: table.ColumnTypeText, src: "DriverId", kind: kSha1, push: true},
			{name: "driver_ver_version", typ: table.ColumnTypeText, src: "DriverVerVersion", kind: kText},
			// Month-first and dash separated on 100 percent of values here, which is
			// neither the slash layout the design contract specified nor the layout
			// the driver package key uses.
			{name: "driver_ver_time", typ: table.ColumnTypeBigInt, src: "DriverVerDate", kind: kTime},
			{name: "driver_package_strong_name", typ: table.ColumnTypeText, src: "DriverPackageStrongName", kind: kText},
			{name: "inf", typ: table.ColumnTypeText, src: "Inf", kind: kText},
			{name: "hwids", typ: table.ColumnTypeText, src: "HWID", kind: kMulti},
			{name: "compids", typ: table.ColumnTypeText, src: "COMPID", kind: kMulti},
			{name: "matching_id", typ: table.ColumnTypeText, src: "MatchingID", kind: kText},
			// Plain text, deliberately not rewritten. The stored value already uses
			// backslashes on every one of the 464 values across the reference hives,
			// so a rewrite gains nothing and would corrupt a value that legitimately
			// contained a forward slash.
			{name: "parent_id", typ: table.ColumnTypeText, src: "ParentId", kind: kText},
			// Lowercased rather than plain text, which is the twelfth kind and the
			// only decoder this file gained after the spec was written. All 464
			// values here and all 84 container subkey names are already lowercase,
			// so it changes nothing measurable -- but the container side is
			// lowercased out of its subkey by kKeyLower, and leaving this side raw
			// would make the join between the two tables depend on a future hive
			// agreeing with today's. A GUID is case-insensitive, so nothing is lost.
			{name: "container_id", typ: table.ColumnTypeText, src: "ContainerId", kind: kLower, push: true},
			{name: "install_state", typ: table.ColumnTypeInteger, src: "InstallState", kind: kInt},
			// A DN_* devnode status word, so bigint despite a small observed range:
			// only bits 0x20 and 0x40 are ever set on the reference hives, but
			// DN_NEEDS_LOCKING is 0x80000000 and would render negative as an integer.
			{name: "device_state", typ: table.ColumnTypeBigInt, src: "DeviceState", kind: kInt},
			{name: "problem_code", typ: table.ColumnTypeInteger, src: "ProblemCode", kind: kInt},
			{name: "install_time", typ: table.ColumnTypeBigInt, src: "InstallDate", kind: kTime},
			{name: "first_install_time", typ: table.ColumnTypeBigInt, src: "FirstInstallDate", kind: kTime},
			{name: "lower_filters", typ: table.ColumnTypeText, src: "LowerFilters", kind: kMulti},
			{name: "upper_filters", typ: table.ColumnTypeText, src: "UpperFilters", kind: kMulti},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
	{
		table: "amcache_device_containers",
		key:   inventory.KeyDeviceContainer,
		cols: []col{
			{name: "container_id", typ: table.ColumnTypeText, kind: kKeyLower, push: true},
			{name: "friendly_name", typ: table.ColumnTypeText, src: "FriendlyName", kind: kText},
			{name: "manufacturer", typ: table.ColumnTypeText, src: "Manufacturer", kind: kText},
			{name: "model_name", typ: table.ColumnTypeText, src: "ModelName", kind: kText},
			{name: "model_number", typ: table.ColumnTypeText, src: "ModelNumber", kind: kText},
			{name: "model_id", typ: table.ColumnTypeText, src: "ModelId", kind: kText},
			{name: "primary_category", typ: table.ColumnTypeText, src: "PrimaryCategory", kind: kText},
			{name: "categories", typ: table.ColumnTypeText, src: "Categories", kind: kMulti},
			{name: "discovery_method", typ: table.ColumnTypeText, src: "DiscoveryMethod", kind: kText},
			// A flags word whose low five bits agree with the five booleans below on
			// all 84 records, so bigint for the same reason device_state is.
			{name: "state", typ: table.ColumnTypeBigInt, src: "State", kind: kInt},
			{name: "active", typ: table.ColumnTypeInteger, src: "IsActive", kind: kBool},
			{name: "connected", typ: table.ColumnTypeInteger, src: "IsConnected", kind: kBool},
			{name: "paired", typ: table.ColumnTypeInteger, src: "IsPaired", kind: kBool},
			{name: "networked", typ: table.ColumnTypeInteger, src: "IsNetworked", kind: kBool},
			{name: "machine_container", typ: table.ColumnTypeInteger, src: "IsMachineContainer", kind: kBool},
			{name: "last_write_time", typ: table.ColumnTypeBigInt, kind: kKeyTime},
		},
	},
}

// columnDefs builds the osquery column list for one table.
//
// Only the one-argument helpers are used. Fleet pins an osquery-go from January
// 2025 whose plugin/table package is a single file with no ColumnOpt, no
// IndexColumn and no variadic column options at all, so anything richer
// compiles against the pin in this repository's go.mod and fails to compile
// when this package is vendored into fleet.
func (s spec) columnDefs() []table.ColumnDefinition {
	defs := make([]table.ColumnDefinition, 0, len(s.cols))
	for _, c := range s.cols {
		switch c.typ {
		case table.ColumnTypeInteger:
			defs = append(defs, table.IntegerColumn(c.name))
		case table.ColumnTypeBigInt:
			defs = append(defs, table.BigIntColumn(c.name))
		default:
			defs = append(defs, table.TextColumn(c.name))
		}
	}
	return defs
}
