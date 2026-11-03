# Opened Windows volume profile experiment

**CONFIRMED native experiment:** completed Windows job41632042195 at
`77a3c0f` passes the GUID-root/fixed-drive experiment, independent C# volume-ID
agreement and 128 cycles with 57 handles before/after. Archive/source review is
recorded in `../evidence/windows-security-raw-ace-41632042195.json`. This validates
the native experiment only; production JNA admission and recovery remain open.
The earlier pending description below records the pre-execution checkpoint.

**PRESENT, UNVERIFIED on Windows:** the native directory fixture has an explicit
`--volume-profile` mode. It cross-compiles with warnings as errors; the updated
PowerShell harness parses. The ordinary directory fixture keeps its existing
behavior, and the new experiment runs after all security/staging checks so it
cannot prevent those earlier outcomes from being collected.

A candidate first filesystem profile is fixed local NTFS with native identity,
ACL support and the verified directory/file flush operations. This experiment
collects evidence for that selection; it is not a production admission rule,
network/removable-filesystem support claim or proof of power-loss recovery.
The user-facing privilege/visibility policy remains a separate open decision.

The test exclusively creates an owned directory and obtains a bounded final
path from its already opened handle with GetFinalPathNameByHandleW and
VOLUME_NAME_GUID. It validates the GUID root, calls GetDriveTypeW on that root,
and opens the root directory read-only to compare its volume identity with the
original directory. It never opens a raw volume device or adjusts privileges.
The fixture repeats the profile read128times alongside the existing flush
controls, requiring stable observations and a flat native handle count.
PowerShell independently decodes/validates the GUID and uses the existing C#
file-ID observer to corroborate the root volume. Original/default fixture
observations are retained separately from the new mode.

The APIs and scalar widths are audited against the existing pinned fileapi.h
snapshot in `windows-directory-api.json`. Their C function-pointer signatures
and constants compile before execution. No new JNA mapping has been added.

Microsoft documents [the handle-based final path](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
as resolving the actual file and distinguishes a volume GUID from a drive-letter
path; network shares do not have volume GUID paths. The
[drive-type API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew)
distinguishes fixed, removable, remote and other drive types. Those documented
properties motivate the experiment; they do not substitute for native test
results or justify assuming that every drive-letter path is local NTFS.

The reviewed native experiment now precedes a Java implementation in
`WindowsDirectorySync`; its snapshot includes the GUID root/drive type and
checks the root directory's volume identity. A same-directory C/C#/Java oracle
has been added. The binding compiles locally but its Windows execution is
**PRESENT, UNVERIFIED**. See `../WINDOWS-DIRECTORY-SYNC.md`.
