# Debuglink filename encoding

**CONFIRMED locally and on hosted Linux/Windows:** the transaction's Linux test hosts now use
`DebuglinkBasename.linuxUtf8` instead of unchecked string-to-byte conversion.
The production encoding component also provides `portableAscii` for the initial
Windows host. Complete host adapters and public attachment remain incomplete.

## Selected contract

The [GNU debuglink format](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html)
contains the literal filename bytes, a NUL terminator, padding and a target-endian
whole-sidecar CRC. It does not declare a character encoding. Attachment must
therefore select a verified consumer filename policy instead of using the Java
default charset or the exporting host's arbitrary active code page.

The Linux policy requires a Linux process with UTF-8 native paths. It preserves
the exact filename, including Unicode, spaces and literal punctuation. UnixPath
objects retaining invalid native byte sequences are rejected if converting them
through a printable string selects a different path. A literal replacement
character in a valid UTF-8 filename remains distinct and can be accepted.
Non-UTF-8 native locales are rejected before candidate preparation.

The initial Windows policy selects a portable ASCII basename, without inferring
the eventual GDB consumer's non-ASCII code page. Unicode ancestors are not
rewritten; the debugger must already be able to open the original in that
directory. Unsupported non-ASCII basenames require selecting an ASCII sidecar
output name explicitly. Reserved DOS devices, stream/path separators, wildcard
and other reserved characters, and ambiguous trailing dots/spaces are rejected
using the [Windows naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
This is an initial attachment restriction; ordinary export retains its existing
filename behavior. Native Windows policy execution passes the independently reviewed completed
job from run `41615861678`; Windows-hosted GDB runtime is not claimed by this
component.

Both policies reject empty/dot-directory leaves and control characters. They
encode only the selected leaf and do not rename files, relocate source, choose
another sidecar, or weaken identity/discovery-directory/all-role checks.
`AttachmentOperation` requests the bytes before live validation or creating any
backup, receipt or candidate.

## Validation

Local results are retained under `build/test-results/debuglink-basename/`.

- `native-v2`: actual Java 21 proves the policy cases, C-locale refusal, and two
  different native files with the same printable name. The invalid-byte file
  is rejected while the literal UTF-8 replacement-character name is accepted;
  both contents remain unchanged. After the native-path check, owned fixture bytes
  are retained under portable artifact names with their original native-name hex
  recorded, so text-only uploaders cannot conflate them. Production JAR and
  source hashes are retained.
- `operation-java21.log`: 80 preparation/refresh/failure checks pass. Two new
  controls require unsupported basenames to fail before invoking a validator,
  leaving every selected input and directory entry unchanged.
- `controller-no-build-id-v1`: a real Forge x86-64 sidecar with Unicode, spaces,
  shell punctuation and a literal backslash passes fresh GNU/LLVM/pinned strict
  validation and the production live validator. Initial commit/rollback,
  independent literal filename/padding/CRC checks, actual GDB source/type/argument
  lookup and native execution pass. A separate corrupted same-name file produces
  an actual CRC-mismatch warning with build-ID/debuginfod fallback unavailable.
  `controller-no-build-id-ci` also passes the exact CI basename, which keeps
  Unicode/punctuation but omits the platform-specific backslash for artifact
  portability.
- `controller-mipsbe-v1`: ELF32 big-endian proves the same independent payload,
  transaction, live-validator and QEMU/GDB behavior with a punctuation-bearing
  portable ASCII name. It still uses the explicitly limited Linux metadata host.

The CI extension job runs the native-byte/locale controls, the native Windows
job executes the portable policy, and all target coordinator lanes use the
production Linux policy. The x86 no-build-ID lane uses the special basename.
The negative CRC fixture always keeps the exact selected basename and requires
GDB's CRC-mismatch diagnostic; merely failing to find a file is insufficient.

No native producer ABI, default exporter address or source mapping changes are
introduced. The target bytes remain unchanged in ordinary export, and all
transaction experiments modify only owned fixture copies.

## Hosted component acceptance

The completed extension and native Windows jobs from run `41615861678` at
`d70bf34` pass the filename policy. Independent archive-digest, exact source,
Java 21 bytecode/runtime and raw-command review passes. Linux's two real native
names have the same printable replacement-character representation but distinct
bytes; the intended refusal/acceptance and preserved fixture hashes agree.
Windows executes all 31 portable-policy checks. See
[`debuglink-basename-41615861678.json`](evidence/debuglink-basename-41615861678.json).

The superseded full workflow was cancelled after those jobs completed and their
artifacts were reviewed. It is not a full required-validation pass, and these
component results do not close A1–A7 or #72.
