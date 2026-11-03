# Windows backup-stream admission

**PRESENT, UNVERIFIED on native Windows:** `WindowsBackupStreams` inventories
non-security backup streams through the audited Windows64 BackupRead/BackupSeek
API. Local C cross-compilation, Java 21 compilation, PowerShell parsing and
actual normal/interpreted request transport pass. Native hosted execution is
required before this mechanism is accepted.

The initial attachment metadata application rejects extended attributes,
object IDs and any other non-ordinary backup stream before changing a private
stage. Both source and stage are checked, followed by readback after application.
This closes a potential silent-loss gap in the accessible-metadata primitive;
it does not make the complete host contract available.

Security processing is deliberately disabled. Empty backup-stream results do
not establish SACL absence. The pending protected-metadata visibility decision,
filesystem admission and namespace durability remain separate requirements.
No privilege is enabled, and ordinary export does not invoke this mechanism.

## Contract

The reader opens a synchronous read handle without backup privilege semantics,
checks its identity against the selected path, and validates opened-file facts
again after enumeration. The internal stage-application path uses its already
opened source/stage handles. Reparse points and unsupported path forms are
rejected by the existing metadata observer.

The stream prefix is 20 bytes, distinct from the padded 24-byte C structure.
Names are bounded, decoded as strict UTF-16LE and never interpreted as paths.
At most 4,096 records and one MiB of names are retained. Payloads are skipped
using the split 64-bit BackupSeek count, with exact skipped-byte readback.
Truncation, incomplete seeks, invalid sizes and native errors fail closed.
BackupRead's context is aborted on success, error and cancellation before the
file handle closes; cleanup does not honor cancellation. Kernel calls themselves
may block. No copying, fallback API or target replacement occurs here.

`requireOrdinaryData` permits only one ordinary unnamed DATA stream matching
the file size, or no streams for an empty file. All other records are unsupported.
The inventory API retains their type/attributes/name/size for diagnostics; it
does not claim to preserve their payloads or classify every future stream type.

## Validation

`src/test/native/windows-backup-api.json` records the pinned SDK headers and
primary API references. `windows-backup-contract.c` verifies scalar widths,
structure offsets, flags and signatures before isolated Java execution.
The native Windows metadata harness adds ordinary/empty files, Unicode named
streams, real EAs, source/stage application refusal and cancellation after a
real stream header. An interpreted Java process repeats inspection/cancellation
128 times with no handle-count growth required.

The independent C fixture sets and reads EAs using NtSetEaFile/NtQueryEaFile,
not the production backup API. Its fixed binary EA payload includes NUL and
non-ASCII bytes. Full ordinary-file hashes/identity/security metadata and raw
EA values must survive both source and stage rejection. The harness retains
all sources/dependencies, native contract results and exact command output.
No native pass is claimed until those artifacts are reviewed.

Primary references: [BackupRead](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread),
[BackupSeek](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupseek),
[WIN32_STREAM_ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id).
