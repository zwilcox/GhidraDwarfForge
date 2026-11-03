# Windows backup-stream admission

**CONFIRMED on native Windows:** run 41611451207 at `440df66` passes the
complete isolated metadata/rename/backup-stream harness. Independent artifact
review verifies 16 exact source files and dependency hashes, actual Java 21,
native C ABI checks, 15 metadata observations, ten namespace cases and the new
EA/Unicode/cancellation/cleanup controls. See
[the review receipt](evidence/windows-backup-streams-41611451207.json).
This accepts the component, not the complete host contract or full PR gate.

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
Those artifacts pass the review recorded above; full host admission remains incomplete.

Primary references: [BackupRead](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread),
[BackupSeek](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupseek),
[WIN32_STREAM_ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id).

## Native investigation

**HISTORICAL failed attempts, superseded by the accepted run above:** runs
41609040809/41609824856 pass real EA detection and source/stage refusal, then
fail the original process-handle assertion. The diagnostic native C control
remains at 57 handles through 128 cycles; Java grows once by nine, rather than
once per operation. Run 41610641482 records GC worker threads 1–3 starting at
09:26:50.127Z, between samples 59/60 where the nine-handle increase occurs.
The separate interpreted serial-GC process remains at 296 throughout all
128 cycles and passes the unchanged exact-equality assertion. Default-GC
observations are explicitly not acceptance results.

That run then fails the Unicode named-stream comparison: the test probe uses
the Windows default output code page and narrows lambda to a question mark.
The probe now explicitly writes UTF-8 stdout/stderr and the native harness
requires a Unicode request/output round trip in both JVM modes. This changes
test transport only. The failed runs remain failed. The corrected native harness and artifact
review pass in run 41611451207. The native C process remains at 57 handles and
the serial-GC Java process at 296 for every one of 128 full/cancel cycles.
Both Unicode round trips and the exact `:extra λ:$DATA` stream name pass.
