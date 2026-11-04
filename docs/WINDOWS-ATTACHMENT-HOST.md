# Windows attachment host integration

**CONFIRMED current runtime acceptance at `be2e806`:** both native host public
journeys, active cancellation, changed-curation refresh, recovery and GDB/CRC
checks pass reviewed run41882141913. See the
[complete acceptance audit](DEBUGLINK-ATTACHMENT-ACCEPTANCE.md) and
[Windows evidence](evidence/windows-attachment-41882141913.json).
The full required target gate and final C1 protected integration remain pending.
Development checkpoint paragraphs below are **HISTORICAL** where superseded by
this audit; they retain their original evidence scope.

**CONFIRMED native host/store/coordinator components and public Windows
journeys within the recorded host contract.** `WindowsAttachmentHost` supplies native metadata,
directory and namespace operations to the isolated helper. The adapter does not
enable privileges. After explicit confirmation, the helper may enable only its
own already-held security privilege under the documented
[authorization contract](WINDOWS-ATTACHMENT-AUTHORIZATION.md).

The native component evidence below includes receipt replacement, actual sharing
locks, initial/refresh rollback, concurrent-target refusal and eight abrupt
process exits. These tests do not substitute for real Windows ELF attachment,
GUI cancellation and GDB consumer acceptance. Current integration status is in
[the completion ledger](DEBUG-LOADING-COMPLETION-PLAN.md). Later historical
checkpoints retain their original commit/run scope.

The adapter admits fixed local NTFS with persistent ACL support. Directory
identity includes the native file/volume identity and a digest of the observed
filesystem/GUID-root/drive-type profile. File fingerprints bind native identity,
link count and a versioned deterministic encoding of preservation metadata,
including the complete raw security descriptor. File size/content are separately
bound by the stores, since a debuglink candidate intentionally has different
bytes. Unsupported SACLs, backup streams and metadata remain explicit refusals.

Metadata application uses complete raw readback. Publication and replacement
use the existing opened-stage FileRenameInfo primitive, with no copy fallback.
The adapter checks both directory profiles and complete installed metadata.
The stores force file contents; the host flushes the observed directory.
The contract name records these mechanisms. It is not proof of power-loss
recovery, filesystem-independent durability or adversarial race resistance.

The dedicated `attachment-windows` CI job runs the production extension JAR
with Java21, JNA5.14.0 and Gson2.9.0 in an isolated process. It reuses the audited
test-only own-token privilege scope and restores the original token state.
It exercises independent backup creation, duplicate-backup refusal, mismatched
metadata refusal, cancellation before replacement, native replacement, backup-
based restoration, unchanged retained backup and 128 handle-lifetime cycles.
A separate disabled-privilege observation must fail with error1314. Raw outputs,
exact JAR/dependency/test hashes and the owned fixtures are retained. The job is
included in `required-validation` and can run before the target matrix finishes.

Local extension/test compilation, standalone test compilation against the built
JAR, PowerShell AST parsing, actionlint and architecture isolation pass. An
initial source-only javac attempt lacked Ghidra types pulled in by the operation
interface; the standalone harness compiles against the built extension JAR.
No native host-integration pass is claimed before its hosted execution/review.

Still required: native acceptance, receipt/coordinator integration and fault
coverage, Windows sharing-lock behavior under the full host, documented crash
recovery tests, complete Linux host, public opt-in controls, real exported ELF/
GDB refresh/discovery acceptance and the final protected integration gate.

The fixture additionally exercises receipt preparation and atomic phase update
through the host, comparing complete fingerprints and raw descriptors. These
receipt-store sentinel records are explicitly test fixtures, not valid ELF
exports or validator approvals. Actual Linux regression and GDB evidence for
the shared receipt change is recorded in `ATTACHMENT-TRANSACTION-PROTOCOL.md`.

## Native lock and process-interruption coverage

**PRESENT, UNVERIFIED on Windows:** the host/store fixture now holds an actual
CreateFileW handle that omits FILE_SHARE_DELETE while allowing ordinary reads
and writes. Replacement must fail specifically at FileRenameInfo, leave original,
candidate and backup unchanged, then succeed after the handle closes. The test
uses the same fixed-width CreateFileW/CloseHandle signatures already checked by
the native rename contract; no new production binding is added.

A separate coordinator fixture exercises commit, failure and cancellation after
replacement, refusal to overwrite an unrelated concurrent target, and four
abrupt child-JVM exits: PREPARED, TARGET_REPLACED, BEFORE_COMMIT and COMMITTED.
Recovery must restore the old bytes/metadata from the independent backup, keep
the interrupted receipt immutable and retain all selected input/backup files.
Child control paths are explicitly supplied by the test, never inferred from a
receipt. Runtime.halt terminates only that owned child and its test token state.
This is a process-interruption test, not simulated power loss. Sentinel files
exercise coordinator semantics without claiming ELF export validation or refresh.

The early attachment-windows job runs these checks with the production JAR;
logs, owned fixtures and exact test/dependency bytes are retained. Standalone
Java21-compatible compilation, extension/test build, PowerShell parsing and
workflow lint pass locally. Native execution and raw artifact review remain
required for these new cases.

**CONFIRMED initial native Host/store acceptance:** completed job41635698690
at `5412e20` passes 268 assertions and128 cleanup cycles with305 handles.
Independent archive/source/JAR review verifies the original, candidate,
installed and restored raw descriptors, reconstructs preservation SHA-256
independently, and verifies retained backup/target bytes. See
`evidence/windows-attachment-host-41635698690.json`. This is the initial store
fixture; subsequent receipt, lock and coordinator additions need their own
passing native artifacts. Full A1–A7/C1 remain incomplete.

**CONFIRMED native receipt acceptance:** completed job41636333521 at `f029b62`
passes272 checks and128 cleanup cycles. Independent source/JAR review verifies
the retained COMMITTED receipt bytes, unchanged transaction claims, replacement
identity and preserved metadata. Wire byte counts are checked as canonical
decimal strings, as specified by the receipt schema. See
`evidence/windows-attachment-receipt-41636333521.json`.

**CONFIRMED native initial recovery acceptance:** completed job41637595188 at
`1ca676f` passes273 host checks,84 coordinator checks and four abrupt child exits.
The actual no-delete-sharing handle causes FileRenameInfo error5, leaves all
three files unchanged and permits replacement after close. Independent review
verifies source/JAR identity, all eight outcomes, exact target/backup/input
hashes, recovery-record binding and immutable interrupted receipts. See
`evidence/windows-attachment-recovery-41637595188.json`. This establishes the
initial process-interruption cases, not power loss or the full attachment UI.

**CONFIRMED native refresh extension at `81d0a8a`:** the same commit/rollback/
cancellation/concurrent-target/four-crash scenarios now run for refresh after
an actual initial coordinator commit. Fixtures retain the original backup,
independent prior-image backup, previous committed receipt and previous pair.
The new pair has a different CRC. Missing previous-sidecar input must fail
before publishing the new receipt without changing other selected files; a
previous pair changed after replacement must leave the complete new image and
report RECOVERY_REQUIRED instead of restoring an invalid association. Each
successful case immediately saves progress, and crash records retain child exit
codes. Standalone Java21 compilation and extension/test builds pass locally.
Completed attachment job41639509678 passes275 coordinator checks across18
outcomes and eight abrupt exits. Independent review compares133 production
sources, four test/harness sources, production JAR identity, all retained file
hashes, previous-generation chains, changed CRCs and immutable interrupted
receipts. See `evidence/windows-attachment-refresh-41639509678.json`. These are coordinator fixtures;
actual Ghidra export/refresh and GDB acceptance remain required separately.

## Real-export operation integration

**PRESENT, UNVERIFIED:** `windows-attachment-operation.py` consumes the actual
Windows headless fixture/report and installed production JAR. Its isolated
Java21 probe selects `WindowsAttachmentHost`, `AttachmentOperation` and
`AttachmentValidator`, with explicit native GNU/LLVM/pinned-checker paths and
the audited process supervisor. The test probe scopes its own existing privilege;
the public launcher separately selects current permissions or explicit RunAs.
Both paths invoke the helper's scoped existing-privilege adjustment and require
durable receipts. No automatic elevation retry is performed.

Each commit/rollback scenario has independently copied inputs and an empty
owned directory. A fault after target replacement exercises restoration from
the independent original backup. Java checks full preservation fingerprints;
Python independently checks original/backup bytes, distinct file identity,
validator log digests and the installed target's exact `.gnu_debuglink` name,
padding and target-endian CRC. The packaged-export job retains all selected
fixtures, transaction records and fresh validation logs. The earlier headless
script's status now accurately says that it does not invoke the strict checker;
strict validation is performed in this separate operation stage.

Standalone `javac --release 21`, Python syntax, workflow lint and diff checks
pass locally. Native runtime acceptance is pending. This adds initial real-ELF
attachment/rollback evidence requirements; it does not substitute for refresh,
public CLI/GUI, GDB runtime behavior or final exact-head integration acceptance.

### Saved-curation real refresh fixture

**PRESENT, UNVERIFIED:** the real-export harness now extends its committed
initial case with an independently saved Ghidra project. It applies the same
fixture names/types, saves analyst edits to a function, structure and member,
then reopens the project twice. An explicit export against the attached target
must fail the original import SHA check without publishing a pair; a fresh
basename exported against the verified original backup must succeed while
retaining the analyst edits. No import hash or export report is rewritten.

`WindowsAttachmentRefreshProbe` runs the real Host, live validator and refresh
coordinator in an isolated Java21 process with the existing test-only own-token
privilege scope. It requires changed CRC, preserved metadata, independent
prior-target backup and unchanged prior generation. Python checks actual ELF
name/padding/CRC, unchanged program headers, receipt ancestry, log/input hashes
and retained source/dependency bytes. The headless helper receives JSON-decoded
argument arrays; its owning harness kills the owned process tree on timeout.
The saved project, arguments, raw logs, selected paths and both generations
remain in the job artifacts. This does not establish native Windows execution
until the hosted job passes, or Linux ELF runtime behavior on a Windows host.

Local validation: `javac --release 21` compiles the Windows security, initial
operation and refresh probes; Python AST parsing, PowerShell parser validation,
`actionlint` with ShellCheck and `git diff --check` pass. The full hosted gate,
artifact review, debugger acceptance and public controls remain required.

### Linux runtime consumer of Windows-produced generations

**PRESENT, UNVERIFIED:** `windows-attachment-gdb.py` consumes only the explicit
known locations in the completed Windows fixture artifact. It verifies initial
and refreshed executable/sidecar/source bytes against committed Windows Host
receipts, then runs separate owned Linux copies. The initial attached image
comes from the retained prior-target backup. Source relocation uses GDB's
[`directory` command](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Source-Path.html);
no sidecar, receipt or source bytes are rewritten. Each generation must provide
automatic discovery, the compiler-reference function address, synthetic source,
recovered types, a named breakpoint and arguments19/23, then exit normally.
Fresh corrupt-sidecar sessions must issue a CRC mismatch and expose no full
DWARF function. Debuginfod and external build-ID directories are disabled.

This is native Windows production/attachment followed by Linux execution of
the Linux ELF target. It does not claim Windows-native ELF execution, preserve
Windows filesystem metadata on Linux copies, or replace the Windows metadata
tests. Downloaded evidence is hashed before and after; only new runtime copies
receive executable mode. The new `windows-attachment-gdb` job is required by
`required-validation`, including refusal of skipped or failed consumption.

**CONFIRMED local consumer mechanism:** the owned compiler control at
`build/test-results/windows-source-transfer-control` uses DWARF5 with its
compilation source directory mapped to a nonexistent Windows drive/backslash
path containing a space. Actual Linux GDB directory lookup, function/type/source,
arguments19/23 and normal exit pass; appending a CRC-only mutation produces the
expected CRC mismatch and absent DWARF symbol. Commands, source and raw logs are
retained there. This is a compiler control, not Windows exporter/Host acceptance.
Both Python harnesses parse, workflow lint with ShellCheck and diff checks pass.
The real two-generation consumer remains pending hosted evidence.

**CONFIRMED local consumer correction:** the receipt serializer writes byte
counts as canonical decimal strings. The first consumer compared those fields
to Python integers and would reject every retained image. Comparing to the
canonical `str(stat_size)` preserves the schema and rejects mismatches. The
owned compiler model in `build/test-results/windows-consumer-compiler-model`
reproduces the old failure and passes all four corrected initial/refresh
runtime/CRC cases. Its producer records are explicitly synthetic; this proves
the consumer orchestration, not native Windows or Ghidra acceptance.
