# Windows attachment host integration

**PRESENT, UNVERIFIED on Windows:** `WindowsAttachmentHost` implements the
transaction's required Host interface using the native metadata, directory and
namespace components. It has no public CLI/GUI entry point and never enables
privileges. Complete security observation requires an already authorized token;
the unresolved user-facing invocation policy is unchanged.

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
the audited process supervisor. The test enables only its already owned token
privilege, then restores it; the product never adjusts privilege state.

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
