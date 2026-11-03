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
