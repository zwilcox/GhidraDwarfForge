# Isolated attachment invocation

**PLANNED public flow:** keep Ghidra unprivileged and perform attachment in a
separate helper process. A user explicitly requests OS authorization when
needed; an existing authorized context can invoke the helper directly. There
is no silent elevation retry, readable-metadata fallback, or automatic target
change after ordinary export. The separate-helper flow is the stated
implementation assumption after the optional preference question, not a claim
that the user supplied a new privilege grant. Actual OS authorization remains
the user's explicit action at invocation time.

The CLI/GUI must explain that attachment changes the selected executable,
show its selected pair, original backup and receipt, and require an explicit
action. A successful export alone is insufficient: the helper must run the
complete production validator and host transaction. Refresh must retain the
previous generation and export against the original backup as ADR-0004 requires.
The convenience launchers, OS authorization and GUI journey remain **PLANNED**.
The standalone recovery interface and saved selections are implemented below;
their native execution remains **PRESENT, UNVERIFIED**. The standalone helper below is implemented;
its actual native execution is **PRESENT, UNVERIFIED** until hosted tests pass. The metadata policy and Ghidra/Java/native producer baselines
are unchanged.

## Explicit selection transport

**PRESENT, UNVERIFIED end to end:** `AttachmentInvocation` supplies the shared
read-only request format. Schema1 has exactly `schemaVersion`, `operation`,
`paths` and `validatorTools`. `operation` is ATTACH or REFRESH. The path object
contains target, sidecar, source, exportReport, originalBackup,
validationEvidence, receipt, recoveryReceipt, restoreImage and recoveryInvocation; REFRESH also
requires previousReceipt, previousSidecar, previousSource and priorTargetBackup.
The tools object explicitly selects helper, readelf, llvm, strict and
configuration. No path is imported from an export report or transaction receipt.

All paths are absolute so an authorization helper's working directory cannot
reinterpret them. Lexical `..` traversal is retained until `AttachmentPaths`
resolves the actual filesystem. The read-only preflight includes the transport
file and every selected tool in addition to the operation's artifact/output
roles, before any helper workspace is created. Existing aliases, including
hard links, fail. The caller must retain/recheck that plan alongside the normal
operation checks; it does not waive native identity, content or metadata binding.

Reading never runs a tool or requests privileges. The file is an explicit
selection document, not proof of authorization or validator success. In
particular, an `elevate` property is rejected as an unknown field; OS permission
must be requested separately by the invoking user interface. The ATTACH/REFRESH parser rejects RECOVER. The distinct recovery format below
requires every path explicitly and never follows artifact paths from a receipt.

The parser reuses the existing bounded strict UTF-8/JSON lexical guard: at most
256KiB, 16384 UTF-16 units per string, depth3 and128 values. It rejects duplicate
and unknown fields, wrong primitive types, missing/extra operation roles,
relative paths, bad Unicode, oversized or trailing input and unknown versions.
Serialization orders path keys deterministically and enforces the byte limit.
Streams close on success, failure and cancellation; cancellation is preserved
as cancellation. The transport input must be a regular non-link file.

## Current validation

**CONFIRMED locally:** actual Java21 passes72 invocation checks, including
ATTACH/REFRESH round trips, exact shape, version/Unicode/limit rejection,
stream closure/cancellation, tool/transport aliases and unchanged sentinel
inputs. The existing80 operation checks and extension build pass. Initial
development tests caught an invalid role label and wrapped cancellation; both
are corrected. Commands and outcomes are in
`build/attachment-invocation-validation.log`. CI runs the new task on both Linux
and Windows; native Windows execution remains pending. This is request/path
admission evidence, not helper execution or complete A2/A5 acceptance.

## Standalone helper entry point

**PRESENT, UNVERIFIED native execution:** the extension JAR now includes
`ghidradwarfforge.output.AttachmentHelper`. Run it only in a separate Java21+
process with the extension JAR and Ghidra's JNA/Gson JARs on the classpath:

```text
java --enable-native-access=ALL-UNNAMED -cp <extension-and-Ghidra-dependencies> \
    ghidradwarfforge.output.AttachmentHelper \
    --request <absolute-request.json> --request-sha256 <exact-lowercase-sha256> \
    --confirm-target-change
```

`--help` explains target mutation and retained recovery material. There is no
implicit confirmation, privilege request, shell evaluation, test-host switch or
captured-success validator. The helper selects the native host and the required
live GNU/LLVM/pinned-libdwarf validator. On Windows the caller currently must
provide an already authorized token with the required privileges enabled; the
public UAC launcher/privilege scope is still required. On Linux the existing
strict ext4/protected-metadata contract applies. Running the helper inside
Ghidra is unsupported; its `main` terminates its standalone JVM.

The request bytes are read with a 256KiB bound and must match the digest the
invoker explicitly selected. Full role/tool/request alias preflight precedes
host workspace creation. Native request/tool snapshots are then retained and
rechecked around validation and transaction boundaries; the request hash is
rechecked against the selection before execution. The helper does not reuse an
absence check after its own transaction has created a selected output.

`--cancel-on-stdin` enables a launcher-owned control channel. Any byte or EOF
requests cooperative cancellation; a launcher must keep the pipe open while
running. The existing supervisor cancels validators and the transaction handles
rollback without interrupting recovery. Abrupt process death still requires
explicit recovery; a durable user-facing recovery invocation remains incomplete.
Neither Ctrl-C handling nor a GUI cancellation journey is claimed by this flag.

Stdout contains one JSON result including the request selection/digest, outcome,
retained paths and, when the transaction returned, the explicit recovery
selection. Exit0 means committed with successful host cleanup; nonzero includes
refusal, rollback, cancellation (130), recovery-required and reporting/cleanup
failure. A cleanup failure after a committed transaction preserves the COMMITTED
outcome in the response and exits nonzero. If stdout is lost, inspect the durable
receipt and preserve every selected backup/generation; never assume a failed
process exit proves that the target is unchanged. The helper opens no log or
result destination that could truncate an input.

**CONFIRMED locally:** actual Java21 passes88 helper admission/refusal checks,
72 invocation checks and80 operation checks, and builds the extension. Python
AST and workflow/actionlint/ShellCheck checks pass. The Linux production matrix
now uses the standalone helper for all15 initial attachments, then applies its
existing independent ELF/receipt/validator/GDB/CRC oracles. It also checks
no-consent and stdin-cancellation refusals preserve inputs and create no output.
Rollback fault injection retains the test bridge. Hosted helper execution,
Windows helper execution, convenience CLI/GUI and full A2/A5/C1 acceptance
remain pending. Local commands are retained in
`build/attachment-helper-validation.log`.

## Explicit interrupted recovery

**PRESENT, UNVERIFIED native helper execution:** invoke `AttachmentHelper` with
`--recover --request <absolute-recovery.json> --request-sha256 <sha256>` and
`--confirm-target-change`. Recovery can replace the target with the verified
pre-operation image. A request has exactly schemaVersion1, operation RECOVER,
receiptSha256, committedReceiptSha256 and paths. Paths explicitly selects targetBefore, targetAfter,
originalBackup, sidecar, source, exportReport, validationEvidence, receipt,
recoveryReceipt and restoreImage; refresh also selects previousReceipt,
previousSidecar, previousSource and priorTargetBackup. `targetAfter` selects the
private candidate's former path, which may now be absent after replacement.
Every other selection must match the canonical path recorded for that role.
No artifact path is taken from the receipt as an instruction to open a file.

The bounded request requires an exact SHA-256 pin. The selected receipt must
match either the explicitly pinned PREPARED bytes or the explicitly pinned
COMMITTED bytes; no other receipt content is accepted.
Only normal PREPARED/COMMITTED interruption records are admitted. Reconstruction
of PREPARED claims preserves every original field, hash, identity and metadata
claim; native recovery compares the actual receipt again before acting.
All-role preflight includes the request before a native host is opened. A fresh
host verifies the selected request and receipt, and the coordinator independently
checks the retained backup and current target. A concurrent unrelated target is
preserved. The original interrupted receipt is immutable; use fresh recovery
receipt and restore destinations. Reusing an existing recovery destination fails.

On success the result is ROLLED_BACK and exit0. RECOVERY_REQUIRED or any
refusal/cleanup failure exits nonzero. Cancellation is honored before recovery
starts; it cannot interrupt restoration halfway through. JSON output is explicitly
UTF-8 on both hosts. Successful attachment responses include a `recoveryInvocation`
selection document in addition to their diagnostic `recoverySelection` data.
Save and inspect that document before invoking recovery; it is not itself consent.

The helper now retains an explicit recovery selection before replacement, as
described below. GUI/authorization integration remains incomplete. A failure before any PREPARED receipt is published cannot have replaced
the target and is not admitted as an interrupted transaction.

**CONFIRMED local admission:** actual Java21 passes108 recovery selection checks,
including both initial/refresh and PREPARED/COMMITTED records, wrong pins, paths,
aliases, malformed requests, terminal records, cancellation and stream closure.
The existing532 coordinator checks (including8 abrupt exits) pass; these are
not new native-helper acceptance. CI's8 production Linux crash cases now launch
a fresh helper JVM for recovery and independently compare target bytes/metadata,
backup retention, immutable interrupted receipt and actual recovery record.
Hosted helper recovery and Windows recovery-helper evidence remain pending.
Commands/results are in `build/attachment-helper-recovery-validation.log`.

## Windows CI scheduling

The Windows host previously waited for the whole target-preflight matrix solely
to receive four x86 reference files uploaded at the end of that lane. A separate
`linux-x86-export-reference` job now builds the same fixture, installs the same
release extension and invokes the existing real headless export plus GNU/LLVM/
pinned-libdwarf checks. Windows consumes that artifact as soon as this job
succeeds. Source comparison and Windows export/refresh/GDB acceptance are unchanged.
`required-validation` explicitly still requires the full five-target matrix and
all host/consumer jobs, plus the new reference job. Lint passes locally; runtime
acceptance of the new scheduling remains pending.

## Recovery selections survive loss of helper output

**PRESENT, UNVERIFIED native execution:** ATTACH/REFRESH requests must now select
an additional fresh `paths.recoveryInvocation` file. All-role preflight protects
it against inputs, outputs, tools and the invocation file. After live validation,
backup and candidate preparation, the helper publishes this selection file
before the transaction can publish PREPARED or replace the target. Publication
uses an owned, flushed stage and the existing native independent-copy/exclusive
publication path, including namespace flush and digest/identity readback. There
is no overwrite or copy-over-existing fallback. Failure leaves the original
target unchanged and retains any completed backup. Unverified partial private
stages are retained, never deleted by guesswork.

The saved file includes every explicit recovery role, including the private
candidate's path, and SHA-256 pins for the exact canonical PREPARED and COMMITTED
receipts of this operation. Both are computed from the same immutable claims
before replacement. Consequently the file remains usable at either interruption
phase without needing stdout or rewriting an approval document after commit.
The helper binds the saved file through the remaining transaction boundaries.
It is inert selection data, not authority to restore a target. A user must still
explicitly invoke `--recover`, pin the saved file itself and confirm target change.

**CONFIRMED local ordering:** initial and refresh tests verify the saved request
is published while the target still has its prior bytes/metadata and the operation
receipt is absent. They decode it against the later durable receipt, exercise
both pin phases, and prove an existing selection file is preserved. A publication
refusal prevents target replacement and retains the independent original backup.
Native CI's eight crash cases now publish this same file *before* the abrupt
child and recover via a fresh helper using those retained bytes. Production
initial cases additionally verify their saved document binds the actual committed
receipt. Hosted execution remains pending; generic tests do not establish native
metadata or real ELF acceptance. See `build/attachment-saved-recovery-validation.log`.
