# Isolated attachment invocation

**PRESENT, UNVERIFIED complete public flow:** keep Ghidra unprivileged and perform attachment in a
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
The Linux launcher, standalone helper, recovery interface and saved selections
are implemented below; their complete native execution remains **PRESENT,
UNVERIFIED** until hosted tests pass. The Windows launcher/owned-token scope are also implemented but await native
acceptance; the initial GUI request review/launch flow is implemented below but
complete GUI journeys remain **PRESENT, UNVERIFIED**. The metadata policy and Ghidra/Java/native producer baselines
are unchanged.

## Script Manager and cooperative cancellation

**PRESENT, UNVERIFIED full modifying GUI flow:** run
`ExportAndAttachGhidraDwarfForge.java` with the analyzed program open to prepare
an initial attachment or refresh. Select the executable, a fresh sidecar filename,
records directory and validator tools. For refresh, also select the original
backup and previous committed receipt/pair; the export uses that original backup
and retains Ghidra's imported-input SHA-256 check. The packaged validator process
supervisor is selected from the verified installation. The strict checker must be
the raw executable from the pinned2.3.2 bundle, with its pinned configuration.

The script exports the current curated program, captures that completed report
directly in script state, binds its hashes to the actual selected input/pair,
and publishes `export.json` and `request.json` in a fresh records subdirectory.
The original executable is not changed during preparation. SUCCESS/PARTIAL and
NOT_RUN keep their meanings; live structural validation remains mandatory in
the isolated attachment helper after the later confirmation. A failed/cancelled
export, missing report or changed/mismatched bytes cannot produce a request.
The temporary script-state report is cleared on success, failure and cancellation.

Fresh pair/report/request publication uses exclusive hard-link creation from
complete owned stages, with rollback when the second installation fails. Existing
destinations, including files appearing after preflight, are never overwritten.
Staging links are removed before return. The selected filesystem must support
same-directory hard links; failure does not fall back to overwrite/copy. This is
separate from the helper's retained independent executable backup and native
atomic target replacement. Ordinary export retains its existing output behavior.

To use an existing request, run `AttachGhidraDwarfForge.java`; to recover, run
`RecoverGhidraDwarfForgeAttachment.java` and select the saved recovery request.
Successful native GUI attachment/refresh/recovery acceptance remains incomplete.

The installed helper first previews the SHA-256-pinned request in a separate,
unprivileged JVM. The GUI displays the executable, pair, backups, receipts and
selected validators. Cancel is the default. After explicit target-change consent,
a separate choice selects current permissions or OS authorization; Linux uses
pkexec, Windows uses the selected PowerShell7 executable and the launcher's RunAs
option. Authorization is never retried automatically. Ordinary export never
enters this flow. The helper still requires live validators and full native host
admission; a successful preview alone cannot authorize a commit.

The GUI owns a fresh empty cancellation file and an open write handle. The
launchers forward `--cancel-file=<absolute-path>` / `-CancellationFile` literally.
The helper includes that file in all-role alias preflight, reads no commands from
it, and never writes it. A nonempty file, observed identity/mtime change, removal
or inspection failure latches cancellation at the existing safe boundaries.
Windows Java file attributes can omit `fileKey`; Windows cancellation therefore
uses the already audited read-only volume/file-ID/size/time handle reader. It
does not enable privileges or query protected security metadata. Native Windows
acceptance of this correction remains pending after job126079953727 exposed the
null Java identity; no pathname/mtime-only identity fallback is used.
The GUI signals cancellation without terminating a modifying helper, waits for
its outcome and drains both output streams. Recovery already in progress finishes
restoring the selected image. Closing an authorization console can lose output;
the durable transaction/recovery receipts remain authoritative. Loss of the GUI
process is not proof that a helper stopped; preserve the saved recovery request.

**CONFIRMED local components:** actual Java21 passes149 helper checks and112
recovery checks; a separate child-process test proves cooperative cancellation
finishes cleanup and drains stdout/stderr larger than pipe capacity. Linux
launcher routing passes12 cases without real elevation. Native Windows and
full modifying GUI cancellation still need hosted artifact acceptance.
Actual installed Linux Script Manager preview/default-Enter decline, unchanged
selected inputs, absent transaction outputs and the existing export/GDB regression
pass under Java21/Xvfb/Openbox. See
[`attachment-gui-local-20261103.json`](evidence/attachment-gui-local-20261103.json).
The subsequent preparation journey also passes: actual curated export, direct
captured report, byte agreement, separate default decline, no executable change
and no transaction outputs. Both the ordinary/loader pair and newly prepared pair
pass GNU/LLVM/pinned-libdwarf and GDB names/source/next/step/normal-exit checks.
Unit controls cover fresh publication collisions/rollback and27 preparation
checks, including fatal, cancellation, changed source and mismatched report.
See [`attachment-preparation-local-20261103.json`](evidence/attachment-preparation-local-20261103.json).

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
live GNU/LLVM/pinned-libdwarf validator. On Windows, `--enable-security-privilege` explicitly enables the helper's
already-owned security privilege for its lifetime and restores the previous
state. The PowerShell launcher can request UAC only when explicitly selected;
its native acceptance remains pending. On Linux the existing
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

## Linux launcher

The installed extension includes executable `support/ghidra-dwarf-forge-attach`.
Prepare an explicit selection JSON as above, then review it without changing any
files or acquiring native privileges:

```sh
support/ghidra-dwarf-forge-attach \
    --ghidra-dir=/path/to/ghidra_12.0.3_PUBLIC \
    --request=/absolute/attachment-request.json \
    --request-sha256=<sha256-of-that-file> --preview
```

To perform the selected operation, replace `--preview` with
`--confirm-target-change`. Add `--authorize=sudo` to explicitly request terminal
OS authorization, or `--authorize=pkexec` to use an installed desktop authorizer.
The launcher previews the same pinned request before invoking either authorizer.
With no authorization option it uses the current process authority and never
retries elevation after failure. `--recover` selects the recovery format instead
of ATTACH/REFRESH. Every modifying invocation requires confirmation; missing
confirmation displays the selection and exits64 without starting a native host.
`--preview` remains read-only even if authorization/confirmation flags are present.

`--extension-dir` selects an installed extension when invoking the launcher from
another checkout. `--java` selects the Java executable explicitly; otherwise it
uses JAVA_HOME/bin/java or Java on PATH. Dependency locations match Ghidra12.0.3.
Installation/classpath paths containing a colon are rejected on Linux because
Java treats that character as a classpath separator; target/request paths remain
literal arguments. Paths with spaces, quotes, Unicode and shell metacharacters
are passed as argument-array elements, never evaluated as shell code. The launcher
opens no requested log or output file. Its stdout is a preview JSON followed by
the helper result on an executing invocation. Preserve the selected saved recovery
request and inspect the durable receipt if the process or terminal is interrupted.

**CONFIRMED local routing/package checks:** ten owned fake-authorizer controls
prove no consent/no automatic elevation, preview failure, exit-status forwarding,
exact argument preservation and explicit sudo/pkexec routing. They do not acquire
privileges. An actual Java21 launcher preview and no-consent run pass with every
selected input unchanged. Helper108 checks pass, and both base ZIP and release
assembly preserve the executable launcher and its exact bytes. A stale cached
ZIP initially retained mode0644; a fresh Gradle rebuild proves the new permission
rule. The release assembler independently enforces the mode. The Linux production
matrix now invokes the packaged launcher for actual attachment, keeping its existing
validator/GDB/CRC/metadata oracles. That hosted execution and actual OS authorization
journeys remain pending; Windows launcher and GUI acceptance remain incomplete.

## Windows launcher

PowerShell7 users can invoke the installed script with explicit selections:

```powershell
./support/ghidra-dwarf-forge-attach.ps1 `
    -GhidraDirectory C:\tools\ghidra_12.0.3_PUBLIC `
    -RequestFile C:\analysis\attachment-request.json `
    -RequestSha256 <lowercase-sha256> -Preview
```

Replace `-Preview` with `-ConfirmTargetChange` to execute; add `-Authorize` only
when requesting OS authorization for the separate helper. `-Recover` selects a
saved recovery request. Ghidra stays in its existing process. The launcher shows
the selected paths before either execution or authorization and opens no log or
result destination. See [the native mapping and authorization contract](WINDOWS-ATTACHMENT-AUTHORIZATION.md)
for the owned security-privilege scope, PowerShell7 dependency, UAC output limits
and exact pending validation. Native Windows launcher/authorization and GUI
acceptance remain incomplete.
