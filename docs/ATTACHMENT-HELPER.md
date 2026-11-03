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
The convenience launchers, OS authorization, durable public recovery interface
and GUI journey remain **PLANNED**. The standalone helper below is implemented;
its actual native execution is **PRESENT, UNVERIFIED** until hosted tests pass. The metadata policy and Ghidra/Java/native producer baselines
are unchanged.

## Explicit selection transport

**PRESENT, UNVERIFIED end to end:** `AttachmentInvocation` supplies the shared
read-only request format. Schema1 has exactly `schemaVersion`, `operation`,
`paths` and `validatorTools`. `operation` is ATTACH or REFRESH. The path object
contains target, sidecar, source, exportReport, originalBackup,
validationEvidence, receipt, recoveryReceipt and restoreImage; REFRESH also
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
must be requested separately by the invoking user interface. Recovery transport
is not implemented by interpreting arbitrary receipt paths; RECOVER currently
rejects rather than guessing selections.

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
