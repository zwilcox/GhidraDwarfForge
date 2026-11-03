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
The launcher, OS authorization, cancellation/recovery interface and GUI journey
remain **PLANNED**. The metadata policy and Ghidra/Java/native producer baselines
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
