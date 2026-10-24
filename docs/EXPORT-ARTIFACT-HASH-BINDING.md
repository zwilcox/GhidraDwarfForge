# Selected files and reported SHA-256 claims

**CONFIRMED:** PR #36 head `c526102` passes all twelve jobs in exact hosted run
`40102754052` and merged normally as `18b3e2e`. Independent package, all five
target and both GUI reviews pass. Fifteen reports, 45 retained copies, the x86
large-file case and eighteen native Windows focused checks are accepted. The
Windows binder has 551 platform-applicable assertions; Linux has 574.
`ExportArtifactHashBinding` composes the current report reader and streamed
digests. Separate main push `40105363431` also passes all twelve jobs and
independent Linux/Windows GUI reviews.
Ordinary export does not call this helper.

`observe(report, original, sidecar, source[, cancelled])` reads one explicitly
selected JSON report and three explicitly selected regular files. It compares
their observed SHA-256 values with the report's input, output and source claims,
respectively. Files are opened read-only and no output is created. The report's
path strings are never converted to local paths or used to find an artifact.

## Results and failure order

The immutable result retains the parsed `ExportReportClaims` and three named
artifact observations. Each artifact has the supplied `Path`, observed SHA-256,
GNU CRC32 and byte count, and one agreement:

| Agreement | Meaning |
| --- | --- |
| `MATCHING_REPORTED_SHA256` | The selected bytes observed during reading have the SHA-256 claimed for that role. |
| `DIFFERENT_REPORTED_SHA256` | The observed SHA-256 differs from that role's claim. |

SHA hex comparison ignores ASCII case; reported strings retain their original
spelling. Only SHA-256 is compared: the report does not claim a CRC or byte count.
An ordinary mismatch does not prevent the remaining roles from being read.
There is no overall success, identity, eligibility or attachment-readiness flag.

Null arguments are rejected, then cancellation is checked. The selected report
must currently resolve to a regular file and is completely parsed before any
artifact is inspected. Current-shape `SUCCESS` and `PARTIAL` reports are accepted;
`PARTIAL` and `NOT_RUN` retain their meanings. Valid `FATAL`/`CANCELLED` reports
throw the reader's typed terminal exception; unsupported historical shapes throw
its typed unsupported-shape exception. Malformed reports remain I/O failures.

The original, sidecar and source must all currently resolve to regular files
before artifact digesting begins. They are then read once each in that order.
I/O, close, supplier failures or cancellation return no result; a failed or
unread role cannot appear as a match. Primary and suppressed exceptions are
preserved. The reused report/digest readers own and close their streams.

## Filesystem and resource limits

The supplied path spelling is retained. Actual host traversal, including selected
leaf links and `..`, determines which file is read; there is no normalization,
canonicalization or exporting-host path interpretation. Explicit aliases and
hard links are permitted for this read-only observation. Equal hashes for the
same selected plain-data file in all three roles do not make it a valid ELF or C
artifact.

Attribute reads reject known directories, FIFOs and other special files before
opening them. Attribute failures propagate. This precondition is not an atomic
open or protection against replacement between the check and read. Cancellation
cannot interrupt an already blocked operating-system call. The helper makes no
concurrent-change, locking or immutable-snapshot guarantee.

The report reader keeps its documented 64 MiB input, string, nesting, value and
array bounds. The lightweight `observe()` methods validate and discard diagnostic
inventories; their returned claims retain counts. Artifact reads use a 64 KiB buffer
and checked long byte counts, independent of file size. No complete artifact is
buffered and no report-file digest is claimed.

## Detailed binding

**CONFIRMED locally; full hosted gate pending:** opt-in `observeDetailed()`
returns `DetailedResult(binding, inventories)`. It uses one complete strict report
parse to obtain both claims and the five immutable diagnostic inventories, then
performs the same three regular-file prechecks and ordered digest observations.
The inventories have the additional entry/string retention bounds documented in
[`EXPORT-REPORT-CLAIMS.md`](EXPORT-REPORT-CLAIMS.md). No second report read joins
claims from one version with diagnostics from another. This still makes no
same-stream report-hash or cross-file snapshot claim.

All three artifact observations remain present when any SHA claim differs. Full
diagnostics accompany `PARTIAL` and `NOT_RUN` unchanged; there is no severity
allowlist or validation-status upgrade. The existing lightweight API and result
shape remain unchanged.

The connected acceptance workflow selects a captured report and full producer
transcript explicitly, binds the selected original/sidecar/source, and retains
separate prefix, allocation, build-ID and reported-target observations before
constructing an owned private candidate. Matching or absent-both build IDs remain
distinct outcomes. Unsupported, missing or differing evidence prevents that test
construction. This fixture workflow is not a public attachment operation or a
generic readiness API; independent DWARF/source correlation and the filesystem
transaction remain separate requirements.

The test handoff is explicit: the early report-claims oracle can publish a new
`--handoff-manifest <path>` using exclusive creation. It points to that completed
reader result by absolute path and SHA-256. Before publication and consumption,
recheck the exact retained producer transcript, its single raw JSON report and
the three retained artifact copies for every role. Reported artifact paths remain
opaque lookup keys in recorded evidence; they are not opened as current files.
This small manifest is an unsigned test handoff, not a product validation receipt.

Run the association harness once per target with its `FORGE_REPORT_MANIFEST` and
`FORGE_MODULE`. A normal run requires the recorded reader and producer installation
paths and JAR/script hashes to match the current installation. An explicitly
retained-export replay uses `FORGE_RETAINED_EXPORT=1`; the underlying consumer
receives `--retained-export` and records that distinction. There is no latest-run,
directory-glob or mutable-export-log fallback. Historical multi-target commands
describe the older harness, before this explicit evidence handoff.

The installed Java 21/64 MiB workflow passes nine retained exec/PIE/no-build-ID
cases across x86-64, AArch64 and MIPS32 big-endian. Independent review reconstructs
18 repeated ordinary candidates and 12 positive control candidates, verifies all
78 controls and the complete unclassified inventories, and checks 27 retained
report/transcript sets, 81 earlier artifact copies and 45 current input copies.
Nine ordinary GDB checks, eighteen plain native/QEMU process executions, three
static GDB source-path failures and three expected LLVM DWARF failures pass.
The ordinary candidates pass GNU ELF and LLVM checks. All 36 original fixtures
and eight protected source/module/base-installation files remain unchanged.

These are new private candidates using retained exports. No fresh Ghidra export
or repeated strict validation of unchanged sidecars is claimed. The source-path
and corrupt-DWARF controls deliberately demonstrate unresolved association
requirements; passing the content observations does not hide either failure.
The exact package, all-five-target pipeline and native Windows acceptance for
this change remain pending. See `VALIDATION.md` for retained commands and scope.

## What agreement leaves unproved

A report is unauthenticated input. Rewriting its SHA claim can make changed
bytes agree again. Its target and producer text are still claims; false target
text can coexist with matching hashes. The helper does not parse ELF, compare
target metadata, inspect DWARF, validate source correlation or run a debugger.

Prefix, allocated-metadata and build-ID observations remain separate. Their
different, unsupported and no-evidence outcomes must not be replaced by hash
agreement. Even all these observations together cannot establish valid appended
DWARF or a cross-file snapshot. A byte-identical source copied elsewhere can
still break the path recorded in DWARF.

Selecting or persisting the correct report from a headless transcript is a
separate caller responsibility. This helper accepts a JSON file, not an entire
console log, and does not authenticate its provenance. Optional attachment,
receipt evolution, explicit mutation choice, verified backups, executable
preservation and rollback remain the separate transaction in
[`ADR-0004`](ADR-0004-DEBUGLINK-ATTACHMENT.md).


## Focused acceptance

Actual Java 21.0.12.1 with `-Xmx64m` passes 574 default checks and 577 with the
optional large-file case. The latter reads 2,147,549,185 bytes and compares SHA,
CRC and count against an independent sparse recipe. Four focused Gradle suites,
the extension build and architecture guard pass. Tests cover writer-generated
SUCCESS/PARTIAL reports, typed terminal/historical failures, all seven nonempty
role-mismatch subsets, opaque report paths and rewritten claims, regular-file
preconditions, actual host traversal/aliases, ordered failures, cancellation and
exact closure/suppressed exceptions. They reuse the existing reader and digest
coverage rather than defining another parser or digest algorithm.

Source, fixture and installed-runtime reviews are clear. The independent
Python oracle passes nine retained real-export reports across x86-64, AArch64
and MIPS32 big-endian, covering exec, PIE and no-build-ID roles. It retains all
27 artifact copies and nine exact reports/complete producer transcripts.
Twenty-one mismatch-subset cases, twelve report-first and twelve selected-file
rejections pass, plus the explicit false-claim, alias and opaque-path controls.
The x86 oracle independently checks a 2,147,614,795-byte sparse selected file;
its retained recipe is independently reconstructed during review after the
large input has been removed.

These are explicit retained-export replays through the installed helper, not
new Ghidra, validator or debugger executions. CI schedules the same oracle in
all five target lanes, its large case on x86 and the focused suite on native
Windows. Independent local package review is clear; the complete hosted gate
remains required. See
`VALIDATION.md` for commands, evidence and limitations.

## Detailed binding hosted acceptance

**CONFIRMED:** PR #40 head `13e706e5` passes exact run `40119714272`, all twelve
jobs, exact package/source review and all five fresh installed preparation
artifacts. Both GUI hosts and 22 native Windows checks pass; detailed432 and
the combined 16,384-entry/1,048,576-UTF-16 boundary are actually observed on
Windows. Merge `25845418` preserves that tree. The earlier local replays remain
separate evidence; the distinct main push is tracked in `VALIDATION.md`.

The next captured-validator handoff is test-only and not yet accepted; see
`VALIDATION-EVIDENCE-HANDOFF.md`. It preserves this API and PARTIAL/NOT_RUN.
