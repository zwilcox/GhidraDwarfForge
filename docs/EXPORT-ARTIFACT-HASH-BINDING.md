# Selected files and reported SHA-256 claims

**CONFIRMED locally; hosted gate pending:**
`ExportArtifactHashBinding` composes the current report reader and streamed
digests. Actual Java 21 focused and installed-oracle checks pass, with
independent source/runtime review.
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
array bounds. Its detailed diagnostic inventories are validated and discarded;
the returned claims retain counts, not enough information to approve every
diagnostic under a future attachment policy. Artifact reads use a 64 KiB buffer
and checked long byte counts, independent of file size. No complete artifact is
buffered and no report-file digest is claimed.

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
Windows. Final package and the complete hosted gate remain required. See
`VALIDATION.md` for commands, evidence and limitations.
