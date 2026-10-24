# Validation evidence in the fixture pipeline

**CONFIRMED locally:** source `9390565`, 100 focused checks, nine fresh validator
pairs and nine connected installed cases pass. Independent capture, candidate,
GDB/runtime and eighteen entry-point rejection reviews are clear. The workflow's
fresh-export integration is **PRESENT, UNVERIFIED** until its complete hosted
gate passes. This document describes the selected test contract and its limits.

The pipeline already validates the exported sidecar, but its later private
candidate preparation previously had only separate selected-file hashes and
historical validator results. The new handoff binds those observations to the
same bytes. It captures the existing LLVM and strict libdwarf invocations once,
then verifies their complete retained evidence before ordinary candidate
construction. It does not change the production exporter or report schema.

## Explicit selection and retention

Each target job creates a fresh directory below
`build/test-results/validation-evidence/`. It retains one validator toolset and
three captures: `exec`, `pie` and `exec.no-build-id`. The tools, case directories,
index and report handoff are explicitly named; none is selected by a glob or a
latest-file rule. Existing destinations are rejected rather than reused.

`headless-symbol-export.sh` opts into capture only when the caller supplies
`FORGE_VALIDATION_EVIDENCE_DIR` and `FORGE_VALIDATION_TOOLSET`. Capture replaces
that invocation's two existing checks. Other calls retain their existing checks.
In particular, the x86 deterministic repeat remains a separate normal validation;
the first capture is retained and its selected bytes must still match the repeat.
Captured output lives in the fresh case directory, independently of the shared
working logs that later regressions may overwrite.

The early report reader receives `--validation-evidence <index.json>`, verifies
each role against its retained original/sidecar copies, and writes handoff schema
2. That test handoff contains the existing `claimsResult` path/hash plus the
`validationEvidence` index path/hash. The exporter report remains schema 1 and
its `validation.status` remains `NOT_RUN`. All five diagnostic inventories and
`PARTIAL` remain unchanged and unclassified.

The connected consumer verifies the exact handoff, index, captures, toolset and
selected bytes before invoking Java. Legacy handoff schema 1 is explicitly
`NOT_CAPTURED` and cannot enter normal preparation. `--retained-export` permits
an explicitly identified older exporter installation; it does not permit absent
validator evidence or silently run new checks for an old capture.

## What a capture establishes

The selected original and sidecar are streamed and hashed before the first
validator and after the complete pair. Their full bytes, size and observed mtime
must agree. The capture retains exact argv, CWD, explicitly selected environment,
normal exit status, separate closed stdout/stderr and their size/hash records.
It verifies the complete output again before publishing a successful receipt.
A failed or incomplete operation retains diagnostics without a success receipt.

The shared toolset retains the pinned validation-only libdwarf bundle, its
source/build/patch/configuration provenance, the strict parser and capture source,
and the selected LLVM executable with explicit distribution notices. LLVM runs
from its original resolved path; its retained copy is for independent rehashing.
The relocatable libdwarf bundle runs from the retained toolset. Capture checks
tool evidence across the complete validation pair. Retained scripts supplied by
an archive are never imported by the reader: it uses the current trusted parser
and requires matching policy source bytes.

LLVM must identify the selected sidecar and complete all expected verification
stages with a single final `No errors.` and no stderr or diagnostic. Strict
libdwarf checks retain their existing compiler/category/totals/final-tail rules.
The sole inherited-frame exception remains exact: matching target and `.eh_frame`
address/size/bytes, the same tool's complete original output, and identical
diagnostic multiplicities. Corroborated nonzero counts remain visible. Selected
file verification recomputes the actual frame correspondence; it does not trust
an unsigned identity field. A stripped candidate's clean log is not evidence
about the separate sidecar's DWARF.

## Limits and failure controls

SHA/copy operations use 64 KiB chunks. Small metadata has a 2 MiB limit; the
existing strict metadata and each full log have a 64 MiB limit, with a 512 MiB
case total. A retained toolset has at most 64 files, 128 MiB per file and 256 MiB
total. JSON is limited to depth 8, 262,144 values including keys, 65,536 UTF-16
units per string and 16,384 units per path. Unsupported or excess input fails
explicitly; a passing capture is never truncated. The existing 65,536-message
diagnostic corpus remains a required capacity regression.

Core controls must reject changed selected bytes, roles, tools, configuration,
parser, outputs and status; malformed schemas and paths; incomplete checker
tables/tails; and changed inherited-frame correspondence. Separate connected
controls call the real consumer with malformed or legacy handoffs, substitute
Java/compiler sentinels and require rejection before either can run. They also
require no normal workspace, candidate or successful result and unchanged inputs.

The prior raw Java-probe controls deliberately remain separate and ungated by
validator evidence. They demonstrate why hashes and ELF observations alone can
construct a candidate from invalid appended DWARF or a missing recorded source
path. Those `CREATED` outcomes are not successful captured-evidence preparation.
Ordinary candidate GDB tests still check the actual selected objfile, source
fullname and listing after creation. Structural validation does not prove source
availability or decompiler semantics.

These limits bound retained-evidence reading/copying, not running-tool duration
or disk growth. The trusted CI helper does not supply production cancellation or
process-tree supervision, and the Java 64 MiB heap limit does not apply to Python
or external tools. Only the selected environment is recorded; inherited dynamic
dependencies and ambient process state are not authenticated. Before/after SHA
does not defeat change-and-restore races. Replacing an entire unsigned evidence
set can forge its claims. No public attachment approval, immutable snapshot,
backup, host metadata preservation, publication or crash recovery follows.

## Local acceptance

The 100 focused checks include 97 core cases and three additional read-only
checks of the retained native 65,536-message corpus. CI runs the core cases plus
its generated complete capacity control; the existing native capacity suite
remains unchanged. Source and tests are independently reviewed. Three owned
sparse size-only placeholders retain their recipe, sizes and rejected hash-call
counts, then are removed after successful checks; substantive evidence remains.

The explicit local capture run checks retained x86-64, AArch64 and MIPS32
big-endian exports in exec/PIE/no-build-ID roles. Independent output review finds
22 exactly corroborated frame diagnostics and zero unexplained errors. Each
target retains 28 tool/source/configuration/version-output files for rehashing.
This is nine new validator pairs on older exports, not a fresh Ghidra export.

The installed consumer then passes nine cases, eighteen actual-entry rejections,
and the separate 78 raw-probe controls. Independent review reconstructs eighteen
ordinary repeated candidates and twelve deliberate raw-control candidates,
checks nine ordinary GDB transcripts, eighteen plain native/QEMU processes and
the three separate missing-source static GDB controls. All 225 globally protected
paths retain SHA/size/mtime. Three later private no-ID CRC tests restore bytes
after changing mtime; those private final mtimes are not claimed unchanged.
Full evidence, commands and remaining hosted/package requirements are in
`VALIDATION.md`.

## Hosted acceptance

**CONFIRMED:** PR #41 head `f52361a` passes all twelve jobs in exact run
`40123518106`, attempt 1. The hosted focused suite records 97 checks, with exact
source/test and six retained compiler inputs independently rebound. All five
fresh exec/PIE/no-ID target sets pass: fifteen captured pairs, thirty actual
entry rejections, unchanged raw130 controls and full independent artifact chains.
Exact package, both GUI hosts and 22 native Windows checks pass. Complete
validator output has zero unexplained diagnostics; the named strict24 subset
remains separate from the primary captures. No report status is upgraded.

Normal merge `fdebe181` preserves the tested tree. Separate main push
`40126173922` is pending; see `VALIDATION.md` for package, review and scope records.
This acceptance does not complete the optional attachment transaction or change
published releases.
