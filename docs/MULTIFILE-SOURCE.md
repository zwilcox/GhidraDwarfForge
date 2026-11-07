# Optional multi-file synthetic source — issue #115

## Scope and decisions

**CONFIRMED requirement:** preserve the ordinary single-file default. Optional
partitioning must preserve the analyzed program's canonical types, scopes,
address ranges, variable locations and evidence-backed source correlation.
Every emitted file remains explicitly synthetic.

**PLANNED production design:** retain one DWARF compilation unit and one type
graph, with multiple entries in its DWARF 5 line-table file table. Partitioning
is presentation grouping, not evidence of original compiler compilation units.
Multiple CUs would introduce cross-CU type references or type duplication and
additional scope/ownership changes without corresponding recovered evidence.
They are therefore not selected for this feature.

The first grouping policy uses a requested source-body line target and stable
function order. Whole functions, failure/omission comments and the global
preamble are indivisible. A unit larger than the target occupies its own part
and is identified as oversized; the target is not a promise to split a function.
Namespace- or memory-block-based grouping is not needed to establish this
bounded-size policy. Default output remains unchanged when no policy is selected.

**PRESENT, UNVERIFIED in production:** `SourcePartitionPlan` partitions the fully
composed logical source after declaration and annotation processing. Its mapping
translates logical lines to file/local-line pairs without changing addresses or
type identity. File zero is reserved for the synthetic index; part files start at
one. These are file-table indices, not compilation-unit indices.

**PLANNED publication:** build and verify a complete immutable source generation
before switching the sidecar. Use deterministic relative filenames and a
manifest of source hashes, partition bounds and function associations. Stage a
generation beside its final location, then install the complete generation
before publishing a sidecar that refers to it. Reuse an existing generation only
after exact verification; reject conflicting content. Retain old generations
so old sidecars and concurrent readers do not lose their sources. Do not delete
unrelated files or infer ownership merely from a filename prefix. Failure,
cancellation and rollback must preserve a usable previous generation.

**PLANNED integration:** translate line-program rows and declaration file/line
attributes through the same partition plan. Keep original logical coordinates
available for source/variable evidence assembly and expose the file translation
in the generated manifest. Audit consumers that currently retain only one
source file, including loader, relocation, attachment and build-ID installation;
none may silently omit referenced parts. Portable output-tree lookup must be
tested with the original export directory unavailable.

## Original acceptance and required proof

1. Deterministic filenames, collision handling, grouping and manifest: identical
   reruns, hostile names, changed grouping, empty/function-failure cases and
   conflicting destination contents.
2. CU/type identity decision: one CU with multiple files, raw file-table and
   declaration-reference checks, and shared recursive types across files.
3. Semantic preservation: compare ranges, scopes, types and variable locations
   with the single-file export, including duplicate names and discontiguous bodies.
4. Debugger behavior: actual GDB file/function lookup, breakpoints, cross-file
   stepping and variable values from a different CWD and a moved tree.
5. Publication: cancellation and injected failures before/during installation,
   rollback, reused/conflicting generations and retained stale files/user content.
6. Measurement: a redistributable source-built large-function-count fixture,
   recording export time/size and debugger navigation. Retain regressions and
   inconclusive measurements; do not assume multiple files improve latency.
7. Validation: GNU/LLVM/strict DWARF checks, deterministic reruns, original-file
   preservation, existing source regressions and final protected CI integration.

## Current checkpoint

**CONFIRMED native-free foundation:** `SourcePartitionSmoke` passes using
Java 21 runtime and `javac --release 21`. It independently reconstructs all
original source bytes across six partition targets, checks every logical-line
lookup, whole function/failure/omission boundaries, duplicate function names,
Unicode, unmapped preambles, oversized units, invalid metadata and mid-operation
cancellation. This does not prove emitted DWARF, debugger behavior, publication,
performance, Windows or hosted acceptance. All seven issue requirements remain
open until their respective production evidence is recorded.

**CONFIRMED line-encoding foundation:** `Dwarf5MultiFileSmoke`, invoked by
`dwarfLineTableSmoke`, independently decodes file tables and line-machine bytes
and resolves every row back to expected part-file text. It passes 32/64-bit and
both byte orders, discontiguous/overlapping bodies, intra-sequence file changes,
multi-byte file counts/indices and unchanged logical source evidence counts.
The optional exporter layout uses the same translation for `DW_AT_decl_file`
and `DW_AT_decl_line` and rejects a plan for different source bytes. Production
option wiring and native/debugger validation are still pending.

The following command passes locally with Ghidra 12.0.3 (Java 21-compatible
classes); the standalone partition check additionally runs on a Java 21 JVM:

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC bash ./gradlew --no-daemon \
    sourcePartitionSmoke syntheticSourceSmoke dwarfLineTableSmoke \
    sourceCoverageSmoke sourceCoverageInventorySmoke annotatedSourceSmoke
```

The native pin remains libdwarf 2.3.2 at
`af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`; no JNA signature or new native
producer call is introduced by this foundation.
