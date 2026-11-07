# Optional multi-file synthetic source — issue #115

## Scope and decisions

**CONFIRMED requirement:** preserve the ordinary single-file default. Optional
partitioning must preserve the analyzed program's canonical types, scopes,
address ranges, variable locations and evidence-backed source correlation.
Every emitted file remains explicitly synthetic.

**CONFIRMED design:** retain one DWARF compilation unit and one type
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

**CONFIRMED local production checkpoint:** `SourcePartitionPlan` partitions the fully
composed logical source after declaration and annotation processing. Its mapping
translates logical lines to file/local-line pairs without changing addresses or
type identity. File zero is reserved for the synthetic index; part files start at
one. These are file-table indices, not compilation-unit indices.

**CONFIRMED local production checkpoint:** the source bundle uses flat sibling files
named `forge-src-<ordinal>-<full-content-sha256>.c` and a canonical JSON manifest
named `forge-src-<full-manifest-sha256>.json`. The ordinary `<binary>.dbg.c` path
becomes an explicitly synthetic index only when partitioning is selected. The
manifest binds the input hash, logical source hash, index name, grouping target,
part hashes/byte counts/line bounds and function identities/dispositions. Names
never interpolate analyst labels. File ordinal distinguishes identical contents
at different file-table indices; changing the input or policy changes manifest
identity without forcing unchanged parts to be rewritten.

`SourceBundleStore` stages complete files beside the output and uses exclusive
hard links to install them without overwriting concurrent creations. It verifies
every referenced part before installing the manifest, then supplies another
verification step before mutable sidecar/index publication. This optional mode
requires filesystem hard-link support; it has no overwrite fallback. Existing
content must be identical, regular and not a symlink or protected-path alias.
An identical complete concurrent creation can be reused; a conflict is refused.
Old parts and manifests, including complete unreferenced files left by a failed
attempt, are retained: another export may already reference them. Only owned
temporary stages are removed. No pruning policy or ownership inferred from a
filename prefix is introduced. The existing recoverable pair/companion publisher
will switch the mutable outputs after the immutable dependencies are installed.

`SourceBundleFiles` identifies the synthetic index, strictly verifies its
manifest and all local parts, checks the headers and line populations, and
reconstructs the logical source hash using bounded streaming reads. It exposes
the entire required file set and checks for changes before use. This supports
retention/transport integrations. The GDB companion and build-ID installer now
consume the inventory, with scoped local tests below. Filesystem checks detect
ordinary concurrent changes, not hostile change-and-restore races between
observations; no cross-file atomic visibility or power-loss durability is claimed.

**CONFIRMED local integration:** translate line-program rows and declaration file/line
attributes through the same partition plan. Keep original logical coordinates
available for source/variable evidence assembly and expose the file translation
in the generated manifest. Audit consumers that currently retain only one
source file, including loader, relocation, attachment and build-ID installation;
none may silently omit referenced parts. Portable output-tree lookup must be
tested with the original export directory unavailable.

**PRESENT, partial production integration:** the underlying
`GhidraDwarfForge.java` script accepts `--source-lines=<positive integer>`.
It partitions the fully composed annotated source, installs its immutable parts,
uses the same file layout for native DIE/line output, and publishes the synthetic
index through the existing recoverable publisher. The default remains one file.
Both wrappers and the optional Script Manager launcher expose the line target;
their scoped local acceptance is recorded below. Broader attachment/installation
integration tests are still pending. The source-relocation
parser now preserves all file entries; its ELF plan exposes their order for
comparison with the bundle manifest. Derived-artifact validation requires and
rechecks the complete retained inventory, so copying the index alone cannot
authorize installation. The build-ID installer now retains both complete copies.

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

**HISTORICAL native-free foundation checkpoint:** `SourcePartitionSmoke` passes using
Java 21 runtime and `javac --release 21`. It independently reconstructs all
original source bytes across six partition targets, checks every logical-line
lookup, whole function/failure/omission boundaries, duplicate function names,
Unicode, unmapped preambles, oversized units, invalid metadata and mid-operation
cancellation. This does not prove emitted DWARF, debugger behavior, publication,
performance, Windows or hosted acceptance. All seven issue requirements remain
open until their respective production evidence is recorded.

**HISTORICAL line-encoding foundation checkpoint:** `Dwarf5MultiFileSmoke`, invoked by
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

**CONFIRMED source-bundle component checkpoint:** local manifest, store and
reader smoke tests pass alongside partition/line-table and both existing
publication regressions. They cover canonical/strict JSON, input/policy binding,
hostile labels, duplicate function names, original-byte reconstruction, immutable
reuse, ordinary and link-time creation races, symlink/hard-link conflicts,
retained old files, rollback of mutable outputs, moved trees with the original
directory unavailable, missing/changed parts, wrong headers/bounds and a source
part larger than the streaming buffer. Cancellation is injected at every
observed preparation (1,879), installation (169), and read (1,913) checkpoint.
The store tests use representative sidecar bytes; they do not substitute for a
real Ghidra export or GDB behavior test. The new tasks are listed in both host
CI jobs, but hosted execution is pending.

All three new suites also pass on the Java 21 runtime after their test classes
are compiled explicitly with `javac --release 21` against the production classes
and Ghidra's Gson JAR. The local Gradle smoke runner uses the installed JDK 25;
its default test bytecode cannot be launched directly on Java 21. This standalone
check verifies the selected Java 21 baseline without changing the native ABI.

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC bash ./gradlew --no-daemon \
    sourceBundleSmoke sourceBundleStoreSmoke sourceBundleFilesSmoke \
    sourcePartitionSmoke dwarfLineTableSmoke companionArtifactPublisherSmoke \
    artifactPairPublisherSmoke
```

## First actual headless multi-file export

**CONFIRMED local x86-64 ET_EXEC checkpoint:** Ghidra 12.0.3 imported and
decompiled the source-built `fixtures/multifile-source.c` fixture after
`strip --strip-debug`. Script option `--source-lines=8` produced an index and
eleven source parts for ten recovered functions and 27 canonical types. GDB
from another working directory resolved both names and `file:function`
breakpoints, listed both function bodies, inspected the function type, stepped
from `recovered_first` into `recovered_second` in a different file, finished the
call, observed global `observed == 10`, and executed `next`. Unknown recovered
parameter locations remain unavailable; this fixture does not claim parameter
lifetime recovery.

`SourceBundleRelocationSmoke` compared real producer line-program, abbreviation,
range/location and aranges bytes, preserved file indices, tested invalid path/
duplicate-file controls and all 1,368 relocation cancellation checkpoints. GDB
also passed from the relocated source tree with the original source directory
temporarily unavailable. `ArtifactValidationBindingSmoke` passes for both the
single-file and multi-file actual exports; removing each manifest/part causes
binding and recheck refusal (35 multi-file and 11 single-file refusal controls).

GNU ELF/DWARF dumps and LLVM verification pass. The pinned libdwarf 2.3.2 checker
passes the existing strict harness with two frame diagnostics independently
corroborated against the original executable. The older system `dwarfdump`
reports 15 line-range diagnostics on both single-file and multi-file exports;
the identical diagnostics are retained and are not suppressed or called a pass.
The fixture's existing recovery omissions keep its report status `PARTIAL`.
Counts, coverage, failed/skipped functions and omission/unsupported evidence
match the single-file baseline. Repeated multi-file exports have identical
sidecar/index/manifest/part bytes and leave the original unchanged.

The initial attempt on the external evidence drive refused hard-link installation
without leaving a final sidecar; the passing output used local tmpfs. Ghidra's
process exit status was zero even for that script failure, so these checks require
the exporter success marker as well as validating actual artifacts.

Evidence is retained under
`/mnt/external_drive/GhidraDwarfForge-agent-artifacts/issue115-multifile/headless-01/`,
including `checkpoint.json`, both reports, command/log files, validator output,
the unchanged-byte inventory and `source-generations.tar.gz`. This checkpoint
does not establish full #115 acceptance: the repeatable CI driver, feature
combinations, recursive/discontiguous fixtures, remaining targets, large-program
measurement, complete consumer retention and hosted/protected integration remain.

## Portable GDB companion and export binding

**CONFIRMED local production checkpoint:** `--gdb-loader` with `--source-lines=8`
generates a schema-2 companion containing the original/sidecar/index hashes and
the manifest and every part's hash, name and byte count. Production preparation
binds the bundle input hash and ordered source names to the actual ELF/DWARF.
Schema-1 single-file companions retain their existing manifest format and path
behavior. A staged index may have a temporary basename; verification uses its
explicit final basename and co-located dependencies.

When the companion is moved, it selects its co-located sidecar, index, original
executable and immutable source dependencies. It does not fall back to an old
export or the working directory. At the original location, a separately located
input executable keeps its explicitly recorded path. All required bytes are
verified before loading symbols, including missing/changed/symlinked parts.

GDB source substitution temporarily maps the recorded compilation directory to
the selected bundle directory. This is needed even if the old source tree still
exists; see [GDB source-path semantics](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Source-Path.html).
The loader borrows an existing exactly matching rule, refuses conflicting rules,
and removes only a rule it installed that still has its expected value after
unload or inferior exit. User replacement rules are preserved. GDB substitutions
are global: simultaneous bundles with the same recorded directory but different
selected directories require separate debugging sessions or an explicitly
rearranged source tree. Unknown GDB substitution output is refused without
overwriting user settings; tests establish the local GDB version, not every
version or locale.

`multifile-loader.py` passes eight live GDB cases on the actual native x86-64
fixture: original location, original conflicting rule, moved tree with old
sources still present, matching/conflicting/replaced rules, quoted Unicode paths,
and a moved tree with old sources unavailable. Cases verify cross-file stepping,
file/function breakpoints, source fullnames, missing-part refusal, unchanged
selected artifacts and rule cleanup. `GdbBundleCompanionSmoke` proves that the
current generator reproduces the published companion exactly with both staged
and final index names; it checks all twelve dependencies, rejects non-colocated
outputs and samples three of 5,879 cancellation boundaries. Python loader tests
pass 29 cases, and the existing live single-file ET_EXEC/PIE/shared-object loader
regression also passes. Foreign Windows paths are covered by Python unit tests;
this does not establish native Windows multi-file acceptance.

Two integration defects were found and fixed: companion publication calls its
preflight callback before the writer installs dependencies, and a Python-driven
GDB `source` command can preserve an outer script's `__file__`. Publication now
checks dependencies once installed; companion registration uses the compiled
function's filename to identify the companion actually executing. Both failures
and corrected runs are retained in the local evidence.

**CONFIRMED attachment-binding component checkpoint:** `AttachmentExportBinding`
now observes and rechecks every manifest/part using the host identity, metadata
and digest contract. The original input hash and DWARF file table must agree
with a recognized bundle. Exported and relocated validation bindings both reject
missing, edited, symlinked or replaced original dependencies. Controls also
reject complete internally consistent bundles for another input or source name,
even with a freshly rehashed report. The existing single-file identity-only test
retains its explicit distinction from DWARF validation. This verifies complete
input dependencies; the subsequent build-ID retention checkpoint follows.

## Complete build-ID source retention

**CONFIRMED local production checkpoint:** installation independently copies the
manifest and every part beside `export.source` and into the retained `source/`
directory. The report's private index basename is verified against the explicit
DWARF index name; it does not override the manifest or copy paths from a report.
Fresh derivative validation observes both complete inventories before publication.
All immutable dependencies are included in the sealed generation inventory and
subsequent managed-generation verification. Removal continues to retain sources.

Generation inventory bounds now admit two complete 65,536-part inventories plus
the previous evidence allowance, subject to the explicit 64 MiB / 1,000,000 JSON
value limits. Command/state records retain their separate 1 MiB / 20,000-value
limits. The 5,000-file record fixture crosses both old record budgets, round-trips
without truncation, and tests cancellation, duplicate fields, unsupported values
and oversized strings. It does not benchmark maximum-size installation. A test
found that the prior generic parser catch wrapped cancellation as invalid input;
the parser now preserves `CancellationException`.

`multifile-installation.py` runs the real Linux ext4 adapter and GNU/LLVM/pinned
libdwarf validators on independent copies of the actual x86-64 fixture. It passes
installation/idempotence, independent-copy checks for all twelve dependencies,
fresh GDB build-ID discovery and cross-file stepping with the export directory
hidden, deletion of every dependency from each retained inventory, restored
idempotence, failure/cancellation after sealing with successful retries, and
removal with retained sources. The final implementation passes the full driver
on Java 21. Single-file installation and fresh GDB source lookup also pass with
the old export unavailable. The initial tmpfs selection was correctly refused by
the production host's ext4 contract; no weaker host was substituted for the
passing production test.

Evidence is under the same `issue115-multifile/` root, including
`retention-driver-java21.log`, the archived ext4 driver artifacts and record tests.
The first automatic-discovery oracle incorrectly quoted GDB's filename parameter;
the corrected oracle uses `gdb.set_parameter`. Both failed and passing output are
retained. These local tests do not establish the complete large-program benchmark,
other target/host profiles, attachment refresh/recovery combinations, wrapper/GUI
exposure, the hosted matrix or protected integration.

## Wrapper and Script Manager controls

**CONFIRMED local checkpoint:** Bash `--source-lines=N` and PowerShell
`-SourceLines N` accept canonical decimal integers from 1 through 2147483647,
forward the selected value and leave default exporter arguments unchanged when
absent. Invalid values fail before opening a log or launching Ghidra. The installed
Bash wrapper exported the saved x86-64 project with `--source-lines=8` and the
GDB companion. GNU/LLVM and pinned strict verification pass (two original-frame
diagnostics corroborated by the existing policy), as do the eight live loader
transport/source-rule cases. The report remains `PARTIAL` for existing unlocated
recovery evidence; selecting the new source layout does not promote that status.

Explicit logs cannot occupy generated source-part/manifest filenames beside the
selected sidecar, including files that do not exist yet. Existing generations are
protected even when a later export chooses the single-file default. The wrappers
check symlinks and hard links, including aliases outside the output directory and
generated-name symlinks pointing to another log path. Bash also checks lexical
and actual traversal spellings and preserves newline-ended directory names during
source-directory resolution. These are pre-launch ordinary-filesystem checks,
not a claim to defeat a hostile concurrent path-swap attack. Independent logs
remain usable, including the same basename in an unrelated directory.

Both wrapper suites pass locally (PowerShell 7.6.8 on Linux); sentinel files and
the actual exported bundle survive rejected log collisions unchanged. Native
Windows execution is still pending. Windows symlink controls retain the existing
test's explicit skip when the runner lacks symlink permission; such a skip cannot
establish Windows symlink acceptance.

`ExportGhidraDwarfForgeMultiFile.java` is the explicit Script Manager launcher.
Its line-target dialog starts at 1000. The real installed Linux/Java 21 GUI
journey passes cancellation before export, invalid-zero refusal before native
loading, target-eight export, repeated source-inventory byte equality and a
subsequent ordinary export with the original single-file bytes. The multi-file
manifest reconstructs the same logical source as the curated baseline, retaining
the GUI's analyst function name, comments and equate. The GNU/LLVM/pinned checks
and GDB function/type lookup, break/list/next/step and equate-value checks pass for
both multi-file exports and the subsequent single-file export. Three inherited
frame diagnostics are independently corroborated for this GUI fixture.

The launcher is a required assembly input; packaging tests reject its absence.
The shared GUI harness and both host validation scripts include the new cases;
this does not substitute for a passing native Windows/hosted run. The first
local GUI negative test left Ghidra's expected error dialog open and blocked the
next case; the corrected test records and dismisses that dialog. Both runs are
retained. Evidence is under `issue115-multifile/source-options-*`, including the
assembled package, actual wrapper report, GUI screenshots/console/validator logs
and the checkpoint archive.

## Semantic comparison and lexical runtime checks

**CONFIRMED local checkpoint:** the production saved-program lexical fixture
passes single-file and repeated partitioned exports on Java 21 for x86-64 and
AArch64, each in non-PIE, PIE and Ghidra-rebased PIE form. AArch64 executes under
QEMU with GDB remote debugging. All six cases pass GNU/LLVM/pinned strict checks,
byte-identical partitioned reruns, original/reference preservation and the
existing saved-program preservation check (only Ghidra's two documented backup
files may change). Existing inherited frame diagnostics are independently
corroborated against the original; no new warning allowance was introduced.

`check-multifile-semantics.py` independently reads LLVM's decoded DIEs and line
rows. It verifies the complete manifest and reconstructs byte-identical logical
source, translates declaration/line coordinates back to that source, and compares
the ordered DIE tree and every attribute. DIE references use traversal identity,
not names; changing a type edge cannot be hidden by equal display names. Only
CU presentation paths, source coordinates and relocated DIE reference offsets
are normalized. Non-presentation debug sections and inherited `.eh_frame` remain
byte-identical, including `.debug_rnglists`, `.debug_loclists` and
`.debug_aranges`. Thirteen mutations of decoded attributes and line rows per
fixture are rejected before/after normalization. This is a bounded LLVM-output
oracle, not a replacement for structural validation or a general DWARF parser.

The existing GDB oracle compares compiler storage with recovered shadowed
locals at each inspected instruction, including unavailable initialization
intervals, an explicit lexical visibility gap, and values read from caller frames
through two calls. Single-file and partitioned observations match exactly. The
new checks resolve `file:function` breakpoints and listings and check that the
caller and callee resolve to their distinct generated files. The x86-64 fixture
has 30 scoped instruction observations and eight callee observations; AArch64
has 34 and twelve, respectively. The lexical gap is not a claim of new
discontiguous-function stepping acceptance.

Reproduce on an installed package with a Java 21 JDK:

```bash
DWARFDUMP=/path/to/pinned/dwarfdump python3 src/test/integration/lexical-shadow-export.py \
    "$GHIDRA_INSTALL_DIR" aarch64 --role pie-rebased --discontiguous --calls --source-lines 8
```

`--java /path/to/java` optionally launches the same production headless entry
point with explicit runtime selection and isolated script caches. Local initial
runs exposed Ghidra choosing Java 25 despite `JAVA_HOME`, then reusing its compiled
script cache under Java 21. Those failures are retained; the successful runs
isolate their Java 21 cache instead of deleting user caches or weakening the
runtime assertion. The normal CI launch remains `analyzeHeadless`.

The workflow includes all six target/layout combinations; hosted execution is
**PRESENT, UNVERIFIED**. Evidence is retained under
`issue115-multifile/lexical-final-*` and `lexical-checkpoint-v1.tar.gz`. Shared
recursive/duplicate-name type fixtures, broader target/Windows cases, complete
publication/consumer combinations and the large-program benchmark remain open.
No full issue acceptance requirement is closed by this checkpoint alone.
