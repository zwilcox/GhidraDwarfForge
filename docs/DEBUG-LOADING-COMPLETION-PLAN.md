# GDB loading and explicit debuglink completion

**CONFIRMED scope:** complete issues [#107](https://github.com/zwilcox/GhidraDwarfForge/issues/107)
and [#72](https://github.com/zwilcox/GhidraDwarfForge/issues/72). #107 is integrated
through PR157 at `c8e3afae3108ffe7d6a4b4d335463040426bc49c`; #72 remains
incomplete. This ledger supplements, and does not narrow, their acceptance
criteria or ADR-0004/ADR-0005. Performance issue #74 is outside this goal.

The selected baseline remains Ghidra 12.0.3, Java 21-compatible bytecode,
Gradle 9.3.1 and the existing pinned native producer. No new native producer
declarations are needed for the loader.

## Delivery and evidence ledger

**CONFIRMED:** L1–L7 are proven for the documented profiles by
[the acceptance record](GDB-LOADER-ACCEPTANCE.md), including the complete hosted
gate at `5654f53`, final-head gate41602638145 at `caa4916`, independent artifact
review and normal protected merge157. Loader C1 is complete; attachment C1 and
A1–A7 remain incomplete. The
separate attachment branch's component evidence does not establish those rows.
The checkpoint sections below are **HISTORICAL**, recording evidence as it
became available; their pending statements do not supersede this status.

**CONFIRMED scoped attachment implementation and Linux execution; final
acceptance incomplete:** the helper, both launchers and Script Manager controls
implement preparation, explicit review, attachment, refresh and saved recovery.
The independently reviewed Linux GUI job at188d413 passes initial/curated-refresh/
recovery and ordinary cancellation. Earlier production Linux artifacts cover
fifteen initial/rollback/GDB cases across five targets, two saved-program refreshes
and eight abrupt recoveries. Native Windows component evidence covers metadata,
sharing locks, initial/refresh coordinator recovery and scoped privilege cleanup.

Run41697807284's Windows rerun reaches real attachment but rejects a hard-linked
validator under the inappropriate recovery-file policy. The corrected read-only
tool observation atbe4c799 has an old/new-JAR causal regression and actual
validator/GDB acceptance locally. Full Windows runtime remains required.
Atf89a9e6, both GUI lanes additionally require cancellation after a native
validator has started; the real button/confirmation and process-cleanup components
pass locally, but the complete authorized journey is **PRESENT, UNVERIFIED**.
See the [hard-link evidence](evidence/validator-input-hardlinks-local-20261104.json),
[cancellation evidence](evidence/gui-active-cancellation-local-20261104.json),
[Linux transaction evidence](evidence/linux-attachment-41693381663.json) and
[Linux GUI evidence](evidence/linux-gui-attachment-41697807284.json).

The Windows job atbe4c799 subsequently passes current-permission/RunAs commits
and rollback with the hard-linked helper; [independent byte/log/CRC review](evidence/windows-attachment-operation-41866768900.json)
confirms those three cases. Saved-curation fails a test-only native-vs-FSRL path
comparison. The new active Linux GUI test fails a TaskMonitorComponent lookup;
Script Manager exposes cancellation through TaskDialog instead. Both observers
are corrected with [local controls and regression evidence](evidence/attachment-test-observers-local-20261104.json).
Linux active GUI cancellation subsequently passes at7d7b2ef in run41873454505,
including independent archived cleanup/target-preservation review and the complete
attachment/refresh/recovery/GDB journey. See [the evidence](evidence/linux-gui-attachment-41873454505.json).
Windows saved refresh subsequently passes both the hosted step and independent
[receipt/byte/log review](evidence/windows-attachment-operation-41873454505.json).
A local Linux GDB consumer confirms both Windows-produced CLI generations and
CRC rejection; this does not replace the full Windows GUI consumer.
[Current Linux attachment reviews](evidence/linux-attachment-41873454505.json) cover
x86-64, ARM32 and both MIPS byte orders. AArch64, Windows modifying GUI/cancellation
and the full gate remain unverified.

The same run's Windows attachment/rollback/saved-curation refresh step now
passes, but the first modifying GUI attachment exits1 before native validator
status or transaction publication. Its nested evidence path exceeds300 characters;
process-start/path behavior is under investigation with an isolated native Windows
observation. Windows GUI and the complete required gate remain failed/unverified.

The following rows retain their full required scope. Prior-head component or
Linux passes do not close a cross-host row or replace the final required gate.

| ID | Required outcome | Evidence required |
| --- | --- | --- |
| L1 | Optional deterministic companion, explicit CLI/GUI controls and documented loading/override semantics | Packaged exporter and both host GUI/wrapper journeys; disabled-default comparison |
| L2 | Same link-time sidecar at different runtime biases | Actual GDB function breaks, source, globals and available variables at each bias |
| L3 | PIE main/shared, ordinary/rebased, stripped/sectionless | Real exporter fixtures with independent ELF/DWARF validation and GDB |
| L4 | Native launch/attach, remote/QEMU, restart/exec/unload/reload | Runtime transcripts, invalidation/no-duplicate assertions; explicit unsupported-discovery diagnoses and working override |
| L5 | x86-64, AArch64 and validated 32-bit target | Same production path in all three CI lanes; widths/addresses derived from target |
| L6 | Ambiguity, wrong identity, absent mappings, special paths | Negative cases prove no incorrect symbol loading; paths with spaces work |
| L7 | Original/configuration preservation and unchanged default addresses | Hashes, deterministic reruns, publication rollback/cancellation; no .gdbinit edits |
| A1 | Linux/Windows identity and metadata contract | Native host tests for supported preservation and rejected links/streams/locks/security metadata |
| A2 | Explicit disabled-default attachment after validated export | CLI/GUI warning and successful validation binding; fatal/cancel refusal |
| A3 | Receipt-bound files/report/validator evidence/candidate; all-path preflight | Cross-role aliases, symlink traversal, hardlinks, dangling links, log/backup/receipt/stage collisions rejected before writes |
| A4 | Independent exclusive verified backup and atomic replacement | Bytes/metadata/identity observations and no-overwrite/no-copy-fallback tests |
| A5 | Cancellation, failure and durable recovery | Faults around preparation/replace/commit; complete old/new target, recoverable backup, protected concurrent target |
| A6 | Changed-CRC refresh with retained generations | Analyst edit, backup-based re-export, fresh pair basename, receipt chain and rejection of lost/overwritten old pair |
| A7 | Automatic discovery and CRC rejection | Fresh GDB sessions, no-build-ID mismatch, actual runtime checks on host/target matrix |
| C1 | Integration and documentation | Required exact-head CI, artifact review, normal protected merge, TODO/context/help reconciliation |

Attachment must implement the full ADR-0004 transaction: selected explicit
paths, preserved executable image/identity, supported metadata, exclusively
owned staging, independent retained backups, prepared and committed receipts,
flush/durability contract, safe rollback and immutable prior generations.
Existing observations and candidate preparation are prerequisites, not proof
of an attachment transaction. Refresh must preserve the strict Ghidra import
hash contract by exporting against the verified original backup.

## Implementation sequence

1. Implement and test architecture-neutral mapping arithmetic independently.
2. Add runtime identity validation, explicit GDB command, lifecycle handling,
   companion generation and complete artifact-set publication.
3. Exercise the loader with real exports across the full L1–L7 matrix.
4. Finish host transaction primitives and validation/receipt binding, implement
   initial attachment and refresh/recovery, then expose controls.
5. Exercise A1–A7, review every acceptance row and integrate through C1.

Mapping discovery must correlate runtime mapping file offsets with ELF PT_LOAD
virtual addresses. It must not substitute a presumed page size, preferred
image base, first mapping address or runtime .text address for load bias.
Missing or ambiguous evidence must produce a diagnosis; an explicit override
does not waive sidecar/target identity checks. Link-time DWARF stays unchanged.

Primary command/API references: [GDB file commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html),
[process mappings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Information.html),
and [Python lifecycle events](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html).

## Mapping arithmetic checkpoint

**CONFIRMED locally:** `src/main/resources/ghidradwarfforge/gdb/loader.py`
implements bounded mapping parsing and file-offset/PT_LOAD correlation without
assuming a page size, section table or preferred base. It returns all complete
module-instance candidates and refuses ambiguous automatic selection. It does
not yet install a GDB command, verify runtime identity or generate companions.
Thus no L1–L7 row is complete from this checkpoint alone.

Commands run from the `debug-loading` worktree:

```sh
python3 -B -m unittest discover -s src/test/python -p test_gdb_loader.py -v
python3 -B src/test/integration/gdb-loader-mappings.py
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew buildExtension
src/test/integration/architecture-neutrality.sh
git diff --check
```

Ten unit cases pass, including offset padding, split/overlapping mappings,
negative bias, ELF32 overflow, absent/ambiguous/inconsistent evidence and paths
with spaces. The live run in
`build/test-results/gdb-loader-mappings/run.5o_878da/` passes three native
non-PIE launches, three PIE launches with distinct ASLR biases and two shared
library load/unload cycles. Function/global addresses are independently checked
against compiler symbols, and GDB checks source, arguments 19/23, stepping and
global values 7/42. Selected fixture/source/reference hashes remain unchanged.
No attach/remote/cross-target or generated-Forge-companion claim follows.

The three reference images pass GNU readelf inspection without diagnostics,
LLVM verification and the locally installed dwarfdump invocation. These are
complete compiler ELF references loaded as symbols for stripped executables,
not artifacts made by the Forge writer. Earlier `--only-keep-debug` references
retained PT_INTERP headers without interpreter contents: readelf reported
`Unable to find program interpreter name` despite a zero exit code. Those
earlier runs remain under the result directory; the current harness preserves
the complete reference and rejects readelf diagnostics explicitly.

The extension builds. Inspection confirms the packaged loader source matches
the working source and both resource/source archives exclude host Python
bytecode, even after local imports. The new unit and live-reference CI steps
are **PRESENT, UNVERIFIED** on hosted runners. Actual GDB integration, complete
artifact-set publication, all loader acceptance lanes and the full attachment
transaction remain required.

## Generated companion and runtime identity checkpoint

**PRESENT, UNVERIFIED as a product feature:** `GdbCompanion.render` now builds
a deterministic self-contained `<sidecar>.gdb.py` from completed staging bytes
and their selected final paths. It requires copied-prefix and allocated-metadata
agreement with the selected original. The caller still needs three-artifact
publication and CLI/GUI controls; the ordinary exporter does not call it yet.

The generated file embeds the packaged Python runtime and inert base64 JSON.
Sourcing registers `forge-load [ID] [--bias INTEGER] [--module EXACT_RUNTIME_PATH]`
and `forge-unload [ID]`; it does not load symbols. Repeated sourcing reuses the
registry; mixed runtime revisions require a fresh GDB session. `forge-load`
checks all three selected file hashes and relocated immutable executable bytes
before adding symbols. It includes mapped ELF header identity where available,
excluding section-table fields that an eventual attachment changes. These memory
exceptions do not waive the selected original's full file hash.

Current bounded runtime contract: one stopped inferior, Python-enabled GDB with
the inspected lifecycle events and scoped parameter API, exact mapping paths,
at most 1 GiB of streamed immutable identity checks. Writable executable LOADs,
text relocations/changed code and unreadable identity bytes are diagnosed rather
than accepted without evidence. An explicit override permits unavailable mapping
queries, but does not bypass contradictory mappings, target width, file identity
or runtime byte checks. Native launch/restart and shared unload/reload have local
reference evidence; attach, exec, remote override and additional architectures
still require actual tests. Windows-host generation/control acceptance remains
open. These boundaries must be reconciled against the complete issue before
claiming completion.

Local tests now exercise the actual generated script through GDB's `source`
command, twice, from a built extension JAR. The smoke helper puts compiler DWARF
through the production matched sidecar writer, then calls the production
generator. It checks deterministic rendering, cancellation and rejection of an
unmatched compiler ELF. This proves neither Ghidra extraction nor final
artifact-set publication. The runtime tests retain function/global/source/
argument/stepping assertions, plus no duplicate objfiles, exit/unload removal,
wrong bias/module rejection, mismatched target/sidecar/source checks and wrong
runtime-code checks. Rejections leave the objfile list unchanged.

Seventeen Python unit tests pass. The generated-reference run
`build/test-results/gdb-loader-mappings/run.e1y_3jc7/` passes all three roles;
all three produced sidecars pass GNU/LLVM and local dwarfdump inspection. The
workflow now selects the installed extension JAR for this check, after package
installation. Hosted acceptance is **PLANNED**. No L1–L7/A1–A7 row is closed by
this component checkpoint.

## Exporter publication and native PIE checkpoint

**CONFIRMED locally:** `--gdb-loader` reaches the real headless exporter and
produces a matched sidecar, deterministic source and generated companion.
`CompanionArtifactPublisher` preflights the three output paths against each
other and the original, observes existing generations, stages complete files,
then installs each by atomic rename. It checks cancellation while hashing and
between installs. Observed failures restore previous outputs in reverse order;
conflicting concurrent edits are retained along with recovery backups. This is
not a crash-atomic multi-file operation and is not the #72 target transaction.
Stages must share the final output directory because the existing line writer
uses that directory for source lookup; only backups live in the private folder.

The publisher smoke covers new/existing output sets, writer failure, failure
after either of the first two installs, cancellation after the third install,
hard-link/input/cross-output aliases, preserved original bytes and rollback
blocked by concurrent user bytes. The Bash wrapper checks flag forwarding and
companion log aliases, including hard/symbolic links and nonexistent outputs.
PowerShell forwarding and companion protections and the separate GUI launcher
are **PRESENT, UNVERIFIED** on their native journeys. Both host CI smoke lists
include the publisher; hosted gates have not yet run.

A private Ghidra installation under `build/ghidra-loader-test` uses the newly
built extension and the previously accepted pinned 2.3.2 native pair through
explicit development paths. `GHIDRA_GDB_LOADER=1 FIXTURE_ROLE=pie` with
`headless-symbol-export.sh` passes the existing full x86-64 fixture validator
harness. Strict libdwarf reports one inherited frame error, independently
corroborated against identical original frame bytes; it is not suppressed.

`gdb-companion-native.py` then passes in
`build/test-results/gdb-companion-native/run.5v9j8q4y/`: three distinct ASLR
biases, independently expected function address, source lookup from another
working directory, structure type, arguments 19/23, initial globals 0/7,
post-step global 42, exited-objfile cleanup and unchanged artifact hashes. The
workflow includes this actual-export test for its x86-64 PIE case. Other
architectures, runtime modes and GUI acceptance remain outstanding.

Retained failed calibration: the earlier uncurated `mapping target` export
correctly omits unavailable parameter locations and has no typed analyst
global named `DAT_00104010`; expecting that debugger symbol was invalid. The
curated semantic fixture supplies explicit typed knowledge through the existing
preparation script. Its first listing assertion also expected an assignment
outside GDB's default ten-line window; a retained lookup investigation proves
the correct source path and declaration, and the corrected oracle tests the
declaration plus actual value changes rather than relying on that window size.
No exporter knowledge was fabricated to satisfy either assertion.

## Real remote, library lifecycle and GUI checkpoint

**CONFIRMED locally, not full L1–L7 acceptance:** the production exporter from
PR157 head `6861f39` supplies the companions used by the new test harnesses.
Six fresh exec/shared exports across x86-64, AArch64 and MIPS32 big-endian pass
GNU/LLVM/pinned-libdwarf validation. Strict diagnostics are independently
corroborated inherited-frame cases: x86 exec/shared 3/1, AArch64 exec/shared
5/5, MIPS exec/shared 0/0. Original fixture hashes remain unchanged.

The tests use independent runtime evidence: `AT_ENTRY` minus the compiler ELF
entry for executables, and `dlinfo(RTLD_DI_LINKMAP)` observed in the target for
libraries. They do not derive expected bias through the production mapping
algorithm. The shared driver uses two linker namespaces to create actual
ambiguous instances, switches the explicit selection, checks distinct global
values, unloads both and repeats. This Linux/glibc test fixture does not impose
a libc dependency on the production loader.

Commands (from this worktree, after the real headless exports):

```sh
src/test/integration/gdb-companion-shared.sh x86_64 normal
src/test/integration/gdb-companion-shared.sh x86_64 ambiguous
for target in aarch64 mips32be; do
    src/test/integration/gdb-companion-remote.sh "$target" exec
    src/test/integration/gdb-companion-remote.sh "$target" pie
    src/test/integration/gdb-companion-remote.sh "$target" pie no-hostio
    src/test/integration/gdb-companion-shared.sh "$target" normal
    src/test/integration/gdb-companion-shared.sh "$target" ambiguous
    src/test/integration/gdb-companion-shared.sh "$target" normal no-hostio
done
python3 -B src/test/integration/gdb-companion-attach.py \
    --input build/fixtures/x86_64/semantic.pie.stripped \
    --sidecar build/fixtures/x86_64/semantic.pie.ghidra-forge.dbg \
    --results build/test-results/gdb-companion-attach
```

Normal local QEMU connections supply usable process mappings. The `no-hostio`
case disables GDB's remote `vFile:open` support on a real connection; automatic
loading must diagnose unavailable mappings, while a correct explicit bias
still loads and a wrong bias is rejected. All runtime checks use actual named
breakpoints, source lookup, arguments and global values, with exit/unload
cleanup and input/artifact preservation. Remote results record ELF32 big-endian
and ELF64 little-endian observations without treating these as all-ABI claims.

The attach fixture permits tracing only an owned test child. A preload
constructor stops that child for attachment and an exit hook executes a
different image. The helper must remove the old symbols and refuse to load the
old companion into the new image. Passing evidence is retained in
`build/test-results/gdb-companion-attach/run.zgozzzvk`. The initial external
libc source warning at attachment is unrelated to Forge source lookup; the
latter is checked explicitly. Earlier handshake/SIGSTOP test-harness failures
remain retained. The shared harness's first run failed while parsing readelf's
column heading; it now requires a numeric symbol index.

**CONFIRMED Linux GUI evidence:** the unchanged production artifact downloaded
from run `41564572526` passes real Script Manager discovery and double-click
execution of `ExportGhidraDwarfForgeWithGdbLoader.java`, fallback output
selection, console reporting, unchanged-input checks and cancellation without
outputs. Evidence is in `build/test-results/gui-script-manager/run.rqRwXQUi`.
The resulting three-file generation passes GNU/LLVM/strict validators and a
fresh GDB session using `source`/`forge-load`, function breakpoints, `list`,
`next`, `step` and normal exit. Display dependencies are extracted private
Xvfb/Openbox tools; the user's desktop and Ghidra installation are untouched.

The candidate CI runs exec/PIE remote and normal/ambiguous shared tests on all
five target lanes, native x86 attach/exec, missing-mapping controls and both
ordinary/optional Script Manager journeys on Linux and Windows. New hosted
steps are **PRESENT, UNVERIFIED** until the exact updated head runs. ARM32 and
MIPS32 little-endian new companion harnesses have no local passing claim here.
Rebased/sectionless companion cases, complete cancellation/failure acceptance,
remaining cross-host evidence and #72's transaction remain required.

The ordinary launcher regression also passes with the same installed package
in `build/test-results/gui-script-manager/run.WSvQsJhX`: exactly two output
files, successful structural/GDB checks and empty cancelled destination. The
final remote/shared replay additionally requires the actual target's exit
status to be zero. Seventeen pure mapping/identity cases, `actionlint`, shell
syntax and `git diff --check` pass. These changes add tests and CI coverage;
production exporter/runtime bytes are unchanged from `6861f39`.

## Rebased, sectionless and in-progress cancellation checkpoint

**CONFIRMED locally:** actual production companions now pass x86-64, AArch64
and MIPS32 big-endian sectionless import/export, independent validators and
GDB named breakpoints/source stepping. These uncurated sectionless programs
use the existing extraction contract: the recovered `main` on AArch64 and
ARM32, and the recovered add function on x86/MIPS. The test does not invent
curated parameters/globals absent from those programs. The companion needs the
ELF program table, not a section-header table.

Six additional curated exports explicitly rebase Ghidra by `0x400000`, across
PIE/shared and the same three targets. GNU/LLVM/pinned strict validation and
actual companion GDB behavior pass, including three ASLR launches from the
same native PIE sidecar and ambiguous-library instance switching/reload. The
new `FORGE_SYMBOL_SUFFIX` and `FORGE_SYMBOL_RESULTS` test controls retain these
outputs/reports separately from ordinary exports. Initial rebased x86 evidence
is retained under `gdb-companion-rebased-export`; it exposed a harness assertion
that incorrectly equated Ghidra's total analysis-to-ELF delta with only the
additional rebase. `analysis_delta` now includes the existing fixture import
base in both address preparation and that assertion. Production normalization
was correct and unchanged. The complete corrected exports are retained under
`build/test-results/gdb-companion-rebased-v2-export` and use suffix
`gdb-rebased-v2.dbg` locally (`gdb-rebased.dbg` in CI).

Successful final runtime examples with retained artifact copies:

| Case | Result under `build/test-results` |
| --- | --- |
| x86 sectionless | `gdb-companion-remote/x86_64.exec.no-sections.normal.weHEiRCc` |
| AArch64 sectionless | `gdb-companion-remote/aarch64.exec.no-sections.normal.1jloJaJC` |
| MIPS big-endian sectionless | `gdb-companion-remote/mips32be.exec.no-sections.normal.dflsuwJF` |
| Native rebased PIE, three ASLR launches | `gdb-companion-rebased-native/run.65pno74g` |
| AArch64 rebased PIE | `gdb-companion-remote/aarch64.pie.normal.QWNFmxa0` |
| MIPS rebased PIE | `gdb-companion-remote/mips32be.pie.normal.gn8vNkKW` |
| Native rebased shared instances/reload | `gdb-companion-shared/x86_64.ambiguous.normal.myJnZit6` |
| AArch64 rebased shared instances/reload | `gdb-companion-shared/aarch64.ambiguous.normal.7mj8kmsh` |
| MIPS rebased shared instances/reload | `gdb-companion-shared/mips32be.ambiguous.normal.5EX65AGe` |
| Native attach/exec | `gdb-companion-attach/run.m1qlxjdd` |

Each runtime harness now retains the exact original/sidecar/source/companion
bytes it checks, so later fixture exports cannot replace that evidence. The
end-of-job bounded diagnostic capture also includes companion files, rebased
outputs and the new source-built library driver; that snapshot is still not a
substitute for earlier invocation hashes. Its local x86 capture has 35 files,
9 absent optional outputs and zero errors; local rebased files deliberately
use the separately retained `-v2` suffix.

The real installed exporter cancels during copying of a 128 MiB owned input,
with an existing three-file generation. All three old files and original bytes
remain unchanged, no staging/backup files remain, and the report is CANCELLED.
The monitor observes 16 MiB copied before cancellation. Command:

```sh
GHIDRA_GDB_LOADER=1 src/test/integration/copy-cancellation-export.sh \
    "$PWD/build/ghidra-loader-test"
```

Evidence: `build/test-results/copy-cancellation-export/run.ekKuATPa` (the test
removes its disposable padded input after retaining hashes and diagnostics).
This complements chooser cancellation and publisher fault tests; it does not
prove crash-atomic publication or #72 recovery. The default two-file
cancellation path is retained in CI alongside the new companion path.

**PRESENT, UNVERIFIED on the updated hosted head:** all five target lanes now
include sectionless and rebased companion behavior; Windows GUI and all
required exact-head results/artifact review remain required before closing
#107. #72's complete attachment/refresh/receipt/recovery transaction is still
**PLANNED**. No new host/architecture release claim or issue closure is made.

A final native replay (`gdb-companion-rebased-native/run.t3b2_74f`) also sets
GDB confirmation on, verifies it remains on after each companion load and
checks an owned pre-existing `.gdbinit` sentinel remains byte-identical. The
sentinel is not executed (`-nx`); before/after text is retained separately.
This test does not edit or replace the user's actual configuration.

## Hosted target pass and Windows publisher assertion

**CONFIRMED:** run 41569991085 at `a198328` passed x86-64, AArch64,
ARM32 and both MIPS32 byte-order target jobs. Its required-validation gate
failed because the Windows publisher smoke test required lexically equal
parent paths. The failure precedes the Windows GUI acceptance checks; it is
not a passing host gate. Raw failure evidence is retained locally at
`build/review-41569991085/windows-failure.log`.

The test now uses `Files.isSameFile` for each of the three staging parents,
rejecting staging in another directory while accepting alternate spellings of
the selected directory. Failure diagnostics retain all parent spellings. A new
Linux symlink-parent fixture exercises the distinction. Five standalone source
files compile with `javac --release 21`, and the actual Java 21 runtime passes
all publisher cases, including rollback/cancellation, with the alias printed in
`build/test-results/companion-publisher-parent/runtime.log`. Workflow lint and
`git diff --check` pass. PowerShell/native Windows execution is unavailable
locally and remains required in CI. An early native-windows job step now runs
this same standalone test; the full Windows-host checks remain unchanged.

This is a test correction, not a production directory-policy change. All host
and protected-integration requirements remain open until the corrected head
passes. Previously reviewed target artifacts retain their original commit/run
identity and do not substitute for the corrected head's gate.
