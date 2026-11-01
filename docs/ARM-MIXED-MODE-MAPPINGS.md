# Recovered ARM section mappings

**CONFIRMED locally; full acceptance and integration pending.** The production
exporter now preserves ARM/Thumb/data transitions in completely evidenced
allocations containing selected mixed-mode functions. This addresses the
reproduction in [the reference record](research/ARM-MIXED-BODY-MODES.md); it does
not complete #70 or any of the unchanged #68–#71 requirements.

## Contract

`GhidraArm32SectionModes` selects allocations touched by a selected function
whose existing listing has both ARM and Thumb instructions. It never decodes or
repairs the program. For each complete allocation, it requires initialized
memory, exact code-unit coverage, consistent current and original decode context,
ordinary instruction lengths/alignment and matching parsed/current instruction
bytes. Data must be explicitly defined in the listing. Default undefined bytes,
holes, partial units and uninitialized tails cause omission with a diagnostic;
they are never silently classified as data.

Evidence binds normalized allocation identity/extent and a SHA-256 of every
byte to the mapping boundaries. The isolated ELF planner compares those bytes
with the original input, rejects overlaps with any other allocated section,
checks code alignment, reconciles inherited mapping intervals/function tags and
supplemental function tags, and bounds symbols, bytes and comparisons. An
inherited mapping is preserved when it agrees, rather than duplicated. Conflicts
or name collisions produce an explicit omission. Cancellation is polled during
selection, unit/byte inspection, hashing and symbol planning.

The writer has distinct sealed representations for local function symbols and
zero-sized local NOTYPE mapping boundaries. The existing nonzero function-size
contract remains intact. Mapping boundaries must lie inside their executable
allocation. ELF addresses remain untagged for mappings and DWARF; ARM function
tags keep their separate semantics. No native/JNA declaration or producer call
was added.

The four modes in the fixture are emitted by the actual installed exporter.
No test-side symbol mutation is used for production acceptance. The old research
mode remains explicit and requires the old static decoding failure; CI invokes
`--production` to require the real sidecar to pass instead.

## Local evidence

The installed v2 package has JAR SHA-256
`0e62944fdf8a5536181d961c382602332a545e9bf3e1dd153358445a8b209ac4` and ZIP SHA-256
`79d4faa977904d33e87c1dbb754aad98ed1918c6c6501f1c91eab656ae8b63ad`.
It retains Ghidra 12.0.3, Java 21 bytecode and pinned libdwarf 2.3.2.

| Layout | Production case | Native failure/cancellation case |
| --- | --- | --- |
| Non-PIE | `exec.6uggp5sp` | `controls.8dvy_bu2` |
| PIE | `pie.kew3u7f9` | `controls.3p8wcreq` |
| Rebased PIE | `pie-rebased.ebf8p4s3` | `controls.0k9we6dl` |

Cases are below `build/test-results/arm-mixed-reference` in the
`work/arm-mixed-modes` worktree; controls are nested inside their production case.
Each production case verifies the exact four raw mapping records, compiler-
relative static decoding and twelve actual instruction observations per symbol
file. These independently check PC, bytes, CPSR state and source-known register
values, ending with the expected result and exit status. PIE verifies a real
runtime bias; explicit Ghidra rebasing normalizes back to link addresses.
GNU readelf, LLVM and pinned strict libdwarf pass with zero errors. Repeated
read-only exports have identical sidecar/source bytes; original/package/harness
files and saved program data are preserved.

For each layout, two real native decompiler rejections retain the failed
function's name/address and section mode boundaries without fabricated formal
children, return type or declaration line. Runtime decoding and all twelve
instruction observations still pass with its symbol-only DIE. The shared
failure helper's explicit `--symbol-only` reference is used because this
fixture writes its parameter register in its first instruction; existing ABI
fixtures still require their positive saved-parameter reference by default.
A separate padded input is imported and cancelled after production copying
starts. The previous artifact pair remains identical and no partial temporary
artifact remains. These are six failure exports and three cancellations.

The ELF/writer smoke passes 33 checks, including original-byte changes, duplicate
or mismatched evidence, inherited conflicts, nonexecutable allocation overlaps,
exact NOTYPE records, deterministic output, cancellation, callback propagation
and existing-output preservation. The real-Ghidra smoke passes 84 checks,
including explicit `undefined4` versus unknown bytes, instruction holes,
modified data, current/stored context disagreement, rebasing and cancellation
at every observed polling point. The first cancellation test used a point
beyond the fixture's actual polling count; its retained failure was corrected
by measuring the full path and exercising every reached point.

Existing mode-symbol, alias/mode-binding and Ghidra function-mode tests pass
231/476/59 checks. The v1 package passes the complete existing ARM PIE command
including sectionless and failure/cancellation children at `run.9hzKkoYq` and
`pie.azdxu6oj`; the only subsequent production change tightens overlap rejection
to include allocated non-code sections, with its new passing negative control.
The final v2 package passes the AArch64 vector exec/runtime/native-failure/
cancellation regression at `build/test-results/aarch64-vector/exec.htj4xv7z`.
It also passes the final existing ARM PIE command at `run.sfOzuXIe`, with
`run.6cidmjx5` controls and sectionless `pie.f1vx09dc`. The updated sectionless
inventory oracle retains the old alias checks and rejects all six old
corruptions at `build/arm-mixed-modes/inventory-regression.6rsa7jjb`.

The first PIE harness comparison forgot Ghidra's default `0x10000` import bias.
Its retained failure is a test-coordinate error, not an accepted runtime result.
The corrected oracle subtracts the observed import delta for listing comparisons
and independently checks raw emitted link addresses and runtime relocation.

```bash
./gradlew arm32SectionModesSmoke ghidraArm32SectionModesSmoke
for role in exec pie pie-rebased; do
    python3 src/test/integration/arm-mixed-mode-reference.py <installed-ghidra> \
        --production --role "$role" --with-controls
done
```

The assembled `--production --role pie --with-controls` command also passes
freshly at `pie.96bxfy2x`, exercising the same command used in CI.
Both model tasks and the three production/control roles are wired into CI.
Hosted exact-head acceptance and protected integration remain pending.

## Expanded layout and source acceptance

The same v2 package now passes eight fresh complete commands, including native
failure and cancellation children. The machine-readable local receipt is
`build/arm-mixed-modes/layout-source-matrix-v2.json`.

| Layout | Production case | Control case |
| --- | --- | --- |
| Non-PIE | `exec.g58nzakc` | `controls.g8zcu6fh` |
| PIE | `pie._gmalpk0` | `controls.24i6yg14` |
| Rebased PIE | `pie-rebased.xcrtar5n` | `controls._lgm884b` |
| Shared library | `shared.3aiyrd58` | `controls.h6673gc8` |
| Rebased shared library | `shared-rebased.xc3gzoo1` | `controls.3w4tm30r` |
| Sectionless non-PIE | `exec.sectionless.33o3o1up` | `controls.kqygfyah` |
| Sectionless PIE | `pie.sectionless._vwh3a13` | `controls.f0cxvwyv` |
| Sectionless rebased PIE | `pie-rebased.sectionless.oxz1ert_` | `controls.5zb5orzq` |

Compiler and Forge symbols each undergo five separate runtime phases: all
twelve instructions, source `next`, source `step`, an address breakpoint at
the Thumb entry, and an injected function-pointer call. The source checks
require `list`, the correct synthetic source path and declaration/return lines,
the curated signature and an honestly unavailable parameter. Compiler assembly
has twelve executable source rows; the synthetic C has two observed stops,
at entry and its recovered return expression. This does not promise one source
line per instruction. Every observed stop checks raw instruction bytes, actual
CPSR mode and the source-known register value. The complete matrix contains
832 observations including failure exports, 16 injected calls, 16 native
failures and eight production cancellations. Every runtime ends with exit zero;
GNU/LLVM/pinned strict validation, deterministic outputs and input/package/
saved-program preservation pass in all cases.

Shared cases retain the driver's symbols, stop after its loader has mapped the
library, measure the `.text` load bias, and explicitly `add-symbol-file` the
library sidecar at that bias with automatic shared symbols disabled. An earlier
`symbol-file` attempt discarded the driver's entry point and caused injected
calls to fail for both compiler and Forge. That retained failed reference is
not counted as acceptance; preserving the executable's entry makes both pass.

The sectionless linker fixture gives the 44-byte mixed allocation a separate
exact-sized executable PT_LOAD. Only section-header discovery fields are
cleared in the copied input. Since synthetic NOBITS sections supply no file
instruction bytes, both symbol variants inspect actual remote memory before
continuing, with architecture `armv7` and automatic ARM/Thumb mode selection.
An independent raw inventory check verifies every inherited dynamic symbol,
load allocation, string prefix and all four exact new NOTYPE boundaries.
Each supplied auxiliary function hint is checked against original compiler
mode intervals; those output-derived sizes are not a completeness claim for
the auxiliary hint set. Nine deliberate record corruptions are rejected per
sectionless case, including wrong mapping type, size and address.

The isolated high PT_LOAD places the mixed function last. A first failure
control correctly rejected the missing later decompiled neighbor. The final
sectionless control selects the lower-address caller by its independent
compiler link address, requires its real decompiler failure and the later
mixed function's successful decompilation, then verifies retained mappings and
runtime. Ordinary/shared controls still fail the mixed function itself.
The helper's existing name selection and positive saved-parameter assertions
remain the defaults for other ABI fixtures.

CI now invokes all five sectioned roles and all three sectionless roles with
`--production --with-controls`; sectionless commands additionally pass
`--sectionless`. Actionlint and Python/shell syntax checks pass locally.
Hosted exact-head acceptance and protected integration remain required.

## Fresh live-program acceptance

`arm-mixed-live-export.py` freshly imports each accepted fixture, performs the
same explicit analyst preparation, and invokes the installed exporter twice
before closing the analyzed program. The exports must be byte-identical; the
listing evidence and complete ELF symbol inventory must match the independently
accepted saved-program case. All ten compiler/Forge debugger phases, raw
sectionless inventories, GNU/LLVM/pinned strict validation and input/package/
harness preservation pass. The eight live cases add 736 debugger observations,
16 injected calls and 16 live exports, without a production change.

| Parent case | Live case |
| --- | --- |
| `exec.g58nzakc` | `live.vegg2sy4` |
| `pie._gmalpk0` | `live.o4ksggrn` |
| `pie-rebased.xcrtar5n` | `live.gtr8sjaa` |
| `shared.3aiyrd58` | `live.porpmire` |
| `shared-rebased.xc3gzoo1` | `live.5i7oyqg_` |
| `exec.sectionless.33o3o1up` | `live.t3tjxw1z` |
| `pie.sectionless._vwh3a13` | `live.lxkbeb5a` |
| `pie-rebased.sectionless.oxz1ert_` | `live.57k4mlur` |

The full `--production --role pie-rebased --sectionless --with-controls
--with-live` command additionally passes at `pie-rebased.sectionless.s8bwln49`.
CI enables `--with-live` for all eight layout commands. This verifies live
analysis/export composition. The split-body evidence below extends this to
discontiguous bodies; the subsequent inherited-mapping section records its
additional runtime acceptance.

## Discontiguous mixed-body acceptance

The maintained `--split` fixture adds an entry branch over the source-known
`0xfeedface` word. The 52-byte allocation contains thirteen executed instructions,
with function ranges `[0,4)` and `[8,48)` and exact mapping boundaries
`$a:0`, `$d:4`, `$a:8`, `$t:24`, `$a:32`, `$d:48`. The trailing literal and
skipped word are excluded from executable DWARF ranges and source rows.
Explicit analyst preparation validates all already-decoded bytes and contexts,
detaches the automatic entry thunk before removing its verified automatic inner
fragment, and records the two-range body and data word. It does not repair
instruction decoding or context to obtain a pass.

The unchanged v2 production package passes the following complete saved/live/
failure/cancellation commands. The receipt is
`build/arm-mixed-modes/split-matrix-v2.json`; child names are retained there.

| Layout | Case |
| --- | --- |
| Non-PIE | `exec.split.6z8_cjmb` |
| PIE | `pie.split.s6fqz0nc` |
| Rebased PIE | `pie-rebased.split.3jt1_4vk` |
| Shared library | `shared.split.s615bdj8` |
| Rebased shared library | `shared-rebased.split.qjdxj_2a` |
| Sectionless non-PIE | `exec.split.sectionless.uab09am5` |
| Sectionless PIE | `pie.split.sectionless.7q4g53im` |
| Sectionless rebased PIE | `pie-rebased.split.sectionless.olypa41a` |

Across these cases, 48 completed exports pass deterministic-output and original/
saved-program/package preservation checks. Saved and live debugger phases each
provide 784 observations; failure exports add 104, totaling 1,672. All 32 injected
calls, 16 native failure exports and eight production cancellations pass.
GNU/LLVM/pinned strict checks pass without reported or unexplained errors.
The independent raw range/line checker rejects eleven deliberate corruptions
per normal/live case, including a range covering the skipped word and source
rows on each excluded data byte. GDB also checks that every skipped byte has
no function owner or executable source line.

Source stepping deliberately retains a real limitation: GDB stops at the second
range entry (offset 8) without a line because Ghidra's first mapped expression
is later. The oracle permits exactly this observed stop and independently
checks its PC, instruction bytes, mode and value. No source line is fabricated.
The entry and later expression still have required valid rows. Instruction,
address-breakpoint and call phases require all applicable executed instructions
and the source-known result 4686; execution into data is always rejected.

Retained setup failures caught the old blanket source-line expectation, a
symbol-only control requiring `low_pc` instead of the valid range list, and GNU
readelf's explicit `(sec_offset)` annotation. Generalizing the fixture also
moved the assembly label outside the contiguous compiler `list` window; the
contiguous oracle now requires its actual first instruction. Fresh complete
contiguous sectionless PIE (`pie.sectionless.d_kgr_dj`) and rebased shared
(`shared-rebased.dvz83c6r`) regressions pass. The final combined split command
also passes at `pie-rebased.split.sectionless.s0crx0i3`.

CI runs both contiguous and split shapes over all eight layouts, each with
`--production --with-controls --with-live`; split adds `--split`. This local
acceptance requires its own exact-head hosted gate and protected integration.

## Inherited mapping and omission controls

**CONFIRMED locally:** the same v2 package passes five split-body cases using
`--strip-debug`, retaining the original symbol table and all original mode
mappings. Every original record and string-table prefix is checked byte for
byte; inherited mapping records must occur exactly once. Four deliberate
inventory corruptions are rejected. Saved/live/failure exports contribute
1,045 debugger observations, twenty injected calls, ten native failure exports
and five cancellations. The cases are `exec.split.retained.iuca9yoa`,
`pie.split.retained.us9915lh`, `pie-rebased.split.retained.r6fl4kei`,
`shared.split.retained.yym0zqtr` and `shared-rebased.split.retained.fuly05uf`.
Each normal/live run includes compiler-relative static decoding, source stepping,
address breakpoints and function-pointer calls; validators and deterministic
original/program preservation pass. The non-PIE case preserves all 94 original
symbols, including 30 mapping records, without inserting duplicate mappings.

All eight stripped split layouts also pass two explicit unknown-data controls.
A read-only Ghidra session removes the definition of either the skipped word
or the trailing literal, without changing its memory bytes or function body.
The actual exporter must diagnose `unknown bytes cannot be mapped as data` and
omit the unsupported section mapping. Repeated exports remain identical, raw
DWARF ranges/lines and structural validators still pass, and saved program/
original/package bytes are preserved. The 208 instruction observations execute
all thirteen instructions correctly for both controls in every layout. Static
decoding is deliberately required to fail the ordinary mapping oracle with its
exact known missing-width assertion; these controls do not claim full decoding
support after evidence is removed. Unrelated GDB failures are rejected.

Receipts are in `build/arm-mixed-modes/inherited-omission-matrix-v2.json` and the
case directories. The first control used the script convenience data lookup,
which did not expose cleared undefined units. The corrected control uses the
listing code-unit API and checks each undefined unit explicitly; the initial
failed attempt is retained as `omissions.i58ldm58`. CI invokes inherited cases
for all five sectioned roles, and `--with-omissions` for every stripped split
layout. The final combined sectionless rebased command with controls, live
exports and omissions passes at `pie-rebased.split.sectionless.1v67x5a6`.
Exact-head hosted acceptance remains pending.

## Sectionless shared-library composition

**CONFIRMED locally:** shared and explicitly rebased shared objects now pass
with no section-header table, for both contiguous and split mixed bodies. The
loader retains the original program headers and dynamic metadata; only the
section-header discovery fields are cleared in the copied fixture input.

GDB's `info sharedlibrary` cannot provide a section-derived From address for
these inputs. The first retained run (`shared.split.sectionless.849qwvj7`)
failed when the previous oracle tried to interpret `No` as that address. The
corrected Linux ARM32 fixture oracle reads the fixed-address driver's `DT_DEBUG`
slot and the loader's public `r_debug`/`link_map` protocol. It bounds traversal,
rejects cycles, requires exactly one matching library path, verifies the live
dynamic-section address against the original ELF, and compares its ELF identity
and complete mixed instruction/data allocation bytes in remote memory. The
sidecar is then added at this independently measured bias. The driver entry
remains available for injected calls.

Because the sidecar's synthetic section has no file-backed instructions,
decoding is checked after the loader runs and before the mixed function executes.
This is recorded as `remote-before-mixed-call`, not a claim of pre-attachment
file disassembly. Both compiler and Forge symbols follow the same measured
loader workflow, with automatic shared symbol loading disabled.

| Shape / layout | Case |
| --- | --- |
| Split shared | `shared.split.sectionless.skdfmw_6` |
| Contiguous shared | `shared.sectionless.43ajrstm` |
| Contiguous rebased shared | `shared-rebased.sectionless.65po9vwb` |
| Split rebased shared | `shared-rebased.split.sectionless.w63yw61y` |

Saved/live/failure runs total 810 debugger observations, sixteen injected calls,
eight native failure exports and four cancellations. Each shared failure control
selects the compiler-identified lower-address `_init` and requires the later
mixed function to decompile successfully. Raw original dynamic-symbol/load/mode
inventories, structural validators, repeated output and original/program/package
preservation pass. The split cases also pass both unknown-data controls, adding
52 instruction observations and exact omission diagnostics. The receipt is
`build/arm-mixed-modes/sectionless-shared-matrix-v2.json`. CI now covers all five
sectionless roles for each shape. A fresh sectioned/rebased split regression
with control/live/omission composition also passes at
`shared-rebased.split.y89lz7hd`. Exact-head hosted acceptance remains required.

## Remaining acceptance

Inherited mapping preservation and unknown-data omission now have runtime
evidence. Additional conflict/context-change controls remain model-only.
Sectionless shared-library composition is covered by the additional matrix
above; its exact-head hosted acceptance remains required.

Unknown gaps intentionally prevent complete section mapping. A successful
homogeneous-function mode hint elsewhere does not establish mixed-body coverage.
The remaining ARM per-function base/VFP ABI, BE8 and storage requirements, MIPS
FPXX/FP64A and wider lifetime work, i386 work, and full integration audit all
remain active in `TARGET-ABI-COMPLETION-PLAN.md`.

## Hosted boundary-audit correction

Run `41354512199` rejected the new isolated ARM extractor/planner because their
exact paths were absent from the architecture-boundary audit inventory. The
review confirms that TMode interpretation and ARM ELF mapping semantics remain
inside those two target modules; the generic writer only serializes explicit
ELF symbol types. The audit now names those exact paths. A separate temporary
generic-source probe containing TMode is still rejected; no broad path or
pattern exception was introduced. This test-inventory correction does not
change the validated production package. Exact-head hosted acceptance is still
required.

Run `41354691661` passed extension/native/release assembly, then the fixture
inventory rejected the three newly added ARM mixed/shared source files before
target tests. The exact filenames are now registered; the source-only inventory
and all 13 x86-64 fixture byte-identical rebuild checks pass locally. The
inventory remains closed to unreviewed files. This correction changes no
production code and does not substitute for the pending hosted target gate.

## Hosted auxiliary-harness regressions

Run `41356347084` exposed two auxiliary test failures before the mixed-mode
step. The large-file standalone javac command omitted the newly required
`ElfLocalSymbol` and `ElfLocalMappingSymbol` sources. Adding those exact inputs
restores the complete over-2-GiB container/64-MiB-heap/GDB test at
`build/test-results/large-elf-sidecar/run.IahgwkHt`. The real headless repeated
large-file export also passes at `large-headless-export/run.7cO6eGu0`, preserving
the original and producing deterministic artifacts. The standalone strict
check reports two corroborated inherited frame diagnostics, not zero reports.

The ARM alias preparation oracle assumed retained symbol tables could not gain
mode hints for PIE. Inspection of the failed hosted artifact proves all 105
original records survive, with nine independently valid local mode hints
inserted. The revised oracle checks every original byte and string prefix,
then checks every new hint against compiler mapping intervals and source-known
function bounds. The independent writer probe also includes those additions
for retained inputs. Its earlier missing-hint comparison failure is retained
at `arm.pie-rebased.retained.7g_t80im`.

All eighteen ARM/Thumb/mixed-state, exec/PIE/rebased and retained/stripped cases
pass fresh preparation and final alias runtime with the unchanged v2 package:
72 injected calls, 36 static function checks, exact independent-writer agreement,
validators, repeat determinism and original/saved-program preservation. Receipts
are under `build/test-results/arm-alias-regression-runtime-v2` and
`build/arm-mixed-modes/alias-regression-matrix-v2.json`. The same preparation
assumption also failed PR130's run `41355781605`; its harness correction is
applied there as well. These local fixes still require fresh hosted gates.
