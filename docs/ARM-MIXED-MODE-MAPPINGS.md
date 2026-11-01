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
analysis/export composition; inherited mappings and discontiguous bodies still
need their own acceptance evidence.

## Remaining acceptance

Discontiguous mixed bodies and additional inherited-map cases,
and runtime omission controls beyond the current model coverage still need
evidence. Sectionless shared-library composition is not covered by this matrix.

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
