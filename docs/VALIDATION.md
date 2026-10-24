# Validation record

> **Release validation reopened (2026-10-23):** historical green jobs did not
> enforce libdwarf's nonzero check summaries when its process returned zero.
> The affected libdwarf results below are not clean-validation evidence. GNU,
> LLVM, native-safety and GDB outcomes remain separately recorded. Alpha.2 is
> unpublished while the diagnostic causes and strict checks are resolved.

## Exit-zero libdwarf check summaries

The corrective candidate `bfc2712` passed all twelve jobs in run
`40057428382` and was merged as `680ecd6`. An independent audit subsequently
verified the downloaded GitHub artifact digest for each target and inspected
201 retained dwarfdump/LLVM result files:

| Target | Nonzero libdwarf summary logs |
|---|---:|
| x86-64 | 25 |
| AArch64 | 14 |
| ARM32 | 4 |
| MIPS32 little endian | 4 |
| MIPS32 big endian | 4 |

These include repeated exports and are not a count of unique defects. Raw
artifact ZIPs, API digest metadata and per-file findings are retained under
`build/corrective-validator-audit/` in the main checkout. The local ARM
static-scope case that exposed the gap is retained under
`arm-unwind-fixture/build/test-results/function-static-scopes/run.mAHnsuSk/`
in the worktree collection. Its GDB scope/value/runtime checks pass, but its
old libdwarf log reports four line-table errors despite exit zero.

The older Ubuntu checker misinterprets DWARF 5 function ranges and relies on
section names for image bounds. Pinned libdwarf 2.3.2 handles those cases, but
its last-line check incorrectly equates an instruction-sequence boundary to a
remembered function's `high_pc`. A valid GCC sequence covering several
functions reproduces that false error without any Forge-generated DWARF.
The isolated checker patch checks sequence termination and nondecreasing
addresses within a sequence instead. It does not change the shipped producer
or consumer library. See `support/validation/README.md` for the exact source,
patch checksums, DWARF specification references and limitations.

The validation-only executable is built by
`support/build-validation-dwarfdump.sh`, with source, patch, reconstruction
instructions, manifests and GPL/LGPL notices in its separate CI artifact.
Every Linux target lane verifies its manifest and selects it explicitly.
Windows continues to record standalone dwarfdump as unavailable.

`check-dwarfdump.py` runs `--no-follow-debuglink -ka -ki -kd`, requires complete
compiler/category/total counts and the completed usage footer, and rejects
nonzero process status, stderr and every unexplained diagnostic. Input/log
alias checks include symbolic and hard links before opening any output. The
only corroborated diagnostic family is
`DW_DLE_DEBUG_FRAME_LENGTH_NOT_MULTIPLE`: the original must produce exactly
the same diagnostic multiset using the same tool, and its ELF identity and
`.eh_frame` address, size and bytes must match the sidecar. These messages are
retained in raw reports and counted as reported errors, not called absent.

**CONFIRMED locally:** helper regression runs reject exit-zero errors, missing
or inconsistent summaries, truncation, stderr, incorrect frame corroboration
and log aliases. The line-sequence tests accept GCC sequences spanning functions,
equal-address rows and independently ordered sequences; they reject decreasing
addresses within a sequence, missing final termination and out-of-image PCs.
Mutated CU/function-range containment fails LLVM. The latter controls are
missed by libdwarf alone, and LLVM alone misses the out-of-image line control;
both validators and GDB remain required.

Independent rechecking of 71 retained artifact instances found 43 with zero
errors and 28 with only frame-length diagnostics (99 messages). Those results
are not themselves strict passes: frame evidence must be corroborated against
each original. The retained set includes unnamed-section outputs but contains
no section-header-free outputs; that absence limits the historical recheck.

Fresh exports through a private copy of the exact `680ecd6` installed extension
passed 25 cases: exec, partially stripped, no build ID, PIE and shared objects
on x86-64, AArch64, ARM32 and both MIPS32 byte orders. Each passed GNU/LLVM,
the strict helper and native or QEMU/GDB behavior checks. Independent review
verified all input/output/source hashes, the private script origin, complete
checker metadata and exact frame corroboration. Logs are in the strict
worktree's `build/strict-matrix/` and `build/test-results/headless-symbol-export/`.
The local launcher used Java 25.0.4.1. The installed Java 21.0.12.1 directory
contains a JRE without `javac`; its launcher override and subsequent Gradle
compiler selection were rejected. The successful build uses JDK 25 and emits
Java 21 bytecode (class major version 65), so these are not Java 21 runtime
results. Hosted Java 21 checks remain required. A prior attempt loaded an older user-installed module and is
retained under `*-wrong-install/`; it is excluded from all pass counts.

The five section-header-free cases failed with location-list bound diagnostics.
Their sidecars had only allocated identity-note metadata, causing even 2.3.2
to treat note addresses as the image bounds. Independent ARM32 and MIPS32BE
inspection found all 170 and 202 location intervals, respectively, inside both
their owning functions and original executable `PT_LOAD` segments. The
selected correction preserves original load extents as inert section metadata
for sectionless inputs, with no guessed source section names or output program
headers.

**CONFIRMED locally:** all five corrected sectionless exports pass strict
libdwarf checking with zero diagnostics, LLVM verification, GDB runtime
behavior and byte-identical source/sidecar repeats. The independent metadata
oracle compares each generated load section to the corresponding original
program header and checks all location intervals against executable loads:

| Target | Location lists | Intervals |
|---|---:|---:|
| x86-64 | 44 | 171 |
| AArch64 | 45 | 143 |
| ARM32 | 35 | 170 |
| MIPS32 BE | 51 | 202 |
| MIPS32 LE | 51 | 202 |

Each copied out-of-image location mutation produces exactly one matching
diagnostic and strict rejection. A separately inflated load-section mutation
fails the original-header metadata comparison. Inputs stay byte-identical.
Evidence is in `build/strict-matrix/*no-sections.{export,metadata,gdb,repeat}.log`
and `build/test-results/sectionless-load-ranges/` in the strict worktree. The
pre-fix failures remain in `build/strict-matrix-sectionless-before-fix/`.
The new installed JAR SHA-256 is
`4f1fede9f6a9b298902a289c81ee27d8be750930aef70d3955c635dd3e77c20a`;
these five cases exercise the corrected writer, while the preceding 25
non-sectionless cases exercised its unchanged path from `680ecd6`.

The current CI set of 19 Java smoke tasks, `buildExtension`, wrapper,
architecture-neutrality and release-package regressions pass. A focused
sectionless-writer regression fails against the old writer and passes the new
one across ELF32/64 and both byte orders, including memory-only/empty segments,
unaligned segment starts, address overflow, original preservation and output
rollback. Compiler-DWARF containers pass GNU/LLVM/strict-libdwarf checks for
all five sectionless targets. The timestamp and greater-than-2-GiB integrations
also pass with precisely corroborated inherited frame diagnostics; the latter
uses a 64 MiB heap. Logs are retained under `build/strict-matrix/` and
`build/test-results/sectionless-load-review/`.
Two fresh imports each of `/usr/bin/true` and `/usr/bin/basename` also pass
determinism, GNU/LLVM, strict checking and GDB source/breakpoint/type/stepping
checks from an unrelated working directory. Each of the four reports retains
seven frame diagnostics precisely corroborated against its unchanged original;
there are no uncorroborated errors or stderr. Evidence is
`build/test-results/real-world-export/run.KZOwoLaM/` and
`build/strict-matrix/real-world-export.log`.
Exact corrected hosted CI/package validation is required before publication.

For the local extracted ARM toolchain, the runtime harnesses accept
`FORGE_ARM32_SYSROOT`; the default remains `/usr/arm-linux-gnueabihf` in CI.


Local validation date: 2026-09-03
Ghidra: 12.0.3
Host: Linux x86-64
Host JVM used by Ghidra/Gradle: OpenJDK 25.0.4
Extension bytecode target: Java 21

This record distinguishes container/oracle validation from real Forge DWARF
export. Export remains explicit: installed wrappers request checksum-verified
packaged natives by default, while source-tree audit runs may supply explicit
library paths.

## Saved-program generic type identity (2026-10-23)

**CONFIRMED locally:** an unchanged, settled program now exports byte-identical
DWARF and synthetic source before saving and after two fresh read-only reopen
processes. The fix is limited to Ghidra's exact `DefaultDataType` class; every
other type's UniversalID and the existing collision policy remain unchanged.
No new native signature or target profile is involved.

The pinned Ghidra `SoftwareModeling-src.zip` SHA-256 is
`ae94f7ede157d57b865eaa7caefd72c9f98bfed04e122db6909dface0bd22748`.
`DefaultDataType` has a private constructor and a generic singleton, inherits
`DataTypeImpl`'s generated UniversalID, and returns itself from clone/copy.
`BuiltIn` overrides that accessor to return null, but this class does not.
The stable class/path/length fallback is therefore used only for this exact
generic type. The native-independent `defaultTypeIdentitySmoke` uses actual
Ghidra classes and verifies that analyst types named `undefined`, typedefs and
explicit imported/persisted IDs retain their distinct original identities.

The new `saved-program-determinism.sh` uses the existing source-built x86-64
semantic reference/stripped pair. It derives function/global addresses from
compiler symbols, applies a signature and analyst structure, settles analysis,
and saves a real Ghidra project. Both reopens use `-noanalysis -readOnly` in
separate JVMs with identical input/output paths and export options. Before and
after each export, a script fingerprints the complete extracted type, function,
global, static, location, range and diagnostic model without serializing DWARF.
It requires the generic undefined type and UID-bearing analyst/imported types
to be present. A fixture-specific normalized comparison rejects ambiguous type
labels; the fixed success gate additionally requires raw model and artifact
byte equality, so normalization cannot conceal an identity regression.

All three artifacts pass GNU readelf, LLVM verification, libdwarf checks and
GDB. The debugger requires full function/type/source DIEs, the compiler-derived
function entry, four integer parameters, the analyst/imported structure layouts,
`left=19`, `right=23`, analyst-global `value=7`, `fixture_sink=42`, source
`next`/`step`, function return and normal exit. Original target, compiler
reference and source hashes remain unchanged. Fresh result directories retain
commands, exporter hash, tool versions, model snapshots and validator/GDB logs.

```bash
make -C src/test/fixtures x86_64
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
    ./gradlew defaultTypeIdentitySmoke typeGraphSmoke buildExtension
# Install that build only into a private Ghidra copy with packaged natives.
src/test/integration/saved-program-determinism.sh "$PWD/build/ghidra"
```

Evidence in this worktree:

| Check | Result |
|---|---|
| Old semantic artifact, `run.JbcC1Hjs` | `FORGE_EXPECT_DEFAULT_UID_DRIFT=1` explicitly reproduced initial/reopen byte difference; models match after normalization, sources and both reopen artifacts match; all three validators/GDB checks pass |
| Fixed artifact, `run.LUvQfGxu` | Initial/reopened/repeat `.dbg` SHA-256 `c7cafd6065ae73f192e37851f7906129448cfd18bd9f5471d498afdda786f367`; all three raw models and sources also match exactly |
| Source in fixed run | All three SHA-256 `e591061441b813ffad29e1c5160882d2e42ef3be491f8ae3ee972de5916080ac` |
| Actual extension | Baseline JAR `170f9d68a39e86831af622c197f455f9a17b3092621276739b22139c4ea5b897`; fixed JAR `366f3b40f52ade1e194be3c3d8dbd32794469bff30b1eb8e12e64e4555bc82a3` |
| Build | All 23 native-independent smokes and `buildExtension` pass; `build/default-type-review/all-smokes.txt` |
| Existing type/location behavior | All eight x86-64/AArch64/MIPS32 BE/LE ET_EXEC/PIE real export, validator and native/QEMU GDB cases pass; `build/default-type-review/<target>-<role>-{headless,gdb}.txt` |
| Repository guards | Architecture isolation, `actionlint`, whitespace and shell/Python syntax checks pass; no fixture sources were added or changed |

The runs live under `build/test-results/saved-program-determinism/`; supporting
commands and baseline/fixed logs are under `build/default-type-review/`.
CI now runs the identity smoke and the real save/reopen case in its existing
x86-64 lane. Hosted validation of this follow-up remains **PRESENT, UNVERIFIED**.
These results establish the unchanged saved-program case, not equality between
independent imports, edited programs, or arbitrary other transient type classes.
The user's installation and corrective alpha.2 candidate were unchanged.

## Combined semantic and corrective validation (2026-10-23)

**CONFIRMED locally:** normal merges `493983d` and `4a4ce38` add reviewed scalar
FP aliases (`1f52431`) and the corrective alpha.2 code (`ddad598`) to the earlier
combined semantic branch (`23d2a63`). Only additive project-context prose
conflicted; both narratives were retained. The final writer and publisher are
byte-for-byte identical to the corrective branch, and all other production
code matches the tested scalar-FP branch. No native signatures changed.

The combined extension ZIP was installed into this worktree's isolated Ghidra
copy at `build/combined-validation/ghidra`. The installed and built JAR hashes
match (`170f9d68a39e86831af622c197f455f9a17b3092621276739b22139c4ea5b897`).
Neither the user's installation nor any other worktree's installation changed.
The following tests use that actual combined artifact:

| Check | Result and evidence |
|---|---|
| Native-independent checks/build | All 22 smokes and `buildExtension` pass; `build/combined-final-review/build.txt` |
| Publication timestamp regression | Original mismatch warns, published pair does not, later source edit still warns; input bytes/mtime and cleanup pass; `build/test-results/artifact-pair-timestamps/run.wMxUHsgD/` |
| Scalar FP | All 24 x86-64/AArch64/MIPS32 BE/LE ET_EXEC/PIE baseline/rebase/repeat cases pass their bounded typed-value/omission oracles; `build/test-results/floating-registers/run.3suVpXM4/` |
| Existing semantic matrix | Four profiles across ET_EXEC, partial stripping, absent build ID, absent section table, PIE and shared library: all 24 real export/validator/GDB cases pass; `build/combined-final-review/existing-*-{headless,gdb}.txt` |
| Strict automatic association | Build-ID and debuglink positive/negative paths, CRC/mismatch checks and exact function/source/type checks pass on all four local profiles and native runtime where applicable; `build/test-results/build-id-discovery/run.GMGl9oDu/` |
| ARM scalar upper slice | Isolated producer plus GNU/LLVM/libdwarf validators pass again on archived source-built ARM input; `build/combined-final-review/arm-slice-*` |
| Repository guards | Architecture isolation, `actionlint`, whitespace and shell/Python syntax checks pass |

The existing matrix preserves integer, stack and composite values. The FP
suite preserves exact source/address/value checks, input hashes, build IDs and
byte-identical repeats. MIPS paired doubles remain unavailable, with the
compiler-GDB transport limitation recorded below; stored globals are not
misrepresented as positive parameter-location evidence. The earlier dedicated
entry, static-owner/failure and register-prefix suites remain the evidence for
those unchanged extraction/emission paths rather than being counted as newly
rerun here.

All additive CI gates survive the merge: function-owned statics, entry ranges,
incoming prefixes, scalar FP, strict association and timestamp publication.
New ARM32 static/FP runtime behavior and the complete combined hosted run remain
**PRESENT, UNVERIFIED** until CI passes the final commit. This is the follow-on
semantic feature branch, not part of the corrective alpha.2 release.

The first PR #20 hosted run, `40056330176`, stopped all five target lanes at
the explicit fixture source inventory: the five new reviewed fixture files
had not been added to its allowlist. No new hosted semantic test ran in that
attempt. The allowlist now names those exact files and still rejects unknown
files. `fixture-reproducibility.sh` passes on all four locally available
targets, including byte-identical rebuilds and the partial-symbol check;
logs are `build/combined-review/fixture-reproducibility-*.log`. ARM32 and the
remaining hosted steps still require a new passing run.

```bash
src/test/integration/artifact-pair-timestamps.sh
src/test/integration/floating-registers-export.sh "$GHIDRA_INSTALL_DIR" \
    "$consumer" "$producer" x86_64 aarch64 mips32be mips32le
# Run headless-symbol-export.sh then qemu-gdb-symbols.sh for each fixture role;
# use shared-object-gdb.sh for shared. Retain all four local target arguments.
src/test/integration/build-id-discovery.sh x86_64 aarch64 mips32be mips32le
```

## Scalar floating register aliases (2026-10-23)

**CONFIRMED locally:** the old real exporter omitted scalar floating arguments
whose logical register had an unmapped physical base. The preserved x86
baseline (`build/test-results/floating-registers/run.Do3jbKMI/`) checks compiler
values and Forge unavailability explicitly. Production now walks the actual
Ghidra parent chain to a mapped covering register and computes the value's bit
offset relative to that register. Whole-base alias clobber checks remain
conservative. No vector/pair register number is guessed and no native API is
added.

`registerAliasSmoke` uses the real pinned language descriptions: XMM within
ZMM, AArch64 scalar registers within Q/Z, ARM single registers within D/Q,
and MIPS scalar registers within pairs. It checks ARM `s1 -> d0` at bit 32,
`s3 -> d1` at bit 32, and x86 `AH -> RAX` at bit 8, while broad unmapped vectors
and MIPS double pairs remain unavailable. `floatingRegisterSliceSmoke` emits
the ARM scalar upper slice in an isolated producer process; readelf confirms
`DW_OP_regx 256; DW_OP_bit_piece 32,32`, and GNU/LLVM/libdwarf validators pass.
That test uses an archived source-built ARM ELF and establishes structure,
not new ARM runtime support.

The canonical ARM D-register mapping follows
[AADWARF32 2025Q4](https://github.com/ARM-software/abi-aa/blob/2025Q4/aadwarf32/aadwarf32.rst#vfp-v3-and-neon-register-descriptions):
D0–D31 use numbers 256–287; scalar single registers are slices of these
registers. Legacy S64–95 numbering is excluded from the chosen mapping.

The real `floating-registers-export.sh` runs six cases per target: ET_EXEC and
PIE, each with baseline, `+0x2000000` Ghidra rebase and byte-identical repeat.
Fully stripped inputs prevent compiler debug information from masking Forge
behavior. Compiler symbols establish independent exact addresses, and GDB
checks parameter types/widths, source, values at entry and before/after stores,
global sinks, `next`, `step` and normal exit. The x86/AArch64 explicit clobber
also requires the incoming value before the write and unavailability afterward.
All artifacts pass strict GNU/LLVM/libdwarf validation, unchanged original
hashes, build-ID preservation and deterministic repeats.

Positive local parameter values are float/double on x86-64/AArch64 and float
on MIPS32 BE/LE. MIPS double pairs are explicitly unavailable in Forge.
The current compiler double-parameter oracle is **PRESENT, UNVERIFIED** on
QEMU 8.2.2/GDB 15.1: `first=0`, `second=0`, and raw `f12..f15=0` at the checked
PCs despite correct stored globals `21.5`/`-9.25` and normal exit. Those globals
prove machine execution, not parameter locations. The harness records this
exact zero observation separately from positive checks and rejects other
unexpected observations; it also accepts exact values if a later debugger
corrects its register view.

A separate probe found status `0x24000010` (FR set), four-byte GDB FP registers,
and no target XML. Forcing `set mipsfpu double` did not change the result.
The likely cause is the QEMU 8.2.2
[MIPS stub](https://github.com/qemu/qemu/blob/v8.2.2/target/mips/gdbstub.c), which
passes the FR-mode 64-bit FP value through `gdb_get_regl`; its
[helper](https://github.com/qemu/qemu/blob/v8.2.2/include/gdbstub/helpers.h)
uses a 32-bit transfer for this target. This source-based inference explains
the missing high halves; emulator repair is outside this change.

MIPS PIE return stepping can also produce GDB's known “can't find the start”
warning. The harness permits it only during the marked return operation and
only when an untouched compiler ELF loaded as separate symbols reproduces the
exact warning text, address and count. Direct compiler-symbol loading remains
strict, as do all other diagnostics and the ARM compiler-corroborated vDSO rule.

**CONFIRMED locally:** ARM32 now passes all six exec/PIE baseline/rebase/repeat
cases, including exact float values `19.25`/`-7.5` in `s0` and the upper `s1`
slice of `d0`, and double values `21.5`/`-9.25` in `d0`/`d1`. Evidence is
`arm-unwind-fixture/build/test-results/floating-registers/run.MuSy5PDD/`.
The compiler, global sinks, source/stepping, normal exit, input hashes and
byte-identical repeats pass. Rechecking every emitted sample with the pinned
consumer 2.3.2 using `-ka -ki -kd` reports completed zero-error summaries;
GNU and LLVM checks also pass. Hosted verification remains pending.

The first reached ARM clobber test (`run.tD6kRvdC`) exposed an overbroad test
expectation: the final `bx lr` has raw `CALLOTHER setISAMode` followed by
`RETURN`, so the existing whole-body prefix proof rejects its opaque p-code.
Preparation now verifies that exact return evidence, and the report/GDB oracle
requires `REGISTER_MODIFIED` and an unavailable `fp_clobbered::value` at entry
and every marker. The independent compiler still proves value `13.75`, and
the stored sink must equal `13.75`. x86/AArch64 positive prefix and overwrite
checks are unchanged. ARM prefix lifetimes for this mode-switching return
remain unsupported; stable scalar locations do not imply that broader proof.
No new ISA/ABI, aggregate/variadic passing, migration or call-crossing support
is claimed.

```bash
./gradlew registerAliasSmoke registerPrefixSmoke variableStorageSmoke buildExtension
src/test/integration/floating-registers-export.sh "$GHIDRA_INSTALL_DIR" \
    "$consumer" "$producer" x86_64 aarch64 mips32be mips32le
./gradlew floatingRegisterSliceSmoke -PlibdwarfPath="$consumer" \
    -PlibdwarfpPath="$producer" -PsidecarInput=/path/to/ARM-fixture \
    -PsidecarOutput="$PWD/build/arm-slice.dbg"
```

Initial retained positive runs: `run.eJVfeqB1` (x86), `run.tF2IBGna` (AArch64;
the subsequent MIPS compiler-pair assertion intentionally failed during the
investigation), and `run.AD3qEszr` (both MIPS orders). Final evidence and
regression commands are under `build/fp-review/`; the branch uses only its
own copied Ghidra installation. Final `run.SrcqG8RO` passes all 24 typed-value
cases on the four local profiles. All 22 native-independent smokes and the
extension build pass (`final-build.txt`), together with architecture, workflow,
shell syntax and whitespace checks. The existing four-target ET_EXEC/PIE/shared
semantic matrix passes with integer, stack and composite values
(`existing-{exec,pie,shared}-{headless,gdb}.txt`). All 12 incoming-register
prefix cases pass in `build/test-results/register-prefix-export/run.Hj0zJfh0/`.
ARM isolated native evidence is `build/fp-review/arm-slice-*`.

## Combined semantic branch validation (2026-10-23)

The `semantic-todo-completion` worktree combines the independently committed
below-entry ranges, function-owned statics and incoming-register prefixes.
It uses a separate Ghidra copy with the combined JAR/script and the existing
checksum-verified packaged native pair. Neither the user's installation nor
the corrective alpha2 branch was changed.

**CONFIRMED locally:** all 21 native-independent smoke tasks and the extension
build pass, together with the architecture guard, `actionlint`, shell syntax
and whitespace checks. The isolated function-entry producer passes all five
current profiles and GNU/LLVM/libdwarf validation. ARM32 uses the archived
source-built hosted `bitfield.stripped` fixture; no local ARM32 compiler/runtime
claim is added. Final build evidence is `build/combined-review/final-build.txt`
and `build/test-results/function-entry-native/`.

The real exporter and GDB pass these combined-source suites:

| Suite | Cases and retained evidence |
|---|---|
| Function entry | Six x86-64 ET_EXEC/PIE baseline, rebase and repeat cases; `build/test-results/function-entry-export/run.68uWJurK/` |
| Incoming-register prefix | Twelve x86-64/AArch64 ET_EXEC/PIE baseline, rebase and repeat cases; `build/test-results/register-prefix-export/run.MgtMLaEv/` |
| Function statics | Twelve x86-64/AArch64/MIPS32 BE/LE ET_EXEC/PIE/rebased-PIE cases, each exported twice; `build/test-results/function-static-scopes/run.LY3BBQCr/` |
| Existing semantic coverage | Four local profiles across ET_EXEC, partial stripping, absent build ID, absent section table, PIE and shared library; `build/combined-review/final-existing-*-{headless,gdb}.txt` |

These suites retain their exact address/value/source/range checks, independent
GNU/LLVM/libdwarf validators, original hashes and deterministic-repeat checks.
The five target CI lanes now all invoke the static-scope harness against their
installed packaged native pair. Hosted combined validation and new ARM32
static-scope behavior remain **PRESENT, UNVERIFIED** until that pipeline passes.

Review found and fixed two additional bounded safety cases. Shared register
clobber detection now handles p-code `STORE` to the register address space,
which has no output varnode; dynamic offsets, partial writes and malformed
inputs are conservative kills. Explicit RAM stores remain allowed. This uses
the pinned Ghidra 12.0.3 `pcodedescription.html` STORE contract and
`PcodeExecutor.getLoadStoreSpace`/`executeStore` semantics. `registerPrefixSmoke`
checks both outcomes without adding a target-specific rule.

`controlled-decompiler-failure.sh` now curates two function-owned statics before
forcing one owner's failure. GNU/LLVM/libdwarf and GDB pass: the failed function
has no variable children or source/type claims, its static is absent, the later
successful owner's static remains typed and reads as 7, and the JSON inventory
counts exactly one exported static with a precise omission diagnostic.
Evidence: `build/test-results/controlled-decompiler-failure/` and
`build/combined-review/controlled-failure.txt`. One shared selection policy
keeps DIE emission, native relocation checks, diagnostics and counts aligned.

```bash
src/test/integration/function-entry-export.sh "$GHIDRA_INSTALL_DIR" "$consumer" "$producer"
src/test/integration/register-prefix-export.sh "$GHIDRA_INSTALL_DIR" "$consumer" "$producer" x86_64 aarch64
src/test/integration/function-static-scopes-export.sh "$GHIDRA_INSTALL_DIR" x86_64 aarch64 mips32be mips32le
src/test/integration/controlled-decompiler-failure.sh "$GHIDRA_INSTALL_DIR" "$consumer" "$producer"
# Existing roles: exec, partial, exec.no-build-id, exec.no-sections, pie, shared.
# Use headless-symbol-export.sh and qemu-gdb-symbols.sh (shared-object-gdb.sh for shared).
```

## Function entries above body ranges (2026-10-23)

**CONFIRMED locally:** `functionEntrySmoke` checks valid/interior entries,
rejection of entries outside the body, exact entry-first interval encoding,
and preserved sorted extraction ranges in both widths and byte orders. The
real isolated producer passes x86-64, AArch64, ARM32 and both MIPS32 byte
orders with `readelf`, LLVM and libdwarf validators. ARM32 uses a previously
archived source-built hosted fixture because its local compiler is unavailable.
This producer check is structural; it is not a new ARM/MIPS runtime claim.
Logs/artifacts: `build/test-results/function-entry-native/`.

`function-entry-export.sh` builds C/assembly ET_EXEC and PIE fixtures with both
a split body below its entry and a contiguous body with an interior entry.
Independent assembler symbols supply expected addresses; inputs loaded by
Ghidra/GDB are fully stripped. The real production exporter, all validators,
and GDB 15.1 pass baseline, `+0x2000000` Ghidra rebase and deterministic repeat
for both roles. GDB verifies each body byte belongs to the correct function,
every gap byte has neither function nor source coverage, exact named entry
breakpoints, source lookup below/at entry, arguments before/after the backward
branch, global values 42, `next`, `step` and normal exit. Input hashes/build IDs
match; repeated `.dbg` and `.dbg.c` are byte-identical.
Evidence: `build/test-results/function-entry-export/run.QVtda8wK/`.

The compatibility decision is grounded in [DWARF 5 sections 2.17.3/2.18](https://dwarfstd.org/doc/DWARF5.pdf)
and [GDB 15.1's block entry calculation](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-15.1-release/gdb/block.h):
the body may be encoded as nonoverlapping intervals in any order. The producer
places the true entry first and also emits `DW_AT_entry_pc`; this avoids the
observed incorrect lower-address breakpoint when using the attribute alone.
The new constant (`0x52`) and reused `dwarf_add_AT_targ_address_c` signature
were checked against the pinned libdwarf 2.3.2 source archive, SHA-256
`7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.

```bash
./gradlew functionEntrySmoke dwarfRangeListsSmoke dwarfLineTableSmoke \
    dwarfInfoRepairSmoke syntheticSourceSmoke variableStorageSmoke \
    dwarfLocationListsSmoke buildExtension
src/test/integration/function-entry-export.sh "$GHIDRA_INSTALL_DIR" \
    /absolute/path/libdwarf.so.2.3.2 /absolute/path/libdwarfp.so.2.3.2
```

For isolated production, add `-PlibdwarfPath`, `-PlibdwarfpPath`,
`-PsidecarInput` and `-PsidecarOutput` to `functionEntrySmoke`. CI runs that
check in all five target lanes and the real runtime harness in x86-64.
`actionlint`, Bash syntax and the extension build pass locally. The new hosted
gate remains **PRESENT, UNVERIFIED** until the branch pipeline passes.

## Function-owned static data (2026-10-23)

The development static-scope slice preserves primary, defined memory labels
whose immediate Ghidra namespace parent is an exported `Function`. Each object
retains its actual type/address and is emitted beneath its owner. An absent
owner is diagnosed and omitted; it is never silently promoted to a global.
An owner whose decompilation fails remains symbol-only: its static objects are
also omitted, diagnosed and excluded from the exported-static count. The
controlled failure fixture proves this while retaining a successful owner's
static object and checking its value in GDB.
Datatype categories and decompiler formatting do not imply source scopes.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC \
    ./gradlew buildExtension typeGraphSmoke exportReportSmoke
# Install the resulting JAR/script in an isolated installation containing the
# packaged, checksum-verified native pair before running the real exporter.
src/test/integration/function-static-scopes-export.sh \
    /path/to/isolated-ghidra x86_64 aarch64 mips32be mips32le
```

**CONFIRMED locally:** build, type-model/report smoke tests, and all twelve
target/layout cases pass on x86-64, AArch64, MIPS32 big-endian and MIPS32
little-endian. Twenty-four fresh imports prove deterministic repeated exports.
Evidence: `build/test-results/function-static-scopes/run.mwlnRbH7/` in the
isolated `static-scopes` worktree. The harness also accepts the existing ARM32
profile; that target and Windows-hosted behavior await hosted validation.

The source-built fixture has two `private_count` objects owned by different
functions (37 and 83), a global of the same name (19), and a namespace global
(61). Compiler DWARF independently supplies addresses and behavior. Ghidra
imports only the stripped original; an analyst-style preparation script sets
the names, types and explicit owners and exercises missing-owner diagnosis.
The real exporter runs twice from fresh imports at each unchanged output path.

Checks include GNU ELF/DWARF dumps, LLVM verification, independent libdwarf,
function/namespace parentage, locationless external-data declarations, exact
GDB owner-qualified and shadowing lookup, runtime addresses and values, source
lookup, breakpoints, `next` until leaving the first owner, and normal exit.
Every case retains input hashes and requires byte-identical `.dbg`/`.dbg.c`
reruns. Each target has ET_EXEC, PIE, and PIE after a Ghidra `+0x2000000`
rebase. Compiler unwind tables are retained in the original executable; Forge
does not synthesize CFI.

**ARM32 fixture correction (2026-10-23):** hosted run `40057031192` at
`8e3fd27`, job `120763742547`, stopped before export because this harness
unconditionally required a DWARF FDE in the stripped compiler input. Its
`.eh_frame` contains only a terminator, while `.ARM.exidx`/`.ARM.extab` retain
valid native unwind rules. The [ARM EHABI index format](https://github.com/ARM-software/abi-aa/blob/2025Q4/ehabi32/ehabi32.rst)
permits an ordered index range to cover adjacent functions with the same
rules. Here `first_scope` and `second_scope` share one decoded compact entry;
`main` has a separate entry.

The ARM-only precondition now uses independent GNU `readelf` decoding, requires
a correctly sized/ordered native index, and verifies usable compact entries
cover the complete compiler-symbol ranges of all three functions. It accepts
merged entries and implicit Finish, and rejects missing tables, malformed
length/order/count, `cantunwind`, and compact Refuse-to-unwind. Other targets
retain their FDE check. The original compiler/Forge runtime oracle, warning
policy and exporter are unchanged. This establishes present/decoded coverage
and observed successful returns; it does not establish whether GDB selected
EHABI rather than frame-pointer unwinding for a particular step.

```bash
src/test/integration/arm-ehabi-regression.sh <arm32-stripped> <compiler-reference>
src/test/integration/function-static-scopes-export.sh /path/to/isolated-ghidra arm32
```

The negative regression runs automatically with the ARM32 exec fixture. It
proves the old FDE-only check rejects valid input, then checks actual private
ELF copies with an absent index, truncated index, `cantunwind` coverage and
compact Refuse-to-unwind. All reject; supplied originals remain unchanged.
Exact hosted artifact `12545114957` has SHA-256
`3dedac03799a187938bfb15416361ea28f3fad52df0491d59ead1a72936c06cf`;
its original failure is retained under `build/hosted-failure-review/`.

**CONFIRMED locally:** ARM32 exec/PIE/rebased-PIE pass all existing compiler and
Forge scope/value/address/source/stepping/return checks, GNU/LLVM,
input preservation and byte-identical repeated exports in
`arm-unwind-fixture/build/test-results/function-static-scopes/run.mAHnsuSk`.
The distro `dwarfdump` 20210528 returned zero but reported four line-table
errors in each summary; the former harness failed to detect them. They must
not be described as a clean validator run. Rechecking the exact three
artifacts with unmodified pinned libdwarf/dwarfdump 2.3.2 (`-ka -ki -kd`)
reports zero errors, with retained full summaries under
`arm-unwind-fixture/build/dwarfdump-2.3.2/comparison/`. Its source archive
SHA-256 is `7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
The broader checker-policy and strict-summary correction is tracked separately;
these local results do not establish that every existing artifact is clean.
Negative evidence is `run.hqFNiphI` (retained hosted input) and `run.adZ1Pf3X`
(fresh compiler input) under `build/test-results/arm-ehabi-regression/`.
Testing uses Ubuntu GCC 13.3/binutils 2.42 and ARM libc 2.39 extracted under
the worktree's `build/arm-toolchain`, with local wrappers redirecting only
compiler/sysroot paths. The exact hosted `8e3fd27` package is installed in a
private Ghidra tree; artifact `12545313779` SHA-256 is
`2b6ad3c49bdb203d2f948b7dd855f17ce71b8ebb1bcfc0fc60ee74d8fe21fa3f`.
No system installation or shared Ghidra module was changed. Hosted verification
of the corrected ARM path remains pending; the old hosted run never reached
its floating-register tests.

**Observed debugger limitation:** local GDB 15.1 with QEMU MIPS PIE can emit
`warning: GDB can't find the start of the function at 0x2b321c03.` while
stepping from the first function back to `main`. The untouched compiler ELF
is clean when loaded directly, but reproduces the same warning under
`file <stripped-original>` followed by `symbol-file <compiler-reference>`.
No Forge DWARF or sidecar container is needed to reproduce it. The compiler
line table needs two `next` operations to leave the function, whereas the
synthetic line table may need one; comparing only one operation was insufficient.

Both compiler loading transcripts are retained beside each Forge transcript.
Only MIPS PIE cases may corroborate this precise warning, including its
address and occurrence count, within the same owner-return operation in the
independent separate-symbol-file oracle. Other diagnostics still fail, apart
from the previously documented compiler-corroborated ARM/QEMU vDSO warning.
This proves scoped-variable behavior, not general MIPS stack-unwind accuracy.
Hosted validation of this new slice remains pending.

## Incoming-register lifetime before overwrite (2026-10-23)

**CONFIRMED locally:** `registerPrefixSmoke` checks the exact boundary after
the first writing instruction, raw unnamed/partial register aliases, adjacent
nonoverlapping registers, hazards before/after the overwrite, decoding gaps,
missing returns, delay slots, flow overrides and cancellation. No prefix is
accepted until the whole body passes the conservative straight-line proof.

`register-prefix-export.sh` builds independent compiler-DWARF references and
fully stripped Ghidra/runtime inputs for x86-64 and AArch64. The x86 fixture
overwrites the low 16-bit argument register; AArch64 overwrites its 32-bit
alias. Compiler DWARF verifies value 19 before/at/after the overwrite. Forge
verifies 19 at entry, before the write and at the writing instruction, then
`<optimized out>` from the next instruction onward. Later restored register
bits are not treated as recovered storage. Both oracles check source stepping,
global value 19 and normal exit. The post-clobber assembly marker is a separate
C statement so the compiler itself updates its location information at that
boundary rather than describing the entry to an opaque inline-assembly block.

The dedicated x86-64/AArch64 ET_EXEC/PIE baseline, `+0x2000000` Ghidra rebase
and repeat matrix passes real exports, readelf/LLVM/libdwarf, GDB values,
input SHA-256/build-ID checks and byte-identical `.dbg`/`.dbg.c` repeats.
Evidence: `build/test-results/register-prefix-export/run.jx2DfFhQ/`, including
the final return-instruction checks, and
`build/register-prefix-review/final-integration.txt`.

The ordinary AArch64 semantic breakpoint remains after its overwrite and still
reports unavailable arguments there; headless checks now require its limited
prefix diagnostic. An archived ARM32 semantic input remains wholly unavailable
under this proof. The existing x86-64/AArch64/MIPS32 BE/LE × ET_EXEC/PIE/shared
matrix also passes all production exports, validators and native/QEMU GDB
oracles; logs are `build/register-prefix-review/existing-*-{headless,gdb}.txt`.
No new ARM32 or MIPS lifetime claim is made by these probes.

```bash
./gradlew registerPrefixSmoke variableStorageSmoke dwarfLocationListsSmoke buildExtension
src/test/integration/register-prefix-export.sh "$GHIDRA_INSTALL_DIR" \
    /absolute/path/libdwarf.so.2.3.2 /absolute/path/libdwarfp.so.2.3.2 x86_64 aarch64
```

The harness needs the existing GNU target toolchains, QEMU AArch64/GDB and
validators. The exact known QEMU synthetic-vDSO warning is allowed only when
also seen in the independent compiler oracle; other diagnostics fail. CI runs
the new smoke and both real target lanes. Hosted validation remains
**PRESENT, UNVERIFIED** until that pipeline passes.

## ELF robustness development (2026-10-23)

The following evidence applies to implementation `3e47589` in
[PR #18](https://github.com/zwilcox/GhidraDwarfForge/pull/18), stacked on the
unmerged correctness fixes. The published alpha is unchanged.

**CONFIRMED locally:** file-backed ELF parsing and streamed sidecar writing
pass independent ELF32/64 × little/big-endian tests for count/index escape
fields, absent names, sparse offsets above 2 GiB, malformed/truncated metadata,
resource limits, changed input files and physical symlink traversal. Output
limits fail before publication; existing output bytes and input hashes remain
unchanged. Late `PT_LOAD`/`PT_NOTE` entries are read beyond the ordinary count
limit. Partial note coverage preserves each note once, with the original build
ID and section indexes intact. See `elfImageReaderSmoke`,
`extendedSectionNumberingSmoke`, and ADR 0001 for exact bounds.

**CONFIRMED locally:** `large-elf-sidecar.sh` runs the writer with `-Xmx64m`
on a 2,147,487,745-byte source-built input. The 2,147,491,192-byte sidecar
passes GNU/LLVM/libdwarf validators and GDB function/type/source lookup,
breakpoints, argument/global values, `next`, `step` and normal exit. Original
payload bytes outside the rewritten ELF header match, the original hash is
unchanged, and repeated output is byte-identical. ELF32 output overflow and
atomic-publication failure preserve prior destinations and leave no temporary
files. Evidence: `build/test-results/large-elf-sidecar/run.tohmsekL/`.

**CONFIRMED locally:** `large-headless-export.sh` imports and exports an
actual 2,147,487,744-byte x86-64 fixture with the production Ghidra exporter,
then runs the existing full GDB semantic oracle. GNU/LLVM/libdwarf validation,
input preservation and byte-identical fresh-import reruns pass:
`build/test-results/large-headless-export/run.e1Vg0Q3x/`. The source-tree
production Bash wrapper also passes large import/export using packaged native
selection: `build/test-results/large-wrapper-export/run.KGWoLV9K/`.
Multi-gigabyte scratch artifacts are removed; compact logs, source and hashes
remain. This proves bounded source-file I/O, not bounded decompilation/model
memory for programs with billions of instructions.

The first large Ghidra import failed before ELF loading: automatic format
detection exhausted the heap inside Ghidra's unrelated `SomLoader`. Explicit
`-loader ElfLoader` fixes this; both production wrappers now select it in
import mode. The failed transcript is retained at
`build/test-results/large-headless-export/run.lMsNrGay/`. It is not counted as
a passing test.

**CONFIRMED locally:** moving all MIPS load headers beyond the ordinary count
limit exposed a separate address bug. Ghidra 12.0.3 records import base zero
after scanning only its first 20 headers, while functions retain link-time
addresses. The previous exporter reported success but placed `main` at
`0x800874` instead of `0x400874`. Reversing the actual loader mapping with
`ElfLoader.getElfOriginalImageBase` fixes it; the before/after artifacts and
GDB transcripts are under `build/elf-layout-probe/{before,after}/`. The fixed
artifact passes GNU/LLVM/libdwarf validators. The independent nonzero-load
file-offset fixture still passes normal/rebased/repeated export, values and
source stepping at function `0x40100e`, global `0x402000`:
`build/test-results/nonzero-load-offset-export/run.YaZrFgCK/`.

**CONFIRMED locally:** the real extended-section-count/index matrix passes on
x86-64 and MIPS32 BE for ET_EXEC and PIE, including exact-input runtime GDB,
validators, identity/build-ID preservation and deterministic repeats:
`build/test-results/extended-sections-export/run.yBMDsFt7/`. The old
`readelf -S | grep -q` pipefail was a test-harness SIGPIPE; assertions now read
the retained complete section dump.

**CONFIRMED locally:** the final layout matrix passes x86-64/MIPS32 BE ×
ET_EXEC/PIE × unnamed sections/extended program counts. All original program
headers follow 65,535 `PT_NULL` entries, so meaningful load/note headers truly
exceed the old reader's limit. Exact function/global addresses match the
compiler oracle; recorded import base zero, ordinary and `+0x2000000` rebased
exports, full runtime values/source/type checks, deterministic reruns and
input hashes pass. Evidence: `build/test-results/elf-layout-export/run.9sEGM71z/`.
The same final layout and extended-section suites also pass AArch64 and
MIPS32 LE, including rebases, deterministic repeats and runtime GDB under
QEMU: `build/test-results/elf-layout-export/run.XHkZz1YZ/` and
`build/test-results/extended-sections-export/run.IVAWyHe8/`.

Direct execution of this `PN_XNUM` fixture fails in native Linux and QEMU
8.2.2. The harness uses the actual extended input for import/export and static
GDB, then the unchanged ordinary fixture for runtime checks after independently
proving unchanged original load bytes/addresses. Every case records that policy;
it is not a claim that the extended input executed. Direct-loader probes are
retained in `build/elf-layout-probe/final-pn-runtime-limits.txt`.

GNU tools emit known diagnostics on the unusual *inputs*: nameless tables
trigger readelf's name-based `.dynamic` lookup and a BFD string-table-index
warning; valid section-zero extended program counts trigger readelf's generic
`sh_info` warning. Allowances match the exact input condition/path/count.
Generated sidecars must remain clean. ARM QEMU vDSO warnings require a matching
independent compiler-DWARF oracle diagnostic; no symbol/value assertions are
relaxed.

**CONFIRMED locally:** cancellation during an actual 128 MiB source copy
stops after the first 16 MiB transfer. The installed production script reports
`CANCELLED`, preserves the original and both previous output files, and leaves
no staging files: `build/test-results/copy-cancellation-export/run.TfMRs1tH/`.
`elfCopyCancellationSmoke` also tests cancellation immediately before atomic
replacement and through the artifact-pair publisher under `-Xmx64m`.
The extension build and all nineteen native-independent smoke tasks pass;
logs are in `build/test-results/elf-robustness/final-build-smokes.txt`.

**CONFIRMED:** the five hosted target lanes pass in run `40047390539`.
ARM32 artifacts were downloaded to `build/elf-robustness-hosted/arm32/` and
independently inspected: all ten archived sidecars pass LLVM/libdwarf again,
hashes/build IDs/deterministic comparisons match, and actual LOAD/NOTE headers
lie after 65,535 null entries. Compiler-oracle function/global addresses are
`0x10464`/`0x12034` for ET_EXEC and `0x578`/`0x2028` for PIE, including the
rebased export. Runtime transcripts confirm `right=23`, stack/global value 42,
source stepping and normal exit with uncertain locations honestly unavailable.
Local ARM32 compilation remains unavailable; this is hosted evidence.
**CONFIRMED:** [run 40047390539](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40047390539)
completed all twelve jobs successfully, including Windows-hosted export and
the aggregate gate. Hosted x86-64 transcripts also confirm the constrained-heap
writer, >2 GiB real export and actual cancellation after 16 MiB; compact
artifacts are retained in `build/elf-robustness-hosted/x86_64/`.
Windows transcripts are under `build/elf-robustness-hosted/windows/` and
confirm original preservation, real export and locked-file publication safety.
That runner uses GNU readelf and LLVM; the standalone libdwarf `dwarfdump`
command is explicitly unavailable there. All five Linux target lanes run it.

Reproduction commands, after building fixtures and installing the current
extension:

```bash
./gradlew elfImageReaderSmoke extendedSectionNumberingSmoke ghidraImageBaseSmoke
./gradlew extendedSectionNumberingSmoke -PfixtureTarget=x86_64
java src/test/integration/ElfLayoutFixtures.java build/fixtures x86_64 mips32be
src/test/integration/extended-sections-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64
src/test/integration/elf-layout-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64 mips32be
src/test/integration/large-elf-sidecar.sh
src/test/integration/large-headless-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2
src/test/integration/copy-cancellation-export.sh "$GHIDRA_INSTALL_DIR"
```

## Published-alpha correctness review (2026-10-23)

**CONFIRMED:** all six findings against `f4a0199` were validated. The
following evidence refers to the development fixes, not the unchanged
published `0.1.0-alpha.1` artifact.

- Wrapper collision: historical Bash and PowerShell wrappers overwrote
  disposable input copies with a fake-headless transcript. The fixed
  `src/test/integration/headless-wrapper.sh` and `headless-wrapper.ps1`
  reject aliases before launch and assert hashes for inputs, outputs, native
  libraries and project files. Direct, normalized, symlink, hardlink, dangling
  output-link and parent-symlink/`..` cases pass on Linux (PowerShell 7.6.8).
  Independent review also reproduced PowerShell collisions after `Set-Location`
  and through wildcard expansion. Provider-based path resolution and literal
  log I/O now pass regressions with mixed absolute/relative paths and bracket
  filenames. Windows alternate-stream log rejection has preventive CI coverage.
  **CONFIRMED:** native Windows checks pass in run `40041110549` without
  skipped cases; the downloaded transcript is retained under
  `build/correctness-review/windows-native-second/headless-wrapper.log`.
- Nonzero load file offset: a source-built x86-64 ET_EXEC places its first
  PT_LOAD at file offset `0x1000`, VA `0x401000`. Before the fix, Ghidra
  reported success but exported function `0x40000e` instead of `0x40100e`
  and global `0x401000` instead of `0x402000`; GDB could not insert the
  breakpoint. The fixed normal, explicitly rebased (`+0x2000000`), and fresh
  repeat exports pass readelf, LLVM, libdwarf and GDB address/value/source
  checks. Arguments are 19/23; the global changes from -1 to 42; `list`,
  `next`, `step`, normal exit, input preservation and byte-identical reruns
  pass. Evidence: `build/test-results/nonzero-load-offset-baseline/run.WsbQolmY/`
  and `build/test-results/nonzero-load-offset-export/run.KzJjsmJB/`.
- Bit-field values: the compiler oracle returns `{a=5,b=17}` for both
  four-byte and packed one-byte aggregates. The old Forge artifact returned
  `{a=5,b=13}` on x86-64 and `{a=5,b=22}` on MIPS32 BE. The fixed real Ghidra
  extraction retains one-byte component storage independently of the
  four-byte base type and emits only `DW_AT_data_bit_offset` for bit fields.
  MIPS32 BE offsets are 0/3 instead of 24/27. Values, sizes, attribute
  exclusivity, validators and input hashes pass on x86-64, AArch64, MIPS32 BE
  and MIPS32 LE. Evidence: `build/test-results/bitfield-values/run.0LBNa3y4/`
  and `run.rF7wLLEx/`; pre-fix runs are `run.9jN1IZAM/` and `run.iiXbxCeP/`.
  A known QEMU ARM32/AArch64 synthetic-vDSO warning is accepted only when the exact
  same diagnostic appears with the independent compiler oracle; stderr is
  retained. Hosted run `40040274616` stopped before the ARM32 export because
  this warning was initially allowlisted only for AArch64. Its retained ARM32
  compiler oracle has the correct values and sizes and exits normally; the
  narrow warning guard now covers both ARM targets. **CONFIRMED:** the full
  ARM32 bit-field export passes in run `40041110549`. Downloaded compiler and
  Forge transcripts both report `{a=5,b=17}`, aggregate sizes 4/1, and the
  identical vDSO warning; see `build/correctness-review/hosted-arm32/`.
  Its cross compiler remains unavailable locally, so this is hosted evidence.
  Earlier `ptype` checks alone did not prove bit-field values.
- Inherited `.gdb_index`: already fixed and validated by the post-alpha work
  below, including a real `gdb-add-index` input and GDB symbol lookup. The fix
  remains absent from reviewed `main` and the published alpha.
- Source lookup: the pre-fix `/usr/bin/true` export resolves functions but
  cannot list `./true.dbg.c` from an unrelated directory (transcript
  `build/correctness-review/source-before/gdb-before.txt`). The strengthened
  `real-world-export.sh` uses output paths with spaces, starts GDB elsewhere,
  and supplies no source-directory workaround. True and basename both pass
  source listing, stepping, validators, input preservation and deterministic
  fresh imports: `build/test-results/real-world-export/run.V4rS12HT/`.

Reproduction commands (installed development extension with packaged natives):

```bash
src/test/integration/headless-wrapper.sh
pwsh -NoLogo -NoProfile -File src/test/integration/headless-wrapper.ps1
module="$GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraDwarfForge"
src/test/integration/nonzero-load-offset-export.sh "$GHIDRA_INSTALL_DIR" \
    "$module/os/linux_x86_64/libdwarf.so.2.3.2" \
    "$module/os/linux_x86_64/libdwarfp.so.2.3.2"
src/test/integration/bitfield-values-export.sh "$GHIDRA_INSTALL_DIR" \
    x86_64 aarch64 arm32 mips32be mips32le
src/test/integration/real-world-export.sh "$GHIDRA_INSTALL_DIR"
```

**CONFIRMED locally:** the extension build and all fifteen native-independent
smoke checks pass, as do wrapper checks, architecture-boundary enforcement,
release assembly checks and workflow lint. The existing x86-64, AArch64,
MIPS32 BE and MIPS32 LE matrix passes real headless export, structural
validators and native/QEMU GDB for ET_EXEC, PIE and section-header-free
ET_EXEC (12 target/role combinations). The GDB harness now asserts the recorded
absolute source path and no longer supplies a `directory` workaround. Logs:
`build/correctness-review/build-final.log` and `matrix-*.log`.

**CONFIRMED hosted:** [run 40041110549](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40041110549)
passed all twelve jobs for implementation commit `cd906de`: the five target
lanes, Windows wrapper safety and hosted export, native builds, extension build,
package assembly, workflow lint and aggregate gate. The earlier run
`40040274616` hit the ARM32 warning check described above; after its x86-64,
AArch64 and MIPS32 LE lanes passed, it was superseded and cancelled while MIPS32
BE was still installing its toolchain. The replacement run completed every
required lane. PR #17 contains these fixes and depends on PR #16 for inherited
index retirement; neither changes the published alpha artifact.

## Alpha release validation (2026-10-22)

**CONFIRMED:** work resumed from clean commit
`f4a01992deb5b2e65736c573cc3e6d2cbe59ce75`, matching remote `main`. The
documented clean extension build and all thirteen native-independent smoke
tests passed locally with `GHIDRA_INSTALL_DIR` explicitly set to Ghidra
12.0.3. An initial invocation without that variable stopped at configuration
and did not run tests.

**CONFIRMED:** fresh [GitHub Actions run 39892474892](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/39892474892)
built the native-inclusive `0.1.0-alpha.1` candidate from that commit and
passed byte-identical repeated assembly. Independent inspection of the
downloaded candidate verified the ZIP, whole-release and both platform
manifests, nested corresponding-source/runtime manifests, pinned source/patch
digests, version metadata, and executable wrapper permissions.

Candidate artifact: `GhidraDwarfForge-0.1.0-alpha.1-ghidra-12.0.3.zip`
(8,083,141 bytes). SHA-256:

```text
27ad36e575ad410df475d2ec45c0fac03287dab19515fcbe39ffc6dd69bfc502
```

**CONFIRMED:** the fresh run passed all twelve jobs, including x86-64,
AArch64, ARM32, MIPS32 big/little endian, Windows-hosted export, and the
aggregate `required-validation` gate. The verified bundle and `SHA256SUMS`
were published as [v0.1.0-alpha.1](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.1)
on 2026-10-22 America/Chicago (2026-10-23 UTC). The public tag resolves to the
tested commit. Downloading the published assets passed `sha256sum -c`; the
downloaded ZIP was byte-identical to the verified CI candidate, and the public
checksum URL was accessible without authentication. This is a prerelease with
the profile and feature limitations listed in its release notes; it does not
close unrelated scope gaps.

## Post-alpha existing-DWARF and GUI checks (2026-10-22)

**CONFIRMED:** the development writer fixes a reproduced GDB warning from the
published alpha: `/usr/bin/true` carried `.gnu_debugaltlink` into its sidecar,
causing GDB to search for obsolete supplementary debug data. Inherited debug
metadata is now retired according to ADR 0001; the original is unchanged.

The extension build and fourteen native-independent smoke tests passed,
including `existingDebugSidecarSmoke`. Its ELF32/64 by little/big-endian
matrix checks replacement payloads/flags, duplicate section names, preserved
bytes/build identity/unwind sections, and deterministic output. The local
development JAR was installed into an isolated copy of Ghidra 12.0.3 with the
verified alpha native package. The user's installed extension was not changed.

The new end-to-end commands are:

```bash
module="$GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraDwarfForge"
src/test/integration/existing-debug-export.sh "$GHIDRA_INSTALL_DIR" \
    "$module/os/linux_x86_64/libdwarf.so.2.3.2" \
    "$module/os/linux_x86_64/libdwarfp.so.2.3.2"
src/test/integration/real-world-export.sh "$GHIDRA_INSTALL_DIR"
src/test/integration/gui-output-fallback.sh "$GHIDRA_INSTALL_DIR" "$module" \
    "$PWD/build/fixtures/x86_64/semantic.exec.stripped" \
    "$PWD/build/fixtures/x86_64/semantic.exec.reference"
```

- **PASS:** plain compiler DWARF, SHF_COMPRESSED zlib, GNU `.zdebug_*`, and a
  real `gdb-add-index` fixture. Each exports through production headless Ghidra,
  contains exactly one Forge CU, passes GNU/LLVM/libdwarf validators, and runs
  the full type/global/local/source-stepping GDB oracle against a debugless
  runtime binary. Input and runtime hashes stay unchanged. Logs/artifacts:
  `build/test-results/existing-debug-export/run.C2v11Pb5/`.
- **PASS:** unmodified GNU coreutils `/usr/bin/true` and `/usr/bin/basename`.
  Two independent imports per binary produce byte-identical `.dbg`/`.dbg.c`.
  Validators and GDB entry/application breakpoints, signatures, source listing,
  `next`, `step`, and exit status pass without warnings; basename prints
  `path` for `/alpha/path`. No analyst preparation or variable expectations
  are injected. Logs: `build/test-results/real-world-export/run.i996N8bM/`.
- **PASS:** Linux GUI chooser selection/cancellation with a read-only input
  directory. The production script runs in a genuine non-headless Ghidra
  process and the test drives real Swing controls and mouse events. Selection
  emits exactly the artifact pair; cancellation emits `CANCELLED` and no
  output. Input hashes, GNU/LLVM/libdwarf validators, GDB source lookup and
  stepping pass. Screenshots/logs from the rebuilt module:
  `build/test-results/gui-output-fallback/run.NZvz59Sx/`.

The GUI check requires Xvfb and a GUI-enabled Java 21+. Locally, Xvfb packages
were downloaded/extracted below `build/gui-validation/dependencies/` without
system installation; the run set `XVFB_BIN` to that extracted binary and
`JAVA_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java`. The default Java 25
installation is headless-only. This does not prove manual Script Manager
navigation or Windows GUI behavior.

**CONFIRMED:** the rebuilt writer also passes fresh real-export, GNU/LLVM/
libdwarf, and native/QEMU GDB runs for x86-64, AArch64, MIPS32 big-endian, and
MIPS32 little-endian across `exec`, `pie`, and `exec.no-sections` (twelve
target/role cases). Commands use `FIXTURE_ROLE=<role>` with
`headless-symbol-export.sh` and `qemu-gdb-symbols.sh`; aggregate transcripts are
under `build/real-world-validation/final-<role>-{export,gdb}.log`. Shell syntax,
architecture-neutrality, wrapper, and actionlint checks pass. Local ARM32
rebuild was unavailable because `arm-linux-gnueabihf-gcc` is not installed;
the hosted lane remains required. One intermediate run was interrupted by a
concurrent edit to its shell harness and was rerun after edits stopped; only
the final stable-script runs are counted as passing.

Two test-harness issues were corrected during validation: GDB must search the
artifact directory to resolve the relative synthetic-source path; and imported
compiler types may share a name with curated types, so the enum oracle also
uses `ptype OP_INVALID` to select the uniquely identified analyst enum. These
are not evidence of an extra inherited compiler CU in the emitted sidecar.

**CONFIRMED:** [GitHub Actions run 39896787460](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/39896787460)
passed all twelve jobs for implementation commit
`3cdc3f851772c9c876952473b7504932de826925` in PR #16. The new existing-DWARF,
real-world, and GUI checks passed in the hosted x86-64 lane. AArch64, ARM32,
both MIPS byte orders, Windows-hosted export, native builds, release assembly,
and the aggregate gate also passed. This is fresh evidence for the post-alpha
implementation, separate from the already published alpha's earlier run.

## Ancillary local checks

```bash
find src/test/integration -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
```

Result: PASS.

`actionlint` 1.7.12 accepted the workflow. The CI workflow also
downloads that pinned release, verifies it against the upstream checksum file,
and rejects workflow changes that fail linting. The historical Maven shaded
JAR path, committed wrapper natives, and unpacked JNA tree were removed in
favor of the Gradle extension plus CI-native release path.

```bash
src/test/integration/release-package.sh
```

Result: PASS. Two assemblies from identical inputs were byte-identical; all
platform and release manifests verified and executable wrapper permissions
were preserved. This synthetic assembly test does not substitute for the
hosted clean-install native exports.

## Hosted continuous validation

**CONFIRMED:** GitHub Actions run 33751896850 passed workflow lint, pinned
Linux and Windows libdwarf builds, the extension build, x86-64/AArch64/MIPS32
target integration, the Windows-hosted exporter, and the aggregate
`required-validation` job. Each job records exact Ghidra, libdwarf, Java,
compiler, binutils, validator, GDB, and applicable QEMU versions. Native smoke
tests run through an isolated crash-status wrapper, and diagnostic artifacts
are retained for 14 days even when a job fails.

**CONFIRMED:** GitHub Actions run 33757707307 passed all 11 jobs, including the
aggregate gate, after adding an ARM32 target job using `arm-linux-gnueabihf`,
an ARMv7 hard-float little-endian ARM-state fixture, `qemu-arm-static`, and
`gdb-multiarch`. The lane passed real Ghidra export for ET_EXEC, PIE,
shared-object, no-build-ID, and no-section-table inputs; GNU readelf, LLVM
verification, independent dwarfdump, and the runtime GDB oracles accepted the
artifacts. This evidence does not claim Thumb, big-endian ARM, or other ARM ABI
profiles.

**CONFIRMED:** after the repository became public on 2026-09-03, `main` branch
protection was enabled with strict/up-to-date status checking and
`required-validation` as its required GitHub Actions check. Force pushes and
branch deletion remain disabled.

**CONFIRMED:** GitHub Actions run 33778570507 passed all 12 jobs after the
native ABI audit and `.debug_str` implementation. Both Linux and Windows
compiled and ran the pinned-header C ABI probe, built patched libdwarf twice,
and passed functional file/export/dependency equivalence. All five target
lanes passed isolated producer smoke, real headless export, GNU/LLVM/libdwarf
structural validation, and native/QEMU GDB behavior with `.debug_str` and
`DW_FORM_strp`. The Windows host passed opaque producer-error callback
delivery, file-lock rollback, explicit-native export, and packaged-native
export.

**CONFIRMED:** post-merge `main` run 33781582940 repeated all 12 checks against
merge commit `c698153` successfully. Issues #1, #2, #3, #5, #6, #7, and #9
were then closed as completed. Issue #8 was closed as not planned for the
current ELF milestone under ADR-0002's evidence requirement.

**CONFIRMED:** GitHub Actions run 33824105805 passed all 12 jobs after the
release-hardening additions. Linux and Windows passed repeated producer
lifetimes and clean installed-extension native loading; all five target lanes
passed reproducible fixture rebuilds and real partially stripped input export.
The table-driven target and architecture-boundary guards, relocation-section
rejection, and `.debug_aranges` absence checks also passed.

The required workflow now also assembles the Linux/Windows native release ZIP
twice, compares it byte for byte, verifies every embedded SHA-256 manifest,
and installs that aggregate artifact for real exports on both host operating
systems without external native paths. `required-validation` cannot pass when
release assembly or either clean-install export is skipped or fails.

## Windows-hosted lane

**CONFIRMED:** `.github/workflows/ci.yml` defines a Windows lane
that builds the pinned libdwarf 2.3.2 DLL pair under MSYS2 MinGW64, checks
required exports, recursively resolves non-system runtime DLL dependencies,
and records DLL hashes, compiler identity, configure flags, and dependency
names. A second Windows job installs Ghidra 12.0.3, runs the isolated native
producer plus native-independent source/publication tests, and performs a real
headless export of the Linux x86-64 ELF fixture.

The PowerShell harness preserves the input hash, rejects staging leftovers and
CR bytes, requires the generated `.dbg.c` to match the Linux lane byte for
byte, compares ELF identity/build ID, and runs Windows GNU `readelf` plus LLVM
DWARF verification. It also holds the existing source open with Windows
`FileShare.None`, forces the second publication move to fail, and proves the
old sidecar/source pair is restored without staged or backup leftovers. GitHub
Actions runs 33751896850 and 33778570507 passed the native DLL build/audit,
real Ghidra export, cross-host source comparison, file-lock rollback, and both
Windows validators. Run 33778570507 additionally passed the pinned-header ABI
probe, clean native rebuild comparison, error callback, and `.debug_str`
checks.
Earlier runs exposed and verified fixes for batch argument
transport, Ghidra's Windows drive-path spelling, and MSYS2 tool discovery. GDB
execution of ELF artifacts remains in the Linux native/QEMU jobs; PE/PDB is out
of scope.

The Windows batch launcher transports script options as separate name/value
tokens. The exporter accepts those tokens as well as the `--name=value` form
used on Linux and normalizes Ghidra's `/C:/...` Windows executable-path form
before Java filesystem access. A real Linux headless export with the split-token
form passed; the PowerShell invocation and Windows normalization then passed on
the hosted runner.

## Extension build

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew clean addressNormalizerSmoke dwarfTargetSmoke outputPathPolicySmoke \
    exportReportSmoke syntheticSourceSmoke typeGraphSmoke variableStorageSmoke \
    dwarfInfoRepairSmoke dwarfLineTableSmoke \
    dwarfRangeListsSmoke dwarfLocationListsSmoke artifactPairPublisherSmoke \
    packagedNativeLibrariesSmoke buildExtension
```

Result: PASS. All thirteen native-independent smoke tests passed and the
installable artifact was generated under `dist/`. `unzip -t` accepted the ZIP,
and inspection confirmed that the local `.ghidra-test` directory was not
packaged.

`dwarfLineTableSmoke` covers overlapping token evidence, one source line with
addresses in discontiguous function intervals, out-of-range evidence, separate
line sequences for each interval, and order-independent serialization. A
shared instruction address deterministically selects the earliest generated
source line.

`exportReportSmoke` covers stable JSON ordering and escaping plus `SUCCESS`,
`PARTIAL`, `CANCELLED`, and `FATAL` terminal states. A real x86-64 headless
export emits `PARTIAL` with target identity, artifact hashes, libdwarf 2.3.2,
export counts, skipped-function reason codes, unavailable-location ranges, and
opaque-type diagnostics. The controlled decompiler-failure oracle reports
`functionsFailed: 1` and names `recovered_add`; its sidecar still passes GNU,
LLVM, independent libdwarf, and GDB checks. A mismatched-input preflight emits
`FATAL` and publishes neither output. Validator state is explicitly `NOT_RUN`
inside the export report because the development harness validates the final
artifact after the report is produced.

`dwarfTargetSmoke` checks the table-driven ELF-machine, class, byte-order, and
libdwarf ISA/flag mapping. It accepts only the validated profiles, including
MIPS32 in both byte orders, and fails closed for MIPS64 and unsupported
big-endian x86-64, AArch64, or ARM inputs. The companion
`src/test/integration/architecture-neutrality.sh` guard rejects architecture
names and register spellings outside `DwarfTarget`, `TargetRegisterMap`, and
the host-only packaged-native selector.

## Packaged headless wrapper

```bash
src/test/integration/headless-wrapper.sh
support/ghidra-dwarf-forge-headless \
  --ghidra-dir=/home/ziggy/ghidra_12.0.3_PUBLIC \
  --import=build/fixtures/x86_64/semantic.exec.stripped \
  --output=build/test-results/headless-wrapper/semantic.dbg
```

Result: PASS. The native-free wrapper contract covers temporary-import and
read-only existing-project arguments plus completed, partial, fatal, cancelled,
missing/multiple report, launcher-failure, and usage exit codes. Real Ghidra
returned `0` for `PARTIAL` and the wrapper converted an analyzeHeadless
zero-status script failure into exit `10` for `FATAL`. Repeated imports produced
byte-identical sidecar/source hashes; GNU readelf, LLVM verification, and
independent libdwarf validation passed. Both wrappers are included in the
extension ZIP. The PowerShell implementation parsed, launched the production
exporter, and completed its report/artifact contract on the hosted Windows run.

## Pinned libdwarf producer ABI

Using a local build of pinned libdwarf v2.3.2:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew nativeProducerSmoke \
  -PlibdwarfPath=<audit-build>/libdwarf.so.2.3.2 \
  -PlibdwarfpPath=<audit-build>/libdwarfp.so.2.3.2 \
  -PtargetProfile=<x86_64|arm64|arm32|mips32be|mips32le> \
  -PnativeIterations=64

GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew packagedNativeProducerSmoke \
  -PpackagedModuleRoot=<installed-GhidraDwarfForge-module> \
  -PpackagedPlatform=<linux_x86_64|win_x86_64> \
  -PtargetProfile=x86_64 \
  -PnativeIterations=2
```

Result: PASS for all five profiles in separate JVM processes. The x86-64
Linux process also completed 64 full producer lifetimes and remained below
the 32 MiB post-warmup RSS-growth bound. A previous installed artifact's old
native demonstrated the cross-lifetime output defect which the updated patch
fixes. GitHub Actions run 33824105805 passed 64 explicit-native lifetimes on
Linux and Windows and resolved the checksum-verified pair from the clean
installed release artifact on both hosts. Each run
created a DWARF 5 CU and subprogram, retrieved `.debug_info`,
`.debug_abbrev`, and `.debug_str`, validated a version-2 symbolic relocation
buffer, checked target-address and string-table relocations, and finished
cleanly. Each run also deliberately passes `DW_AT_data_bit_offset` to
libdwarfp's restricted fixed-width constant helper, checks the expected
`DW_DLE_INPUT_ATTR_BAD (143)`, and safely decodes the producer error both from
an explicit error output and through the opaque callback. This specifically
guards the producer/consumer `Dwarf_Error_s` layout mismatch.

The local audit build applies
`native/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch` to the
pinned v2.3.2 source. Besides preserving AArch64 relocation types, the patch
makes producer string tables handle-local and frees them at finish. Without
that fix, the repetition test observed `.debug_str` grow by 95 bytes per
identical producer lifetime; with it, all 64 lifetimes emitted the same
95-byte section. A clean second Linux build produced functionally
equivalent library file sets, ELF identity, exports, SONAME/dependencies, and
normalized RUNPATH. The exact binary hashes differed because the compiler
embedded distinct build paths/build IDs; both sets are recorded rather than
misrepresented as byte reproducible. The pinned-header C ABI probe compiled
with warnings as errors and reported 64-bit `Dwarf_Unsigned`, `Dwarf_Signed`,
`Dwarf_Off`, and `Dwarf_Addr`, plus the expected callback/function signatures
and 24-byte relocation record layout.

## Cross-target fixtures and Ghidra

```bash
make -C src/test/fixtures all
src/test/integration/fixture-reproducibility.sh x86_64
src/test/integration/fixture-reproducibility.sh aarch64
src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
FIXTURE_SUFFIX=exec.no-sections.stripped \
  src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
FIXTURE_SUFFIX=pie.stripped \
  src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
```

The reproducibility harness builds each selected target twice, requires
byte-identical outputs, records SHA-256 and `readelf -h -l -S -n` metadata,
and proves the partially stripped artifact retains symbols while containing no
compiler DWARF. Local x86-64 and AArch64 runs pass; hosted confirmation for all
five profiles passed in GitHub Actions run 33824105805.

Result: PASS for x86-64, AArch64, MIPS32 big-endian, and MIPS32 little-endian.
Ghidra selected the expected processor, byte order, address size, and pointer
size. This is import/preflight evidence, not export evidence.

## Matched sidecar container

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew sectionlessSidecarSmoke
```

Result: PASS for all five target profiles and three variants per profile:
ordinary ET_EXEC, PIE, and ET_EXEC with no input section-header table. The
writer preserved class, byte order, type, machine, flags, note/build-ID data,
and original input hashes. It created a new `SHT_STRTAB` `.shstrtab` and
section table where none existed.

Every generated container then passed without sidecar warnings:

```bash
readelf -h <sidecar>
readelf -S <sidecar>
readelf -n <sidecar>
readelf --debug-dump=info <sidecar>
readelf --debug-dump=abbrev <sidecar>
readelf --debug-dump=decodedline <sidecar>
```

The DWARF payload in this test comes from the fixture's compiler-DWARF
reference file. The test validates packaging, byte order, and loading—not the
future Forge semantic producer.

## GDB/QEMU behavior oracle

```bash
for role in exec exec.no-build-id exec.no-sections pie; do
  FIXTURE_ROLE="$role" DEBUG_ARTIFACT_SUFFIX=forge-container.dbg \
    src/test/integration/qemu-gdb-oracle.sh
done
```

Result: PASS on x86-64 natively and on AArch64/MIPS BE/MIPS LE through QEMU.
For all 12 cases GDB:

- loaded the stripped original and external matched sidecar;
- broke at `recovered_add` at the correct runtime address;
- reported arguments `left=19` and `right=23`;
- performed a source-level step;
- printed local `sum` as 42; and
- observed normal process exit.

QEMU AArch64 exposes a system-supplied synthetic DSO that this host GDB warns
has a corrupt string-table index. The same warning occurs with the unmodified
compiler reference and is not emitted for the sidecar itself. Sidecar
`readelf` checks are warning-free.

## Real headless Forge function/source-line/type export

Using the installed extension and the same explicit pinned native pair:

```bash
for role in exec exec.no-sections pie; do
  FIXTURE_ROLE="$role" src/test/integration/headless-symbol-export.sh \
    /home/ziggy/ghidra_12.0.3_PUBLIC \
    <audit-build>/libdwarf.so.2.3.2 \
    <audit-build>/libdwarfp.so.2.3.2
  FIXTURE_ROLE="$role" src/test/integration/qemu-gdb-symbols.sh
done
```

Result: PASS for x86-64, AArch64, MIPS32 big-endian, and MIPS32
little-endian—16 real exports in this executable section. Headless Ghidra
emitted deterministic synthetic source, evidence-backed line rows, canonical
types/signatures, and recovered contiguous/discontiguous functions depending
on target/input. It
also emitted honest unavailable locals, stable register locals, SP-relative
stack location lists, and exact register composites. It preserved address gaps
with DWARF 5 range lists. For every sidecar:

- original input SHA-256 was unchanged;
- `readelf -h`, `-S`, `-n`, `--debug-dump=info`,
  `--debug-dump=abbrev`, `--debug-dump=aranges`, `--debug-dump=decodedline`,
  and `--debug-dump=loc` completed without sidecar warnings;
- LLVM 18.1.3 `llvm-dwarfdump --verify` and libdwarf 20210528
  `dwarfdump -ka -ks` passed;
- GDB listed the generated function, resolved both function and explicit
  file/line breakpoints, executed `next`, `step`, and `nexti` through useful
  mapped code, and hit the expected runtime addresses; and
- for ET_EXEC/PIE, GDB `ptype` validated the analyst-applied function
  prototype, recursive struct, aggregate/member layout, union, array, signed
  enum, typedef, function pointer, variadic signature, and no-return
  signature; and
- for ET_EXEC/PIE, GDB resolved the analyst-applied `int fixture_sink`, read
  zero before its assignment, stepped the recovered statement, and read 42;
  and
- for ET_EXEC/PIE, GDB displayed the analyst-applied locationless local as
  `analyst_local = <optimized out>` rather than reading invented storage; and
- for ET_EXEC/PIE, GDB read `analyst_register` as 31, reconstructed the
  two-register `analyst_composite` as `0x1122334455667788`, and read
  `analyst_stack` as 42 both before and during a controlled SP adjustment; and
- for ET_EXEC/PIE, GDB displays the real favorite Ghidra `packed_flags`
  structure with unsigned 3-bit and 5-bit fields; and
- for ET_EXEC/PIE, `readelf` reports `DW_AT_calling_convention: normal` on the
  explicitly curated `recovered_add` signature; and
- for ET_EXEC/PIE, a typed `external_counter` declaration has
  `DW_AT_declaration`/`DW_AT_external` but no invented location, while
  `scoped_counter` is a child of the preserved `analyst_scope` namespace and
  GDB reads its defined value as 7; and
- the inferior exited normally, natively on x86-64 and under QEMU for the
  other targets.

For ordinary ET_EXEC and PIE inputs, a test-only post-analysis script renamed
the known fixture function to `recovered_add` with `USER_DEFINED` provenance
before export. It also applies `USER_DEFINED int recovered_add(int left,
int right)`, three analyst local-storage cases, and favorite recursive fixture
types. `readelf` and GDB observe that curated state rather than only initial
loader symbols. Two fresh x86-64 headless analyses produced byte-identical
outputs after the loaded-memory global filter and P1.9
declaration/namespace milestone:

```text
3d346c6f6e02e6da80f145a05cf445e4c1b88015cc6d45b8e04b0163051512c1  semantic.exec.ghidra-forge.dbg
c743c8f3dba3b7884b4d40c76e93e1c0208302c37384ce2351d498fc98423a2d  semantic.exec.ghidra-forge.dbg.c
```

These are validation-fixture hashes, not release artifact checksums; update
them after an intentional producer-string or semantic change.

## Explicitly rebased Ghidra project

```bash
src/test/integration/rebased-program-export.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS. The harness compared fresh analyses at the ELF loader base and
at a Ghidra image base shifted by `0x2000000`. The rebased export retained
original ELF link-time PCs, ranges, global addresses, and location-list ranges;
GNU readelf, LLVM, independent libdwarf, and the complete native x86-64 GDB
source/type/variable oracle passed. The original ELF hash was unchanged.

The `.dbg` and `.dbg.c` hashes differ between the two Ghidra databases because
Ghidra rewrites address-derived `FUN_...`/`DAT_...` names and decompiler text
when its database is rebased. Those strings are preserved as current Ghidra
knowledge; executable DWARF addresses are normalized. The regression also
found and fixed an unrelated loader-artifact leak: labels in non-loaded memory
blocks such as `ElfComment` are no longer exported as runtime globals.

## Output path and stale-input recovery

```bash
src/test/integration/output-path-policy.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS. The test changes the imported program's stored executable path
to a nonexistent file, supplies the original through explicit `--input`, and
omits `--output`. The exporter verifies the supplied file against Ghidra's
imported SHA-256 and publishes the required defaults
`semantic.exec.stripped.dbg` and `semantic.exec.stripped.dbg.c` beside the
input. The real artifact passes the normal readelf/LLVM/libdwarf checks, the
input hash is unchanged, no pair-specific staging file remains, and final
input/output/source SHA-256 values are reported.

`outputPathPolicySmoke` independently covers deterministic default/explicit
naming, missing input, original-file alias rejection, nonexistent output
directories, and an injected unwritable-directory result. GUI directory
selection is implemented for a valid input whose default destination fails,
and the automated Linux Swing chooser/cancellation test passes in a genuine
non-headless Ghidra process (see the post-alpha GUI record above). Manual
Script Manager navigation and Windows GUI behavior remain **PRESENT, UNVERIFIED**.

## Automatic build-ID and debuglink association

```bash
src/test/integration/build-id-discovery.sh x86_64 aarch64 mips32be mips32le
```

**CONFIRMED locally (2026-10-23):** all four targets pass strict ET_EXEC/PIE
automatic association with real Forge sidecars. Every target CI lane now runs
the same harness; ARM32 and hosted verification of the fix remain pending.
Evidence: `build/test-results/build-id-discovery/run.UxH079CS/` in the
`automatic-debug-association` worktree. The existing four-target/six-role real
export and native/QEMU runtime matrix also passes with this writer.

The old discovery test accepted successful lookup despite section-matching
warnings. The writer now retains allocated relocation names and extents as
inert `SHT_NOBITS`, with only `SHF_ALLOC` and no relocation linkage. GNU/LLVM/
libdwarf validation and isolated ELF32/64 × both-byte-order writer tests pass.
The unnamed-section regression retains physical indexes/names/payload checks
while distinguishing allocated extents from nonallocated retirement.
No-name/extended-program tests on x86-64 and MIPS32 big-endian pass at
`build/test-results/elf-layout-export/run.aZ5Bd0vd/`.

For positive automatic cases, GDB loads only a private copy of the stripped
executable. Build-ID files use a private `.build-id/xx/rest.debug` tree;
debuglink cases use target `objcopy` to attach a link to a private executable
copy and an empty global debug directory. Tests require an actual full DWARF
function symbol from the exact expected sidecar, the exact synthetic source
file, compiler-oracle function address, correct prototype/type/source lookup
and a resolved named breakpoint. A minimal linker symbol cannot satisfy these
assertions. The x86-64 automatic runtime cases also hit `recovered_add`, read
arguments 19/23 and exit normally.

Negative controls place the opposite executable kind's sidecar under the
requested build-ID path and deliberately corrupt a debuglink sidecar's CRC.
The CRC case uses a `--build-id=none` executable and sidecar, eliminating
build-ID fallback. Restoring the same copied sidecar must restore automatic
lookup. Only each control's exact expected rejection diagnostic is accepted;
positive cases reject every unexpected diagnostic. Existing no-build-ID
explicit lookup remains covered. All original executables, sidecars and
sources retain their hashes, and each run retains copies/transcripts.

These are sidecar compatibility tests. The extension still does not implement
a product `.gnu_debuglink` attachment option, and default export remains
non-mutating.

## Shared-object export and runtime loading

```bash
FIXTURE_ROLE=shared src/test/integration/headless-symbol-export.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
src/test/integration/shared-object-gdb.sh
```

Result: PASS for native x86-64 and QEMU-backed AArch64, MIPS32 big-endian,
and MIPS32 little-endian. Each stripped `ET_DYN` input passes `readelf`, LLVM,
and independent libdwarf validation. GDB can inspect types and link-time
source rows before the library is mapped. Once the loader maps the library,
the tested manual loading sequence is:

```gdb
set auto-solib-add off
file <stripped-driver>
# Run or continue until the shared library appears in `info sharedlibrary`.
# BIAS = relocated .text start - link-time .text address.
add-symbol-file <library>.ghidra-forge.dbg -o BIAS
break recovered_add
continue
```

The automated harness derives `BIAS` from `info sharedlibrary`, verifies it is
nonzero, and checks that the relocated function and global addresses are
outside every main-executable `PT_LOAD` range. The breakpoint receives 19 and
23 on the targets whose stable parameter registers are exportable; AArch64
reports its intentionally omitted overwritten registers as optimized out. In
every lane, GDB recognizes the typed locationless external declaration and the
namespace child, reads `scoped_counter` as 7, reads `fixture_sink` as zero
before the recovered assignment and 42 after stepping it, then observes normal
process exit.

`artifactPairPublisherSmoke` also injects a failure after the staged sidecar is
installed. It verifies that an existing sidecar/source pair is restored and
that a fresh failed publication leaves neither final path behind. Production
uses the same stage-and-publish helper and supplies Ghidra cancellation as its
pre-publication callback. The smoke test injects cancellation after both
staging writers finish and verifies that the prior final pair remains intact
and no staging file survives.

## Controlled decompiler failure

```bash
src/test/integration/controlled-decompiler-failure.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS on Linux x86-64. The headless test forces `recovered_add` through
the production per-function exception path, requires exactly one failed
decompilation and a later successful one, and verifies the diagnostic source
comment. The failed function remains an addressed, symbol-only subprogram DIE
without source/type/variable assertions. `readelf`, `llvm-dwarfdump --verify`,
`dwarfdump`, and GDB accept the result; GDB resolves the failed function but
has no line for it, while a later function retains its source line.

The exporter deliberately omits Ghidra functions marked external/import or
thunk and emits a diagnostic for each. Treating those stubs as ordinary
addressed definitions produced misleading decompiler output; external-function
declarations, linkage names, thunks, and aliases remain future work. Typed
external-data declarations are covered by the real-export matrix above. Every
integration lane asserts that the function-omission policy was exercised.

The x86-64 fixture's recovered `FUN_00401090` has real intervals
`[0x401090,0x4010ae)` and `[0x4010b0,0x4010b1)`. `readelf` reports two
`DW_RLE_start_end` entries under one subprogram `DW_AT_ranges`; GDB resolves
both addresses to `FUN_00401090` and reports no line information at the gap
address `0x4010ae`. The CU has its own merged, non-gap-covering `DW_AT_ranges`.
`.debug_aranges` is intentionally absent because it is an optional accelerator,
not required for the validated GDB lookup path. Every real-export role now
asserts that it remains absent; the x86-64 discontiguous-range oracle verifies
the authoritative CU/subprogram `DW_AT_ranges` intervals and gap behavior.

Global extraction is deliberately narrower than “every address with a name”:
the symbol must be a primary, non-default, non-external Ghidra label with
defined listing data at the same memory address. Its type joins the canonical
graph and its definition receives a `DW_OP_addr` location. The curated
`fixture_sink` test passes on x86-64, AArch64, MIPS32 BE, and MIPS32 LE for
ET_EXEC and PIE; PIE values remain correct after runtime load-bias relocation.
The no-section-table roles continue to export only information Ghidra actually
recovers and do not require the preparation label.

PIE inputs were loaded by Ghidra at a nonzero analysis base. The exporter
normalized those addresses back to ELF link-time VAs. GDB then applied ASLR
correctly: the x86-64 breakpoint, for example, was described by DWARF at
`0x1149` and hit at a randomized `0x5555...5151` runtime address.

The no-section-table runs are the real regression for ghidra2dwarf issue 29:
headless export did not crash, the writer created the output section table,
and source generation, line tables, structural validation, and runtime source
stepping passed for all four targets. The type/signature path is also active on
these inputs (using only information Ghidra actually recovers); future variable
paths must retain the same regression.

libdwarf 2.3.2 does not generate producer `.debug_line` for DWARF 5. The Forge
path therefore writes its deterministic DWARF 5 line program in Java and uses
the audited producer for CU/subprogram DIEs. The file table includes an
explicit directory (historically `.`, now the absolute artifact directory):
GNU `readelf` and LLVM accept an empty directory table,
but Ubuntu's older libdwarf consumer crashes while resolving source paths when
it is empty.

The producer's public `dwarf_add_AT_dataref_a` writes eight-byte section-offset
payloads in an otherwise DWARF32 ELF64 CU. Forge parses the
producer `.debug_abbrev`/`.debug_info`, removes the surplus bytes, adjusts all
CU-relative `DW_FORM_ref4` targets, and fails on unknown forms/layouts. A
native-free smoke test covers the repair; all emitted type references pass LLVM
verification.

## Independent DWARF validators

After installing Ubuntu's `llvm` and `dwarfdump` packages, every real Forge
function/source/type sidecar in the four-target by three-input-role matrix passed:

```bash
llvm-dwarfdump --verify <sidecar>
dwarfdump -ka -ks <sidecar>
```

Full transcripts are retained under
`build/test-results/headless-symbol-export/`, and the headless integration
harness runs both validators for every artifact.

`dwarfdump -ka` reports two harmless `.eh_frame` length-alignment diagnostics
for the x86-64 fixture. The matched sidecar retains those original target
sections byte-for-byte, and the same diagnostics occur on the original input;
they are not emitted from Forge DWARF sections. **HISTORICAL CLAIM WITHDRAWN:**
the previous statement that line-table, range and other error counts were zero
was based on an insufficient harness. The retained-log audit above finds
nonzero summaries and requires explicit explanation and enforcement.

## Generated source freshness at pair publication (2026-10-23)

Main commit `1f2a46b`'s [run 40053041949](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40053041949)
failed in AArch64 `elf-layout-export`, `exec/extended-programs/rebased`, at the
static GDB stage. Its retained `static-gdb.txt` reports only
`warning: Source file is more recent than executable.`; function/type/source
addresses remain correct. The failing source path is the generated
`build/fixtures/aarch64/semantic.exec.ghidra-forge.dbg.c`.

This is a publication defect, not an architecture, PIE, or fixture warning to
suppress. [GDB 15.1 source-cache.c](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-15.1-release/gdb/source-cache.c)
uses the source compilation unit's objfile mtime when available, falling back
to the executable only otherwise. In this workflow `symbol-file` selects the
Forge sidecar. GDB Python confirms `gdb.find_pc_line(0x400728).symtab.objfile.filename`
is the loaded `.dbg`, while `info files` separately names the original ELF as
the local executable. A source newer than the `.dbg` warns even when the original
ELF is newer than both; making only the `.dbg` newer removes that warning.
GDB compares whole seconds, explaining the intermittent boundary condition.

The publisher used to complete the sidecar writer before the source writer.
It now preserves that cancellation-compatible order but makes the staged
sidecar mtime at least its completed source's mtime before backing up or
replacing either final file. Full `FileTime` comparison preserves subsecond
ordering, does not lower an already newer sidecar timestamp, and does not
backdate the source or modify the original ELF. An adjustment failure uses the
existing cleanup/rollback path. No GDB diagnostic policy was weakened.

Reproduction and checks:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew \
    artifactPairPublisherSmoke elfCopyCancellationSmoke buildExtension
src/test/integration/artifact-pair-timestamps.sh
```

- **PASS:** the new publisher test fails deterministically against the old
  implementation, then passes after the fix. Callback timestamps cover older,
  equal, and newer sidecars within the same second. Existing rollback now also
  checks preservation of previous final timestamps; copy cancellation still
  stops before the source callback and preserves the prior pair.
- **PASS:** `build/test-results/artifact-pair-timestamps/run.DYGYC2J6/` builds a
  small compiler-DWARF ELF symbol-file fixture and deliberately supplies
  source/artifact timestamps on opposite sides of a second boundary. Before
  publication GDB reports exactly the known warning. After the real publisher,
  GNU/LLVM/libdwarf validation and GDB lookup, breakpoint, `next`, `step`, value
  and normal-exit checks pass with empty diagnostic streams. Appending a real
  source comment and advancing its timestamp produces the exact warning again.
  Original ELF hash and mtime remain unchanged; no staging files remain.
- **PASS:** the actual failed AArch64 Forge pair was downloaded and republished
  on private copies through the fixed production publisher. Its bytes stay
  unchanged, GNU/LLVM/libdwarf checks pass, and GDB function/type/line lookup
  produces no diagnostics. A subsequent source edit warns again. Logs are
  `build/timestamp-probe/forge-fixed.txt`, `forge-fixed.stderr`,
  `forge-edited.stderr`, and `forge-{readelf,llvm,dwarfdump}.txt` in the isolated
  timestamp worktree. The original extended-program ELF's hash and mtime remain
  unchanged. This is a retained-artifact reproduction, not a new Ghidra import.

The hosted archive contains copies made by the diagnostic collector, and
artifact download does not preserve the original publication timestamps.
Consequently the exact hosted nanosecond gap is unavailable. The retained
warning/source identity, pinned GDB comparison, and deterministic same-pair
reproduction establish the cause without claiming those lost timestamps.

The x86 CI lane now runs the deterministic GDB regression; the existing
publisher smoke also runs on native Windows. Local build and focused checks
pass. The next exact versioned candidate still requires full hosted validation.

## Native patch checkout and provenance consistency (2026-10-23)

Prepublication audit of candidate `ddad598` in run `40055176326` verified the
GitHub artifact digest, all release/native/source/runtime manifests, embedded
source and Java 21 bytecode, and twenty packaged Linux producer lifetimes using
the downloaded production JAR. It also found a provenance mismatch: Windows
build metadata recorded `733405d03e2fd34f7bba971e6bbfe534d72ee9b3c1856879a7652f4eff17bc2a`,
while the bundled patch and release pin were
`b98561b3e63b76546bd2f18d81d53e188b56deb637b5e145205b3b6eedadf696`.

The former is exactly the latter patch converted from LF to CRLF. Applying
each with GNU patch to independently extracted copies of the pinned libdwarf
archive produced byte-identical source trees; the CRLF application explicitly
reported stripping trailing CRs. This establishes equivalent patched content
locally, not that the previous raw provenance records agreed. Evidence is under
`corrective-alpha2/build/exact-release-verification/patch-equivalence/` in the
isolated worktree collection. No patch content, native API or version changed.

The correction forces LF patch checkouts and checks the pin before all four
Linux/Windows primary/comparison applications. Release assembly requires both
platform metadata records to match the canonical bundled patch. It rejects
missing, malformed, duplicate or mismatched records and a nonpinned bundled
patch before replacing any previous output ZIP. GNU checksum escaping in
Windows paths and CRLF metadata lines remain supported.

The assembler requires an unbundled Gradle base ZIP and native inputs with
their own nonempty regular metadata files. Native-inclusive or already-bundled
compliance bases are rejected before copying; base contents cannot supply a
missing native file or cause new compliance files to nest below stale ones.

```bash
git check-attr text eol -- native/libdwarf/patches/*.patch
src/test/integration/release-package.sh
```

**PASS locally:** a temporary Git checkout with `core.autocrlf=true` reproduces
the CRLF hash without attributes and the pinned LF hash with them. The exact
pre-application checksum check rejects the former and accepts the latter.
The updated package regression fails against the previous assembler, which
accepted the inconsistent Windows hash; the fixed suite passes all rejection
cases, previous-output preservation, escaped Windows metadata, every manifest,
wrapper permissions and two byte-identical assemblies. Logs are in
`native-patch-provenance/build/provenance-review/`. Native Windows and the full
exact-candidate matrix remain pending; this audit does not authorize publishing
the earlier mismatched package.

## Semantic and strict-validator merge (2026-10-23)

The normal merge of strict branch `bf7f2b1` into semantic branch `0b754078`
preserves both histories, the semantic gates and the strict validator's
independent source/provenance contract. The five semantic-only shell suites
(function entry, static scopes, register prefix, scalar FP and saved-program
determinism) and the isolated entry/ARM-slice producer checks now pass their
exact original ELF to `check-dwarfdump.py`. No runtime oracle or diagnostic
exception was relaxed.

**PASS locally:** all 23 semantic CI Java smoke tasks and `buildExtension`,
`actionlint`, the architecture-neutrality guard, changed-shell syntax checks,
the release-package regression and the strict checker's rejecting controls.
The build used Ghidra 12.0.3 and local JDK 25, producing Java 21 bytecode.
Logs are retained in `build/strict-semantic-merge/`; parser controls are in
`build/test-results/check-dwarfdump/run.kfb96j1p/`.

The merged strict helper also passes five retained artifact/original pairs:
function entry (2 inherited frame diagnostics), scalar FP (6), static scopes
(2), register prefix (4), and saved-program determinism (3). Each diagnostic
is exactly corroborated against its paired original, with zero uncorroborated
errors and empty stderr. Both input hashes remain unchanged. Exact paths,
commands, hashes and reports are in `build/strict-semantic-merge/replays/`.
These are validator replays of prior outputs, not fresh Ghidra/GDB executions
on the merged source. The full merged target/host matrix remains pending.
