# Validation record

> **Corrective release gate closed (2026-10-24):** alpha.2 was published from
> exact main `2f88c4a` after all twelve push-CI jobs, the final package audit and
> downloaded-asset verification passed. See [the final publication record](#corrective-alpha2-official-publication-2026-10-24).
> The earlier missed libdwarf summaries remain invalid clean-validation evidence;
> the incident and failed runs below are retained. Pending statements in the
> dated investigation checkpoints describe their state at that time, not the
> later publication result.

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
The core artifacts and logs were copied to
`build/strict-matrix-core-before-layout/` before the later ELF-layout harness
reused its ordinary exec/PIE output paths.
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

### First corrected hosted run and extended program-header reader

Run `40061424810` for PR #22 head `bf7f2b1` passed workflow lint, both native
builds, extension compilation, release assembly and the full ARM32/MIPS32 BE/LE
lanes. x86-64 and AArch64 failed during the extended-program-table fixture;
Windows-hosted validation was skipped and the aggregate gate failed.
The target artifacts were checked against their GitHub digests before analysis.

The original x86 ELF has `e_phnum=0xffff` and section-zero `sh_info=65549`;
AArch64 uses 65545. Both complete program tables end exactly at EOF. Standalone
libdwarf 2.3.2 rejects these with `DW_DLE_IMPROPER_SECTION_ZERO(497)` before it
can examine the original frame bytes. Its ELF32 and ELF64 reader paths reject
nonzero `sh_info` unconditionally. The [Linux ELF definition](https://man7.org/linux/man-pages/man5/elf.5.html)
assigns that field the actual program-header count when `e_phnum=PN_XNUM`.
The sidecar LLVM checks pass and libdwarf reports only the three/five expected
inherited frame messages; the strict runner correctly refuses to corroborate
them from an original that the tool did not read successfully.

Evidence is retained under `build/hosted-pr22-investigation/` in the strict
worktree. The separate validation-only static-consumer patch now passes 16
positives and 60 malformed-header controls across ELF32/64 and both byte orders,
including genuine 65535/65536-entry tables, a compiler-built fixture and exact
corroboration of both hosted original/sidecar pairs. Negative controls require
normal checker termination with the expected diagnostic and empty stderr;
crashing is not an accepted rejection. The final source-consistent tool bundle
is `build/validation-tool-pn-xnum-reviewed/`, with binary SHA-256
`cb552b4aba27c1ec88268da9fdee1eb240293d127b04df22a88cd79ee187e284`.
All bundled source, patch, helper, README and license manifests verify. The
production native pair and frame diagnostic policy remain unchanged.

The final tool's complete reader regression passes in
`build/test-results/dwarfdump-extended-programs/run.zz6h3yib/`; its existing
line-sequence/malformed-range regression passes in `run.jf01eivu/` under the
corresponding `dwarfdump-line-sequences` results directory. Five sectionless
location corruption controls also require normal checker termination and pass.
Fresh full x86-64 and AArch64 ELF-layout export suites pass in
`build/test-results/elf-layout-export/run.B3PvreYC/` and `run.L6iuQTIY/`,
covering unnamed sections, extended program tables, repeats, explicit rebase,
PIE, strict validators, GDB and original preservation. Extended-input runtime
checks retain the documented equivalent ordinary-load-image rule; actual
native/QEMU execution of `PN_XNUM` inputs is not newly claimed. Independent
review found no remaining issue. The previously failed hosted run stays failed;
the complete corrected hosted matrix is still required.

An independent exact-package precheck passed for this candidate, with release
ZIP SHA-256 `9b52381bc6dd3795bb69d09293d08bcc473e305d3b4603cff52132cf4a3b3589`.
It checked five manifests, 29 exact source files, 131 Java 21 classes, both
platform native provenance records, class origins and 20 deterministic
producer lifetimes under a Java 21 runtime. Logs are in the corrective-alpha2
worktree at `build/exact-release-verification/run-40061424810.LWVjQSe7/`.
This precheck does not override the failed hosted gate.

The subsequent report-parser regression removes zero-count category rows:
the old parser accepted a missing `locations` row because arithmetic still
matched. Every table now requires all 22 pinned categories (21 for the legacy
format). Fifteen missing/unknown-category controls and 52 retained artifact
and original reports pass; evidence is in
`build/validator-probes/missing-zero-category.77mdlsjb/` and
`build/strict-matrix/checker-complete-categories*.log`.


Local validation date: 2026-09-03
Ghidra: 12.0.3
Host: Linux x86-64
Host JVM used by Ghidra/Gradle: OpenJDK 25.0.4
Extension bytecode target: Java 21

This record distinguishes container/oracle validation from real Forge DWARF
export. Export remains explicit: installed wrappers request checksum-verified
packaged natives by default, while source-tree audit runs may supply explicit
library paths.

## Measured line-table address index (2026-10-23)

**CONFIRMED locally:** `Dwarf5LineTable.plan` builds one earliest-line address
index and queries each half-open function range. The focused smoke preserves
starts, excludes ends/gaps, keeps overlapping bodies independent and retains
the earliest line for repeated addresses. Width/byte-order and deterministic
ordering checks continue to pass.

**HISTORICAL:** five alternating `ddad598` baseline/indexed exports of the same
saved 10,000-function project produced byte-identical `.dbg` and `.dbg.c` files
in all ten runs, with whole-process medians of 10.86 and 9.18 seconds. GNU,
LLVM and full GDB symbol/source/type/address/runtime checks passed. The old
libdwarf log reports 11,833 errors despite exit zero; its clean-validator claim
is withdrawn. Exact timings, hashes and workload limits remain in
`docs/PERFORMANCE.md` and `build/line-profile/paired.8k_6dt_w/`.

The historical indexed build passed nineteen native-independent smokes and
x86-64, AArch64, MIPS32 BE/LE ET_EXEC/PIE/shared-object GDB cases. Those runs
predate strict summary enforcement; their old libdwarf pass labels are not
current validation evidence. Logs remain under `build/line-profile/verification/`.
The prior benchmark/research branch was merged normally at `5bc72f1`.

**CONFIRMED locally after merging strict `99845c7`:** the planner source is
unchanged, and the line-table/source/range smokes and extension build pass.
Fresh ARM32 ARMv7 hard-float ET_EXEC, PIE and shared-object exports pass GNU,
LLVM, strict libdwarf (zero errors) and QEMU/GDB runtime assertions. A repeated
fresh ET_EXEC import/export is byte-identical; originals remain unchanged.
A fresh ten-function, two-export benchmark rehearsal also passes strict
validation, byte equality and GDB. These are functional checks, not new timing
comparisons. Evidence: `build/line-profile/merged-verification/` and
`build/test-results/export-benchmark/run.3h1im338`.

A retained 10,000-function artifact initially failed strict validation because
the standalone consumer printed only 49 of 10,002 reported inherited frame
messages. A separately pinned validation-only capacity patch now retains up to
65,536 messages with checked allocation and explicit overflow/failure exits.
The full GNU/LLVM/strict/GDB replay passes: all 10,002 errors are exactly
corroborated against the unchanged original's identity/frame bytes and
same-version diagnostics; every other category is zero. Recorded artifact
hashes and the complete saved-project manifest remain unchanged. No timed
10,000-function export was rerun. Boundary, missing/duplicated diagnostic and
allocation-failure controls are documented in `support/validation/README.md`.

The only exporter runtime optimization is the line-table index. There is no
new native interface or timing threshold. Broader workloads and the combined
hosted matrix, including Windows, remain **PLANNED**.

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
libdwarf ISA/flag mapping, including MIPS32 in both byte orders. It fails closed
for MIPS64 and unsupported big-endian x86-64, AArch64, or ARM inputs. It does
not classify every ARM/MIPS ABI or validate every accepted storage convention;
see [the exact tested profiles and remaining gaps](TARGET-PROFILES.md). The companion
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
non-headless Ghidra process (see the post-alpha GUI record above). Actual Linux
Script Manager discovery/run/reporting and native Windows chooser behavior
are additionally validated below; the current combined-head reproducibility
gate remains separate from those component results.

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

The shared-object QEMU harness uses a unique UNIX socket in a short private
`/tmp/ghidra-forge-qemu.*` directory (mode 0700). QEMU 8.2.2's
[`gdbstub/user.c`](https://github.com/qemu/qemu/blob/v8.2.2/gdbstub/user.c)
and [GDB's connection contract](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Connecting.html)
support this transport. The helper checks child liveness and Linux
`/proc/net/unix` listener state for 100 polls at 50 ms intervals without opening a
connection, which would consume QEMU's single debugger client. It retains
stdout/stderr/endpoint/exit evidence and removes/reaps its own socket/child on
success, startup failure, timeout and caller failure. GDB and validator
failures are not retried or filtered.

This addresses run `40055880742`, MIPS32LE job `120759663719`: QEMU reported
`bind: Address already in use` on the PID-derived TCP port `40514`, then GDB
timed out. Local `shared-object-port-collision.py mips32le` deliberately holds
the exact historical port for the launched harness PID while the actual
shared-object GDB type/value/source/load-bias/step/normal-exit checks pass over
the private socket. The startup suite also proves a real QEMU missing-input
failure is not retried, a child without a listener times out, and a ready
emulator is terminated on cleanup. No processes or socket directories survive
these cases. The pipeline runs the collision control in the MIPS32LE shared
lane and the startup/failure suite in the x86-64 lane.

```bash
src/test/integration/qemu-socket-startup.sh
src/test/integration/shared-object-port-collision.py mips32le
```

Local evidence: startup `run.DwftsTvR` and final collision `run.7c6sr2ei`; the latter
holds TCP port `31527` for harness PID `286525`. QEMU and GDB diagnostics are
empty, recovered parameters are 19/23, global values are 0/7/42 as expected,
and the inferior exits normally. This change is limited to shared-object
startup. Other QEMU harnesses still use TCP and are not claimed to be migrated;
the exact updated hosted matrix remains pending.

Attempt 2 of GUI run `40058560162` stopped at the x86-64 startup suite with
`/usr/bin/qemu-x86_64-static: No such file or directory` (child exit 127).
Only cross-target lanes installed `qemu-user-static`; the x86-64 dependency
list now includes it because the startup control runs real native QEMU.
This failure preceded GUI testing. The native Windows dependency mirror
retry succeeded, but its GUI job was skipped by the failed prerequisite.
It is not a GUI product failure or a new Windows GUI pass. `actionlint`, shell
syntax checks and the local real-QEMU startup/failure/cleanup regression
`run.1XeKubtJ` pass for this dependency correction. The complete corrected
hosted gate remains pending.

An additional MIPS32BE shared-object run passes with empty QEMU diagnostics.
AArch64 reaches normal exit using the same socket transport but retains the
existing synthetic-vDSO `corrupt string table index` warning in its GDB log;
that run is not counted as clean diagnostic evidence. No new warning filter
or acceptance exception was introduced.

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
**HISTORICAL:** `.debug_aranges` was absent and every real-export role required
that absence for the lookup path tested at this checkpoint. A later direct
global-address formatting regression exposed another GDB path; the exact code
index described in `ADDRESS-INDEX.md` replaces the absence assertion. The
x86-64 discontiguous-range oracle continues to verify authoritative
CU/subprogram `DW_AT_ranges` intervals and gap behavior.

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

## Installed Script Manager export journey (2026-10-23)

The explicit `ExportGhidraDwarfForge.java` launcher is needed because Ghidra
12.0.3's `GhidraScriptComponentProvider.runScript(ResourceFile)` constructs a
`RunScriptTask` without setting script arguments. The original
`GhidraDwarfForge.java` intentionally remains native-free with no arguments.
The Export launcher delegates to it using the verified packaged native pair.

```bash
export GHIDRA_INSTALL_DIR=/path/to/isolated/ghidra_12.0.3_PUBLIC
./gradlew buildExtension
support/assemble-release.sh dist/*.zip /path/to/verified-linux-natives \
    /path/to/verified-windows-natives /path/to/gui-candidate.zip
# Extract into an isolated Ghidra installation, then:
module="$GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraDwarfForge"
src/test/integration/gui-script-manager.sh "$GHIDRA_INSTALL_DIR" "$module" \
    "$PWD/build/fixtures/x86_64/semantic.exec.stripped" \
    "$PWD/build/fixtures/x86_64/semantic.exec.reference"
```

**PASS locally:** `build/test-results/gui-script-manager/run.5CZSfnND/` in
`work/gui-script-manager`, using Ghidra 12.0.3, GUI OpenJDK 21, Xvfb, and the
existing verified Linux native package. The private installation links the
unmodified Ghidra platform and contains its own assembled extension; no user's
installed extension or original fixture is changed. The wrapper supports
`JAVA_BIN` and `XVFB_BIN` for locally extracted tools.

The harness compiles only its own GUI driver/support classes. It creates a
real Ghidra front end and Script Manager plugin, discovers both installed
script source paths, and launches them by double-clicking their visible table
rows. It does not instantiate either production script. A known fixture
function is renamed in the current Program to `gui_recovered_add`; GDB then
resolves that analyst name from the output. Each selection/cancellation case:

- Proves the default directory denies an actual file creation, preserving its
  original permissions for cleanup.
- Runs native-free preflight through Script Manager and observes Console.
- Runs the Export launcher, verifies packaged-native selection, and drives the
  real Swing chooser with Robot clicks.
- Records screenshots and Console transcripts, checks the final JSON report,
  verifies the input hash, and requires exactly the selected artifact pair or
  no artifacts after cancellation, with no staging files left behind.

Selection emits a `PARTIAL` report because the fixture's uncurated thunk and
undefined-type information is diagnosed. Cancellation emits `CANCELLED` and
Script Manager's cancellation message. Ghidra's loader also logs its existing
GNU-hash markup limitation and missing external libraries during fixture
import; those are retained in `gui.log`, not hidden or counted as validator
success. The emitted sidecar passes GNU headers/sections/notes/DWARF dumps,
`llvm-dwarfdump --verify`, and `dwarfdump` with empty diagnostic streams. GDB
finds the synthetic source without a directory workaround, resolves the renamed
function/signature, breaks, lists, executes `next` and `step`, and exits normally.
Its diagnostic stream is empty. A displayed decompiler source comment saying
`WARNING` is retained as source text, not treated as a debugger warning.

Release-package tests require both script entries, reject a ZIP missing the
Export launcher, verify their unchanged bytes in the assembled archive, and
check deterministic archive/manifest output. Build, package regression,
PowerShell syntax, and Java 21 compilation pass locally. Hosted component
results and the later focus regression are recorded below.

**CONFIRMED on native Windows in run `40054563515` at `83b74a6`:**
`src/test/integration/windows-desktop-acl.ps1` compiles a standalone Java probe,
records host/user/session evidence, denies directory writes with a real ACL,
requires actual file creation to fail, restores the ACL, and requires a real
Robot click on a visible button. The Windows CI lane retains its screenshots,
ACLs and logs. Native execution is required; portable PowerShell syntax or
Linux execution cannot establish Windows GUI support.

The same Windows CI lane runs the full journey after feasibility and isolated
packaged-native checks:

```powershell
./src/test/integration/windows-gui-script-manager.ps1 `
    -GhidraDirectory $env:GHIDRA_INSTALL_DIR `
    -ModuleDirectory "$env:GHIDRA_INSTALL_DIR\Ghidra\Extensions\GhidraDwarfForge" `
    -Fixture C:\fixtures\semantic.exec.stripped `
    -Reference C:\fixtures\semantic.exec.reference
```

This harness verifies the installed release hashes, compiles only the shared
GUI driver, uses Java argument files to avoid Windows command-line limits, and
selects a directory whose path contains spaces. It runs both real Script Manager
entries and both chooser outcomes using packaged Windows natives. The Java
driver verifies actual ACL denial, current-Program analyst rename, Console
reports, input preservation, and artifact counts; it restores the saved ACL
and propagates restoration failures. Native GNU readelf
and LLVM validate the resulting artifact, including target header and build-ID
agreement. Independent `dwarfdump` is used if available and otherwise recorded
as unavailable. Linux ELF runtime GDB checks cannot run natively on Windows and
are explicitly recorded as not run there; the Linux GUI journey retains those
checks. All Windows logs and screenshots are retained under
`build/test-results/windows-host/gui-script-manager/`.

The initial local checks covered PowerShell syntax, workflow YAML, shared Java
21 compilation, Java argument-file quoting (spaces, backslashes, quotes, and
literal brackets), and the repeated Linux GUI/validator/GDB journey
`run.BVL5Ysph`. Subsequent run `40054563515` passed all twelve jobs. Linux
job `120756043691` passed the real Script Manager journey and GNU/LLVM/libdwarf
plus GDB checks. Native Windows job `120758328246` passed the desktop Robot/ACL
probe and full Script Manager journey. Downloaded artifact `12545630489` has
verified GitHub SHA-256
`98d50281bc7cf0a906c23739827a161b9de9b27220e27eb27bb8a59621a71f0b`.
Its selection report is `PARTIAL`, cancellation is `CANCELLED`, actual file
creation is denied by ACL, and recorded input/output hashes independently
match the retained files. Native GNU/LLVM diagnostic streams are empty.
`independent-dwarfdump=UNAVAILABLE_ON_WINDOWS_RUNNER` and
`gdb-linux-elf-runtime=NOT_RUN_ON_WINDOWS_HOST` are explicit limitations.
This proves that component at `83b74a6`; it does not establish reproducibility
of later combined heads.

### Hosted Script Manager focus regression

The first Linux hosted GUI run `40053779323` timed out before the preflight
script started. Its empty `script.log` and retained `preflight-manager.png`
showed other Ghidra windows covering the Script Manager component. Swing's
`isShowing()` alone did not establish that a coordinate click would reach the
table. A controlled Xvfb experiment reproduced a visible target's click being
received by the covering window; explicit foreground activation corrected it.

The initial correction raised the target ancestor, waited for native window
focus and then table focus, and clicked the actual visible Name cell using
fresh bounds. It retained the real double-click, timeouts, and failure
Console/desktop/window diagnostics.

The corrected full local journey `run.B4Zeob4d` passes both chooser outcomes,
GNU/LLVM/libdwarf checks and GDB source stepping/normal exit. Controlled focus
evidence is under `build/hosted-gui-review/focus-probe-final/`.

Attempt 2 of run `40055880742`, Windows job `120763476912`, exposed another
pre-click harness race. Selection/export completed, but the cancellation
case failed `Script Manager target row is not focused and fully visible`
before its preflight script ran. Artifact `12546375795` (verified SHA-256
`5a25475dd8a6f0ab463cfc12b90044fbe7c156e09591f0a1be7f81e199bbcea7`)
retains the foreground Script Manager with the intended selected, visible
row and caret in its filter. Ghidra 12.0.3's
`GhidraScriptComponentProvider.componentActivated()` explicitly requests focus
for that filter, so a transient table-focus assertion races ordinary activation.

The corrected harness requires the foreground window, selected visible Name
cell and matching filename, then observes exactly one real BUTTON1
double-click delivered to that cell. Script Manager still performs the
production launch; existing Console/chooser/report assertions remain.
`GuiTableClickSmoke` deliberately gives keyboard focus to the filter, proves
the former table-focus condition is false, and requires exactly one target
invocation through Robot. Both host harnesses run this control. Full Linux
run `run.syAI9N4O` passes the control, both chooser outcomes, original hashes,
GNU/LLVM/libdwarf validation and GDB source lookup/stepping/normal exit.
No timeout, debugger warning policy, script call path or production behavior
changed. A new full native Windows run and complete exact-head matrix remain
required before integrating the combined GUI change.

The merge of strict-validator commit `bf7f2b1` preserves both GUI host journeys,
the filter-focus control, private QEMU sockets and their x86 package dependency.
The Linux Script Manager validator now uses the strict helper with its actual
private input copy. Rechecking retained GUI result `run.V2OaAzmR` passes with
three inherited frame diagnostics exactly corroborated against that input and
zero uncorroborated errors. This is a validator replay, not a fresh GUI journey
on the merged source. Workflow/shell/Python checks and the release-package
regression, including both required launchers and provenance rejection cases,
pass; the full merged hosted gate remains pending.

### Modal Script Manager compilation dispatch (2026-10-24)

Run `40062946718` at `cec4b5b` failed the x86 Script Manager step; its Windows
job was skipped. Downloaded target artifact `12548841209` matches GitHub SHA-256
`8816a64fedbb1c60bb41916c35c9c7f389f89219043248aa7a09d4316de292d1`.
The retained screenshot shows the intended preflight row and Ghidra's real
"Compiling Script Directory" modal dialog. Nevertheless, the harness reported
`real double-click missed intended cell: delivered=0 actual=null`. Evidence is
under `build/hosted-gui-review/run-40062946718/` in the GUI worktree.

Pinned Ghidra 12.0.3's `GhidraScriptComponentProvider.doGetScriptInstance()`
starts `TaskBuilder.launchModal()` synchronously inside its mouse listener.
An observer appended after that listener cannot run until the modal action
returns. Meanwhile, Swing's nested event loop can process `Robot.waitForIdle()`.
This was an observation race, not evidence that the real click missed the row.
The failure's subsequent Swing timeout is also retained; no exporter or
native-producer failure is inferred from this run.

`GuiTableClickSmoke` now opens a real modal dialog inside its table listener.
With the old helper, the control fails with the exact hosted assertion
(`build/modal-click-review/baseline/control.log`). The correction uses a
Toolkit `AWTEventListener`, which observes the mouse event before component
dispatch, filtering its exact table, event kind, button, click count, row,
column and filename. It never consumes or substitutes the event. Cleanup
removes the observer, and the production listener still launches the script.
The control proves one real action while the late component observer remains
pending, then one late observation after the modal dialog closes. Both host
harnesses execute this control; no timeout, retry or production path changed.

**PASS locally:** `build/test-results/gui-script-manager/run.O3SsqvwH/` uses
OpenJDK 21.0.12.1, Xvfb and the exact hosted `cec4b5b` package, downloaded from
artifact `12548278023` with verified outer SHA-256
`014721f8bde1fa28943260d173e0f93b6eda83391bef469419f43c54ac5deea8`.
All release manifest entries pass, and both installed script sources match the
checkout. The private Ghidra platform uses actual directories with hardlinked
unmodified files; it contains no symlinked platform roots or user extensions.
The package JAR SHA-256 is
`89011edf2e6b47c8445a9b47d9662739a05d97e5188e0a77895c2d42ae13e9bc`.

```bash
export JAVA_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java
export XVFB_BIN=/path/to/Xvfb
export DWARFDUMP=/path/to/verified-validation-tool/bin/dwarfdump
export PATH="$(dirname "$DWARFDUMP"):$PATH"
src/test/integration/gui-script-manager.sh /path/to/private-ghidra \
    /path/to/private-ghidra/Ghidra/Extensions/GhidraDwarfForge \
    /path/to/semantic.exec.stripped /path/to/semantic.exec.reference
```

The fresh run passes both focus/modal controls, installed discovery and
native-free preflight, real chooser selection/cancellation, Console reports,
original hashes and exact artifact counts. GNU and LLVM validation pass.
Strict libdwarf checking retains three inherited frame diagnostics, each
exactly corroborated against the actual private input, with zero uncorroborated
errors. GDB resolves the renamed function and synthetic source, steps with
`next`/`step`, and exits normally with empty stderr. This is a fresh Linux
journey with the corrected harness; a new full hosted run, including native
Windows, is still required.

### Managed Linux display geometry (2026-10-24)

Run `40064976588` at `a977a93` passed the four cross-target lanes and the Linux
chooser-only check, but failed the real Script Manager step. Windows was
skipped. Artifact `12549133765` has verified GitHub SHA-256
`68e34a584d8588aa3333986ef2d8c69c9f74b7d6c8bc018347d025c1865e16e4`.
Its filter-focus and modal controls both pass. The screenshot instead shows
the Apple category selected after the attempted preflight table click. Java
window diagnostics report `(0,0)`, while the desktop places the same 684×519
Script Manager at `(298,253)`; the pre-click crop also uses the wrong origin.
This establishes a native/Java coordinate mismatch, not a script/native-export
failure. Evidence is retained in `build/hosted-gui-review/run-40064976588/`.

Pinned Ghidra's `DockingFrame` is a plain `JFrame`; `DetachedWindowNode` packs,
positions and then shows a new floating window. A standalone probe of that
creation order under bare Xvfb independently compares Java coordinates with
`xwininfo`. It reproduces the mismatch in 7/100 exploratory cases and 2/100
cases in the final comparison (`run.haXOAIX9`, `run.xF2sFukx` under
`build/native-geometry-review/`). The matching Openbox comparison
`run.UyGCVVwx` passes all 100 after accounting for normal WM decorations.
This is observed virtual-display behavior; no general JDK regression or
specific vendor defect is claimed.

The Linux Script Manager wrapper now requires `openbox` and `x11-utils` in
addition to Xvfb. It starts its own WM on its fresh display, supplies an owned
XML configuration and empty menu, checks the native WM readiness property,
and terminates the WM before Xvfb on every exit. It never manages the user's
desktop. Locally, packages were downloaded/extracted under ignored `build/`;
no system package or user installation changed. `OPENBOX_BIN`, alongside
`XVFB_BIN` and `JAVA_BIN`, allows that private executable setup.

`GuiWindowGeometrySmoke` checks 100 separate packed/centered/shown windows,
comparing native X11 client coordinates with Java bounds plus decorations.
Queries have bounded process cleanup, and failures retain native output and
screenshots. This Linux-only control precedes the unchanged actual Script
Manager click, Console, chooser and export checks. The shared Windows journey,
click observation, action count, existing timeouts and validator policy are
unchanged; no failed launch is retried.

**PASS locally:** final `build/test-results/gui-script-manager/run.KPdcV6p3/`,
using OpenJDK 21.0.12.1, Openbox 3.6.1 and the verified hosted production
package identified above. All 100 geometry cases and both filter/modal
controls pass. The full Ghidra journey passes installed discovery, native-free
preflight, real selection/cancellation, input preservation, exact output counts,
GNU/LLVM, strict libdwarf checking and GDB source lookup/stepping/normal exit.
Three inherited frame diagnostics are exactly corroborated against the private
input; zero remain unexplained. Openbox and validator/GDB stderr logs are
empty, and no WM/Xvfb/Java test process remains. Full hosted verification of
the updated branch, including native Windows, is still required.

### Script Manager pending-filter readiness (2026-10-24)

The first combined-product managed-display run, `run.yI7ooUik`, passed all 100
geometry cases and delivered the intended table double-click, but timed out
waiting for preflight Console output. The original failure is retained under
`build/native-geometry-review/combined-full-gui.log`. Five fresh diagnostic
runs passed; they did not resolve that failure. The subsequent buffered
selection-stack reproduction `run.3HcGrt32` failed the same Console assertion
and records the actual cause in
`build/native-geometry-review/event-probe/selection-stack-gui.log`:

- Ghidra's `GTableFilterPanel` timer calls `TableModelWrapper.setTableFilter`,
  which causes `JTable.tableChanged` to clear the selection after mouse press 2.
- The real second click is unconsumed, has previous/current left-button state,
  and reaches the correct Name cell, but `getSelectedScript()` is null.
  `lastRunScript` remains null. Selection is restored only afterward.
- Pinned Ghidra 12.0.3 queues this restoration through
  `RowObjectSelectionManager.repairSelection` using `invokeLater`.

The harness observes the known initial refresh/category/filter/sort work and
drains queued selection repair before selecting the final row. It reads the
pinned private update-manager fields because Ghidra exposes no public filter
or ScriptList busy query; missing fields fail the test. It never flushes,
disables or replaces those updates. A final idle check precedes the unchanged
single real double-click and all existing Console/chooser/export assertions.

The new control uses actual `GTable`, `GhidraTableFilterPanel`, and
`GMouseListenerAdapter`. A public filter-text change proves the old
selected-visible-row predicate accepts pending work. The test observes real
selection clearing/restoration, waits for completion, and requires exactly one
action with no selection change during its gesture. Development checks caught
and corrected immutable control-data cleanup and declaring-class reflection
errors; those failed runs are retained (`run.HSMGcl7Q`, `run.XSKtqHhL`).
No production exporter, script launch path, timeout or retry policy changed.
Fresh combined hosted acceptance, including native Windows, was required at
this local checkpoint; it subsequently passed in the final combined acceptance
record below. The failed attempts remain historical evidence.

**PASS locally:** `build/test-results/gui-script-manager/run.LFXUdxrq/` and
`build/native-geometry-review/combined-filter-readiness-reviewed.log`, using
OpenJDK 21.0.12.1 and the final managed-display wrapper. All three controls,
100 independent geometry cases, actual installed preflight/export, chooser
selection/cancellation, original hashes, GNU/LLVM and GDB pass. The configured
strict checker reports three exactly corroborated inherited frame diagnostics
and zero unexplained errors. GNU/GDB/checker stderr and the Openbox log are empty.

This run uses the combined production build supplied by the integration branch
with audited release-native bytes, installed only in a fresh private Ghidra
copy. Its entire release manifest verifies and all 33 packaged production
source/script files match that combined tree. Recorded SHA-256 values are:

- Combined ZIP: `1348d100f7dd0508929726039313444419d551d7bf794838cdd8bf29ce62d8dd`.
- Production JAR: `d6e94336652ddc2cc3a14f9bc2971f58d1ca7cb1dcbd980fb713bd058779470e`.
- Production source ZIP: `890f2d4a95a3ede4e4c42c44def06a48beda4bb427c914416f6b3a6a4d22ea4b`.

The retained local command uses extracted display dependencies, not installed
user-desktop packages (`$PWD` is the GUI worktree):

```bash
export XVFB_BIN=/home/ziggy/GhidraDwarfForge/build/gui-validation/dependencies/extracted/usr/bin/Xvfb
export OPENBOX_BIN="$PWD/build/native-geometry-review/openbox-local.sh"
export JAVA_BIN=/usr/lib/jvm/java-21-openjdk-amd64/bin/java
export DWARFDUMP=/home/ziggy/GhidraDwarfForge-worktrees/line-table-index/build/line-profile/validation-tool-config-final/bin/dwarfdump
export PATH="$(dirname "$DWARFDUMP"):$PATH"
src/test/integration/gui-script-manager.sh \
    "$PWD/build/native-geometry-review/combined-ghidra" \
    "$PWD/build/native-geometry-review/combined-ghidra/Ghidra/Extensions/GhidraDwarfForge" \
    /home/ziggy/GhidraDwarfForge/build/fixtures/x86_64/semantic.exec.stripped \
    /home/ziggy/GhidraDwarfForge/build/fixtures/x86_64/semantic.exec.reference
```

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

## Definite ELF/Ghidra target agreement (2026-10-24)

The isolated `target-language-agreement` worktree starts from strict baseline
`bf7f2b1`. A fresh build of that baseline reproduces two semantic preflight
gaps: x86-64 imported as `AARCH64:LE:64:v8A` and MIPS32 little-endian imported
as `ARM:LE:32:v8` both produce `PARTIAL` sidecars and pass LLVM verification.
Both imports use `-loader ElfLoader -processor <language> -cspec default
-noanalysis` on private copies of source-built reference ELFs, so imported
symbols suffice to reach the exporter. Original hashes remain unchanged.
Evidence is `build/target-agreement/baseline/{x86_64,mips32le}/`, the exact
baseline package is `build/target-agreement/baseline.zip`, and its installed
JAR SHA-256 is `4f1fede9f6a9b298902a289c81ee27d8be750930aef70d3955c635dd3e77c20a`.
This replaces the earlier research's older-JAR reproduction with a current
baseline observation.

The expected processor strings come from Ghidra 12.0.3's installed
`Processors/{x86,AARCH64,ARM,MIPS}/data/languages/*.opinion` and `*.ldefs` files.
The adapter reads `Language.getProcessor`, `Language.isBigEndian`,
`Program.getDefaultPointerSize`, `Language.getLanguageID`, and
`CompilerSpec.getCompilerSpecID`; pinned source is in
`Framework/SoftwareModeling/lib/SoftwareModeling-src.zip`. Source hashes are
recorded in `build/target-agreement/pinned-api-sources.sha256`. The check uses
the Program's data-pointer size, preserving the existing width policy; it
does not infer that instruction/register width equals pointer width. Compiler
and variant IDs are diagnostic only. Passing this guard does not establish
ABI, ISA-variant, calling-convention or ELF-flag support beyond the tested
profiles.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew \
    dwarfTargetSmoke ghidraTargetAgreementSmoke exportReportSmoke buildExtension
python3 src/test/integration/target-language-agreement.py "$private_ghidra" x86_64
python3 src/test/integration/target-language-agreement.py "$private_ghidra" mips32le
```

**PASS locally:** the metadata smoke covers five expected profiles, both
same-width processor families, pointer-width/endian contradictions, unsupported
ELF machines, and acceptance of nondefault variant/compiler metadata without
Program mutations. All twenty native-independent CI smoke tasks, extension
build, architecture guard, `actionlint`, Python syntax and release-package
regression pass. Build logs are `build/target-agreement/{fixed-build,final-build,
architecture,actionlint,package}.log`. Local JDK 25 produces Java 21 bytecode;
native Windows execution is pending.

The real mismatch harness passes all four absent/existing-pair controls in
`build/test-results/target-language-agreement/run.bsu5k34q/` and
`run.k9c5fhqg/`. It requires a structured `FATAL` report naming the expected
and actual processors, ELF machine/class/endian/flags, pointer width and full
language/compiler identity. Explicit native paths deliberately do not exist;
the mismatch must be reported before loading them. Input and prior-output
hashes/mtimes are unchanged and the output directory has no new files.
The analyzer itself must exit normally without a JVM crash; Ghidra 12.0.3
reports the expected post-script failure in its log rather than its exit code.

**PASS locally:** correct x86-64, AArch64, ARM32, MIPS32 BE and MIPS32 LE
ET_EXEC imports run through the installed production exporter and the existing
GNU/LLVM/strict-libdwarf plus GDB type/source/value/stepping/normal-exit oracles.
The strict checker reports three x86 and five AArch64 inherited frame-length
diagnostics, each exactly corroborated against the matching unchanged original;
the other three profiles have zero reported errors. Every profile has zero
uncorroborated errors. Commands follow `headless-symbol-export.sh` and
`qemu-gdb-symbols.sh` with `DWARFDUMP` set to the pinned patched consumer and
`FORGE_ARM32_SYSROOT` pointing to the previously extracted ARM sysroot.
Evidence is `build/target-agreement/positive-*-{export,gdb}.log`,
`positive-identities.json`, and `build/test-results/headless-symbol-export/`.
All installations and fixture copies are private; the user installation and
the supplied originals are unchanged. Existing CI retains every target/role
and host gate, and adds the rejection controls plus Windows metadata smoke.
The complete new hosted matrix remains pending.

## Performance-branch validator configuration incident (2026-10-24)

**CONFIRMED:** [run 40064815083](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40064815083)
at `d12be10bc93d9096042ca620f712fc0baf8063db` failed native Linux job
`120785718398` in the first diagnostic-capacity positive. The actual checker
returned zero but emitted `ERROR: dwarfdump found no dwarfdump.conf` and
suppressed frame access; strict validation rejected the result. Artifact
`12548957019` matches GitHub digest
`7ea4ad1d70bc7a1a512977a73293708e6c28b3f27ba5e0918fb8f284e1944ba7`.

The standalone bundle now includes its unchanged pinned upstream config and a
relocatable launcher selecting it explicitly. It has no dependency on an
installed distro, CWD or HOME configuration. Missing/altered config and option
aliases fail closed, and raw allocation-injection controls keep the same
explicit config. See `support/validation/README.md` for source hashes and
reproducible controls. The failure does not change historical timing results
or the indexed planner; no performance export was rerun. Corrected hosted
acceptance remains pending, and this feature branch stays outside alpha.2.

**PASS locally:** the final configured bundle is
`line-table-index/build/line-profile/validation-tool-config-final/`.
Its complete manifest and bundled-source comparisons pass. Launcher SHA-256:
`cb6c594b13fa18d0e30339390d3985ba594eb0fafa597ec1845c14dde940aaaa`;
ELF executable SHA-256:
`94435663cf53fafea90c40db053b90bd5bff77d3974de4471548df0cd88b37fd`.
Configuration controls pass in `build/test-results/dwarfdump-configuration/run.1n891ve7`;
full capacity/allocation/static-rollback controls pass in
`build/test-results/dwarfdump-diagnostic-capacity/run.yfxuwuz0`.
Strict parser, line/range and extended-program negatives also pass, and the
retained 10,000-function sidecar again matches all 10,002 original frame
messages with zero uncorroborated errors. Commands/results are retained under
`build/hosted-capacity-review/run-40064815083/`. The developer build's initial
override control caught the older grouped-option filter before correction;
that failing evidence is preserved. A reviewer independently verified source,
manifest and controls. Corrected hosted acceptance remains pending.

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

## Semantic hosted acceptance and main integration (2026-10-24)

**CONFIRMED:** PR #20 head
`b14e8109ca95358bacba6b0d11223a913d32db80` passed all twelve jobs in
[run 40063017269](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40063017269),
a `pull_request` run completed successfully at `2026-10-24T04:57:49Z`.
This is fresh hosted execution of the combined semantic and strict-validator
source, superseding the earlier pending-hosted statements for these bounded
features. It is not a release-publication result.

| Job | Result | Job ID |
|---|---|---|
| workflow-lint | PASS | `120780364456` |
| native-linux | PASS | `120780364420` |
| native-windows | PASS | `120780364441` |
| extension-build | PASS | `120780364272` |
| release-package | PASS | `120781766923` |
| target-preflight (x86_64) | PASS | `120781815421` |
| target-preflight (aarch64) | PASS | `120781815413` |
| target-preflight (arm32) | PASS | `120781815523` |
| target-preflight (mips32be) | PASS | `120781815437` |
| target-preflight (mips32le) | PASS | `120781815513` |
| windows-host | PASS | `120783767660` |
| required-validation | PASS | `120784450732` |

No job was skipped or failed. Target-specific conditional steps remain
intentional; a passing lane does not mean every feature ran on every target:

- Function-owned static scopes and scalar floating-register oracles ran on all
  five Linux-hosted target profiles. ARM32 reached and passed the corrected
  EHABI precondition, static values/returns, stable floats/doubles and the
  upper-`s1` register slice. These tests retain strict validation, unchanged
  originals, rebases and deterministic repeats.
- Incoming-register prefix lifetimes ran on x86-64 and AArch64. They establish
  the value only through the first overwrite in the bounded straight-line
  leaf proof. ARM's opaque `setISAMode` return remains rejected, and no MIPS
  prefix-runtime claim follows. Migration, call-crossing, later-starting and
  more general control-flow lifetimes remain unimplemented.
- Function-entry producer/structural checks ran on all five targets. The real
  below-entry/interior-entry GDB fixture and explicit rebases ran on x86-64.
  P1.8's documented acceptance is complete within that evidence boundary.
- Saved-program type identity across fresh headless processes ran on Linux
  x86-64; the native-independent identity smoke ran in the Linux extension
  build. Windows ran its five selected address/path/report/source/publication
  checks, not that identity smoke. Only the generic `DefaultDataType`
  transient-ID case is corrected; unrelated persisted type identities are unchanged.
- MIPS scalar floats have positive value checks, but paired doubles remain
  unavailable in Forge. The compiler pair oracle records `UNVERIFIED` when
  the tested QEMU/GDB register view returns zero, or accepts the exact expected
  value. Correct memory sinks are not promoted to parameter-location proof.
- Windows passed native-independent checks, native production, publication
  rollback, headless ELF export and clean packaged-native export. Its structural
  tools are GNU/LLVM; no native Windows libdwarf-checker or runtime-GDB result
  is claimed. The newer Script Manager journey belongs to a separate branch.

The strict helper remains mandatory in every semantic suite and isolated
producer check, with the exact original ELF supplied for inherited-frame
corroboration. No new diagnostic allowance, skipped assertion or target
support policy was introduced by this integration.

The subsequent normal merge of `main` commit
`2f88c4a1a7dd90dfedbd8d578b27242dfb8a73b7` adds no source, test, workflow or
packaging changes: its tree is identical to already-merged strict parent
`99845c71954430a5105891a0e3507075e48fa41a`. Only this documentation is updated.
The new current-base PR head still requires its own hosted checks; the passing
run above is attributed to its exact historical head. Corrective alpha.2
publication status is unchanged, and no GUI, target-language agreement or
performance branch was incorporated.

## Corrective alpha.2 official publication (2026-10-24)

**CONFIRMED:** [v0.1.0-alpha.2](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.2)
was published at `2026-10-24T05:15:20Z` from
`2f88c4a1a7dd90dfedbd8d578b27242dfb8a73b7`. Corrected PR #22 run
`40062747733` passed before normal merge. The exact-main
[push run 40064204515](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40064204515)
then passed its exact twelve-job set, with no failed or skipped job:

| Job | Result | Job ID |
|---|---|---|
| native-linux | PASS | `120783901405` |
| native-windows | PASS | `120783901516` |
| extension-build | PASS | `120783901546` |
| workflow-lint | PASS | `120783901553` |
| release-package | PASS | `120785341821` |
| target-preflight (x86_64) | PASS | `120785394884` |
| target-preflight (aarch64) | PASS | `120785394875` |
| target-preflight (arm32) | PASS | `120785394952` |
| target-preflight (mips32be) | PASS | `120785394861` |
| target-preflight (mips32le) | PASS | `120785394901` |
| windows-host | PASS | `120786949510` |
| required-validation | PASS | `120787583460` |

The aggregate completed at `2026-10-24T05:13:58Z`. Target-conditional steps
retain their documented scope: this is the corrective baseline's matrix, not
the later semantic-feature matrix. Linux lanes enforce the pinned standalone
checker and its narrow corrections, GNU/LLVM checks and native/QEMU GDB
oracles. The Windows lane proves headless export, native safety, publication
rollback and GNU/LLVM validation; it does not claim native Windows runtime GDB
or a Windows standalone libdwarf checker.

The independent final audit used `mode=final`, requiring the exact `push`
event, head and twelve successful jobs. It downloaded artifact `12549365222`
and verified its outer ZIP SHA-256
`37b88a94b9f0a5e8497ea4b4c5dc6db587b46482fb8af30e850d2dcb41f49309`.
All five manifests passed (53 release files, 5 Linux native files, 6 Windows
native files, 6 source records and 3 Windows-runtime records). The 29 embedded
production sources matched the exact commit; all 131 classfiles use Java 21
bytecode. Version/compatibility/scripts/docs, absence of private JNA, Linux
RUNPATH, Windows exports and canonical native-patch provenance on both hosts
passed. The later GUI launcher is absent, as required for this release scope.

Using the downloaded production JAR/native pair, class-origin checks and 20
isolated producer lifetimes passed on Java 21, including deterministic output.
Measured resident growth was 7,221,248 bytes against the smoke's 33,554,432-byte
limit; this is bounded smoke evidence, not a general memory guarantee. Audit
compilation used `javac --release 21` from JDK 25; execution used Java 21.
No shared or user installation was modified.

Final-audit evidence is retained at
`corrective-alpha2/build/exact-release-verification/run-40064204515.nbGbxUuA/`
in the worktree collection (`result.txt`, `package-verification.txt`,
`production-class-origin.txt`, `packaged-producer.txt`, `run.json` and digests).
The main checkout's `build/alpha2-publication/final-audit.json` links this exact
result; `exact-main-ci.json` retains the full final job/step record.

The published ZIP is `GhidraDwarfForge-0.1.0-alpha.2-ghidra-12.0.3.zip`, SHA-256
`0ae14cf8f4760703d4778d5b414fd14b9c8a68414edc89dcf8cb58a21669ade6`.
Release `422532694` is a published prerelease, with ZIP asset `671345358` and
`SHA256SUMS` asset `671345364`. Both draft and public downloads match the
audited ZIP and checksum text; the checksum asset SHA-256 is
`a0c935e1553f0b458d117dee55d29747690489a5415afafd2ca09e00e3e3a0f5`.
The public tag resolves directly to the tested commit. Each phase also checks
alpha.1's tag, release identity and asset digests against the retained baseline.
Both record `release-assets=PASS` and `alpha1-unchanged=PASS` in
`build/alpha2-publication/{draft-verification,published-verification}/`, with
the downloaded assets and API metadata retained alongside those results.

Alpha.1 remains unchanged and affected by its documented correctness findings.
The earlier failed runs and hidden-summary incident are not erased by this
release. Exact inherited frame diagnostics remain visible and strictly
corroborated; profile/ABI, PN_XNUM runtime, missing-location and synthetic-source
limits remain as documented. The semantic additions in this branch and the
separate GUI/target-agreement/performance work are excluded from alpha.2. The
tagged documents are the immutable prepublication snapshot; this subsequent
handoff record does not modify the release tag or assets.

## Reviewed TODO integration scope (2026-10-24)

This combined tree contains the semantic, Script Manager, target-agreement and
line-table changes plus the inline/debuglink research records. The preceding
component results remain scoped to their exact commits and tool bundles. No
combined-head acceptance is inferred from those independent passes; the full
current-base hosted result is recorded below. The published corrective alpha.2
artifact is unchanged and excludes these subsequent features.

The historical generic-undefined type-ordering observation in the debuglink
research is resolved here by semantic commit `3070e95`. The saved-program
regression above and hosted semantic run `40063017269` prove raw-model and
DWARF/source byte equality for that bounded singleton case. This does not
implement optional attachment/refresh/rollback or replace other type identities.


## Combined local checks and component hosted status (2026-10-24)

**CONFIRMED locally:** combined production source
`a328a15f625331d17c7c7e45d62d4645e9a1e4b0` compiles and passes all 24
native-independent Java smoke tasks plus `buildExtension`. The package and
headless-wrapper regressions, workflow lint and architecture-neutrality guard
also pass. Independent source review found no material production conflict;
the workflow composition review confirms all 61 distinct named component CI
steps are retained. These review results do not replace execution of the
combined pipeline.

Build, package, wrapper and assembly transcripts are retained in the
`reviewed-todo-integration` worktree's `build/integration-review/` as
`build.log`, `package.log`, `wrapper.log` and `combined-assembly.log`.
The locally assembled package SHA-256 is
`1348d100f7dd0508929726039313444419d551d7bf794838cdd8bf29ce62d8dd`.
It is a private integration artifact, not a new published release. Subsequent
merge `c1c7485a8518a048fc5f798ac0cc249a412baf28` changes only managed Linux GUI
harness/control sources, CI and documentation; its production source matches
the tested `a328a15` tree. The full combined runtime/host matrix was still
pending at this local checkpoint; the final result is recorded below.

Fresh GitHub queries confirm the following exact component `pull_request`
runs are completed successfully. Each has exactly twelve successful jobs, with
no failed or skipped job: lint, both native builds, extension, release package,
all five target lanes, Windows host and the aggregate gate.

| Component | Exact head | Hosted run | Aggregate completion (UTC) |
|---|---|---|---|
| Target-language agreement | `96e6972f64f6e47e8f37dc2c99f72990a8768bf7` | [40064731597](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40064731597) | `2026-10-24T05:22:37Z` |
| Semantic features | `2d47e122add294dcd50e4fb0820855be19cb6f39` | [40066078653](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40066078653) | `2026-10-24T05:43:27Z` |
| Line index and validation-tool packaging | `b0bcdb83e23bc09bc1efc79d9f2b02e3e6f3b1a7` | [40065823442](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40065823442) | `2026-10-24T05:41:26Z` |

Full API metadata, job IDs and conditional step results are retained as
`build/integration-review/component-run-<run-id>.json`. These supersede the
respective component's earlier pending-hosted statements. Target-conditional
coverage and existing limitations remain unchanged; the performance run does
not create a new timing measurement. None of these runs validates this combined
head or the newer managed-display GUI change.

**FAILED combined GUI attempt:** the actual combined-artifact run is
`gui-script-manager/build/test-results/gui-script-manager/run.yI7ooUik/`
in the worktree collection. Its 100 native-window geometry checks pass, but
selection stops at `GuiScriptManagerSmoke.awaitConsole` with:
`timed out waiting for console text: Symbol export was not requested.`
No preflight script start was observed. Correct geometry and observed click
delivery do not establish execution of the script action. Console/window/
desktop diagnostics and logs remain retained. No combined GUI/export/validator/
GDB pass is claimed from this failed run.

The earlier managed-display `run.KPdcV6p3` pass used the isolated GUI component
and its verified hosted production package. It remains useful component
evidence, but is not promoted to a combined pass. The later causal reproduction
`run.3HcGrt32` identifies the deferred-filter selection race recorded above.
The readiness fix, pending-filter control and fresh actual combined-product run
`run.LFXUdxrq` pass on Java 21 with the unchanged production JAR. That run proves
100 native geometry cases, all three controls, preflight/export, both chooser
outcomes, original preservation, GNU/LLVM/strict-libdwarf (three exactly matched
inherited diagnostics, zero unexplained errors), and GDB stepping/normal exit.
Diagnostic replays were not substituted for this post-fix run. The complete
exact-head hosted matrix, including Windows GUI, was still required before main
integration; it subsequently passed as recorded below. Published alpha.2 stays
immutable at `2f88c4a`; its verified
release artifacts exclude these subsequent features.

## Combined hosted acceptance and main integration (2026-10-24)

**CONFIRMED:** PR #25 exact head
`961265543762e96fa6e9a80a9b06210b5d9397e9` passed
[run 40068401197](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40068401197)
(`pull_request`, attempt 1). All twelve expected jobs succeeded; no job failed
or was skipped. The required aggregate completed at `2026-10-24T06:22:06Z`.

| Job | Result | Job ID |
|---|---|---|
| workflow-lint | PASS | `120796384505` |
| native-linux | PASS | `120796384526` |
| native-windows | PASS | `120796384363` |
| extension-build | PASS | `120796384531` |
| release-package | PASS | `120797864090` |
| target-preflight (x86_64) | PASS | `120797907707` |
| target-preflight (aarch64) | PASS | `120797907489` |
| target-preflight (arm32) | PASS | `120797907499` |
| target-preflight (mips32be) | PASS | `120797907712` |
| target-preflight (mips32le) | PASS | `120797907508` |
| windows-host | PASS | `120800293230` |
| required-validation | PASS | `120800933558` |

This is combined-source acceptance, independently of the component results
above. The 24 native-independent smokes run in the Linux extension job; the
Windows host runs its selected six smokes plus native producer, wrapper,
file-lock/publication, headless and actual Script Manager checks. Conditional
skipped steps retain their intended scope; this is not every test on every
host or target:

- All five Linux-hosted target lanes pass the ordinary executable, PIE,
  shared-object, rebase and special-layout exporter/validator/GDB checks,
  function-owned static lookup, scalar FP oracles and entry producer checks.
  Exact float/double values are proved on x86-64/AArch64/ARM32; both MIPS orders
  prove scalar floats and conservative double-pair omission. ARM's opaque
  mode-switching-return prefix remains unavailable at the checked PCs.
- Positive incoming-register prefixes and first-overwrite boundaries are
  exercised on x86-64/AArch64. Advanced/interior function-entry GDB behavior,
  saved-program fresh-process byte determinism and greater-than-2-GiB/copy-
  cancellation tests run on x86-64. Five-profile metadata tests and actual
  forced x86-as-AArch64/MIPSLE-as-ARM imports cover definite target disagreement;
  nondefault language variants/compiler specifications alone are not rejected.
- QEMU private-socket startup/failure controls run on x86-64, with the occupied
  historical TCP-port control on MIPS32LE. Shared-object runtime checks pass on
  all five targets. Other TCP-based harnesses are unchanged.
- The configured standalone checker, bounded complete-diagnostic capacity,
  allocation/resize rollback and parser corruption controls pass on Linux.
  Precisely corroborated inherited frame diagnostics remain visible; acceptance
  requires matching original bytes/identity and the exact diagnostic multiset,
  with zero unexplained errors. The validation-only patches do not alter the
  shipped native libraries. Passing CI does not create a new performance timing.

The independent package precheck downloaded artifact `12550562112` and verified
its GitHub digest/outer SHA-256
`1fa7f0046e39ad7179f820e379d6ca2cd147aeb7fdb0f0b9800ca4a58494f3d4`.
The native-inclusive package SHA-256 is
`a1ea4069dce1ea66aee8ecb59751b690a069bada19dea348306e0c9243aa412f`.
The audit compares all 31 production Java sources and two installed scripts
with the exact head, verifies nested manifests and native provenance, checks
135 Java 21 classfiles, and passes 20 packaged Linux producer lifetimes with
verified class/native origins. Evidence is retained in the
`reviewed-todo-integration` worktree at
`build/combined-package-audit/run-40068401197.43nKQbGP/`.
This precheck validates an integration package; it is not publication of a new
release. Full run/job/conditional-step API evidence is retained at
`build/review-preparation/final-{run,jobs}.json` in the same worktree.

Both actual GUI journeys use the installed launcher and packaged natives,
verify input preservation, and exercise discovery, native-free preflight,
export, Console reports, chooser selection and cancellation. The shared three
click/filter/modal controls pass on both hosts. Independent artifact review
confirms:

| Host | Artifact ID and SHA-256 | Retained GUI run |
|---|---|---|
| Linux | `12550497695`; `72ef62bb0ddb0f76bbdbaa25df27d1bbca52a823f2bbe129a221f961aba6f4d0` | `artifact/gui-script-manager/run.N0EhE52D/` |
| Windows | `12551006258`; `27a2d6064d3f85e8eb8ebc1a99f1e615c9b3f1572b12e20401d793543b6e14dc` | `windows-artifact/windows-host/gui-script-manager/run.c8c18a94b260448eaa51197cc5887425 GUI paths/` |

These paths are relative to the `gui-script-manager` worktree's
`build/hosted-gui-review/run-40068401197/`; the downloaded artifacts, API digest
records and `x86-job.log`/`windows-job.log` are retained there. Linux also passes
100 independent native/Java window-geometry comparisons, GNU/LLVM, the strict
checker (three exactly matched inherited frame diagnostics, zero unexplained),
and runtime GDB source/value/stepping/normal-exit checks. Validator/GDB stderr
and the Openbox log are empty; inherited checker diagnostics remain explicit
in its stdout/report. Windows proves real ACL denial, selected paths and
available native GNU/LLVM validation with empty stderr. Independent libdwarf
is unavailable and Linux-ELF runtime GDB is not run on Windows. The 100-window
Openbox geometry control is Linux-only. Neither the earlier failed runs nor
the diagnostic replays are promoted to passing acceptance.

PR #25 merged normally as
`befce2c5aa621d7c72a1803a3bbcfd566db6d31b` at `2026-10-24T06:23:24Z`.
Its tree equals the tested `9612655` tree, and component PRs #20/#21/#23/#24
are observed merged. The separate
[main-push run 40070016394](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40070016394)
targets `befce2c` and was still running when this checkpoint was recorded;
no passing result is attributed to it here.

This closes the combined integration gate for the documented profiles. It
does not complete richer scopes, external-function declarations, general
storage migration/call-crossing, additional ABIs, vector/composite FP cases,
optional debuglink transactions or inline DIE emission. P3.5 retains its
historical local timing boundaries and open complex-workload/phase profiling.
Existing PN_XNUM direct-execution and resource/layout limits still apply.
Published alpha.2 remains immutable at `2f88c4a`, excluding these later
features; no version, tag, published package or release assets changed.

## Qualified analyst function display names (2026-10-24)

**CONFIRMED locally; exact hosted acceptance pending.** Production commit
`fd56d74` retains plain Ghidra namespace paths separately from lexical function
identity and emits qualified CU-owned display names under C11. Fixture commit
`17bab25` checks two nested scopes sharing `curated_same`, their separate
`private_count` values 37/83, a global `private_count` of 19, and a real global
`curated_same` returning 29. Namespace-global value 61 and the existing typed
external-data declaration remain intact. No native signature, language,
linkage-name, alias, global-data scope or source-key policy changed.

Five focused Java checks (`qualifiedFunctionNameSmoke`, `syntheticSourceSmoke`,
`dwarfRangeListsSmoke`, `dwarfLineTableSmoke`, `typeGraphSmoke`) and the extension
build pass. The new smoke uses actual Ghidra ProgramDB namespaces, verifies
rebased bodies/entry, immutable paths and lexical source declaration mapping,
diagnoses class fallback, and rejects real literal-delimiter collisions. A
public-export negative uses regular invalid ELF/native files: collision
rejection wins before parsing/loading, leaving all inputs and an existing
destination unchanged with no temporary residue. Existing file preflight order
is preserved. Independent production and fixture/workflow reviews are clear.

The real installed exporter passes all **15** target/role cases below. Every
case performs two fresh imports/exports with byte-identical `.dbg` and `.dbg.c`,
unchanged original hashes, GNU/LLVM and strict libdwarf checks. Compiler-reference,
compiler separate-symbol, and Forge GDB oracles require exact function/static
addresses, initial types, one-location named breakpoints, owner-local shadowing,
separate global lookup, stepping/returns and normal exit zero. The Forge oracle
additionally lists the synthetic source and requires that association on full
function symbols; inherited minimal ELF symbols cannot satisfy it. Runtime ASLR
bias is checked consistently.

| Target | Roles | Retained run |
|---|---|---|
| x86-64 | exec, PIE, rebased PIE | `run.uEbWkHrg` |
| AArch64 | exec, PIE, rebased PIE | `run.gMpe6aQp` (three completed cases) |
| ARM32 ARMv7 hard-float | exec, PIE, rebased PIE | `run.7BXiMlNg` |
| MIPS32 big-endian O32 | exec, PIE, rebased PIE | `run.7BXiMlNg` |
| MIPS32 little-endian O32 | exec, PIE, rebased PIE | `run.7BXiMlNg` |

Paths are under the `qualified-function-names` worktree's
`build/test-results/qualified-function-names/`. Strict reports retain two
exactly corroborated inherited frame diagnostics for x86 exec, seven for each
AArch64 role, and zero errors for the other eleven cases; unexplained errors
are zero throughout. ARM EHABI positive/rejecting controls and the existing
operation/address/count-matched MIPS return diagnostic policy remain unchanged.
The original x86 static-scope mode also passes all three roles in
`build/test-results/function-static-scopes/run.Ssk77Ote`.

Commands use the real installed private extension:

```bash
FORGE_SCOPE_QUALIFIED=1 DWARFDUMP=/path/to/pinned/validation-tool/bin/dwarfdump \
    src/test/integration/function-static-scopes-export.sh /private/ghidra \
    x86_64 aarch64 arm32 mips32be mips32le
DWARFDUMP=/path/to/pinned/validation-tool/bin/dwarfdump \
    src/test/integration/function-static-scopes-export.sh /private/ghidra x86_64
```

Local ARM compiler/binutils libraries and its runtime sysroot were supplied
from the retained private toolchain. The first cross run completed AArch64 but
stopped at missing ARM host-library setup. Subsequent setup attempts exposed
missing strip/objcopy wrappers before export. Those failures are retained;
only `run.7BXiMlNg` supplies complete ARM/MIPS acceptance. No user installation
or shared Ghidra tree was modified. Exact tool versions, command transcripts,
15-case retained-evidence/hash audit and package assembly log are in
`build/qualified-integration/`. **Correction:** that toolchain JSON queried
Java 21.0.12.1 directly, but the retained headless logs show JDK 25.0.4.1;
the local Java 21 installation lacks `javac`, so Ghidra's JDK launcher selected
25. The isolated smoke/package checks use Java 21, and hosted CI uses a full
Java 21 JDK. GDB is 15.1 and QEMU is 8.2.2. This does not change the supported
Ghidra 12.0.3 / Java 21 bytecode baseline.

The actual private package SHA-256 is
`a32ccc4ea0acb2d008fec7689297b5c4919a1cda14257280aeb22e85a3d4bc97`;
production JAR SHA-256 is
`e17309610a07650ace27e015179f03505c1add527d9f1d117c4801b3a5822c3b`.
Its two production changes match `fd56d74`; native inputs are the previously
verified unchanged integration pair. This is an unreleased local package.

The old installed package (`a1ea4069...`) in `run.odZEvuXT` passes the ordinary
validators but fails the missing-qualified-name assertion and actual GDB lookup.
The first new-package run `run.YVyfznAh` exposed a harness parser incorrectly
splitting GNU attribute-offset lines as DIE headers; the artifact already had
the correct names. The corrected parser requires a full DIE header and the
passing rerun retains CU-depth, C11, declaration-line and no-linkage assertions.
These failed attempts are not counted as passing evidence.

CI adds the qualified real-export regression to every existing target lane and
the real-Ghidra smoke to Linux and native Windows. Hosted acceptance remains
pending for this feature; the preceding PR #25/main runs do not exercise it.
Final extension build, release-package regression, workflow lint and architecture
isolation checks pass locally; the production JAR is unchanged from the runtime
tests. Independent reviews cover code, fixtures/workflow and the retained evidence.
[FUNCTION-NAMING.md](FUNCTION-NAMING.md) records quoting and limitations. Full
namespace/class/lexical/alias semantics and external-function declarations stay
partial/planned, and published alpha.2 remains unchanged.

### Qualified-name hosted acceptance (2026-10-24)

**CONFIRMED:** head `d5f2521e09b3920c3d7408cfe503f02fec59562f` passed all twelve
expected jobs in pull-request run `40071594248`, attempt 1. Independent artifact
review confirms all 15 qualified-name cases, the native Windows naming smoke,
and the actual Linux/native Windows GUI journeys. PR #26 merged normally at
`2026-10-24T07:15:49Z` as `89c07cec086e35bdbecb9809f5e9c3fe893a82eb`; its tree
matches the tested head. Separate post-merge main push `40073445177` is pending
at this checkpoint. The prior PR #25 main push `40070016394` finished with all
twelve jobs successful, superseding its earlier pending checkpoint.

The naming package audit verified artifact `12550999990`, outer SHA-256
`d0c3a6c1dfb9feb3d4ea32848a846fb11e97a421af03433130c269e1931ec56f`, and package
SHA-256 `560a1f5b62e3026069a62830b246f4af7250cb585970bf7f5343186c9d05a3ac`.
All five manifests, native provenance, 31 production sources, two scripts and
135 Java 21 classfiles pass. The downloaded production JAR passes the actual
Ghidra naming smoke and 20 producer lifetimes with verified class origins.
Evidence is retained in the qualified-function-names worktree at
`build/qualified-package-audit/run-40071594248.ofwYwpWq` and
`build/qualified-integration/final-{run,jobs}.json`. Independent hosted evidence
is in the GUI worktree at `build/hosted-gui-review/run-40071594248`.
Neither published alpha is changed by this acceptance.

### Opaque instruction effects: wrong-register-location regression (2026-10-24)

**CONFIRMED locally, hosted gate pending:** `GhidraVariableStorage` now treats
raw `CALLOTHER`/`UNIMPLEMENTED` effects as invalidating otherwise-stable register
locations. This shared proof covers scalar/composite parameters and locals.
Existing call/modeled-write diagnostic precedence remains intact. The only
`CALLOTHER` exception is a proven ordinary terminal-return boundary:
unconditional non-call/non-jump flow, no override/delay slot/fallthrough,
well-formed full-width final RETURN, and no preceding p-code control transfer.
The location describes state before that instruction; this is not a purity
assumption; `UNIMPLEMENTED` always rejects the proof. No target identifiers,
syscall ABI whitelist, inferred register
migration, pre-syscall prefix or native calls were added.

The source-built Linux AArch64 fixture takes `-19` and a destination pointer,
copies the value, executes `getpid` through `svc`, then stores the original
value. Pinned Ghidra decodes SVC as outputless falling-through `CALLOTHER`.
Old Forge reports a positive process ID as the parameter after SVC, while the
compiler oracle and stored global retain `-19`. Negative input cannot equal
the returned positive PID. The fixed artifact retains both parameter names
and types without `DW_AT_location`, and reports two `UNKNOWN_LIFETIME` omissions.
The GDB oracle checks entry, before SVC, after SVC and return, raw registers,
global address/value, synthetic source, `next`, `step` and normal exit.

Acceptance commands, using an isolated installed package and private settings:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew \
    opaqueRegisterEffectsSmoke qualifiedFunctionNameSmoke registerPrefixSmoke \
    registerAliasSmoke variableStorageSmoke buildExtension
DWARFDUMP=/path/to/pinned/bin/dwarfdump \
    src/test/integration/opaque-register-effects-export.sh /private/ghidra
DWARFDUMP=/path/to/pinned/bin/dwarfdump \
    src/test/integration/register-prefix-export.sh /private/ghidra \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64 aarch64
FORGE_ARM32_SYSROOT=/private/arm/sysroot DWARFDUMP=/path/to/pinned/bin/dwarfdump \
    src/test/integration/floating-registers-export.sh /private/ghidra \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 arm32
src/test/integration/fixture-reproducibility.sh aarch64
src/test/integration/release-package.sh
src/test/integration/architecture-neutrality.sh
```

All evidence below is in the opaque-register-effects worktree:

- `build/test-results/opaque-register-effects/run.vxhBWrdr`: exec, PIE and
  `+0x2000000` Ghidra-rebased PIE pass, with six fresh-import exports, identical
  repeated output pairs, original/build-ID preservation, GNU/LLVM and strict
  libdwarf checks. Each role has six exactly corroborated inherited frame
  diagnostics and zero unexplained errors. GDB has only the exact same QEMU
  vDSO message as its compiler oracle. `build/opaque-validation/acceptance.json`
  records hashes, reports and diagnostics. Local headless runtime is JDK 25.0.4.1.
- `build/test-results/register-prefix-export/run.ROeouQv6`: all twelve
  x86-64/AArch64 exec/PIE baseline/rebased/repeat exports pass validators and
  runtime GDB; values become unavailable after the proven first overwrite.
- `build/test-results/floating-registers/run.Ml4wk7yJ`: all six ARM32 scalar
  exec/PIE baseline/rebased/repeat exports pass with zero checker errors. Proven
  terminal-return float/double locations remain correct; unproven prefix
  cases remain unavailable. `build/opaque-validation/positive-regressions.json`
  records these two suites. The sysroot override changes only local setup;
  CI retains its default path.
- `build/opaque-proof/final-java21.dh0zlsu7/result.json`: the same test compiled
  with `--release 21` reproduces the old JAR's incorrect available storage and
  passes the fixed JAR on actual Java 21.0.12.1. Class origins and JAR hashes
  are checked. Real decoded SVC and ARM returns, parameters/locals/composites,
  malformed/overridden/delayed/control-flow returns, cancellation and existing
  diagnostic precedence are covered. All five combined focused tasks, build,
  package regression, source-inventory reproducibility and workflow lint pass.

The first fixed local package SHA-256 is
`55489152cc8c7a12782989b8129f791b0a2427ccf84e4caa80d4c2c1b2bd5175`; its JAR is
`29036f0e3255acf83fe4926ddccbfde197cfb5cdbc9d310d814be6351b8a49a8`.
This predates the normal merge of naming changes from main. The combined build
passes both new smokes. CI preserves both gates, adds the AArch64 real SVC test
and runs the new smoke on Linux and native Windows; no hosted acceptance is
claimed yet. The architecture-isolation check initially flagged the comment
word `PC` as a register spelling; replacing it with `instruction` passes without
changing the guard or weakening that check.

**CONFIRMED combined local acceptance:** after normal merge `73eb0e5` of the
accepted naming changes, `build/test-results/opaque-register-effects/run.NZ60WkMr`
passes all three roles and six fresh exports again. The production JAR is
`73bf512060dbd7cac9b0c105ba3388e145ec0c34672c2a365dfe6e3aab46c99d` and its
private test package is
`294291e44944b75dfc71253c0981b2e94de58e64dc77f3c7965f8ef08d32d9a5`.
All previous fixed acceptance assertions remain enforced, including strict
diagnostics and byte-identical repeats. `build/opaque-validation/combined`
retains assembly/identity/runtime evidence. Independent merged source, CI and
fixture reviews found no blocker; the exact hosted matrix is still required.

**CONFIRMED separate issue, not fixed here:** baseline runs `run.Q8z14rHD` and
`run.7D4Odl05` reproduce the wrong parameter value but fail strict GDB diagnostics
on additional data-address symtab warnings; neither is counted as a passing
test. Direct `p/a 0x420028` against both the old and fixed exec sidecars reproduces
the warning without executing the program. Logs are retained under
`build/opaque-pointer-review`. Fixed location omission avoids automatic pointer
argument formatting, but does not resolve this CU-address-map issue. It needs
its own standards-backed coverage change and direct GDB regression before a
future release. No warning allowance was added. A private Java-home setup
failure (`run.XAmnFSC7`) is also retained; both successful negative probes used
JDK 25 despite an attempted Java 21 selection, as explained above.

### Exact code-address index and pointer formatting (2026-10-24)

**CONFIRMED locally; hosted gate pending:** production commits `5342d53` and
`540a2ec` emit the exact exported function union as `.debug_aranges`. The
authoritative DIEs, line rows and variable locations are unchanged. The table
uses the single CU's header offset zero, version 2, DWARF32 offsets, target
width/order, aligned tuples and a zero terminator. A full ELF32 address-space
union is split into two length words without overflow or loss of coverage.
`docs/ADDRESS-INDEX.md` records the decision and bounded support contract.

The motivating GDB 15.1 warnings are independently reproduced with both old
and opaque-guard sidecars. Official GDB source archive SHA-256 is
`38254eacd4572134bca9c5a5aa4d4ca564cbbd30c369d881f733fb6b903354f2`.
The investigation, unmodified-artifact hashes and code-only copied-artifact
controls remain in the opaque-register-effects worktree at
`build/opaque-pointer-review/HANDOFF.txt`. The production fix adds no warning
exception or data/gap coverage. It supersedes the historical aranges-absence
policy, not the established function/CU-range authority.

The following evidence is retained in the cu-address-index worktree:

| Suite | Evidence | Result |
|---|---|---|
| Five profiles, exec/PIE/rebased PIE | `build/test-results/qualified-function-names/run.y31bjNGv` | All 15 cases pass compiler/Forge GDB address formatting, scoped/global values, stepping, validators, hashes and byte-identical repeats |
| AArch64 supervisor call | `build/test-results/opaque-register-effects/run.dI8HAKKH` | All three roles pass direct `p/a` before exec CU expansion and after runtime bias resolution, typed-pointer formatting and existing four-stop unavailability checks |
| x86 advanced function entries | `build/test-results/function-entry-export/run.k5q9t0qb` | All six exports retain true entries, backwards execution, split bodies, source/gap checks, pointer formatting and deterministic repeats |
| Generic x86 and MIPS32-BE sectionless | `build/address-index-review/{core-x86,sectionless-mips}*.log` | Real headless export, structural checks and native/QEMU GDB pass; original targets unchanged |
| Existing compiler debug data | `build/test-results/existing-debug-export/run.uwM33Zpy` | Plain, zlib, GNU-zlib and indexed inputs pass; exactly one fresh aranges table, old compressed/index data retired, actual GDB and input hashes preserved |

These are 30 runtime cases, not 30 distinct architecture profiles. The independent
checker decodes raw aranges headers/tuples and compares them to LLVM-expanded
subprogram intervals; it also rejects ten malformed variants per artifact.
The final anchored parser was replayed against the 24 qualified/SVC/advanced-entry
artifacts with 240 rejecting controls. It accepts the necessary adjacent
full-ELF32 partition and rejects overlapping or descending tuples. No checker
error is unexplained: the SVC roles each retain six exactly corroborated frame
diagnostics; advanced-entry exec roles each retain two and PIE roles have zero.
The remaining suites retain their individual strict reports.

The final installed private package SHA-256 is
`2ce372b5589402d4a993838ab7e9b4cca06e9bae7d762f02e8507f035bfe7542`; its JAR is
`57bd25a7ffbac4dc28940c42c7923d07a6e634f9cb3ca61c2b4ba0d729f62dc7`.
All five manifests pass. Private platform directories and replaced launch
files isolate settings/cache/home; original installation hashes are unchanged.
Local headless runtime is JDK 25.0.4.1. The format smoke also passes on actual
Java 21.0.12.1 after separate `javac --release 21` test compilation, with all
four relevant production classes loaded from that exact final JAR. Four
adjacent format smokes, existing-debug/info-repair smokes, build, workflow lint
and architecture isolation pass. Detailed summaries are in
`build/address-index-review/{qualified-acceptance,root-runtime-acceptance,final-oracle-replay}.json`.

Representative commands:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew dwarfAddressRangesSmoke \
    dwarfRangeListsSmoke dwarfLineTableSmoke dwarfLocationListsSmoke \
    existingDebugSidecarSmoke dwarfInfoRepairSmoke buildExtension
FORGE_SCOPE_QUALIFIED=1 DWARFDUMP=/path/to/verified/bin/dwarfdump \
    src/test/integration/function-static-scopes-export.sh /private/ghidra \
    x86_64 aarch64 arm32 mips32be mips32le
DWARFDUMP=/path/to/verified/bin/dwarfdump \
    src/test/integration/opaque-register-effects-export.sh /private/ghidra
src/test/integration/function-entry-export.sh /private/ghidra /path/to/libdwarf /path/to/libdwarfp
src/test/integration/existing-debug-export.sh /private/ghidra /path/to/libdwarf /path/to/libdwarfp
python3 src/test/integration/check-code-address-index.py artifact.dbg --negative-controls
```

**Retained failures/setup limits:** qualified attempt `run.Use09Xbe` stopped on
a harness variable-name typo before GDB; the corrected fresh run supplies
acceptance. Existing-debug attempt `run.djZBJGkH` exposed its historical active
section whitelist, now explicitly extended with one exact-coverage aranges
table. `run.2bjtLdFN` passed plain input but correctly rejected compressed-original
corroboration because the local checker lacked zlib/zstd. Its sidecar had only
the expected frame diagnostics; no warning was suppressed or original input
decompressed to bypass that failure.

The final replacement suite instead uses the digest-verified standalone checker
from exact PR #27 run `40073884397`: artifact `12552870316`, archive SHA-256
`977737f22ec4e18471dbdef211445a44b05454c3f4d6836fb5ec0783076c9683`.
All 19 manifest entries and exact source/helper/three-patch/config pins pass;
its actual zlib/zstd dependencies and relocated configuration are checked.
The retained failed zlib pair independently passes with this tool, then all
four fresh variants pass. Evidence is under
`build/address-index-review/hosted-validator`. This is a local validator setup
correction, not a product fix or a reason to invalidate the earlier uncompressed
checks. An initial manual Java 21 attempt used JDK-25 test classfiles and was
rejected before execution; its log remains alongside the correctly compiled
passing smoke. An earlier pre-partition package was never installed or tested.

CI adds the format smoke to Linux and native Windows and replaces absence
checks with exact decoded coverage throughout the existing real-export lanes.
The new pointer commands retain strict diagnostics, all five target gates and
the original architecture scopes. Independent code, harness and evidence
reviews are clear. Exact hosted acceptance and normal main integration remain
pending; no version, tag or published alpha assets change.

### Opaque-guard hosted acceptance and integration (2026-10-24)

**CONFIRMED:** exact PR #27 head `e7a289cd3443c277ee5617076fede8b75703f83b`
passed all twelve expected jobs in `40073884397` (`pull_request`, attempt 1),
with none skipped. Hosted AArch64 `run.mCwg0Cpm` independently proves all three
roles and six deterministic exports on Java 21, with the two typed locationless
parameters, multi-address GDB assertions, hashes and six exactly corroborated
frame diagnostics per role. Linux GUI `run.SMCbkEa2` and Windows GUI
`run.f9e72d7f394642d4b7eaa5c2c8ea49a2 GUI paths` pass their real Script Manager
journeys, three controls, Console, chooser selection/cancellation and preservation.
Windows also passes all eight smoke checks including opaque effects and naming.
Its previously documented validator/runtime limitations remain explicit.

Exact candidate package SHA-256 is
`ab7545fd3b00da7aaeac6e3fc0c1dafc65a68d7b34942d49d63a348a691012ce`.
The source/provenance/manifests/135-Java-21-class audit, actual Java 21 opaque and
naming smokes, 20 native producer lifetimes and verified production class origins
pass. Evidence is in opaque-register-effects at
`build/opaque-package-audit/run-40073884397.BkMdIvb0` and
`build/opaque-package-audit/final-{run,jobs,gate}.json`; digest-verified target/GUI
evidence is in the GUI worktree under `build/hosted-gui-review/run-40073884397`.

PR #27 merged normally at `2026-10-24T07:51:07Z` as
`ce0c3a4a71c2e5f9414ccd9a36878617c827818c`, whose tree equals the tested head.
Separate exact-main push `40075761646` is pending at this checkpoint. Naming
merge `89c07ce` also passed its separate main push `40073445177`; its earlier
pending notes are historical. These results close the opaque-guard feature's
hosted gate but do not validate the subsequent address-index implementation.
Published alpha.2 and alpha.1 remain unchanged.

## Exact code-address index hosted acceptance (2026-10-24)

**CONFIRMED:** PR #28 head `a5f79109f5cb345dff789938f2b41741967f47ad`
passed all twelve jobs in
[run 40076025207](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40076025207),
`pull_request`, attempt 1, with no job failed or skipped. Normal merge
`b4d786947ab49902c2fa86da73ba7e03c043f05d` at `2026-10-24T08:23:21Z` retains
the tested tree. Its separate main-push run `40077843290` is pending. The prior
opaque-guard main push `40075761646` also passed all twelve jobs and independent
Linux/Windows artifact checks, superseding its earlier pending checkpoint.

The digest-verified five target artifacts pass 30 core address-index cases,
including all five sectionless inputs, and 30 ordinary/qualified static-pointer
cases. Each applicable index check rejects ten malformed controls. Six x86
advanced-entry cases and three AArch64 opaque-effect cases retain their exact
range/value/omission and pointer-formatting expectations. Structural checks
report zero unexplained errors; precisely corroborated inherited frame counts
remain visible. Recomputed input hashes and applicable byte-identical repeats
pass. Actual Linux and native Windows GUI journeys pass; Windows runs all nine
native-independent smokes, including address ranges, opaque effects and naming.
The documented Windows independent-libdwarf/runtime-GDB limits remain.

Candidate artifact `12553008801` has archive SHA-256
`8e1a529ef9f32812047329d6994dc836d1a2a57458432581d5a84591e73596ef`;
its package SHA-256 is
`a6edcb42cee25a81b598ad01703b34445394ccb0a829827b6172773a7d6459f3`.
All five manifests, exact 32 production sources/two scripts, native provenance
and 136 Java 21 classfiles pass. Actual Java 21 address/opaque/naming smokes and
20 packaged producer lifetimes pass with all 31 loaded production class origins
verified against the downloaded JAR. Evidence is retained in the code-index
worktree at `build/address-package-audit/run-40076025207.GWY1Pu8C` and
`build/address-package-audit/final-{run,jobs,pr,review-threads,gate}.json`.
The GUI worktree's `build/hosted-gui-review/run-40076025207` contains final run,
host, all-target index/pointer, advanced-entry and opaque-effect audit records.

This closes the code-index integration gate within its recorded profile. It is
not a new release and does not alter either published alpha. The optional
opaque baseline-reproducer mode now also requires the code index; historical
pre-index packages need their retained historical harness, and are not claimed
to pass the current harness unchanged.

## Bounded register-copy lifetimes, final local acceptance (2026-10-24)

**CONFIRMED locally; hosted gate pending:** independently reviewed production
commit `5ba6f39c5c862ee4cf8bf22b70231cbc9dd5840c` tracks one completed direct
register backup for an incoming parameter in a fully decoded straight-line
leaf. It retains the original through its writing instruction, then the
backup, and no location after an unproved backup write. No native call, memory
migration, call preservation, arbitrary copy chain, later-local or entry-value
recovery is added. `REGISTER-COPY-LIFETIMES.md` defines the exact proof.

The shared checks also close physical result-register overlap, referenced
instruction interiors and external fallthrough-reference gaps. Only an actual
preceding decoded instruction's ordinary fallthrough is exempt. Unproven STORE
destinations invalidate stable locations and reject the whole prefix fallback;
known RAM stores retain their behavior. The new proof separately rejects
length/fallthrough overrides and mixed code address spaces. Controlled tests
verify these conditions without pretending that every malformed proxy is an
observed machine-code defect. Tests assert reference setup explicitly because
the pinned database can remove invalid fallthrough references automatically.

The final private installed JAR SHA-256 is
`70514244380b83df22644bc8ea4c5c73a504f5ba87cb2e21ed3f6cdf7ee3457c`;
the native-inclusive private package SHA-256 is
`823699e9d7cceba1b35b35a6dc0b56657e7249e61678346321c0d9ca8fc6acf4`.
All five manifests and exact 33 production sources/two scripts pass. The shared
Ghidra installation and launch settings remain unchanged; each test platform
uses separate real directories and private settings/cache/temp locations.

The `register-copy-lifetime` worktree retains the exact commands and results:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 ./gradlew \
    registerCopySmoke registerPrefixSmoke opaqueRegisterEffectsSmoke \
    registerAliasSmoke variableStorageSmoke dwarfLocationListsSmoke buildExtension

DWARFDUMP=/path/to/verified-standalone-validator/bin/dwarfdump \
    src/test/integration/register-copy-export.sh \
    "$PWD/build/register-copy-review/ghidra-closure"
```

The final run is `build/test-results/register-copy/run.V0gUehki`: six
x86-64/AArch64 exec/PIE/rebased-PIE roles, twelve fresh exports and 72 calls per
compiler/Forge debugger mode. Four functions per role cover signed 32/64-bit
`19`, `-19` and high-bit negative patterns, saved-register survival and backup
destruction. Raw low bits, parameter types/values, globals, exact PCs, source
lookup, stepping and normal exit pass. Compiler entry-value recovery remains
an exact original-value oracle after destruction; Forge reports unavailable.

Independent raw `.debug_loclists` parsing matches the two exact intervals for
each parameter to compiler symbol boundaries. Both exporter reports per role
contain exactly the two expected kill-tail omissions. GNU, LLVM, code-index
coverage, original hashes and byte-identical output/source repeats pass. Strict
libdwarf reports exactly 6/4/4 inherited frame diagnostics for x86 exec/PIE/
rebase and 8/8/8 for AArch64, with zero unexplained errors; same-tool original
diagnostic multisets corroborate them. GDB stderr is empty on x86 and exactly
matches the compiler's established QEMU-vDSO diagnostic on AArch64. Evidence:
`build/register-copy-review/{closure-runtime-acceptance,independent-closure-audit}.json`.

All six focused Gradle smokes, build and architecture isolation pass. Actual
Java 21.0.12.1 separately runs copy, prefix, opaque and alias smokes after test
compilation with `--release 21`; production and test class versions are 65.
`build/register-copy-review/java21-closure/{commands,result}.json` records this
execution. Local headless runs use Java 25.0.4.1; they are not Java 21 headless
evidence. Isolated hierarchy-only and instruction-start-only predicate replays
fail their exact new assertions. Workflow lint, shell/Python checks and the
x86/AArch64 fixture inventory/reproducibility checks pass, including thirteen
byte-identical semantic artifacts per target.

The same final JAR separately passes 36 regression exports in three isolated
platforms: updated x86/AArch64 prefixes (`run.45p8qA6r`, twelve exports), AArch64
opaque effects (`run.3OW60qMl`, three roles/two fresh imports), and scalar FP
on x86/AArch64/ARM32 (`run.Io71toGI`, eighteen exports). The prefix now retains
the directly copied `19`; the supervisor-call parameters remain unavailable.
ARM scalar/double RAM stores, upper slices and ordinary terminal-return values
pass, while its clobbered opaque-return parameter stays omitted. Exact original
and artifact diagnostic Counters, zero unexplained errors, GNU/LLVM, runtime
values, source, preserved inputs and deterministic pairs pass. Source/script
origins and all manifests remain verified. Evidence and exact invocation:
`build/register-regression-closure/{results.json,run-suite.sh,audit-results.py}`.
Together with the new suite, this is 48 final-build fresh exports. The earlier
preliminary ARM toolchain setup failed before export because a private binutils
library path was missing; owned compiler/strip wrappers now scope that path
only to those child tools, and the final six ARM exports pass. No global
Ghidra/GDB/QEMU library path was changed.

Earlier runs remain explicitly separate: old package `run.XYn8f8Rr` fails the
new interval oracle because it has no backup range; `run.ZKip4EFg` accidentally
selected the system checker using the wrong environment variable and fails
strict validation. The retained GDB harness failures are `run.ma7S3IdX`
(Ghidra's `longlong` spelling), `run.xF3usUMa` (an unsupported integer-type range
query) and `run.4T5PpKuf` (a numeric pre-load PIE breakpoint, after passing x86
exec). Final tests use semantic width/signedness checks and symbolic entry
breakpoints that relocate. Intermediate JARs `4f2c8d`/`83471f` pass their
recorded full runtime suites but predate the final shared guards; they do not
substitute for final `70514244` acceptance. No validator exception or value
expectation was relaxed to turn a failed run into a pass.

The new runtime gate is required for x86-64/AArch64, and the focused copy smoke
is added to Linux and native Windows CI. All five existing target gates and
strict diagnostics remain enforced. Exact-head hosted acceptance and package
audit are still required before normal merge. Neither published alpha changes.

## Unsupported nonzero stack-local first-use (2026-10-24)

**CONFIRMED locally; exact hosted gate pending.** Production commit
`27d47dcf00077785fd7f9b7eaf6b5905397004ee` adds the conservative local-storage
guard and real-Ghidra smoke. The local runtime JAR SHA-256 is
`0bffbe24632d077f9c25a8e6f2f17e8cae9b84ac0c7884d3e93a01ea264ef181`.
The private runtime package SHA-256 is
`4ccb391a62b069bbe5a4f8b47a93f35a5ba0fab27e8404a6e429b97171b89c35`;
all five nested manifests pass. It was installed into an owned Ghidra clone,
preserving the original installation's launch-properties hash. Native source,
bindings, target mappings and DWARF encoding are unchanged. Published alpha.2
remains immutable and does not contain this guard.

Commands from the `stack-first-use-guard` worktree:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
    ./gradlew stackFirstUseSmoke variableStorageSmoke dwarfLocationListsSmoke buildExtension
src/test/integration/architecture-neutrality.sh
src/test/integration/fixture-reproducibility.sh x86_64
src/test/integration/fixture-reproducibility.sh aarch64
DWARFDUMP=/path/to/verified-pinned-dwarfdump \
    src/test/integration/stack-first-use-export.sh /path/to/private-fixed-ghidra x86_64 aarch64
FORGE_STACK_EXPECTATION=baseline-reproducer \
    DWARFDUMP=/path/to/verified-pinned-dwarfdump \
    src/test/integration/stack-first-use-export.sh /path/to/private-pr29-ghidra x86_64 aarch64
```

The strict checker is the compression-capable pinned build retained at
`cu-address-index/build/address-index-review/hosted-validator/tool/bin/dwarfdump`,
whose artifact archive SHA-256 is
`977737f22ec4e18471dbdef211445a44b05454c3f4d6836fb5ec0783076c9683`.
The local complete headless runtime is JDK 25.0.4.1. Actual Java 21.0.12.1
standalone tests compile with `--release 21`; their classfile major version is
65. Do not attribute local headless runs to Java 21.

Focused checks pass for x86-64, AArch64, ARM32 and MIPS32 BE/LE, including actual
ProgramDB save/reopen, immutable snapshot preservation, constructor/insertion
restrictions, positive/negative/offcut/outside/extreme offsets, name/type/offset
retention, zero/parameter positives and cancellation. The isolated guard-absent
Java 21 replay fails the new location assertion as required. Existing copy,
opaque, storage and location-list checks also pass. These are five-language
extraction checks; the new runtime fixture covers only x86-64/AArch64.

Final fixed `build/test-results/stack-first-use/run.zHNit33c` passes six roles,
two fresh imports each. Compiler GDB proves disjoint scopes, measures a shared
entry-SP-relative slot, and observes raw `11,11,22,22`. Forge keeps `second`
typed but unavailable at all four PCs, emits no location or guessed scope
start, and records the exact `UNKNOWN_LIFETIME` omission for both exports.
The zero-first-use local remains `37`. Independent DIE/type/report checks,
source lookup, next/step, global pointer formatting and normal exit pass.
Original hashes, exact build IDs, code-address index/negative controls and
byte-identical `.dbg`/`.dbg.c` pairs pass. Native GDB/GNU/LLVM stderr is empty;
AArch64 GDB has only the exact compiler-matched QEMU vDSO warning.

GNU/LLVM validation passes. Strict libdwarf reports only the exactly
corroborated inherited frame diagnostics: x86-64 exec/PIE/rebase `5/3/3` and
AArch64 `4/4/4`, with zero unexplained diagnostics. These visible inherited
errors are not described as absent. The structural/report oracle additionally
rejects 21 deliberately malformed location/type/preparation/report/hash cases.

Baseline `run.R6pJS512` uses unchanged PR #29 JAR
`70514244380b83df22644bc8ea4c5c73a504f5ba87cb2e21ed3f6cdf7ee3457c`
and package `823699e9d7cceba1b35b35a6dc0b56657e7249e61678346321c0d9ca8fc6acf4`
in a separate owned installation. All six roles reproduce the earlier
object's `11` as `second`, then `22`; the compiler says `second` is out of scope
at the first two observations. Its twelve baseline exports validate/repeat,
but the result is explicitly `BASELINE-REPRODUCED`, not an accepted correction.
The old behavior is rejected by the fixed structural oracle.

Evidence is retained under `build/stack-first-use-review/`: runtime and baseline
logs, platform manifests, Java 21/baseline replay results, checker controls,
compiler probes, lint and fixture-inventory logs. Both inventory lanes retain
13 byte-identical standard fixture artifacts; the new fixture is compiled by
its dedicated harness. Initial `run.PaItIwFG` stopped after its first repeated
x86 export because the independent checker had not yet been created; it is
not a passing suite. A private baseline-install filename typo and initial
architecture-check path typo failed before validation, were retained, and
were corrected. No source policy was weakened. Workflow lint, shell/Python
syntax and whitespace checks pass.

CI adds required Linux/native-Windows focused checks and x86-64/AArch64 runtime
gates while preserving the existing five target lanes. Its exact-head full
acceptance remains pending. Broader stack identity/lifetime recovery and the
rest of P1.11a remain partial; this guard does not infer initialization or
original compiler scope boundaries.

### PR #29 exact hosted acceptance

**CONFIRMED:** run `40079317009` for head
`698e9398c382923b50274516f26e928c1d4fc738` is a completed `pull_request`
attempt 1 with all twelve expected jobs successful and none skipped. Independent
source, package and final-gate review is clear. Package SHA-256
`e147f60544a0a16cd801444000ff94109e916066e4c7a9bdd9fde37bc4a9f46e`
and downloaded JAR `44269ecb90ef9364a0d35d148aef7568d18d70c58e7a5e10ea40abc525ecb8b1`
pass all five manifests, exact 33 production-source checks, native provenance,
138 Java 21 classfiles, actual Java 21 smokes, 20 producer lifetimes and
34 verified production class origins.

Digest-verified target artifacts prove all six new copy roles, 72 calls and
432 observation checks per compiler/Forge mode, exact two-interval locations
and kill tails, input preservation, byte-identical pairs and zero unexplained
diagnostics. x86-64 strict inherited counts are `6/4/4`, AArch64 `8/8/8`.
Existing x86/AArch64 prefixes and floating cases, AArch64 opaque cases and
ARM32 floating cases also pass independent artifact review. MIPS target job
successes are CI evidence; those PR #29 artifact contents were not separately
reviewed. The Linux GUI `run.hktB46GC` passes its three controls, 100-window
geometry probe, actual Script Manager/chooser/Console workflow, validators,
runtime GDB and input preservation, with empty stderr.

Windows artifact `12555336741`, SHA-256
`9883fdb87b95a9d107e3048ecdf29ba1add52eb4b64934a86ccd06610ca90cf2`,
proves all ten focused smokes and actual GUI
`run.ec83bfc03c5b4a04bb47282f9c1e0b48 GUI paths`: controls, ACL rejection,
selection/cancellation, Console, GNU/LLVM and input hashes, with empty stderr.
Independent libdwarf and Linux-ELF runtime GDB remain unavailable on Windows.
The GUI review evidence is retained under
`gui-script-manager/build/hosted-gui-review/run-40079317009`; package/final-gate
metadata is under `register-copy-lifetime/build/register-copy-package-audit`.

Normal merge `25f9830f64899a1b3ed9f45e60c3b7404f0fc67c` retains the exact
reviewed tree. Its distinct main-push gate remains pending. This accepted
change is not in either immutable published alpha and does not validate the
subsequent stack-first-use guard's hosted pipeline.

## Filesystem traversal and public pair identity (2026-10-24)

**CONFIRMED locally; hosted acceptance pending.** Production `a0b75fb` corrects
actual parent traversal and public publication preflight; `821808a` restores
stale-input guidance and avoids unrelated output advice. The final JAR is
`14c6fb2e4a89a98888570873e27790761ea3785c543dc1fc6fa4f43dd19f47f3`;
the production script SHA-256 is
`73c11b45f6f87cd93df7e011964699cf2172638bafc5bc2a2f0333433c51a1c2`.
Private package `df4c89e2261187a7176932ea777274714998df578a1dc97c444c4fa6ea6654b1`
passes all five manifests and is installed in an owned Ghidra clone. The base
installation's launch-properties hash remains unchanged. No native mapping,
producer-source patch, release version, tag or published asset changes.

The six focused traversal/output/publisher/source/report/native-resolver checks,
architecture guard and extension build pass. Focused checks also pass on actual Java 21.0.12.1 using test classes compiled
with `--release 21`. Publication/report checks passed before the diagnostic-only
follow-up; the changed policy/traversal checks were rerun against the exact
final JAR. All 139 production classfiles match that JAR and are Java 21-compatible. Local
headless uses the complete JDK 25.0.4.1. A reviewer's initial attempt to run
Gradle's Java 25 test classes on Java 21 failed correctly and is retained;
the explicit release-21 recompilation then passed. Do not conflate those runs.

Meaningful baseline controls reproduce wrong traversal, cross-stage publication
cleanup deleting the new source, and a directory final target being moved before
cleanup throws. Fixed controls reject before mutation, preserving all sentinels,
stages and the directory child. Real links/hard links, all six path-pair aliases,
NOFOLLOW stage checks, dangling output links/rollback, missing/invalid parents,
nonregular targets and cancellation/failure regressions pass. Windows tests use
host lookup as their oracle and do not silently skip missing link capability.
Native Windows acceptance remains pending.

Final real fixture `build/test-results/path-traversal/run.ua6ucr7i` uses the
installed wrapper and saved curated Program. All four cases pass two exports:
traversed input, traversed output, input-leaf default names and output-leaf
replacement. The artifact-bound reports select exact intended paths and hashes;
input/reference/lookalikes and link referents remain unchanged. Both `.dbg` and
`.dbg.c` repeat byte-for-byte. GDB from an unrelated directory resolves the exact
source fullname and analyst signature, prints `19`/`23`, observes return `42`,
executes next/step and exits normally. Installed production-script origin is
verified in all eleven export/rejection transcripts. Two alias negatives and a
missing-input-parent negative pass with no published artifact or sentinel
changes; the latter has `--input` and no misleading `--output` hint.

GNU/LLVM pass with empty stderr; GDB stderr is empty. Exact code-index and its
negative controls pass. Strict libdwarf retains four exactly corroborated
inherited frame diagnostics per case, with zero unexplained errors. The same
verified pinned checker used for the preceding stack regression is required
through `DWARFDUMP`, not a system-tool fallback.

The saved-program oracle inventories every file and requires a real `.gbf`.
Only `PathTraversal.rep/idata/~index.bak` and `~journal.bak` may differ; every
other addition/removal/change fails. Final `.gbf`, live indexes and properties
remain byte-identical through all eight exports and three negatives. Initial
`run.9timcjtk`/`run.7myq952c` failed an overbroad whole-project assertion. The
latter records only replacement of the index backup and removal of the journal
backup; pinned `IndexedLocalFileSystem` explicitly rotates those files. Its
source digest/excerpt is retained in
`build/path-traversal-review/project-housekeeping-source.txt`. This is precise
program-database preservation, not unchanged project-directory bytes.

Baseline `run.hiu23mk3` uses unchanged stack-guard JAR `0bffbe24632d077f9c25a8e6f2f17e8cae9b84ac0c7884d3e93a01ea264ef181` and requires
two wrong-input FATAL results plus two wrong-directory exports. Its exported
artifact still validates and works in GDB, demonstrating why artifact validity
alone does not prove correct destination selection. It is explicitly a
`BASELINE-REPRODUCED` outcome, not a successful fix. Intermediate fixed JAR
`bd090c67e803c38f7ea2545ad54a6549416c10a9cfd8d1add370f5b1f9ac7b49` run `run.r1m2kptu` passed before the diagnostic follow-up; final
acceptance above is tied to JAR `14c6fb2e4a89a98888570873e27790761ea3785c543dc1fc6fa4f43dd19f47f3` and the final installed script.

The isolated direct-native probe
`build/path-traversal-review/direct-native-yd0wje9q` independently supplies raw
traversed input, library and output paths to the public exporter/source APIs.
Final-JAR native runs preserve original bytes and repeat validator-inspected
outputs exactly. GNU/LLVM/strict checks and GDB exact source fullname/list,
entry breakpoint and normal exit pass. The directory lives in the DWARF 5
line table, not a CU `DW_AT_comp_dir`; an initial info-only assertion was wrong,
was retained, and was corrected to check the actual line table. Full signature
and value acceptance belongs to the separate headless fixture above. Exact final provenance is in
`build/path-traversal-review/final-hint-java21-result.json` and the probe's
`final-hint-{first,repeat,llvm,gdb}` logs. The probe's older `result.json`
intentionally names intermediate JAR `bd090c67...`; it is retained historical
evidence, not the final-JAR record.

Representative commands:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
    ./gradlew pathTraversalSmoke outputPathPolicySmoke artifactPairPublisherSmoke \
    syntheticSourceSmoke exportReportSmoke packagedNativeLibrariesSmoke buildExtension
src/test/integration/headless-wrapper.sh
src/test/integration/architecture-neutrality.sh
DWARFDUMP=/path/to/verified-pinned-dwarfdump \
    python3 src/test/integration/path-traversal-export.py /path/to/private-fixed-ghidra
```

Independent source/fixture reviews and final runtime audit are clear. Evidence:
`build/path-traversal-review/independent-closure-audit.json`, the standalone
results, final Java 21 results and `build/path-independent-review/` controls.
Workflow lint, wrapper log-collision regressions, Python syntax and whitespace
checks pass. The pipeline adds one Linux x86 runtime fixture and a focused smoke
on Linux/native Windows while retaining all existing architecture and host
lanes. Its exact-head full gate and candidate-package audit are still required.

### PR #30 exact hosted acceptance

**CONFIRMED:** exact head `fb2fa406908822fe4ced131da843ad5dc31df1b7`, run
`40081385807`, is a completed pull-request attempt 1 with all twelve expected
jobs successful and none skipped. Package artifact `12555706337` has archive
SHA-256 `2dabdd729904feeef583c1ddcb03d0cbf1a8844170af9e066089ba1f8f3d2991`;
release ZIP `f307eecf89a2869a7df42ee7f54f224232e1bd2dbf011748376363121c94a47b`
and JAR `3af84d8eff21cf2d0c5f01776c04a679f82bad3eba25a173d11ce39290595f04`
pass exact 33-source/two-script checks, five manifests, native provenance,
138 Java 21 classfiles, guarded Java 21 smokes and 20 producer lifetimes.

Independent artifact review verifies all six new stack roles/twelve exports,
exact local DIE/report policy, compiler/Forge observations and zero-offset
values, preserved hashes and identical repeats. Related copy/prefix/floating,
AArch64 opaque and ARM32 floating cases pass. Forty-six relevant strict reports
were independently reparsed with exact inherited-section/message corroboration
and zero unexplained errors. MIPS target jobs pass; their PR #30 artifacts were
not separately manually reviewed. Runtime exporter hashes match the audited JAR.

Linux GUI `run.7JrIbn7v` passes controls/geometry, actual Script Manager,
selection/cancellation/Console, validators and GDB with empty diagnostic
streams. Windows artifact `12555644141`, SHA-256
`86470a62247e4d0d920c18e0c95b5001810872d887b2457880e573653c17a715`,
proves all eleven focused smokes and actual GUI
`run.4531e95ac2374eb79cd026e997c3ce10 GUI paths`: controls/ACL,
selection/cancellation/Console, GNU/LLVM, original hashes and empty stderr.
Independent libdwarf and Linux ELF runtime remain unavailable on Windows.

Source/gate/package review and runtime/GUI review are clear. Evidence is in
`stack-first-use-guard/build/stack-first-use-package-audit/` and
`gui-script-manager/build/hosted-gui-review/run-40081385807/`. Normal merge
`74a7466a6ff03f44b143bad0e764d65c1e11d521` preserves the exact tested tree;
its distinct main-push gate remains pending. Earlier main run `40081314935`
for PR #29's merge now also passes all twelve jobs and both GUI artifact
reviews. Neither published alpha changes.

The path candidate's first local exact-package audit rejected
`dcf310f1f278073a047ef9200a4500236e4640a10f476884deadfe08aff68868` because
its base extension ZIP preceded two documentation precision edits. Rebuilding
the extension before assembly produced
`06ec77fe4c0c2f62b8ae4dbf4acecfdc110d66235cdfa1c94a68ca2ee64bab1a`,
which exactly matches then-frozen commit `83adf3c` across 34 sources, two scripts,
support/docs, five manifests and 139 Java 21 classfiles. JAR/script/native bytes
were unchanged, so no runtime retest was attributed to this docs-only rebuild.
Both audit outcomes are retained under `output-path-traversal/build/path-package-audit/`.
That local audit does not substitute for the path PR's forthcoming exact hosted
package, which also includes this later acceptance record.

### Windows trailing-dot candidate refinement

PR #31 head `50e0a4` and run `40083416513` are intermediate evidence only.
Its exact package audit passes (release ZIP
`5ee1205f7080a89fc993b71f841f94a6c33a5514db4bb0236bdf0cb9276da82f`,
JAR `ceb60af72366cfb2da9e0c6076b54af5fd5080a78b76a6409847a3d02f70cfb1`),
but late review identified an untested native Windows absent-leaf alias.
No earlier passing package/target/GUI result is attributed to the updated head.

The bounded follow-up changes only `FileSystemPaths` and its focused smoke:
Windows file leaves ending in dot/space are unsupported rather than trimmed;
Unix legal dotted filenames remain distinct. The native Windows test requires
one actual short-path `out`/`out.` entry with identical sentinel bytes/file
identity, records Java/OS/path evidence, then checks both target orders and both
publisher APIs. Existing staged files and unrelated sentinel hashes/timestamps
must remain intact, callbacks must not run, and no output/temporary entry may
appear. The current Windows JDK may reject a trailing-space path at construction;
that explicit provider rejection or the policy rejection is checked. There is
no silent skip or new 8.3/arbitrary-filesystem alias claim.

All five configured focused smokes/build and explicit `--release 21` tests on
actual Java 21.0.12.1 pass on Linux. The final candidate JAR is
`125d6753d0f16e97af04c2c99d5d70ee1740f671d580ffda24c90bd2b4b1447b`;
all 139 packaged classes match the tested bytes and major version 65. Evidence:
`build/path-traversal-review/windows-dot-java21/result.json` and
`windows-dot-configured-build.log`. An initial invocation without
`GHIDRA_INSTALL_DIR` failed before compilation and remains in
`windows-dot-build.log`. Native Windows behavior is still **UNCERTAIN** until
the new hosted probe succeeds. The preceding eight Linux exports remain
recorded for their exact pre-refinement JAR; updated-head CI will run the full
runtime fixture again. Script bytes and native bindings/provenance are unchanged.

The intermediate `50e0a4` run `40083416513` failed at the standalone timestamp
harness's `javac` step: its explicit source list omitted the publisher's new
`FileSystemPaths` dependency. The same omission exists in candidate `ffe6c81`;
neither run is accepted as the final gate. Adding the helper to that source
list passes the full local timestamp regression in `run.n90Mvxpa`, using
`DWARFDUMP` set to the pinned compression-capable checker. GNU/LLVM and GDB
pass, with two corroborated inherited frame diagnostics and zero unexplained
strict errors. The publication warning disappears, a later source edit still
warns, typed values/stepping work, and original bytes/mtime remain unchanged.
Exact updated-head package, native Windows alias and complete CI evidence are
still required; the implementation and packaged production bytes are unchanged
by this harness-only correction.

### Windows short-parent oracle follow-up

**CONFIRMED:** `e465e07` / run `40085186824` passes all five target lanes and
the exact package audit. The corrected timestamp check, new path fixture and
Linux Script Manager journey pass. Independent x86 artifact `12557765728`,
SHA-256 `bc2a4193fb6e8e1594bc1da805211b543eb252cbdd79c046e4ac0e7639e50329`,
proves path `run.iepckxq7` (eight exports, three rejection cases), timestamp
`run.23cF4CZi` and GUI `run.dBhFyP46`; 24 relevant strict reports have zero
unexplained errors. JAR/script hashes match the exact audited package.

The complete run nevertheless fails native Windows before `PathTraversalSmoke`.
Failure artifact `12556703937`, SHA-256
`a15aac78efa714cec8ea55cfe99bab4f1c97158f99596296414bbe53ca7b8b01`,
records `OutputPathPolicySmoke` expecting a short `RUNNER~1` temporary parent
while production correctly returns its canonical `runneradmin` spelling.
Only the preceding address-normalizer smoke passed; the new alias controls and
Windows GUI did not run. This candidate is intermediate evidence, not acceptance.

The correction keeps the raw temporary/input paths as production arguments,
derives the real directory independently, and checks all five exact literal
filenames plus `Files.isSameFile` for the input. It records both parent spellings
and an `output-policy-existing-parent=PASS` marker. Production and published
artifacts are unchanged. Configured Linux and actual Java 21 checks pass in
`build/path-traversal-review/windows-parent-configured.log` and
`windows-parent-java21/`; independent source review is clear. The updated exact
package, native Windows alias/GUI evidence and full twelve-job gate remain required.

## Streamed digest foundation (2026-10-24)

**CONFIRMED locally; hosted gate pending:** production commit `e74b1b7` adds
`FileDigests` and replaces the two private SHA loops with thin callers. The
JAR SHA-256 is `25becac3eec70ff1c9c405a74dd98b7ea9eda232406ae1593c577566eff94644`;
production script SHA-256 is
`3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
The private runtime ZIP is
`2744ff2573b63f42131feb1455527fe52f6f5ce06650b6f876bde27cb7e09323`.
It predates this acceptance text; final package review must use a fresh build.
All five manifests pass and the source Ghidra installation is unchanged.

`fileDigestsSmoke`, native-library checksum/tamper, export-report, output-policy,
path-traversal and pair-publication checks pass through Gradle and separately
on actual Java 21.0.12.1 using `javac --release 21`. All 142 packaged classes
match the tested bytes and have major version 65. Initial compilation tried
the local runtime-only Java 21 directory and failed because it lacks `javac`;
that setup failure is retained. The completed checks compile with JDK 25 and
execute with Java 21, rather than attributing the Gradle runtime to Java 21.

Nine fresh headless exports cover executable, PIE and absent build ID on
x86-64, AArch64 and MIPS32 big-endian. GNU/LLVM, exact code-address-index controls
and QEMU/GDB behavior pass. Strict libdwarf reports x86 inherited error counts
3/1/3 (exec/PIE/no-build-ID), AArch64 5/5/5 and MIPS 0/0/0, all exactly
corroborated with original frame bytes/diagnostics and zero unexplained errors.
Local headless uses the complete JDK 25. Packaged-native path tests additionally
pass eight saved-program exports and three negatives, exact output/report
hashes, source lookup, typed values/stepping, preserved input/program databases
and identical pair reruns, retaining only the two documented Ghidra backup-file
exceptions. These exercise the shared native checksum caller in a real export.

The installed-JAR digest oracle passes in `x86_64.7u0baef5`,
`aarch64.av6bgmlu` and `mips32be.cqscp2f6` under
`build/test-results/file-digests/`. Each requires the actual production class
origin and installed script transcript, then checks report paths/hashes against
independent Python observations for all nine original/sidecar/source files.
GNU `objcopy` uses explicit owned output paths. Its exact debuglink basename,
padding and target-endian CRC match the helper and Python `zlib`; explicit
class/endianness/machine assertions prevent a mislabeled fixture from counting
as another target. All protected bytes/mtimes and the installed JAR are unchanged.

The x86 sparse input has 2,147,614,787 bytes and nonzero boundary/tail markers.
Two actual Java 21 runs use a maximum heap of 67,108,864 bytes and agree with
Python `hashlib`/`zlib` and GNU `sha256sum`: SHA-256
`48da45d2cb6bfe6de79a3a91613cddfe7b892c019514168c7a89fb5c251723ed`,
CRC32 `f00f4493`. The large file was removed; layout, hashes and commands remain.
Automatic-association run `run.azEoJZMi` independently passes the existing
three-target build-ID/debuglink/CRC-rejection GDB tests, including x86 runtime.
This is compatibility evidence on private copies, not a product attachment.

Source and oracle reviews are clear. Evidence lives under `build/digest-review/`
and the named `build/test-results/` directories. Workflow lint, architecture
guard and syntax checks pass. CI adds the focused smoke to both hosts and the
installed CRC oracle to all five target lanes; only Linux x86 runs the large
case. Native Windows and full exact-head package/hosted acceptance remain
pending. P2.8's receipt/identity/backup/refresh transaction and all published
release artifacts remain unchanged.

## Read-only build-ID observation foundation (2026-10-24)

**CONFIRMED locally; hosted gate pending:** production commit `72d41da` adds
the observer and isolated note-format table; the only `ElfImage` change exposes
its existing bounded source read within the package. Ordinary export has no
call to the observer. JAR SHA-256:
`04398abf04201525fcfeffcf31485ae11fded7b1f9909c199e234f1db8c7cd8c`.
Initial private ZIP `d87eadc05c7d3b67cc32a381c56708aa78eea9caed4567fa42d755163efa2f88`
predates this documentation; final package review must use a fresh build.

Pinned GNU 2.42 source/provenance and tool probes establish eight positive
width/endian/alignment cases with nonzero padding and sixteen malformed-padding
controls. GNU exits zero for these warnings; the oracle treats the diagnostics
as failures. Peer review additionally reproduced a real ID displayed from an
IA-64/OpenVMS 24-byte header while the first observer returned absent. The
final isolated format exclusion rejects that exact case, with both-endian and
paired-discriminator controls. No unsupported architecture is advertised.

`elfBuildIdSmoke`, `elfImageReaderSmoke`, `fileDigestsSmoke`, extension build,
architecture guard and whitespace checks pass. The new smoke separately passes
on actual Java 21.0.12.1 using `javac --release 21` and `-Xmx64m`: immutable
provenance, exact/over-limit cases, overlapping views, conflicting IDs, extended
section/string/program counts, late/high-offset notes, cancellation, ordinary
source-change detection and closed channels. These are observations rather
than atomic snapshots or a stronger file-identity guarantee.

Final independent installed-JAR oracle runs are `x86_64.o3ne2_54`,
`aarch64.uefa5721` and `mips32be.hxwxg8jf` under
`build/test-results/elf-build-id/`. Each consumes three previously validated
executable/PIE/no-build-ID pairs from the digest worktree, checks exact target
class/byte order/machine, loads observer and ELF-reader classes from the private
release JAR, and runs on actual Java 21 under a 64 MiB heap. ID values, physical
duplicate counts and all five relationship outcomes match independent GNU
observations. Typed nameless sidecars, sectionless originals, renamed sections,
vendor decoys, repeated identical IDs and conflicting/malformed owned variants
pass their required positive or rejection checks. Every probe preserves input
bytes/mtime, and all original pairs, sources and the installed JAR stay unchanged.
This does not reattribute the earlier artifacts' DWARF/GDB acceptance to a new
export from the observer package.

Initial `x86_64.0p8v1jtt`, `aarch64.54rkrphf` and `mips32be.61gb2tdi`
stopped on GNU's `no .dynamic section in the dynamic segment` diagnostic for
nameless dynamic originals, despite displaying their correct note IDs. The
nameless positive now uses the actual sidecar, which has no program headers;
GNU diagnostics remain strict. Intermediate successful runs before per-probe
mtime checks are retained separately. No diagnostic was silently ignored.

Source/provenance and focused evidence are in `build/build-id-review/`.
The pipeline adds the observer smoke on both hosts and the installed GNU oracle
to all five existing target lanes. Native Windows and full exact-head hosted
acceptance remain pending. The earlier path-parent test correction must also
be integrated from its accepted parent before this candidate's hosted gate.
No attachment option, executable rewrite or release publication is added.

## PR #31 exact hosted acceptance (2026-10-24)

**CONFIRMED:** head `3632f2b581e3080e92567b0e00479c4f38b00cdb` passes all
twelve expected jobs in pull-request run `40087258846`, attempt 1, without
skipped jobs. Independent source/package and Linux/native Windows artifact
reviews are clear. Normal merge `00aaba161c5663556302c10da658ddab88b96d92`
at `2026-10-24T11:16:51Z` preserves the tested tree. Its separate main-push run
`40089265777` is pending at this checkpoint.

The exact package artifact `12557528240` has download SHA-256
`7c3e395ba21a2edc791de2ab669bad3070f26a35b0095740cdfb1f89b3b72974`.
Its release ZIP hashes to
`8dfc572c70ddb8dead8813ad8aaced4998c292148f0f002ff216f80235a3ea9f`,
JAR to `11d98a42591196b3aac0760648e479539ebc10c70cc59d4ad7f8cd369537289f`,
and production script to
`73c11b45f6f87cd93df7e011964699cf2172638bafc5bc2a2f0333433c51a1c2`.
All 34 production sources, two scripts, support/docs, 139 Java 21-compatible
classes, five manifests and pinned native provenance match the exact source.
Actual Java 21 checks, twenty isolated producer lifetimes and 67 class-origin
checks pass. Evidence: the path worktree's
`build/path-package-audit/run-40087258846.Wm5FGOa6/` and final gate records.

- Linux artifact `12557807726`, SHA-256
  `6e659525bacf483dbbdc0f5029b87eb9e7519dd4f2b61c1b1f7c1e29e19c640c`:
  path run `run._lvr55m0` passes four cases with two exports each and three
  rejection controls; timestamp `run.m26PftBW` and GUI `run.8xu20lvD` pass.
  All eleven path invocations bind the exact protected JAR/script and report
  their installed origins. Independently reparsed strict reports have zero
  unexplained errors. All eleven saved-project inventories and final database,
  live-index and property bytes match except the documented two exact backup
  files. GUI control/100-window geometry, Script Manager, chooser select/cancel,
  Console, validators/GDB and input preservation pass.
- Windows artifact `12557934070`, SHA-256
  `1205197f68ec10264c5665d97220a4bdffefab39fa3149d4a6f4b170cf3c8613`:
  actual Java 21.0.12.1 on Windows Server 2025 passes all twelve focused checks.
  Requested `RUNNER~1` and actual `runneradmin` parents resolve to the same file
  with literal expected filenames. The real trailing-dot alias is confirmed;
  both publisher APIs reject both target orders before callbacks, timestamps
  or cleanup, retaining all six sentinel hashes. Trailing-space rejection and
  all link/rollback controls pass without skips. GUI
  `run.bb9d10050d9b4f90adeff51dbbf8f433 GUI paths` passes discovery, native-free
  preflight, export/select/cancel, Console, ACL/input preservation and GNU/LLVM.
  Independent libdwarf and Linux-ELF runtime remain unavailable in this host
  lane; no Windows GDB runtime claim is made.

All five target jobs pass CI. Their cross-target archives were not separately
inspected in this PR review. Both GUI artifact reviews are retained at the GUI
worktree's `build/hosted-gui-review/run-40087258846/acceptance-scope.json`.
No review thread remains unresolved. This supersedes the earlier missing-helper
and stale-parent-oracle candidates; their failures remain recorded above.
PR #30's distinct main-push `40083338151` also subsequently passed all twelve
jobs and both GUI artifact reviews, superseding its pending-main checkpoint.
No release asset changes.

## Combined read-only foundations, fresh local regression (2026-10-24)

**CONFIRMED locally; exact hosted gate pending:** digest and build-ID components
are tested together, using frozen source `40aa249` and reviewed package
SHA-256 `8b17d98136c348258e3c7770709c2b54b5bf189b188f9bdf0aa57d16e4b47e34`.
The installed JAR is
`04398abf04201525fcfeffcf31485ae11fded7b1f9909c199e234f1db8c7cd8c`; the
script is `3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
The package audit matches 37 production sources, two scripts, support/docs,
153 Java 21-compatible classes, five manifests and pinned native provenance.
It contains no private JNA. The fresh runtime installation is
`build/build-id-review/ghidra-combined`; original Ghidra launch configuration
SHA-256 remains `7704bd03868adab49901de813d62b0f4c6ebc52372e0fe505112c5617fc665e8`.

| Check | Observed result |
| --- | --- |
| Fresh semantic exports | Nine source-built cases: ET_EXEC, PIE and absent build ID on x86-64, AArch64 and MIPS32 big-endian. GNU, LLVM, strict libdwarf, code-address controls and native/QEMU GDB pass. |
| Strict inherited diagnostics | Exec/PIE/no-build-ID counts are x86 `3/1/3`, AArch64 `5/5/5`, MIPS `0/0/0`. Each permitted frame diagnostic matches original bytes and exact messages; zero unexplained errors. The GDB oracle permits only its exact known AArch64 vDSO warning. |
| Saved-program path workflow | `run.kpaqvews`: eight fresh exports, four byte-identical pairs, three fatal rejection controls, exact paths/hashes, source/value/step behavior and original preservation pass. Four inherited frame diagnostics per positive case; zero unexplained. All eleven database inventories plus final state preserve everything except the two documented backup files. |
| Installed digest oracle | Fresh-pair runs `x86_64.jyoltydc`, `aarch64._hxp695z`, `mips32be.bppyhu2q` pass independent Python/GNU comparisons, repeated reads and input bytes/mtimes. |
| Large digest case | x86 repeats the 2,147,614,787-byte input under actual Java 21 and `-Xmx64m`. Full Python/GNU SHA agrees with `48da45d2cb6bfe6de79a3a91613cddfe7b892c019514168c7a89fb5c251723ed`; CRC32 `f00f4493`. Marker layout and removal of the temporary input are independently checked. |
| Installed build-ID oracle | Fresh-pair runs `x86_64.f9navmv_`, `aarch64.ebsya__2`, `mips32be.loeg8vpp` pass GNU ID comparisons, all five relationship outcomes, typed/nameless/sectionless/duplicate controls, exact negative diagnostics and protected bytes/mtimes. |
| Existing association harness | `run.rhUIWr0G` passes all three roles on all three targets. Runtime checks here are x86 executable build-ID/debuglink and no-ID explicit loading; other association cases prove strict symbol/type/source/address lookup. The nine semantic tests separately cover target runtime. |

Headless Ghidra uses the complete local JDK 25. Actual Java 21/64 MiB evidence
is attributed to the standalone helper and focused checks, not to that headless
process. Commands/transcripts are the `combined-export-*`, `combined-gdb-*`,
`combined-path-runtime.log` and `combined-association.log` records under
`build/build-id-review/`, with the corresponding oracle result directories.
The final independent audit `combined-runtime-audit.json` accounts for all
seventeen fresh exports and three rejections, checks exact package/origins,
manifests, diagnostics, database snapshots and both independent oracles, and is
clear. Earlier component results remain tied to their original packages.

Normal merge `409c029` then incorporates accepted PR #31. Relative to `40aa249`,
production Java, Ghidra scripts, build and workflow files are unchanged; only
the corrected Windows parent oracle and additive incident records arrive.
That oracle passes actual Java 21 against the combined JAR in
`combined-parent-java21/`. Final documentation/package matching and the full
hosted matrix remain required: fourteen Windows focused checks, both installed
helper oracles in all five target lanes, and both GUI hosts. This is a read-only
foundation; attachment, receipt parsing, stable file identity and readiness
remain unimplemented. Published alpha.2 remains unchanged.

## Combined-oracle report-generation isolation (2026-10-24)

**Failed initial hosted gate:** PR #32 head
`65f5bb8723ca0461af5cc973b649ba9a0e358468`, run `40089908416`, attempt 1,
has nine successful jobs, failed x86/aggregate and skipped Windows. Its package
precheck is independently clear: artifact `12558697497`, download SHA-256
`d7152317b4a0aabb3c2eb16409598c2e119840a32bdfa6d51af0464f6c239bc5`, release ZIP
`dd8146d43ca90e38ee622be215519d7cc281e2962dc841da0a8b7a10a19523a3`, JAR
`f3b123fa4693eda94d9b84a99b6148d1cdbbefdd418539d5cf6ffeeea0a81307` and script
`3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
All 37 sources, 153 Java 21-compatible classes, manifests and native provenance
match; actual Java 21 focused checks, twenty producer lifetimes and 83 class
origins pass. This package result does not accept the failing integration head.

The four cross-target jobs and both new helper oracles in each artifact pass
independent review. The x86 artifact `12559112653`, SHA-256
`90acd9294fab51fbc77843230d48b3ae94599e412aab773e33380c1760cd4f48`, proves the
failure: repeated Java digests agree with Python, but the shared exec report
names `semantic.exec.stripped.dbg`, SHA-256
`4651382fed80e9a045d05003b07e1c717b6969d5e6c8a1f9dcf24d66349c9428`.
The ordinary pair is `semantic.exec.ghidra-forge.dbg`, SHA-256
`cbf02d77c03b32f8aeb42bb04baf262138f3fbc98c6a946cc37f21fae96e3eac`.
The source bytes agree but their paths differ. PIE/no-build-ID report bindings
match. `output-path-policy.sh` invokes the shared exporter with default output
and overwrites `headless-symbol-export/x86_64.exec.log` after the ordinary pair
was produced/restored. The digest oracle correctly rejects that report mismatch.

The x86 large-file digest and build-ID oracle were not reached; Windows was
skipped. Earlier Linux GUI `run.XGnQjNXL`, traversal and 24 strict reports pass
as component evidence only. Full failure metadata, downloaded artifact and
diagnosis are retained in `build/build-id-package-audit/failed-target-40089908416/`
and the GUI worktree's `build/hosted-gui-review/run-40089908416/`. No missing or
skipped check is counted as passing.

**CONFIRMED local correction; new hosted gate pending:** move both helper
oracles immediately after the six-role primary export/GDB step, preserving
every later gate and assertion. The digest oracle reads each transcript once,
retains its exact UTF-8 bytes as `<role>.export.log`, and records its source,
retained path and SHA-256. Later tests can reuse their own shared paths without
changing the evidence consumed by these checks. Production Java, native code,
export behavior and report schema are unchanged.

Independent source review, workflow lint and Python syntax pass. Local replay
against the unchanged installed `04398abf...` JAR passes on actual Java 21:
`x86_64.seo92nr6`, `aarch64.7_jd4j7p`, `mips32be.lckj930j`. All nine retained
transcripts match the original validated logs. An owned derived control changes
only exec report output names to the default-output spellings; the unchanged
path/hash assertion rejects it. Overwriting that owned source-log copy leaves
the earlier retained transcripts intact. All original evidence logs and fixture
bytes/mtimes remain unchanged. Reproduction and result are
`build/report-order-review/check-retention.py` and
`retention.40kvd6hd/result.json` beneath that directory. This is a harness
selection/retention replay on already audited exports, not new export/GDB or
large-file execution. The full updated hosted gate remains required.

## Read-only current report claims (2026-10-24)

**CONFIRMED locally; exact hosted gate pending:** production commit
`3d1c62c3a9b0182f9670d672e4627d49731ab415` adds the immutable claims reader
and a bounded lexical guard ahead of supplied Gson 2.9. The current writer and
ordinary exporter are unchanged. The reader opens only the supplied report;
path/hash/target/count/native-version values remain reported claims, and
validation remains `NOT_RUN`. Valid terminal reports are distinguished from
malformed reports and unsupported historical schema-one shapes. See
`EXPORT-REPORT-CLAIMS.md` for the exact scope and limits.

The provided dependency is Ghidra 12.0.3's
`Framework/Generic/lib/gson-2.9.0.jar`, SHA-256
`c96d60551331a196dac54b745aa642cd078ef89b6f267146b705f2c2cbef052d`.
The earlier read-only research audited the pinned upstream `JsonReader.java`,
SHA-256 `1fd32e5161484c3a05f9e88b35dc63082bfdd487bc56cf354cfe1c10bf552cb5`.
Nonlenient mode alone accepts some invalid literal/string forms and cannot
bound token growth. The new guard checks lexical/UTF-8 bounds while Gson retains
object/array grammar and decoding responsibility; no private dependency is added.

| Check | Result and evidence |
| --- | --- |
| Writer-derived focused smoke | All four statuses, reordered fields, uppercase hashes, opaque paths, independent count semantics, unsigned failure addresses and empty allowed strings pass. Every object/field receives missing/unknown/duplicate/type/nullability controls; 429 malformed controls pass. |
| Default resource boundaries | Exact/over 64 MiB bytes, 65,536 UTF-16 string units, 250,000 array entries, one million values and depth eight pass under `-Xmx64m`. Large inputs stream; tests do not build a large JSON tree to satisfy the reader. |
| Failure and cancellation | Cancel before open/during reads/after EOF, supplier failure, zero/invalid read counts, open/read/close failures and primary/suppressed ordering pass with exactly one owned-stream close. Only the supplied report path reaches the opening seam. |
| Build and actual Java 21 | Reader, existing report, output-policy and digest smokes plus `buildExtension` and architecture guard pass. Tests separately compile with JDK 25 `--release 21`, then all four run on actual Java 21.0.12.1 with `-Xmx64m`. Exact commands/logs are under `build/report-claims-review/java21/`; source hashes and peer review are in `source-acceptance.json`. |

The preliminary packaged JAR is
`37a37df922014cf0716e980f90e63689a0aafaee0dc5d21afaa5c00437d754b8`, unchanged
through the final focused tests. Package SHA-256 is
`17a47a196b794bf08e5965ce6eb10699a87a64d43e56062a566c3eb11aa114cb`.
It is installed in `build/report-claims-review/ghidra`, with all five manifests
checked and the original Ghidra launch configuration unchanged. This package
predates the final documentation and is runtime evidence, not a final source/
documentation package match.

Installed-reader oracle runs `x86_64.tw9tn8ig`, `aarch64.l4i0tlia` and
`mips32be.0l8b__ra` each read three actual retained exporter reports twice,
compare all returned fields with independently decoded JSON, and exercise two
opaque/reordered positives plus 23 rejection controls. They verify installed
reader and provided-Gson origins, actual Java 21/64 MiB, exact ELF fixture
profiles, all sixteen protected file hashes/mtimes, extracted-report bytes and
producer package provenance. Valid terminal/status and unsupported-shape
exception types are asserted separately from malformed-terminal rejection.
FIFO/foreign/nonexistent artifact paths and uppercase hashes remain literal;
no referenced artifact is opened. The owned FIFO is removed in `finally`, also
on failure, so artifact upload cannot block reading a retained special file.

These runs explicitly name the earlier combined exporter installation and its
`04398abf...` JAR; `same_reader_export_installation` is false. The reports come
from that previously audited nine-export run. No new headless/GDB execution is
claimed for this read-only parser. Independent source, smoke and oracle review
is clear, including rehashed protected files, repeated claims and Unicode values.

**Historical failed oracle controls:** the initial x86/AArch64/MIPS attempts
successfully read the real reports but failed the opaque Unicode comparison.
Java's standard output under `LC_ALL=C` substituted `?` for `é` and the emoji in
the adapter's JSON output. The reader preserved the values. Encoding the adapter
payload explicitly as UTF-8/Base64 fixes the transport; the same installed
production JAR passes. Initial transcripts and the corrected transcripts remain
under `build/report-claims-review/`. No production parser fix or silent
diagnostic suppression was attributed to this harness failure.

After the separate PR #32 run exposed reuse of primary log names by a later
default-output regression, this reader oracle was also placed beside both
read-only helpers immediately after primary exports. It now retains all three
consumed full transcripts and all nine independently checked fixture byte
copies, alongside its extracted reports. Preservation snapshots describe this
invocation, not a promise that later tests never reuse original paths. Final
retention runs `x86_64.fmhmew9m`, `aarch64.ccvr7mki` and `mips32be.yh95ftq5`
pass the same actual-Java-21 comparisons and 23 rejection controls with the
unchanged `37a37df9...` reader JAR. Earlier runs remain separately attributed.

Final documentation/package matching, accepted-parent integration and the
complete hosted gate remain required. CI adds the focused reader smoke to both
hosts and the installed oracle to all five target lanes; the Windows focused
list grows to fifteen. Existing exporter/GDB/GUI checks remain required. P2.8's
attachment/receipt/identity transaction and published alpha.2 are unchanged.

### PR #31 post-merge main confirmation

Exact main `00aaba161c5663556302c10da658ddab88b96d92` push `40089265777`,
attempt 1, subsequently passes exactly all twelve jobs. Independent Linux
artifact `12559350094`, SHA-256
`070d6026a5273a4f306891a34f6a8aed78bf794730f46b002bddbba7b0061241`, verifies
GUI `run.DQaHs2E2`, path `run.533ev5__` (eight exports/three negatives/eleven
project checks), timestamp `run.Jt1S3CrH` and 24 strict report replays. Native
Windows artifact `12558414467`, SHA-256
`4e94f1890bddd6500204670e3f80f9186dea47da20d934ab431e1055dfc15ea0`, verifies
all twelve focused checks, actual short-parent/dot-alias/both-API/order/six-hash
controls and GUI `run.fa24221a64f84c9a87e67fef8e799444 GUI paths`. Both host
reviews are clear; cross-target claims here remain CI conclusions. Evidence is
retained in the GUI worktree's `build/hosted-gui-review/run-40089265777/`.
This supersedes the earlier pending-main checkpoint for PR #31 only.

## Read-only foundations hosted acceptance (2026-10-24)

**CONFIRMED:** PR #32 corrected head
`c94158b34bfd8e848b89eecae553fe9255198e48`, pull-request run `40091937766`,
attempt 1, passes exactly twelve expected jobs with no skips. Independent
source/package and all-five-target plus Linux/native Windows artifact reviews
are clear. No review thread remains unresolved. Normal merge
`7f9c0d2606a8f7db0007b256d256e6edb49dd473` at `2026-10-24T12:27:43Z`
preserves the tested tree. Its distinct main-push run `40094022212` is pending
at this checkpoint; no result is inferred for that separate run.

Exact package artifact `12559024704` has download SHA-256
`21bd10299f2acd12dc792c85ca3fd54edb07b8707b5a56e497ae498369e1b89c`.
The release ZIP is
`ddc8b395461fa148ec7da2bbf89ae7cc3a999aeb3bebfc53e322fde5c5376f53`, JAR
`f3b123fa4693eda94d9b84a99b6148d1cdbbefdd418539d5cf6ffeeea0a81307`, and script
`3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
All 37 production sources, two scripts, current docs/support, 153 Java
21-compatible classes, five manifests and canonical native provenance match.
Actual Java 21 focused checks, both new helpers under a 64 MiB heap, twenty
producer lifetimes and 83 downloaded-JAR class origins pass. Evidence:
`build/build-id-package-audit/run-40091937766.WSqW0TED/` in the build-ID worktree,
with final source/job/review-thread records alongside it. Native bindings and
`VERSION` are unchanged.

| Target artifact | ID | Verified download SHA-256 |
| --- | --- | --- |
| x86-64 | `12559763343` | `abe8f70a2df34eda0e29b8b2b6e655672da543a3a12f7ecfa7a6f57d24006b68` |
| AArch64 | `12559424039` | `f6512fa737f4f2ed9bee9182b5af4c5f9af843ee7cd2ae5067fae1fcbfb48748` |
| ARM32 | `12559747059` | `b842c901bb7193c141fb4cdbbef16346efc9287bee256625d9d1bf6fd1d59be3` |
| MIPS32 big-endian | `12559372256` | `5a88c1eaa36ce2f29e2003695fbbb9e946d3fda86484bee0c2caf88452726f7d` |
| MIPS32 little-endian | `12559831650` | `e9d936fc7ed348c2d4893a817f2e21ab2121433884b5d9fb0e3da52667f0da0c` |

Both installed helper oracles pass independent review in every target artifact:
all fifteen exact consumed transcripts are hash-verified, all nine reported
input bindings per target agree with Python and repeated Java digests, GNU
debuglink payloads have exact target-endian CRC bytes, and typed-note variants,
relationships and precise rejection controls pass. Actual Java 21/64 MiB and
the installed JAR origins are verified. Eight of nine raw digest inputs per
target were separately retained and rehashed; the no-build-ID original is
corroborated by the report/Python/two-Java records rather than falsely claimed
as an independently retained byte copy.

The x86 2,147,614,787-byte layout was independently reconstructed and hashed:
SHA-256 `48da45d2cb6bfe6de79a3a91613cddfe7b892c019514168c7a89fb5c251723ed`,
CRC32 `f00f4493`. Both Java passes and GNU SHA agree. The artifact also proves
the later shared exec log contains the default-output report while the
preserved consumed log correctly describes the ordinary pair. Linux GUI
`run.olYMdtr3`, path `run.5jp5kjj9`, timestamp `run.UGl7DBq8` and 24 strict
report replays pass; all explained inherited errors remain corroborated.

Windows artifact `12559189475`, SHA-256
`240bc465a87b0a4bead0427a4a7db7956dae3eb206feb9813544927897c10cd2`, proves
all fourteen focused checks, actual short-parent/trailing-dot alias controls,
both publisher APIs/order protections and GUI
`run.e697e19dfe0047be8d4ed9d27830432f GUI paths`. GNU/LLVM, ACL/input preservation,
select/cancel and Console checks pass. Independent libdwarf is unavailable and
Linux-ELF runtime GDB is not run in this Windows lane; those limits are unchanged.

Detailed runtime evidence is in the GUI worktree's
`build/hosted-gui-review/run-40091937766/`, including
`foundation-evidence-x86_64-aarch64-arm32-mips32be-mips32le.json`,
`report-retention-evidence.json`, Windows path-smoke/GUI records and
`acceptance-scope.json`. This accepts the corrected current foundations only;
the failed `65f5bb8` run remains historical failure evidence. Published alpha.2,
the unimplemented attachment transaction and the separate report-reader hosted
gate are unchanged.

The report-reader branch then incorporates accepted main as `bcd60ee`, whose
tree equals the previously reviewed local `ccb21a9` before these documentation
updates. Its retained-prefix successor is separate work; no prefix-helper
implementation or acceptance is attributed to this report-reader gate.


## Matched ELF prefix local checkpoint (2026-10-24)

**CONFIRMED locally; hosted gate pending:** source `c676862` adds only
`MatchedElfPrefix` and its fixture/smoke classes. Existing `ElfImage`, matched
writer, exporter and native declarations are unchanged. Independent source
review is clear. The implementation has four new major-65 classes; local JAR
SHA-256 is `650209bac834ca293a6d0f3f7aecc4abdb0b6bc5b9fa4a19b790df84b5c99060`.

- `GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew --no-daemon
  matchedElfPrefixSmoke elfBuildIdSmoke fileDigestsSmoke elfImageReaderSmoke
  buildExtension` passes, including the architecture guard. Final extra stream
  failure controls pass separately. Exact commands/logs are retained under
  `build/prefix-review/` in the retained-prefix worktree.
- Compiling fixtures/probe with JDK 25 `javac --release 21`, then running actual
  Java `21.0.12.1` with `-Xmx64m`, passes both default and `--large` smokes.
  Twenty-four writer-derived containers cover both classes/orders and named,
  unnamed, sectionless, extended-section, `PN_XNUM` and oversized-header layouts.
  The large original is 2,147,549,185 bytes and the first changed byte is
  2,147,549,184. Files are cleaned after the test. Evidence:
  `build/prefix-review/java21-final/` and `source-acceptance.json`.
- A preliminary read-only probe also passes 27 retained historical/current
  pairs, preserving original bytes/mtimes. This is supplementary comparison
  evidence, not 27 new exports. See `retained-pairs.json`.

Preliminary private package
`1b996de8e4c6d05d75cd98b48f843675065de871584e27c0ae82dae9d9242d68` uses the
JAR above and unchanged exporter script
`3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
All five manifests verify; base Ghidra launch properties remain unchanged.
The private platform is `build/prefix-review/ghidra`. The package predates
final acceptance docs and is not the eventual final reviewed ZIP.

`make -C src/test/fixtures x86_64 aarch64 mips32be` and the retained
`build/prefix-review/run-local-target.sh` execute six fresh roles per target:
`exec`, `partial`, `exec.no-build-id`, `exec.no-sections`, `pie`, `shared`.
All eighteen installed production exports pass GNU/LLVM, strict libdwarf,
input preservation and applicable GDB checks; sectionless allocation-range
checks also pass. Local headless Ghidra uses JDK `25.0.4.1`, not Java 21.
Strict reported errors in that role order are x86 `3/3/3/0/1/1`, AArch64
`5/5/5/0/5/5` and MIPS `0/0/0/0/0/0`; every nonzero error is corroborated in
the original ELF, with no unexplained error. Local runs do not claim native
Windows, ARM32 or MIPS32 little-endian execution.

The independent installed-helper oracle uses actual Java 21 with `-Xmx64m`:
`x86_64.g2_zsi34`, `aarch64.fe33e6gr`, `mips32be.ubeqojee` in
`build/test-results/matched-elf-prefix/`. Each verifies six real pairs twice,
retains six full consumed transcripts and all eighteen input/output/source byte
copies, and checks 26 protected paths during its invocation. Matching report
hashes and installed class/script origins bind this evidence to the selected
production exports. Subsequent tests may reuse original fixture/log paths;
the retained copies preserve this checkpoint.

Owned controls show changed original code detected despite identical metadata
and GNU build ID, while an appended active `.text` address change still passes
prefix comparison and GNU structural reading. That explicit allocation mismatch
prevents a false stronger claim. Layout/shorter-candidate observations and two
malformed-input rejections pass. The x86 run independently constructs another
sparse ELF above 2 GiB, checks matching and last-byte-difference results against
Python, records reconstructible header/tail recipes and hashes, then removes
both large inputs. None of these observations proves a snapshot, active ELF/DWARF
correctness or attachment readiness.

Independent runtime/oracle artifact review is clear:
`build/prefix-review/independent-runtime-audit.json` rehashes all 54 retained
byte copies and eighteen consumed transcripts, checks exact original/sidecar
`.eh_frame` bytes/addresses and diagnostic sets, and reconstructs all three
large-case SHA-256 values independently from the sparse recipe. Repeated prefix
observations do not claim a fresh deterministic exporter rerun. Final docs/package
review and the full exact hosted gate remain pending at this checkpoint. CI adds the default
focused check on Linux/native Windows and the six-role installed oracle to all
five target lanes before later shared-path reuse. The x86 lane adds the large
case; native Windows has sixteen focused checks, without a large-file claim.


## Report-claims reader hosted acceptance (2026-10-24)

**CONFIRMED:** PR #33 exact head
`67785a482c561cce5763248440e26f206df8e09c`, pull-request run `40094712284`,
attempt 1, passes all twelve expected jobs with no skips. Independent source,
package, all-five-target reader artifact and both GUI reviews are clear, with
zero unresolved review threads. Normal merge
`464caf7e8b71555e3a87f6d8d601a3db57215679` at `2026-10-24T13:08:47Z`
preserves the tested tree. Separate main-push run `40096877943` remains pending;
no result is inferred for it. Native declarations and `VERSION` are unchanged.

Package artifact `12560590859` has download SHA-256
`5c3250d00b21074aeabb43a3704b5eda68568ee34b5a006a31717ef9f1a953f0`.
Release ZIP SHA-256 is
`dad2624df988afa96227684d1fdfe28267b01a0c56ee7186be104fae79d749e2`; hosted JAR
`469e3e62971512c1a42552b88dc13b964e0905255a28993c2847f92752b8a63a` and script
`3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`
match exact sources. All 39 production sources, two scripts, current docs/support,
165 major-65 classes, five manifests and canonical native provenance pass review.
Actual Java 21 reader checks include 429 malformed controls and default bounds
under a 64 MiB heap; twenty producer lifetimes and 112 downloaded-JAR production
class origins also pass. Provided Gson has SHA-256
`c96d60551331a196dac54b745aa642cd078ef89b6f267146b705f2c2cbef052d`;
no private Gson or JNA is bundled. Evidence: the report-reader worktree's
`build/report-claims-package-audit/run-40094712284.VftAEvjY/` and final gate
records, including hashes binding the separate runtime artifact reviews.

| Target | Artifact ID | Verified download SHA-256 |
| --- | --- | --- |
| `x86_64` | `12560767357` | `0f717c5e4e97d27016a0d146a4b7e154f10d88af72758a910915e6e91c488c53` |
| `aarch64` | `12561290527` | `ba1dce351a9568f96d82571557b6cc63745b6c6dd86aef9327e8698f39388746` |
| `arm32` | `12559899096` | `37258365bf36bba13d6e453fa54ca64dd3f70114c485bbf0016f5bfd36ab8e36` |
| `mips32be` | `12560910713` | `2214c076bec4b174ab35c89f3993aa8cd3051a99237e431e9d1ecdaaa057ffa3` |
| `mips32le` | `12560223092` | `ce3020c1ae07d3fd892e085d51d882cba6c740ae6c00e517cf526ff92b8752ec` |

All five installed reader oracles pass independent reconstruction: 45 retained
fixture byte copies and fifteen complete consumed transcripts are rehashed,
all returned claims agree with the original JSON, and all 115 targeted rejection
controls pass. Two opaque-path positives per target preserve foreign/missing/FIFO
paths as text. Actual Java 21, the 64 MiB limit, installed producer/reader JAR
origins and pinned Gson are verified. Original before/after metadata checks apply
to the oracle invocation; uploaded copies are verified by SHA, not archive mtimes.
This establishes parsing behavior and evidence binding, not authenticated claims.

Linux actual GUI `run.RmC1XNbi`, eight saved-program path exports/three rejection
cases, timestamp `run.te8tSAK9` and 24 inspected strict reports pass with zero
unexplained errors. Windows artifact `12561237271` has SHA-256
`3c1fe4bd8e71c8b28480f0c257b6a422ac1260b89a6fd4c3289b0000d873dbb6`:
actual Java 21, all fifteen focused checks, native short-parent/dot-alias controls,
six preserved-input sentinels and GUI
`run.0bb874e90f604be7baf0b8a7833a0010 GUI paths` pass. Native GNU/LLVM,
ACL/input preservation, chooser selection/cancellation and Console reports pass.
Independent libdwarf is unavailable on Windows; Linux-ELF runtime GDB is not run
there. Detailed evidence is in the GUI worktree's
`build/hosted-gui-review/run-40094712284/acceptance-scope.json` and aggregate
`report-claims-evidence-x86_64-aarch64-arm32-mips32be-mips32le.json`.

Separately, exact post-merge main `7f9c0d2606a8f7db0007b256d256e6edb49dd473`
push run `40094022212`, attempt 1, passes all twelve jobs. Independent Linux
artifact `12560781342` has SHA-256
`3f8228301c2dd7f06c5c9b43310e21860db96ac955cceafe9cc17d85802b6b43`;
actual Script Manager GUI `run.sIeKZrHa` and 24 inspected strict reports pass
with zero unexplained errors. Windows artifact `12560633059` has SHA-256
`30b6150fe1b131c4ce67a51f8bfad046e4735c9216bfcd941cbe7f8d9ea47060`;
all fourteen focused checks, path protections and real GUI
`run.32da5392128a4e069b000e443729d6ab GUI paths` pass on Java 21.0.12.1.
Independent libdwarf remains unavailable on Windows and Linux-ELF runtime GDB
is not run there. Cross-target results for this separate push are CI evidence;
the detailed helper artifact reviews belong to the earlier exact PR gate.
Evidence is retained in the GUI worktree's
`build/hosted-gui-review/run-40094022212/`. This supersedes the earlier pending
main-push checkpoint for PR #32, without changing either published release.


The next prefix work's local review at `6b5e4c1` is also clear: package
`874b549f7f7010caa0e61578f8b8fe0cd4428061b649378427d0092c7838c2cb`
contains all forty exact production sources, 169 major-65 classes, current
docs/support, five manifests and unchanged native provenance. Its JAR remains
`650209bac834ca293a6d0f3f7aecc4abdb0b6bc5b9fa4a19b790df84b5c99060`.
Evidence: `build/prefix-package-audit/local-6b5e4c1.95h18tbo/result.json`;
separate raw runtime corroboration: `build/prefix-review/release-review-runtime.json`.
That ZIP predates these new acceptance docs. Accepted-main merge `7513236` keeps
the same tree before this docs update; the next exact package and hosted gate
remain required. No additional unchanged exporter/native executions are claimed.


## Active allocation metadata local checkpoint (2026-10-24)

**CONFIRMED locally; hosted gate pending:** source commit
`bdd6befff1ae876dae7d995aeb6f50f3f827637a` adds only the new allocation helper,
fixtures and smoke. `ElfImage`, matched writer, exporter and native bindings
are unchanged. Eight new helper classes are major version 65; final local JAR
SHA-256 is `136407474e48c6f6251a8d0c7a9f39a4843f33558ef278ecf32ae7ff5ac32e58`.
Source and narrow raw-name-resource reviews are clear.

The new focused check, prefix/build-ID/ELF-reader regression checks,
`buildExtension` and architecture guard pass. Tests compiled by JDK 25
`javac --release 21` run on actual Java `21.0.12.1` with `-Xmx64m`: 532 default
assertions and 535 with `--large`. The latter uses a 2,147,549,185-byte original
without scanning its sparse payload. Twenty-four writer-derived class/order/
shape cases, target/indexed field mutations, raw-name collisions, relocation/
LOAD/note boundaries, unsupported outcomes, cancellation and source-change checks
pass. Exact 65,536-note-view acceptance and 65,537 rejection pass. Separately
reread used names enforce 65,536-byte per-name and 16 MiB aggregate limits;
two owned same-size rewrites restore exact mtime but fail the intended direct
resource checks. Inputs are restored and the valid result rechecked.

The initial focused build failed because its note-overflow fixture changed an
existing original note address without updating the candidate; the earlier
indexed mismatch correctly took precedence. That test was corrected and its
failed log retained, not counted as acceptance. Pre-reread-guard checks are
superseded by the final evidence. Exact commands, hashes and outcomes:
`build/allocation-review/source-acceptance.json`, `raw-reread-build.log`,
`java21-raw-reread/` and `retained-pairs-raw-reread.json` in the allocation
worktree. The final retained-pair probe matches 45 historical/current pairs
with ninety selected file hashes/mtimes unchanged; it is not 45 new exports.

Preliminary private package SHA-256
`6eba89b188597008c7303a1f91500f7be8dbd475fe842f9d6f5b3b4fec6d689c`
installs the JAR above at `build/allocation-review/ghidra`. Its five manifests
verify and base Ghidra launch properties remain unchanged. The exporter script
remains `3b7b0ef415e974cfcb03ee1566f3c25bab9151d7405b965a80150a8be6e53821`.
This ZIP predates final acceptance docs and is not the final reviewed package.

With `JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java` and
`JAVAC=/usr/lib/jvm/java-25-openjdk-amd64/bin/javac`, run
`python3 src/test/integration/matched-elf-allocations.py <installed-module>
<target> --prefix-result <retained-prefix-result>` (plus `--large` for x86).
Passing runs are `x86_64.nukedp8z`, `aarch64.oyot1wwe`, `mips32be.u3see4zt`
under `build/test-results/matched-elf-allocations/`; commands/outcomes are in
`build/allocation-oracle-review/acceptance.json` and per-target logs.

All eighteen six-role pairs and repeated results pass the independent indexed
Python model on the installed JAR. All 54 copied input/output/source files and
eighteen consumed transcripts are rehashed and bound to their original reports.
Each run preserves 27 protected paths. The 13/13/12 metadata mutants retain a
matching copied prefix yet return precise indexed differences; the three
changed-code controls retain matching allocation metadata while their prefixes
differ. Six malformed-operand checks return IOException. Explicit replay records
`same_export_installation=false`: the earlier producer JAR is distinct. Path
equality alone cannot override different recorded JAR/script hashes. No fresh
ordinary export, validators, GDB execution or exporter determinism claim is made
for this read-only replay; its backing exports have their separate prior records.

The x86 sparse original/candidate are 2,147,487,952 / 2,147,488,240 logical bytes,
using 8,192 disk bytes each. Their active tables and names lie above 2 GiB.
Matching NOBITS metadata passes; changing index 1's address from `0x500000` to
`0x600000` returns that exact `sh_addr` difference. All nine selected metadata
range hashes are independently reconstructed from the recipe; both sparse files
are removed. This is explicitly not a whole-file hash or large-prefix proof.

Independent source/runtime reviews are clear:
`build/allocation-review/root-runtime-audit.json` and
`build/allocation-review/release-review-evidence.json`. Root additionally derives
normal retained/relocation/sectionless load/note records from the retained bytes
and checks all transcript/protocol origins, input snapshots, index swaps, opposite
code controls and sparse recipes. All command stderr is empty. Final package
review and the exact hosted gate remain pending. CI schedules all five six-role
oracles after the prefix step, the sparse case on x86 and seventeen default
focused Windows checks. No new native Windows/ARM32/MIPS32LE runtime result is
inferred from this local subset, and no attachment operation is introduced.


## Retained-prefix hosted acceptance (2026-10-24)

**CONFIRMED:** PR #34 exact head
`888406e244c0265422a2b07ed3f66b11b97be130` passes pull-request run
`40097366322`, attempt 1: exactly twelve expected jobs succeed, none skipped,
with no unresolved review threads. Normal merge
`837cec8110490635783e037faf48a95c2a2bd86f` at `2026-10-24T13:47:37Z`
preserves the tested tree. The separate main push is still pending.

Package artifact `12561239257` has download SHA-256
`49c84ad5dd929df46eeb582e113fa2897d6a5cff3703f1136982a9a263b5bfb5`;
release ZIP SHA-256 is
`294181f9592c83a1baf48d62cfb443814c9575b7bcb94a7d0f120bc7fcc17f29`.
The hosted JAR is
`ed4f1be4fcdd9946aec673c4c88829541f125df0e7192edd90597b25b7a8907c`,
with forty production sources and 169 Java-21 classes, exact installed scripts,
five manifests and pinned native provenance. The independent package audit
runs actual Java 21 focused checks, twenty producer lifetimes and 118 production
class-origin checks. Native declarations and version remain unchanged.

All five downloaded target artifacts independently pass the new prefix oracle:
thirty real pairs/repeats, ninety byte copies and thirty full producer logs,
plus changed-code, changed-active-address, layout and malformed-input controls.
The x86 2,147,549,185-byte sparse recipe hashes are independently reconstructed.
Linux actual GUI `run.9sXkD5mJ` and all 24 strict reports pass with zero
unexplained errors. Native Windows artifact `12562012029`, SHA-256
`121519292fe10a0fbee35f63fced1968a28c58e2aa806d52c10e4e7d12cff0a7`,
passes sixteen focused checks, reader's 429 controls, path protections and actual
GUI `run.90ee363453964ad19bd94a0acaf5c7cd GUI paths`. Independent dwarfdump
is unavailable on Windows; Linux-ELF GDB runtime was not run on that host.

Evidence: prefix worktree `build/prefix-package-audit/` final gate, merge result
and `run-40097366322.FgTVof1A`; GUI worktree
`build/hosted-gui-review/run-40097366322/acceptance-scope.json`. The full existing
runtime matrix is accepted through CI; no claim is made that each old runtime
transcript was manually re-audited. A matching prefix still does not prove active
metadata, valid DWARF, identity or attachment eligibility.

Separately, PR #33 main-push run `40096877943` at `464caf7` now passes all twelve
jobs and independently reviewed Linux/Windows GUI artifacts. Linux artifact
`12562052005` (SHA-256
`bc927d13391623939e048ecd5c0065a5e2210dac36c5b1a8728f97dadd54b959`)
contains GUI `run.4vXL606F` and 24 strict reports with zero unexplained errors.
Windows artifact `12561833590` (SHA-256
`842ca15e84ab1cbadeec4d2c9649a3e42b4432318397d662c90ab194cb507008`)
passes fifteen focused checks and GUI
`run.9c6fc5ed8df24d5888b708d680b3b473 GUI paths`. This supersedes its earlier
pending checkpoint; target jobs on this separate push have CI-only acceptance.


### Allocation package review before hosted gate

**CONFIRMED locally:** integration `00e2216` builds successfully. Package
`build/allocation-review/reviewed-00e2216.zip`, SHA-256
`a548be4d9f7d9afd0a88c6a4edcd59719c43f3ce48ed44d49e034295a8ee5746`,
passes independent source/docs/support, all five manifest and pinned native
provenance checks. It contains 41 production sources, two scripts and 177
Java-21 classes; there is no private Gson or JNA. Its JAR remains the tested
`136407474e48c6f6251a8d0c7a9f39a4843f33558ef278ecf32ae7ff5ac32e58`.
All 28 runtime/native/provenance files match the earlier installed package,
so this is a packaging review, not another runtime execution. Evidence:
`build/allocation-package-audit/local-00e2216.5gewdk36/result.json`.

Accepted prefix main is incorporated through normal merge `bb02f85`. Following
acceptance documentation updates are packaged and checked against their exact
commit before the new PR; the complete hosted gate remains pending.


## Selected artifact hash binding focused checkpoint (2026-10-24)

**CONFIRMED locally; installed/hosted acceptance pending:** source commit
`5a2f8d749c0b99e39c945086d9dcb6eba0c9b080` adds only the helper and two focused
test files. Existing report/digest/exporter/native code is unchanged.

`GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew --no-daemon
exportArtifactHashBindingSmoke fileDigestsSmoke exportReportClaimsSmoke
pathTraversalSmoke buildExtension` passes. Java 25's compiler separately builds
test classes with `--release 21`; actual Java 21.0.12.1 executes default 574 and
optional `--large` 577 checks with `-Xmx64m`. Existing digest and reader suites
(429 malformed controls) also pass on that runtime. The extension has six new
major-65 classes. The architecture guard and whitespace checks pass. An initial
guard command used a nonexistent filename; its failed setup log is retained,
and the corrected command passed without a source change.

The sparse original is 2,147,549,185 bytes, zeros followed by `0x57`, with SHA
`90fe8779c170ec19522008da8aab882ee4570236a47438342b13034bec75902f`.
The bounded-memory recipe independently supplies SHA/CRC/count expectations;
the observation preserves size, mtime and sentinel. Focused checks cover every
role mismatch subset, report-first typed errors, special-file preconditions,
actual host traversal/aliases, injected attribute/open/read/close failures,
cancellation at each stream's read/EOF/close boundary, exact stream closure and
primary/suppressed exception preservation.

Evidence in the hash-binding worktree: `build/hash-binding-review/initial-build.log`,
`java21/`, `source-acceptance.json` and `release-review-source.json`. Independent
root and peer source/fixture reviews are clear. The preliminary private package
SHA is `a2e7782e4924b5c84c29701a022659116badf610fd09323c389e3a7dbcd6ea91`,
with JAR `fc8a1c5f0cdb017962ad23b1619e1663a1dc13f9834980b003007f7cece5f3f1`.
Its five manifests pass, and the base Ghidra launch file is unchanged. This
preliminary package predates final acceptance documentation. Installed-JAR
comparisons and full native Windows/five-target hosted acceptance remain pending.


### Installed selected-file hash observations

**CONFIRMED locally:** final installed-oracle runs are `x86_64.7pt1hw75`
(with `--large`), `aarch64.vfw09p2b` and `mips32be.6yfjh3b1` under
`build/test-results/export-artifact-hash-binding/`. The commands use actual
Java 21.0.12.1, `-Xmx64m`, Java 25's `javac --release 21`, the private installed
module above and explicit `--claims-result` paths to the earlier reader results.
They record different reader/export installations rather than infer new exports.
All command stderr is empty.

The nine report groups and repeats agree with independent Python SHA/CRC/count
observations. Evidence retains 27 complete artifact copies, nine exact JSON
reports, nine full producer logs and each parent reader receipt. Each target
preserves nineteen selected parent/module paths. All seven nonempty mismatch
subsets run per target, so one mismatch cannot hide later role observations.
Twelve report-first rejections preserve historical/terminal/malformed outcomes
before missing selections; twelve missing/directory/FIFO selections reject.
Uppercase hashes with foreign/NUL/FIFO reported paths, false target claims,
rewritten source hashes, selected symlinks and aliased plain data demonstrate
the observation's explicit limitations. FIFOs are removed in `finally`.

Peer review identified a harness-only cleanup edge: the FIFO was created before
symlink setup entered the cleanup block. Setup now falls inside `try`; a
controlled symlink collision proves FIFO removal and existing-sentinel retention.
Initial passed runs/logs remain separate from the three final runs above.
No production code or assertions changed for that fix.

The installed x86 case independently creates a sparse 2,147,614,795-byte file,
with recipe writes around the 2-GiB boundary and final byte. SHA-256 is
`85f08b2604c993ee278b2546339222fea6307c0b67a1ba99039d8e7101976216`,
CRC32 is `1053664050`, and the reported long count is exact. The file is removed
after checks; its retained recipe reconstructs the whole-file digest. This
plain-data control makes no ELF or native-Windows-large claim.

Independent root review rehashes every retained artifact/log/report and protected
path, compares every returned claim/digest/path with the selected bytes, checks
all installed class origins and typed failures, and independently reconstructs
the complete large recipe. Evidence: `build/hash-binding-oracle-review/acceptance.json`,
`setup-cleanup.txt`, and `build/hash-binding-review/root-runtime-audit.{py,json}`.
CI now schedules the oracle after the preceding report/ELF observations in all
five target lanes, the large case on x86, and eighteen focused native Windows
checks. Existing validators/GDB/GUI gates remain intact. These local replays
introduce no new exporter/validator/GDB execution claim; exact package and
hosted acceptance are still required.


## Indexed allocation hosted acceptance (2026-10-24)

**CONFIRMED:** PR #35 exact head
`d5bd9fe8181605a703d601b1ae07faf4b4435b8f` passes pull-request run
`40099934709`, attempt 1: exactly twelve expected jobs succeed, none skipped,
with no unresolved review threads. Normal merge
`0f05ec88704bd2681e7451efdd94d0992cb88af2` at `2026-10-24T14:24:51Z`
preserves the tested tree. Separate main-push run `40102383229` is pending.

Package artifact `12562268847` has download SHA-256
`af19b29573f4dfb455044b67db2350edc3a148eccee1ff6b74c7432b3ebde7b2`;
release ZIP SHA-256 is
`819592da98a6d92c90bba4eb7a87dff749d1804f3227981999ad92c58495712c`.
The hosted JAR is
`3ddcc04bf380ff458558a2c6f182fe75cbde4a33f4e45163a5c423235937bdb5`,
with 41 production sources and 177 major-65 classes. Exact docs/scripts/support,
five manifests and both native provenance records pass independent review.
Actual Java 21 runs allocation's 532 focused assertions with `-Xmx64m`, prior
smokes, twenty producer lifetimes and 126 production-class origin checks.

All five downloaded target artifacts independently pass thirty real pairs and
repeats, ninety retained byte copies, thirty complete producer logs, 63 indexed
metadata mutations, complementary code changes and malformed operands. Parent
prefix receipts remain bound to the exact producer/helper snapshots. The x86
sparse metadata recipe is independently reconstructed; no whole-file digest
or large-prefix proof is inferred. Linux actual GUI `run.ciQxjRTc` and 24
strict reports pass with zero unexplained errors. Native Windows artifact
`12562873317`, SHA-256
`10157695c940ed086242f2877004ea68ba924b22758f8d769f1b81eb356b7a2b`,
passes seventeen focused checks (allocation 532, reader 429), path protections
and GUI `run.342627fb99a147d39a325049301c369d GUI paths`. Independent dwarfdump
is unavailable on Windows; Linux-ELF runtime GDB was not run on that host.

Evidence: allocation worktree `build/allocation-package-audit/final-gate.json`,
its bound artifact records, `merge-result.json` and `run-40099934709.p3B9UZdp`;
GUI worktree `build/hosted-gui-review/run-40099934709/acceptance-scope.json`.
Unchanged older runtime checks have exact CI acceptance, without a claim that
every historical transcript was manually re-audited.

Separately, PR #34 main push `40099669427` at `837cec8` now passes all twelve
jobs and independent Linux/Windows GUI reviews. Linux artifact `12563171687`,
SHA-256 `a761c7e94b04aeadf025abbeecdb64f8895a1e9650afbd814c0138b2d18c1f94`,
contains GUI `run.g9LiEFcv`; Windows artifact `12562922011`, SHA-256
`b0dd5cbc83b0c3e4d343bc91bb1cc753013fe99c5593a5c70cbab898f51c9319`,
passes sixteen focused checks and GUI
`run.bbf95b8d87644a83bc3b44c9fd479dab GUI paths`. The cross-target results on
this distinct push are CI evidence; this supersedes its earlier pending status.

### Selected-file binder package before hosted acceptance

**CONFIRMED locally:** package at reviewed integration `e974524` has SHA-256
`8e2602254940b97cf2a335ae41df85020800b131dd2739a9da05cd9943e96f1e`.
Independent audit verifies 42 production sources, two scripts, 183 major-65
classes, current docs/support, five manifests and both native provenance records.
All 28 runtime/native/provenance files match the earlier installed package;
JAR `fc8a1c5f0cdb017962ad23b1619e1663a1dc13f9834980b003007f7cece5f3f1`
is unchanged. This is a packaging review, not another runtime execution. Evidence:
`build/hash-binding-package-audit/local-e974524.aud02m7f/result.json` and
`build/hash-binding-review/release-review-runtime.json`. Accepted allocation main
is incorporated normally as `480b6e2`; following acceptance docs are rebuilt
and audited against their exact commit before the next PR. Full hosted
acceptance remains pending.


## Executable program-byte observations: local acceptance (2026-10-24)

**CONFIRMED locally; exact hosted gate pending:** source
`79dbc290eaa88578f758c64d6bed8464a900caa8` and its independent review pass.
No existing exporter, ELF writer, parser or native binding changes. The bounded
comparison covers the complete declared header, resolved program count, raw
program table and all non-NULL file payloads. Section-table header fields are
exempt; active section metadata, debuglink bytes, unmapped data and identity
remain outside the byte predicate.

Commands in the executable-program-bytes worktree:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew \
    executableProgramBytesSmoke matchedElfPrefixSmoke \
    matchedElfAllocationsSmoke elfImageReaderSmoke buildExtension
/usr/lib/jvm/java-25-openjdk-amd64/bin/javac --release 21 \
    -cp build/libs/GhidraDwarfForge.jar -d build/program-byte-review/java21/classes \
    src/test/java/ghidradwarfforge/elf/ExecutableProgramBytesFixtures.java \
    src/test/java/ghidradwarfforge/elf/ExecutableProgramBytesSmoke.java
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx64m \
    -cp build/libs/GhidraDwarfForge.jar:build/program-byte-review/java21/classes \
    ghidradwarfforge.elf.ExecutableProgramBytesSmoke --large
bash src/test/integration/architecture-neutrality.sh
FORGE_MODULE="$PWD/build/program-bytes-review/ghidra/Ghidra/Extensions/GhidraDwarfForge" \
    JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java \
    JAVAC=/usr/lib/jvm/java-25-openjdk-amd64/bin/javac \
    src/test/integration/build-id-discovery.sh x86_64 aarch64 mips32be
python3 build/program-bytes-review/root-runtime-audit.py
```

Actual Java 21.0.12.1 passes 431 default and 443 large assertions at 64 MiB;
all four width/order combinations compare a payload ending at byte
2,147,553,280. Related smokes/build and architecture guard pass. An additional
read-only survey checks sixteen retained backend candidates and preserves 27
paths. The initial boundary test incorrectly expected every pre-`e_shoff` change
to make an ELF malformed; one valid big-endian program-table move correctly
produced a header difference. Only the expectation changed. The survey's first
origin comparison also expected `file:///` instead of equivalent `file:/`;
it now compares decoded URI paths. Failed setup logs are retained in
`build/program-byte-review/source-acceptance.json`.

Initial private ZIP SHA-256 is
`0b245ce8b528274fa4d84de10ff866cfe284a21fa14f19d151f3d825bb01fbe6`;
installed JAR is
`340049330c2c10f51fce63407f1bca342d84318be0b93c659bd92babe029a0e3`.
Five manifests pass and the base Ghidra launch file remains unchanged. The
consumer runs actual Java 21 at 64 MiB and verifies helper/parser code origins.
`build/test-results/build-id-discovery/run.UmBq92Je` contains nine newly created
private candidates, exact backend argv/version/tool digest/status/environment
and quiet diagnostics. Repeated Java observations and an independent Python
model agree. All before/after receipts match; all 36 retained original/reference/
sidecar/source fixture snapshots remain unchanged. The no-build-ID private
sidecar is intentionally corrupted and restored by the later GDB CRC test;
its final bytes, rather than the helper-time mtime, are compared.

Fifteen owned mutants distinguish changed loaded bytes, raw header and program
records from complementary active-address and CRC changes outside this property.
Three controlled NOTE payloads outside every LOAD are rejected; these metadata
copies are not executed or asserted runtime-valid. Six malformed operands reject.
Synthetic no-LOAD and declared-header-tail cases preserve difference precedence.
The x86 large case has 2,149,584,913 logical bytes and a 2,097,169-byte payload
starting above 2 GiB. Its selected header/table/payload hashes and exact final-byte
mutation are independently reconstructed after removal; no whole-file hash or
copied-prefix claim is inferred.

All 27 existing GDB association transcripts pass: matching/mismatched build ID,
exact debuglink discovery, explicit no-ID loading and bad-CRC rejection. GDB
checks compiler-oracle function addresses, selected sidecar/source paths, types,
source listing and named breakpoints. Native x86 exec additionally hits the
build-ID and debuglink associations with arguments 19/23 and exits normally.
These are new backend/helper/GDB executions on earlier exported fixtures, not
new Ghidra exports, cross-target execution or structural-validator runs.

Root independent runtime evidence is
`build/program-bytes-review/root-runtime-audit.json`. Corrected research-probe
replay `build/program-byte-review/corrected-research-probe.bfr_znzz/result.json`
accepts an ordinary retained candidate and rejects the old escaped NOTE mutation
at offset 14676; five inputs and three copied source paths remain unchanged.
It uses actual Java 21/64 MiB and changes no backend files. Independent runtime
review is clear in `build/program-bytes-oracle-review/runtime-review.json`.
Final package review and exact hosted acceptance remain required. Native
Windows results are pending and their conditional assertion count must be
observed on that host, not inferred from Linux.


## Selected-file SHA binding hosted acceptance (2026-10-24)

**CONFIRMED:** PR #36 head
`c52610204f99ad8914a0f44cf0616e16cdb02256` passes exact pull-request run
`40102754052`, attempt 1, all twelve expected jobs with no skips or unresolved
review threads. Normal merge `18b3e2e4b7899052424e438108191412178d72ef` at
`2026-10-24T15:05:08Z` preserves its tested tree. Distinct main-push run
`40105363431` remains pending.

Package artifact `12563512220` has download SHA-256
`8003971fab9ee425d8166432c5dbf05534a2acbbaede784cd16bde8405f0121e`;
release ZIP SHA-256 is
`fa57fcc29bb50bc0a8382fa884d13d3c7ffe9f0f4622fe8b01f60a6536c32a5f`.
The package includes 42 production sources; hosted JAR
`260142092f03bee75680fe0ffb0ddac88caf5fc3b5fc15e5da246784d95d4224`
contains 183 major-65 classes. Exact docs/support,
five manifests and both native provenance records pass. Actual Java 21/64 MiB
passes binder 574, prior smokes, twenty native producer lifetimes and 132
production-class origin checks.

All five target artifacts pass independent review: 45 retained byte copies,
fifteen exact reports/full producer logs, 35 mismatch subsets and forty typed
failures. Repeated installed observations preserve opaque reported paths and
selected-file semantics. The x86 sparse-file recipe is independently rebuilt
and cleanup verified. Linux GUI `run.AyYtHmZZ` and 24 strict reports pass with
zero unexplained errors. Native Windows artifact `12564307419`, SHA-256
`25da374f4ec42701783f96c34592a5b79c810a47ce8dcdbbc1f11ce870cc4fb1`,
passes eighteen focused checks, including the observed platform-applicable
binder count 551, path protections and GUI
`run.d4c589e23297461fb3a0350f6e77e35b GUI paths`. Independent dwarfdump is
unavailable on Windows; no Linux-ELF runtime GDB, native Windows large-file or
FIFO claim follows from that host's result.

The binder worktree retains `build/hash-binding-package-audit/final-gate.json`,
which binds the three independent target/Windows/GUI evidence records by hash;
`run-40102754052.MTqrKKQV` holds the package audit. The GUI worktree retains
`build/hosted-gui-review/run-40102754052/acceptance-scope.json`. These are exact
PR evidence; unchanged older checks have CI acceptance without a claim that
every historical transcript was manually audited again.

Separately, PR #35 main push `40102383229` at `0f05ec8` passes all twelve jobs
and both GUI artifact reviews. Linux artifact `12564067245`, SHA-256
`858736c7b8640c09f341a021a2a42fd294aeec7b49c2f340c1fe16acbf8f95b5`,
contains GUI `run.e4hJ4OOT` and 24 strict reports with zero unexplained errors.
Windows artifact `12564595019`, SHA-256
`9c4a1644f9e9ab92e98f1c2b39cee5f94818af590e3b7d26075d4a3b37a0c3ca`,
passes seventeen focused checks and GUI
`run.896ef9cf3c4f4eb4925c46dba736f505 GUI paths`. This supersedes the earlier
pending main-push checkpoint and preserves the same host limitations.

### Program-byte package before hosted acceptance

**CONFIRMED locally:** integration `36b5ea9` package SHA-256
`4b06489f1ae9d063033a0b87203b2b89e33495a98c98feb0fd8a1287e8f91dd0`
passes independent exact-source/docs/support review: 43 production sources,
two scripts, 192 major-65 classes, five manifests and both native provenance
records. All 28 runtime/native/script files match initial installed package
`0b245ce8b528274fa4d84de10ff866cfe284a21fa14f19d151f3d825bb01fbe6`;
The production JAR is unchanged. Evidence:
`build/program-bytes-package-audit/local-36b5ea9.i17dsktq/result.json`.
This is a packaging audit, not repeated runtime execution. Accepted binder main
is integrated normally; the following acceptance-docs build is independently
audited against its exact commit before its own hosted gate.


## Callback exception identity correction before PR #37 acceptance

**CONFIRMED locally; corrected exact hosted gate pending:** independent review
found a cancellation supplier's post-parse `IllegalArgumentException` was caught
and wrapped as malformed ELF in `ExecutableProgramBytes.read`. Root then found
the same pattern in `MatchedElfPrefix.readMetadata`. Both fail closed; no
incorrect byte match, target modification or cleanup defect was found.

Separate scoped commits `c38cd9821f24aac1c7fa3dadfde32a0c3b7f497c` and
`791631ffab58854f17e5f3ba8fa5e9f2c48f0e60` narrow only the parser catches and
add exact-identity regressions at the completed-parser/pre-comparison boundary.
The new controls demonstrably fail the exact old hosted JAR with the wrapped
`IOException` and pass the corrected implementation. Source review is clear;
malformed metadata keeps its prior wrapping. The allocation/build-ID readers
already keep supplier polls outside those catches.

Four focused Gradle suites (`executableProgramBytesSmoke`, `matchedElfPrefixSmoke`,
`matchedElfAllocationsSmoke`, `elfImageReaderSmoke`), `buildExtension` and the
architecture guard pass. Actual Java 21.0.12.1 at 64 MiB passes program 434/446
and prefix default/large tests. One setup command mistakenly named a nonexistent
Python architecture guard; its failure is retained, followed by the successful
correct shell command. Evidence is under
`build/program-bytes-package-audit/{callback-fix,prefix-callback-fix}/result.json`,
with exact old-JAR regression failures and independently bound source reviews.

The corrected private ZIP has SHA-256
`d6ef6f14a2992a46180fa07775c6ad6afadf10c5bfbcdf89ea12e6fea79fedc1`;
installed JAR is
`f1c87f29652be3148dc68bb72390f372710279e191bfb03362673e8e59402740`.
Five manifests and unchanged base launch-file hash pass. Repeating the documented
three-profile association command with
`FORGE_MODULE="$PWD/build/program-bytes-review/ghidra-callback/Ghidra/Extensions/GhidraDwarfForge"`
passes nine new private candidates, all controls/large selected-byte checks and
27 GDB transcripts in `build/test-results/build-id-discovery/run.7eQn9koH`.
All 36 retained fixture SHA/size/mtime snapshots remain unchanged. Root's
independent audit is `build/program-bytes-review/root-callback-runtime-audit.json`;
peer review is clear in `build/program-bytes-oracle-review/callback-runtime-review.json`.
The retained-export versus fresh backend/helper/GDB scope is unchanged; this
replay makes no new exporter, structural-validator or cross-target execution claim.

Initial PR #37 head `e25c148` and run `40105620219` are intermediate evidence,
not final acceptance. Their package audit and completed component evidence are
retained. The corrected source requires a fresh exact package audit and full
hosted gate before merge; no result is transferred between different JARs.


## Candidate content: local installed acceptance (2026-10-24)

**CONFIRMED locally; final package/full hosted gate pending:** source
`e30fae38568e65ac16e2ce84da29f65372090c4f` adds the three owned implementation/
fixture/smoke files. Independent source review is clear. Source acceptance
`build/candidate-content-review/source-acceptance.json` records actual Java
21.0.12.1/64 MiB default 970 and large 972 assertions; the large selected sidecar
has 2,147,549,185 bytes and CRC32 1024963657. The tests cover all four ELF
width/order combinations and preserve separate predicate outcomes. Review added
indexed ALLOC demotion/removal and long-common-prefix raw-name diagnostics.
No original exporter, writer, native binding or existing helper was changed by
that scoped commit.

After incorporating the parent callback corrections, the combined build passes:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew --no-daemon \
    debuglinkCandidateContentSmoke executableProgramBytesSmoke \
    matchedElfPrefixSmoke buildExtension
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx64m \
    -cp build/libs/GhidraDwarfForge.jar:build/candidate-content-review/java21/final-classes \
    ghidradwarfforge.elf.DebuglinkCandidateContentSmoke
FORGE_MODULE="$PWD/build/candidate-content-review/ghidra/Ghidra/Extensions/GhidraDwarfForge" \
    JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java \
    JAVAC=/usr/lib/jvm/java-25-openjdk-amd64/bin/javac \
    src/test/integration/build-id-discovery.sh x86_64 aarch64 mips32be
python3 build/candidate-content-review/root-parent-runtime-audit.py
python3 build/candidate-content-review/root-runtime-audit.py
```

The unchanged dedicated smoke classes were compiled with `javac25 --release 21`
as recorded in source acceptance. Actual Java 21 default 970 passes again with
the corrected parent. The initial source JAR
`19659462d780b44a5cfd26ae42bfbe935cb45e4f147d541e4f74a6ee6352f3c2`
is distinct from the installed combined JAR below; no acceptance is silently transferred between them.
The earlier standalone large test is source evidence; the installed large test
is independently repeated on the combined implementation.

Private ZIP SHA-256:
`9655d10a4eb11f49dac503d044e3ee0ccb97ca98911d4e7397c7070ac34e1c41`.
Installed JAR SHA-256:
`4dd5f62a3d8fc5d5792e800c2e9ba45895b797147f3bb7f62d6e9c5b60bf3414`.
Five manifests and the unchanged base Ghidra launch-file hash pass. Actual helper,
program, ELF and digest classes load from that installed JAR on Java 21 at 64 MiB.
`build/test-results/build-id-discovery/run.EB9Gq9mR` contains nine new private
GNU candidates for exec/PIE/no-build-ID across x86-64, AArch64 and MIPS32
big-endian, with both observer passes before the existing GDB checks.

Independent root and peer runtime audits verify 27 retained input copies, 135
exact parent receipt/tool/log copies, repeated observations and 72 content
controls. Program bytes, allocation metadata, new-link fields/payload and sidecar
digests are compared separately. Controls include complementary code/address/CRC
changes, every link field, duplicate/missing links, padding/trailers, literal raw
names, existing associations, uncovered allocation and plain-data CRC matches.
Six malformed ELF operands and eighteen invalid basename arguments reject with
the expected exception types. A source review found a test-only hex display
mismatch (`NN` versus `0xNN`); byte issue values are now compared semantically,
with both raw values retained. The corrected adapter parsing has an independent
protocol-only control; no production check was weakened.

The x86 sparse sidecar has 2,147,614,795 bytes. Its full recipe is independently
reconstructed after file cleanup: initial SHA-256
`85f08b2604c993ee278b2546339222fea6307c0b67a1ba99039d8e7101976216`,
CRC32 1053664050; after the final-byte XOR, SHA-256
`603462f17ee52cf08eeefe87da01073bb24b9afb462c15a56a7c1c5f3dc0ca2c`,
CRC32 1238012836. Exact pre-invocation digests and size/mtime are bound to each
Java observation. The candidate's unchanged CRC then differs as expected. This
synthetic content fixture is not claimed to be valid DWARF or automatically
discoverable under its supplied literal basename.

All 36 selected original/reference/sidecar/source fixture snapshots remain
unchanged. The existing 27 GDB transcripts pass, including original/candidate
compiler addresses, selected debug/source paths, types, source listing,
breakpoints, mismatched build ID and no-ID CRC rejection. Native x86 exec hits
both automatic associations with argument values 19/23 and exits normally.
No new Ghidra export, structural-validator or cross-target execution is attributed
to this replay. The later CRC rejection test intentionally changes/restores a
private debug copy's mtime; final byte equality is required for that copy.

Evidence: `build/candidate-content-review/{root-parent-runtime-audit,root-runtime-audit}.json`
and `build/content-oracle-review/{runtime-review,parent-runtime-review}.json`.
Final exact package review and the full hosted/native Windows gate remain
required after corrected PR #37 acceptance. The optional attachment transaction
and its receipt/metadata/backup/recovery prerequisites remain unimplemented.

### Distinct PR #36 main-push acceptance

**CONFIRMED:** main push `40105363431`, exact head `18b3e2e`, event `push`,
attempt 1, passes all twelve expected jobs and both independent GUI reviews.
Linux artifact `12565465043`, SHA-256
`fe5fbf527905a5152a81b1d9d50062d3f7180beb81e78cd581ff1eb3d7fef00d`,
contains GUI `run.mDYSWCws` and 24 strict reports with zero unexplained errors.
Windows artifact `12564798916`, SHA-256
`4383118197d8f8f43eaf230e58cb523246a0853a1bb0fa7ac04286ada9dc08c2`,
passes eighteen focused checks (binder 551 actually observed), preserved alias/
link/rollback markers and GUI
`run.bcf351c64b5c437c89ee2814e7c5cd80 GUI paths`. Cross-target results on this
separate push are CI evidence; detailed all-five binder audits belong to the
accepted PR run. Evidence: GUI worktree
`build/hosted-gui-review/run-40105363431/acceptance-scope.json`.

The corrected five-source research probe also passes actual Java 21/64 MiB
replay in `build/candidate-content-review/corrected-research-replay.rf2sc_90/result.json`:
the retained GNU positive is accepted, while the historical `.text` address
mutation rejects in allocation `sh_addr` at index 15 and the link address/
alignment mutation rejects in new-link `sh_addr` at candidate index 28. All
eleven protected input/source/old-evidence files remain unchanged. This adds no
backend, GDB or saved-program export execution. Final independent integration/docs
review is `build/candidate-content-review/independent-doc-replay-review.json`.


## Corrected executable program bytes: hosted acceptance (2026-10-24)

**CONFIRMED:** exact PR #37 head `89fa8b7e1a2540f562028c59c2390021343b33da`,
pull-request run `40107222339`, attempt 1, passes all twelve expected jobs with
none skipped. Independent final gate checks the current base, clean tree, zero
unresolved review threads and source/native/version scope. Package artifact
`12565198088` has outer SHA-256
`04e119ac74f39240e3eeaca13f6af54e4ddfadbc1b24559c9543af22154635ac`,
ZIP SHA-256 `e28030d7cb9b4e62151dabe771b8ffde405983f6aceac49c1957bd0c261f54cc`
and JAR SHA-256 `890fc267bbcfe6573d1e6724e124545a4d5f5c26c1b15102fc73559839bec017`.
It contains the exact 43 production sources, two scripts, 192 Java21 classes,
five verified manifests and pinned native provenance. Actual Java21/64MiB
program434, corrected prefix and prior smokes pass, with twenty native producer
lifetimes and 141 production-origin checks.

All five target artifacts pass independent program-byte review: fifteen cases
and repeats, fixed mutation controls, quiet backend records, retained byte
copies and GDB evidence. The x86 sparse recipe reconstructs only the selected
program ranges above 2 GiB. Linux artifact `12565886519`, SHA-256
`00f41f8a64f7e3746f1b8d7650f2e806443253f0e9dba9d8298cad1fcf36023a`,
contains association `run.O5LoloJB`, GUI `run.MurNQFOz` and 24 strict reports
with zero unexplained errors. Windows artifact `12566320977`, SHA-256
`da2d9d9cc3bf6a9183a99266f38c8aaf3ec96c367374632fb49b0471516588cf`,
contains GUI `run.d87be02251fb453897b4d4e92a0c0d2a GUI paths`, nineteen native
focused checks, program431 and binder551 actually observed, with alias/link/
rollback protection markers. Both real GUI journeys pass.

Artifact uploads exclude hidden `.build-id` payload files. The first new artifact
auditor correctly stopped when its path-only lookup expected those omitted
files. The corrected audit derives the unique matching build ID independently
from retained original/sidecar GNU notes, including target-endian note framing,
and checks the exact warning path. It does not claim the missing payload bytes
were verified. GDB transcripts retain runtime discovery evidence. Strict warning
policy is unchanged. The initial audit failure is retained. Windows independent
dwarfdump, Linux ELF runtime, POSIX FIFO and large-file results remain unavailable
on that host; archive mtimes do not prove original invocation nanoseconds.

Evidence in the program-byte worktree:
`build/program-bytes-package-audit/run-40107222339.VWoO5LIv` and
`build/program-bytes-package-audit/final-gate-40107222339.json`. The final gate
binds four GUI-worktree artifact receipts by SHA; detailed target, Windows and
GUI evidence is under `build/hosted-gui-review/run-40107222339/`. An initial
final-gate receipt-schema assumption stopped before merge; its corrected binding
uses the actual receipt schema and preserves the failed invocation.

Normal merge `29055f6c81755761c3bbc7257f7460e21af43e6c` at
`2026-10-24T16:09:38Z` is tree-identical to the tested head. Distinct main push
`40110261306` remains pending. Earlier `e25c148` / `40105620219` remains
intermediate; no result is transferred to the corrected build.

Candidate-content local integration `5ee38af` also has an independently reviewed
exact package: ZIP SHA-256
`330413824c3381324f1fb179367c201f7c8f11c879e57f381f455c5c4397ad7f`,
44 production sources, two scripts, 201 Java21 classes and five verified
manifests. All 28 runtime/native/script payloads equal the installed private
package; this docs/package check adds no runtime claim. Evidence:
`build/candidate-content-package-audit/local-5ee38af.05ymbvo5/result.json`.
Normal parent incorporation `d2eadf2` changes no tree bytes. Candidate-content's
own full hosted gate remains required.


## Candidate content: exact hosted acceptance (2026-10-24)

**CONFIRMED:** PR #38 head `b269ec56e03598f5a132caecb9ec0bb344cb841f`,
pull-request run `40110565271`, attempt 1, passes all twelve expected jobs,
no skips, with independent final head/base/clean-tree/review-thread checks.
Package artifact `12566721084`, outer SHA-256
`04c8fda19fc9badf6914b38e77abb3575535a3d2dddbcb33f6b3a640e9bbc6e8`,
contains ZIP `dbbe3973a553cb4b05ea6bbaf7b0922fb79cfe1587d60ba6c85b0d5c75f35be5`
and JAR `2f35b5476aedb5fe7af29ab778da16f934c57ef889b6dc657c04e8a5aaa013a9`.
All 44 production sources/two scripts, 201 Java21 classes, five manifests and
native provenance match the exact head. Actual Java21/64MiB content970, prior
smokes, twenty native producer lifetimes and 150 class-origin checks pass.

Independent audits verify all five targets: fifteen cases/repeats, 120 exact
content mutations, 45 input copies, 225 parent records and the full x86 sparse
sidecar recipe. Linux artifact `12567017967`, SHA-256
`535b0417dd9e370272b6b3f54e36703c3316bc7b41841b2ac11ea381d797b6fb`,
contains association `run.Ja1f9Z5r`, GUI `run.ssCof786` and 24 strict reports with
zero unexplained errors. Windows artifact `12567705118`, SHA-256
`41aed9818bbc1f526a95dc12eec2c8d62339c56b0a3a34d3d59d6efb3ffed78a`,
contains GUI `run.9488c3f91d1b49f8af19aa8fc9d0e611 GUI paths`, twenty native
focused checks, observed content965/program431/binder551 and the alias/link/
rollback protection markers. Linux's content970 is not attributed to Windows.
Hosted hidden `.build-id` payloads, original invocation mtimes and Windows
independent dwarfdump/Linux ELF runtime remain outside artifact verification.

Evidence in the candidate-content worktree:
`build/candidate-content-package-audit/run-40110565271.Pd3Ig7Sj` and
`build/candidate-content-package-audit/final-gate-40110565271.json`; GUI-worktree
`build/hosted-gui-review/run-40110565271/acceptance-scope.json` binds the target,
large, native-host and actual GUI records. Normal merge
`2bd673900198c00de90f6adfa5079dd21e2f3d2d` at `2026-10-24T16:48:24Z`
is tree-identical to tested `b269ec5`. Separate main push `40113254401` remains
pending; no result is transferred between events or heads.

### Distinct PR #37 main-push acceptance

Exact `29055f6`, push `40110261306`, attempt 1, passes all twelve jobs and
independent Linux/Windows GUI reviews. Linux artifact `12566694247`, SHA-256
`43b6f32b310b7aefd489d671a26ddc8784639d46f1c6bfbd3630225262760b09`,
contains GUI `run.h0peIJig` and 24 strict records with zero unexplained errors.
Windows artifact `12567297640`, SHA-256
`834f7133ded6c9c7daf11390f30ca116a0cad04419ef88a8311b7a274b6805f3`,
contains GUI `run.c96313b6d7a9427c9e1b6c4de452501c GUI paths`, nineteen focused
checks with program431/binder551 observed, and alias/link/rollback protections.
Other target results on this separate push are CI evidence; detailed all-target
program-byte audits belong to the accepted PR. Evidence: GUI-worktree
`build/hosted-gui-review/run-40110261306/acceptance-scope.json`.

## Owned append-only candidates: local acceptance (2026-10-24)

**CONFIRMED locally; exact package/full hosted gate pending:** source
`1763ebd0268ab9283915a543243b5bdaf1acb9a6` adds only the owned writer and its
fixture/smoke files. ADR-0005 records the explicit backend decision. The connected
consumer preserves GNU reference provenance separately and invokes the installed
writer through `OwnedDebuglinkCandidateProbe`; it verifies actual Java21 and all
five class origins with a 64MiB heap before checking complete output bytes.

Commands in the owned-candidate worktree:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew --no-daemon \
    ownedDebuglinkCandidateSmoke debuglinkCandidateContentSmoke \
    executableProgramBytesSmoke matchedElfAllocationsSmoke fileDigestsSmoke buildExtension
/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx64m \
    -cp build/libs/GhidraDwarfForge.jar:build/owned-candidate-review/classes \
    ghidradwarfforge.elf.OwnedDebuglinkCandidateSmoke --large
JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java \
JAVAC=/usr/lib/jvm/java-25-openjdk-amd64/bin/javac \
FORGE_MODULE="$PWD/build/owned-candidate-review/ghidra/Ghidra/Extensions/GhidraDwarfForge" \
    bash src/test/integration/build-id-discovery.sh x86_64 aarch64 mips32be
bash build/owned-candidate-review/run-shared.sh
python3 build/owned-candidate-review/root-runtime-audit.py
```

Focused test classes were compiled separately with `javac --release 21` before
the actual Java21 commands; Gradle's local test runtime is not the Java21 proof.
Default/large counts are 1,142/1,148. Both widths/orders, raw duplicate/suffix/
nonUTF8 names, allocated old name tables, two independent extended-section
transitions, PN_XNUM, malformed/unsupported inputs, resource limits, aliases,
determinism, callback identity, exact cleanup and injected I/O failures pass.
The large artifact is one ELF32 big-endian case: original 2,147,549,185 bytes,
sidecar 2,147,483,665 bytes, output 2,147,549,672 bytes. Full masked-prefix
comparison, complete input/digest preservation and a precise mutation at
2,147,549,184 pass under 64MiB. Files are cleaned afterward; exact end 2^32
is arithmetic-only. No four-layout large, Windows-large or sparse-allocation
claim is made. Maximum metadata combinations are not guaranteed at 64MiB.

The initial independent oracle used a wrong new-name offset (+14 instead of +15)
and a later aggregate fixture inherited stale bytes in newly designated NULL
records. These setup failures and corrections remain in the source acceptance
logs. Peer review required explicit zero-filled alignment and rejection of
nonzero unused section-zero extension bookkeeping. An isolated copy removing
only the two pad writes fails at `link alignment pad`; the positive test checks
both pads, without claiming a separate second-pad negative. Evidence:
`build/owned-candidate-review/source-acceptance.json`,
`independent-source-evidence-review.json` and `padding-negative/`.

Private ZIP SHA-256
`6360fb3ca12b97bde1c1bd657cb2090529b7dfca25e0b6e98fab027245941353`
contains JAR `780909c106fd72a5c5b055a5c8af0c416b849518c3088f5a27c1fdfc2ce3d9e9`
and 207 Java21 classes. Installation verifies five manifests and preserves the
base Ghidra launch file. The installed Python oracle is SHA-256
`8c24db64839484518cca9e7e85993a5d4969226cbc32bde34375609598d97121`.
Nine exec/PIE/no-ID cases pass in `build/test-results/build-id-discovery/run.j35EcKvB`;
three separate shared cases pass in `build/test-results/owned-candidate-shared/run.xbmyRUDS`.
These use retained exporter fixtures, not a new Ghidra export.

Independent root and peer audits reconstruct 24 deterministic main candidates
plus three plaintext counterexamples, verify sixty retained input copies and
264 separate GNU/program/content parent records, and confirm all 48 selected
original fixture SHA/size/mtime snapshots unchanged. Nine precise mutations and
24 typed failures pass. Each real candidate passes GNU header/program/section/
note checks and LLVM's explicit completion marker with recorded tool identity.
Eighteen writer GDB transcripts cover automatic association, source/type/address
lookup, three native x86 argument19/23 runs and no-ID CRC rejection/restoration.
Nine original/candidate execution pairs (eighteen processes) pass with zero exit,
identical output and empty stderr, natively on x86 and under QEMU for AArch64/MIPS.
Shared cases prove lookup only. The original 27 GNU association checks also pass.

Only owned test copies receive execution permission or colocated debug bytes.
The later no-ID GNU CRC test changes/restores a private debug copy's mtime;
final bytes, not its pre-test mtime, are checked. Writer-colocated no-ID debug
bytes are likewise deliberately corrupted/restored; successful candidate bytes
remain unchanged. Tool/argv results cover known fixture paths, not generic host
encoding. Unchanged Forge sidecars are not rerun through strict DWARF validation
in this replay. The full pipeline's fresh export/validator gates remain required.

Runtime evidence: `build/owned-candidate-review/root-runtime-audit.{py,json}` and
`build/owned-oracle-review/{source-review,runtime-review}.json`. No additional
runtime is attributed to those independent audits. The current integration adds
one focused Linux/native Windows check and installed writer execution in each
existing target association lane. Final exact package, native Windows and all-five
hosted acceptance remain pending. No target replacement, original permission
change, report attestation, snapshot or attachment transaction is exposed.

## Layout compiler-oracle transport correction, 2026-10-24

**CONFIRMED failure:** PR #39 head `6f1a220`, run `40114403014`, is not full
acceptance. ARM32 extended-section PIE failed before Forge export or writer
checks: QEMU could not bind TCP33168, then GDB timed out. The listener's owner is
**UNCERTAIN**. Artifact `12567689679`, SHA-256
`15f453f29e93dacd8c3fad1a9450d11c6337a46a0592308ec5162a337dad67d1`,
is retained under the owned-candidate worktree's
`build/owned-candidate-package-audit/watch-40114403014/arm32-failure`.
Successful intermediate package/other-lane checks do not fill unreached steps.

The one-file `elf-layout-gdb-oracle.sh` correction uses the existing private
UNIX-socket helper within the compiler oracle's subshell, including startup
readiness and cleanup. It preserves native execution, the 30-second GDB timeout,
compiler assertions and diagnostic policy; ARM uses the existing optional
`FORGE_ARM32_SYSROOT` override. No production exporter/native source changed.

`src/test/integration/qemu-socket-startup.sh` passes real QEMU/GDB startup,
missing-input rejection, bounded startup timeout and ready-child cleanup in
`run.nLECFaEu`. Ten fresh compiler-reference exec/PIE checks pass across x86-64,
AArch64, ARM32 and both MIPS32 byte orders in `compiler-oracles.jqmyt7ll` under
the retained failure directory. All ten input SHA/size/mtime snapshots remain
unchanged; all eight emulator children and private socket directories are gone.
The fixture Makefile built only these private references. This does not rerun
Ghidra exports or sidecar validators. Earlier local setup failures, including an
archived-reference source-mtime warning, are retained without relaxing policy.
Commands, source hashes and tool versions are in `fix-acceptance.json`. A new
exact-head package and complete hosted gate remain required.

## Corrected owned-candidate hosted acceptance, 2026-10-24

**CONFIRMED:** PR #39 head `a190026534c70f89d09ac807f6e755fcbcd81473`, exact
run `40116314882`, passes all twelve jobs. Independent package/source, all five
target artifacts, native Windows and both GUI reviews pass. Normal merge
`4e05060939ebcfdd0bf762ed6782780b7389f226` preserves the accepted tree; the
native ABI and version are unchanged. The first failed `6f1a220` /
`40114403014` is retained separately, with no acceptance inherited from it.

Hosted artifact `12569995661` has outer SHA-256
`88d02c7cfc34c4cf329591d4db970a87266dab9347477b5853d42f229610c4f1`,
package `ceb8a57601bbbe22c5bc43bab922bb5e6067eeb4883b2d8916b1e5db0235ac0e`
and JAR `7bf8d7e470d2b9419a3061182fb808e059721d24e98d092bfc70439b5ba6678f`.
All five manifests, 45 production sources plus two scripts, 207 Java 21 classes
and native provenance match the exact head. Guarded packaged smoke checks include
1,142 owned assertions and twenty producer lifetimes on actual Java 21.

The five installed target receipts verify fifteen cases: thirty deterministic
ordinary candidates and five plaintext controls, 75 input copies, 330 separate
GNU/program/content parent records, fifteen mutations and forty typed failures.
Twenty-five writer GDB checks and fifteen original/candidate runtime pairs pass.
x86 artifact `12569711897` is SHA-256
`f318806a34979b0b2df62202407811d72115b7acba051ba8cc18755954bd324a`,
association `run.IztoSpxZ`, GUI `run.bAY7AqlA`. Its 24 strict reports have no
unexplained errors; three corroborated inherited GUI frame diagnostics remain
visible. ARM32 reaches all writer cases in `run.yu4mHxOQ`, artifact
`12569781821`, SHA-256
`d173b99b0e4945fd5b91e0f36316867e99bf3db1f37ad569f6683c1497f8cb1e`.
All five exact artifact IDs/digests and receipt hashes are in the aggregate audits.

Windows artifact `12569653068`, SHA-256
`e496d1b59edceec811bb7a847d8f963f868ff6026f07cfcedb635a7a6922185e`,
passes 21 focused checks: owned 1,140, content 965, program 431 and binder 551
are the native counts actually observed. GUI
`run.a68533bff0d74c74a9f5e96870d77f1a GUI paths` passes. Native alias, sentinel,
link and rollback markers pass without skipped cases. Linux-only large/FIFO and
Linux ELF runtime behavior are not inferred on Windows; independent Windows
libdwarf validation remains unavailable. Hidden `.build-id` payload bytes are
absent from uploaded archives, and remote tool hashes remain recorded invocation
evidence. The exact limitations are retained in the final acceptance receipt.

Evidence in the owned worktree:
`build/owned-candidate-package-audit/run-40116314882.MolxxNBr`,
`final-gate-40116314882.json`, and
`watch-40116314882/{independent-final-review,windows-focused-review,target-receipt-binding}.json`.
GUI and all target aggregates are under the GUI worktree's
`build/hosted-gui-review/run-40116314882`. No extra runtime is attributed to these
independent audits. Separate main push `40118899783` remains pending.

PR #38's separate main push `40113254401` attempt 1 failed when the Windows
runner lost communication; no native Windows log/artifact survived and dependent
package/target/GUI checks were skipped. The annotation and log-endpoint failure
remain retained. Failed jobs/dependents were retried as attempt 2, with native
Linux, extension build and lint explicitly reused from successful earlier jobs.
That main gate remains pending. Neither main gate is inferred from PR acceptance.

## Detailed report binding and private preparation, 2026-10-24

**CONFIRMED locally; refreshed final package and hosted gate pending:** source `1d80348`
adds optional diagnostic retention to the same strict parser and report-first
binder. Actual Java 21 with `-Xmx64m` passes 432 new focused assertions, including
16,384 combined inventory entries and 1,048,576 UTF-16 units reached together,
independent over-limit failures, Unicode, immutable lists, cardinalities, late
parse/close failures and ordered all-role observations. Lightweight reader 429
and binder 574 assertions still pass. Four focused Gradle checks, extension
build and architecture guard pass. Source/API and test-adapter reviews are clear.

Private package SHA-256
`0d6adf8fccaebda1292babc62094b8a6baa16a73f26719753a4e5ff6a76a22b3`
installs JAR `42a4631744597a7ae160de0a39f65597716ddfd34734d855e2801b9ed5fa0408`
with five verified manifests and an unchanged base Ghidra launch file. The JAR
contains 212 Java 21 classes; the package includes 45 production sources plus
two scripts. The new
consumer is SHA-256 `99da32dc028bb1cef432d79436bc6b8265eea615f87dec3fec8d292a2e013dc5`;
the additive reader/handoff script is
`cff65c9faa3fb27ff398fee7ae662bd468844c5b1868eb5ab5f4e16ca486feda`.
The prior owned-writer oracle remains unchanged at `8c24db64...`.

The root command `python3 build/reported-preparation-review/run-installed.py`
records exact commands/environment and protection snapshots under
`build/reported-preparation-review/installed-workflow.c_iw0egr`. It invokes the
association harness once per target with its explicit `FORGE_REPORT_MANIFEST`,
private `FORGE_MODULE`, `FORGE_RETAINED_EXPORT=1`, actual Java 21 and `javac
--release 21`. The three successful association directories are
`run.h1JRL8NH` (x86-64), `run.EETVW8KW` (AArch64) and `run.cPi9NaOT`
(MIPS32 big-endian). This is explicitly an older-producer replay, not a new
Ghidra export by the current reader/writer installation.

All nine exec/PIE/no-ID cases pass. Independent review reconstructs 18 ordinary
repeated candidates and twelve successful control candidates byte for byte,
checks all 78 controls, and verifies each complete inventory against its report.
The retained evidence includes 27 report/full-transcript sets, 81 earlier
artifact copies and 45 current input copies. Hash differences, metadata
differences, unsupported target/allocation layouts and no allocation evidence
prevent construction; malformed/terminal reports fail before selected-file
access. Unknown valid diagnostic text remains unclassified with PARTIAL/NOT_RUN.
Ten independent handoff controls check exclusive creation, provenance/digest
failures and strict manifest version types. Separate three-profile checks prove
default rejection of older installations and acceptance only with explicit
retained-export mode.

Ordinary candidates pass GNU header/program/section/note checks and LLVM's
completion marker with exact tool identities. Nine ordinary GDB transcripts
prove source/type/address lookup, including three native x86 value19/23 runs;
the six cross-target debugger checks are static. Nine original/candidate plain
execution pairs pass natively or under QEMU with matching output and zero exit.
Three intentionally corrupted appended-DWARF sidecars fail LLVM with positive
error exit codes. Three independently owned sidecars with missing recorded
source paths still bind by hash/ELF predicates, but static GDB emits the exact
missing-source warning despite loading the selected sidecar. These negative
checks do not relax ordinary debugger diagnostics or invent validator approval.

All 44 globally protected paths remain byte/size/mtime identical, including 36
original fixtures. Later outer GNU CRC tests change and restore three private
no-ID sidecar mtimes; final bytes and each component's exact before/after records
are verified, without claiming those private final mtimes unchanged. The prior
GNU/program/content/owned-writer oracles also pass in these same invocations.
No repeated strict validation of unchanged sidecars is attributed to this replay.

Independent runtime audit:
`installed-workflow.c_iw0egr/independent-runtime-audit.json`, SHA-256
`087c6d66609a30774f801e857fef13678bf7f954110ef796aa350f533f2799d9`.
It checks 715 retained files without additional exporter/validator/GDB execution.
Earlier test-setup failures remain retained: invalid required inventory fields
correctly rejected by the strict parser, and GDB returning a missing-source
warning rather than the initially expected exception. The final assertion checks
the exact warning and loaded symtab. An earlier preliminary receipt's broad
"no GDB" wording was inaccurate: its three static source-negative checks did
run GDB. That wording is withdrawn here; those checks did not run an inferior.

The workflow adds the detailed suite to Linux/native Windows and explicit
report handoff plus connected preparation to all five existing target lanes.
Local exact package review for `de4f68f` passes: ZIP SHA-256
`7db090e00a3eb7908f0cccb8c22b5c4b44a4f48d139b1f435634e3f575a038d7`,
45 production sources plus two scripts, 212 Java 21 classes, five manifests and
pinned native provenance. All 28 runtime/native/script payloads equal the
tested private installation. Normal merge `c76d851` incorporates accepted
PR #39's compiler-oracle helper and preserves both documentation histories.
A refreshed final package and full hosted/native Windows acceptance remain
pending. No
public attachment, independent validator receipt, authenticated report, generic
source-correlation proof, immutable snapshot or host transaction is exposed.

## Detailed preparation hosted acceptance and normal merge, 2026-10-24

**CONFIRMED:** PR #40 head `13e706e5cc11011f11576958940303fe0d0c213a` passes all
twelve jobs in exact pull-request run `40119714272`, attempt 1. Normal merge
`2584541849ffd4c7d6a9ab3933e2d3ec3d89ed4b` at `2026-10-24T18:43:12Z`
preserves the tested tree. Exact-head/base/protection and zero unresolved review
threads were checked before normal merge. Native ABI and VERSION are unchanged.
The separate exact-main push `40121995458` subsequently passes all twelve jobs
on attempt 1. Digest-verified Linux/Windows GUI and native Windows 22 checks pass;
main target-job conclusions remain CI scope, distinct from the prior PR audits.

Hosted package artifact `12571071079` has outer SHA-256
`b993006870372a218eb2dbab5afb2f723c4cb06d130c90fcbb09398b88a67b2f`,
ZIP `561d737161556e292f038f3bf5afc380544428c7a92b632b752f484082394ebe`,
and JAR `3c4d4100812b5b1be3f668f531527c4d5ea566b4ab3d78c50e83b2c07d070099`.
Independent review verifies 45 production sources plus two scripts, 212 Java 21
classes, five manifests, exact packaged docs/support and pinned native provenance.
Actual Java 21 passes detailed432, both retention caps reached together, prior
focused checks and twenty producer lifetimes; 161 production class origins are
bound to the downloaded package. Hosted JAR identity is separate from local42a.

All five installed target artifacts pass independent review. Fifteen fresh cases
produce thirty ordinary repeated candidates and twenty positive-control candidates,
all independently reconstructed. Review verifies 130 controls, 45 complete report/
producer-log sets, 135 earlier byte copies and 75 current input copies. Fifteen
ordinary GDB transcripts pass (three native x86 value checks, twelve static cross
checks), and thirty plain original/candidate processes pass natively or under QEMU.
The prior GNU/program/content/owned audit chains remain separately bound. Reports
retain PARTIAL/NOT_RUN and complete unclassified diagnostics.

Linux artifact `12571726025` is SHA-256
`a42cda157fbbc6d5dab760224c6a474397e1dba94032640cfb27d85e53b3b85d`,
association `run.XR94fa2L`, GUI `run.AjhVwB4E`. Its 24 strict reports have zero
unexplained errors; three exactly corroborated inherited GUI frame diagnostics
remain visible. Windows artifact `12570898973` is SHA-256
`8da3cc9097613c5dc32147915b699d3795fd7e3c5122eb2dbeb4fc89e46bf10d`,
GUI `run.923e87944dca4e5d941544ccdba0156a GUI paths`. All 22 native focused suites
pass on Java 21.0.12.1, with detailed432, owned1140, content965, program431 and
binder551 actually observed. The combined 16,384-entry/1,048,576-UTF-16 boundary,
real aliases/sentinels/link/rollback cases and both GUI journeys pass without skips.

The initial MIPSBE artifact audit assumed empty negative workspace directories
would survive upload. Its ZIP contains 2,400 files and zero directory entries.
The corrected, independently reviewed auditor requires no retained descendants
for an absent negative workspace, while preserving all positive path/ownership/
byte reconstruction checks. That first auditor failure is retained. Runtime
assertions are unchanged; negative-directory existence cannot be independently
recovered from the archive. Remote tool hashes remain recorded invocation facts;
hidden `.build-id` payloads and invocation-time nanosecond mtimes are not retained.
Windows independent libdwarf/Linux ELF runtime, Linux FIFO/large and hosted shared
writer coverage are not inferred.

Evidence is under the reported-preparation worktree's
`build/reported-preparation-package-audit/run-40119714272.pSzdTK5H`,
`independent-final-gate-40119714272.json`, `root-final-*.stdout`, and
`watch-40119714272/windows-focused-review.json`. The eight peer aggregate/GUI/
Windows receipts and exact artifact hashes are under the GUI worktree's
`build/hosted-gui-review/run-40119714272`. Independent audits ran no new exporter,
validator, GDB or inferior processes. No attachment transaction or release follows.

## Separate PR #38 and #39 main-push acceptance, 2026-10-24

**CONFIRMED:** exact-main run `40113254401` at `2bd6739`, attempt 2, passes all
twelve effective jobs. Native Linux, extension build and workflow lint explicitly
reuse successful attempt-1 results; the other jobs and both GUI journeys ran again.
Independent Linux/Windows GUI and native Windows20 evidence passes. Attempt 1's
runner communication loss, absent Windows logs and skipped dependents are retained.
Linux artifact `12570464772` / GUI `run.D9Zrhoax` and Windows `12570921782` /
GUI `run.67b2302f93b446cfa9ea6ab7bebe8843 GUI paths` are bound in the exact receipt.

Exact-main run `40118899783` at `4e050609`, attempt 1, also passes all twelve jobs.
Independent Linux artifact `12571655098` / GUI `run.HqxTXfrA` and Windows
`12571500634` / GUI `run.0166695351a14e19be6c1170aee1cd23 GUI paths` pass. Native
Windows21 observes owned1140/content965/program431/binder551. These receipts are
`build/hosted-gui-review/run-<run>/acceptance-scope.json` in the GUI worktree.
The four main cross-target conclusions are CI evidence, separate from each PR's
already accepted detailed target artifact audits. Neither retry nor main success
changes the published releases.

## Captured validator evidence and connected local acceptance, 2026-10-24

**CONFIRMED locally; full hosted integration PRESENT, UNVERIFIED:** source
`93905654b11b10b3bdbaa5a616d72eedec524002` introduces the test-only capture/reader
and focused controls. Core SHA-256 is
`6cb11a1ec2d4071eddf1a8dae82c66278f066a6b7138b42d2c077902167a3647`;
test `e6b0c2c5766ef1e30d0efaf718d1fc907418e5b180b7280de5ad5cd03831c491`.
Final focused `run.4k9nvpm6` passes 100 checks: 97 core cases plus three additional
read-only checks of the actual retained native 65,536-message corpus. Core cases
include generated complete capacity output, real compiler exec/PIE/no-ID captures,
zero and exactly inherited diagnostics, typed high-bit ELF64 frame metadata,
rewritten-SHA frame rejection, bounded parsing/I/O, aliases and failure cleanup.
The three size-only 128 MiB sparse placeholders retain recipe/sizes/hash-call
counterproof before exact owned cleanup. Older prototype/test runs remain retained.
Independent source/test review is `independent-core-review.json`, SHA-256
`28ce0de09d9bf572eb7140b3baac5cb04efa6147ba5476380643009f503990ec`.

Root command `python3 -B build/validation-evidence-review/capture-retained.py`
produces `live-capture.esjs8pj1`: nine new LLVM/strict pairs on explicit older
x86-64/AArch64/MIPS32BE exec/PIE/no-ID exports. It makes no Ghidra export.
Each job-local toolset retains 28 tool/source/configuration/version-output files.
Independent streamed rehash and complete-output review verifies exact selected
bytes, invocation arguments and frame correspondence. Strict reported counts
are x86 3/1/3, AArch64 5/5/5, MIPSBE 0/0/0; all 22 diagnostics are exactly
corroborated against the originals and unexplained errors are zero. LLVM passes.
The current libdwarf checker binary is SHA-256
`cac5a7a3a0d2e82326a4f8a6cc9b8f5b9ca356630b846c7215592bd2f9cf4afc`;
LLVM binary is `07cf5eb367dcf51a8f462e046b08409fbe4a6fe60506fb0d4e5604db024873a1`.
Their retained bytes, configuration, parser and provenance are actually rehashed;
dynamic dependencies and ambient process state are not authenticated.
Capture audit: `independent-capture-audit.json`, SHA-256
`c78e9d5d2bdee74d703bc0a6ea7dc1c1f773d67fcb0feb9776ea1fa799f74a4d`.

Root command `python3 -B build/validation-evidence-review/run-installed.py
build/validation-evidence-review/live-capture.esjs8pj1/selection.json` runs the
existing association workflow through the unchanged installed Java-21 JAR
`42a4631744597a7ae160de0a39f65597716ddfd34734d855e2801b9ed5fa0408` with explicit
retained-export mode. All nine cases pass in `installed-workflow.o5o8aav8`:
x86 `run.LqI25sJt`, AArch64 `run.U8QRCmt2`, MIPSBE `run.GqDXrfAW`.
Independent review reconstructs eighteen ordinary repeats and twelve successful
raw-control candidates, verifies 78 raw controls/45 mutant inputs, 27 report sets,
81 earlier byte copies and 45 current input copies. Nine ordinary GDB transcripts
include three native x86 value runs and six static cross checks; eighteen plain
original/candidate processes pass natively or under QEMU. Three deliberately bad
DWARF controls fail LLVM, and three missing-source checks are static GDB only.
The existing GNU/program/content/owned oracles pass separately in the same runs.

Six malformed/legacy handoffs per primary exec call the actual connected entry
point with Java/compiler sentinels: eighteen normal nonzero rejections, no sentinel
invocation, and no classes/workspace/candidate/success result. Rejection evidence
distinguishes NOT_CAPTURED from NOT_VERIFIED. Normal cases bind their current
selected bytes to schema2's explicit index before Java preparation. All 40 capture
protected and 225 runtime globally protected paths retain SHA/size/mtime. The three
later private no-ID CRC tests change then restore bytes, with changed private
mtime documented separately. PARTIAL/NOT_RUN and raw-probe limitations remain.

Runtime audit `installed-workflow.o5o8aav8/independent-runtime-audit.json` is
SHA-256 `4fbccbc565cc58651f3c3287d5166d680768cfa9c87adb4409523fb087f8b3ca`;
independent raw recipes are `independent-control-recipes.json`, SHA-256
`315999d0293daa5208668bd6189e2c0aed2f374d80aec499a777fa37ae065570`.
Connected capture/gate audit is `independent-capture-and-gates.json`, SHA-256
`ac6217f1bc59419a29b30697e17f9b332cb974b5793e3f12e09d6046c18eb6af`.
These paths are under the validation-evidence worktree's
`build/validation-evidence-review`. Auditors execute no new tools/targets. An
initial audit-only raw-versus-resolved fixture-spelling assertion is retained;
corrected argv checks use the explicit spelling and separately bind resolved bytes.

Workflow/shell/Python syntax and source reviews pass. The pipeline captures its
three selected primary roles once each, then passes the exact index through the
early report handoff. Focused controls run in x86 CI; all five target lanes use
the normal evidence gate. Fresh-export workflow integration, exact final package
and full hosted acceptance remain required. No production API/native ABI, public
validator supervisor, attachment, source-authenticity or release claim follows.

### Captured validation hosted acceptance and normal merge (2026-10-24)

**CONFIRMED:** PR #41 exact head `f52361a374fbf62fd7168eb8e8a8c4e8be0d7b4c`
passes all twelve jobs in pull-request run `40123518106`, attempt 1. Normal merge
`fdebe181185ffe7fa5a454252261f070a3099a3c` at `2026-10-24T19:37:50Z`
preserves the tested tree. The separate exact-main push `40126173922` passes
all twelve jobs and independent both-GUI/native Windows 22 review. This main
review is distinct from the detailed PR artifact audits below.

Hosted package artifact `12572202938` has outer SHA-256
`de909dbfd111ae3fb105af6f2c85f01b177579b4dd3f3660a78e03acac050d9a`,
ZIP `76728eccb3ca54a6bb69a6fd552851c77ddbe41fc89f29ee6385938f193d9411`
and JAR `3c4d4100812b5b1be3f668f531527c4d5ea566b4ab3d78c50e83b2c07d070099`.
Exact 45 production sources/two scripts, 212 major-65 classes, five manifests,
current docs/support and pinned native provenance pass. Actual Java 21 detailed432,
both retention caps, inherited focused checks, twenty native producer lifetimes
and 161 production origins pass. Production Java/native/script bytes are unchanged
by this test-harness change.

All five target artifacts pass independent review: fifteen fresh cases/captured
validator pairs, thirty actual entry-point sentinel rejections, raw130 limitation
controls, thirty ordinary plus twenty counterexample candidate reconstructions,
45 report sets, 135 earlier copies and 75 current input copies. Fifteen ordinary
GDB transcripts and thirty plain native/QEMU processes pass. Full retained tool/
configuration/output/source and selected-file bytes are independently rebound.
Reports retain unclassified PARTIAL/NOT_RUN; malformed DWARF and missing-source
counterexamples remain explicit in the separate raw controls.

The hosted focused result `run.g1kmmtxk` records 97 actual checks, with exact core/
test hashes and all six tiny compiler inputs independently verified. This is
separate from local100, which includes three optional retained native-corpus
checks. Existing named-suite strict24 replay is separate from the fifteen primary
captures. Complete output has zero unexplained diagnostics; exact inherited frame
counts stay visible. No optional local capacity replay is inferred from hosted97.

Both GUI artifacts pass independent digest review. Linux run `run.wWYTJ9vi` is
in artifact `12573555669`, SHA-256
`a392892d617181061f3a73bf34ca1b1a05a82569dd5720d84e43281d6de8c869`.
Windows run `run.2cc954bed9214bdaa76bd69163802a11 GUI paths` is in artifact
`12572637140`, SHA-256
`17b0e757994b54e96bc56a30705ecec534b633e5d50e7a24a039f656c43af36e`.
Windows actually observes 22 focused checks under Java21.0.12.1, including
detailed432 with both caps, owned1140/content965/program431/binder551 and real
alias/sentinel/link/rollback controls. Linux-only runtime/FIFO/large behavior is
not inferred on Windows; independent libdwarf dwarfdump remains unavailable there.

Final independent source/package/artifact receipt SHA-256
`74d270179107eb769be68b2a1da2f5b78d7481ba64898baa1048d63a66a0799f`
is retained under `validation-evidence-handoff/build/validation-evidence-package-audit/`.
It binds the exact package plus eight peer receipts, including acceptance scope
SHA-256 `9e35d6d06eaa6fd0d225642298de3611093a018d37154e7bf4c75112fe918fe7`.
Root separately checked fresh exact head/base, strict required-validation, all
jobs and unresolved reviews before the normal matched-head merge. Empty negative
archive directories and invocation-time mtimes retain their documented limits.
The attachment transaction and published releases remain unchanged.

### External-function inventory local acceptance (2026-10-24)

**CONFIRMED locally, subsequently accepted in the hosted record below:** the ordinary Ghidra iterator
excludes genuine external functions. The production correction enumerates them
separately, retains qualified diagnostic names and one skipped row per function,
and leaves memory-thunk multiplicity distinct. The former external-or-thunk log
assertion passed without proving this inventory. External declaration/signature
emission remains deferred; no target address, type, source or serializer path
is expanded by this correction.

Evidence is retained in
`/home/ziggy/GhidraDwarfForge-worktrees/external-function-research/build/external-function-review/`.
The implementation directory records exact commands, versions, before/after
snapshots and full outputs. The tested private JAR is
`d983a2989178cdc8503b90d92dbcf1bbddd1251fed5b7805ab6e2a31f5a5e395`.

- `./gradlew externalFunctionInventorySmoke qualifiedFunctionNameSmoke
  exportReportSmoke buildExtension` passes. The new focused test exercises real
  ProgramDB iterators for all five language models, same-leaf/different-library
  and duplicate-qualified-name functions, unreferenced and unknown signatures,
  typed external-data exclusion, separate memory thunks, deterministic report
  order and cancellation. Its source-selection callback returns null for the
  sole real definition; no external/thunk reaches it, and no actual decompilation
  or DWARF producer is invoked by that callback.
- Actual Java `21.0.12.1` passes the same focused check. Compilation uses
  `javac 25 --release 21` because the local Java 21 installation has no compiler.
  Running against prior JAR `42a46317` rejects at the intended missing-inventory
  assertion. Nine checker controls reject missing/duplicate external rows,
  thunk-only inventories, mismatched counts, missing diagnostics, duplicate
  markers and unexpected trailing logger text. The parser accepts the exact
  GhidraScript suffix; the initial whole-tail JSON parsing error is retained.
- The original saved project exports under the old, fixed and repeated fixed
  exporter to byte-identical `.dbg` SHA-256
  `008fda823bf2031c48a35a53553a94c5f398548b0ed9d71d52ae498ac60c938a`
  and `.dbg.c` SHA-256
  `5800c8fbf780258c51564b4a1b376283014d4ec372f3f17955904dc694d9eb5c`.
  All nine definitions/decompilations/signatures and all other counts remain
  unchanged. Only skipped/diagnostic inventories and their counts change:
  five to nine skipped rows, six to ten diagnostics. All fifteen protected
  files retain bytes and sizes. Four Ghidra project index files
  (`idata`/`versioned` `~index.dat`/`~index.bak`) change mtimes only; their bytes
  and the actual program database remain unchanged. The failed assertion that
  every project mtime would remain unchanged is retained and superseded only
  by this precise post-run observation.
- Five fresh primary ET_EXEC fixtures are built, imported, analyzed and exported
  through `headless-symbol-export.sh`, then checked by `qemu-gdb-symbols.sh` for
  x86-64, AArch64, ARM32, MIPS32 big-endian and MIPS32 little-endian. All commands
  pass. Exact external rows/counts and both unreferenced curated functions are
  required by the shared fixture. GNU/LLVM validation passes; strict libdwarf
  preserves inherited-frame counts 3/5/0/0/0 with zero unexplained errors.
  Existing GDB type, source, parameter/value and stepping checks pass natively
  or under QEMU. AArch64 and ARM32 GDB logs retain the existing system-supplied
  DSO corrupt-string-table-index warnings; the established harness assertions
  pass without a new warning exception. Twelve fixture/module paths preserve
  SHA-256, size and mtime.
  Headless execution uses Java `25.0.4.1`, separately from the actual-21 smoke.

Retained setup failures include the omitted packaged-native flag, an unavailable
`javac` under the Java 21 runtime and the overbroad project-mtime assertion; they
are not counted as passing invocations. Independent source and retained-runtime
reviews pass, including all artifact hashes, original frame bytes, complete
checker output and the exact four project-mtime exceptions. This read-only
review does not rerun any exporter, validator or inferior. The exact final
package and all hosted roles subsequently pass the separate record below. No Ghidra,
Java, GDB baseline, release or optional attachment operation changes.

**CONFIRMED exact local inventory package:** source `0804b46`, ZIP SHA-256
`32d6dcfaca87db85dafbb22dff457d6bf3f4b4106fafeb08bf4084000790f582`,
passes 45-source/two-script/212-major-65/five-manifest review. All 28 runtime
payloads match the tested private installation; comparison to the prior accepted
package finds only the `GhidraFunctionSymbols.class` JAR member changed. Actual
Java 21 five-language inventory and inherited checks, twenty producer lifetimes
and 163 production origins pass. A copied hosted-only audit footer subsequently
failed on an unset mode; the failed wrapper/stderr are retained. Independent
post-run output/hash review closes that audit without repeating JVM/native tests.
Normal merge `e3d0709` incorporates accepted PR #41; only two appended document
histories conflicted, and both were retained. The refreshed combined package
and full hosted acceptance subsequently pass the separate record below.


### External-function inventory hosted acceptance and merge (2026-10-24)

**CONFIRMED:** exact PR #42 head `296395e9496042bd34f0a383fce334c6a8019f5a`
passes all twelve jobs in `40126794530`, attempt 1. Independent source, package,
all-five-target artifact and both-GUI reviews pass. Native Windows observes 23
focused suites, including all five external-inventory language models. Fifteen
unique primary inventories match the exact Ghidra API observations; 45 repeated
child bindings remain separately counted. Existing fifteen captured validator
pairs, thirty entry-point rejection controls and 130 raw controls remain intact.
The named 24 strict reports have zero unexplained errors and are separate from
captured primary pairs. External declarations remain deferred.

Hosted package artifact `12572623938` has SHA-256
`5dea29bd1cbec048c0ecced842b5dce33491dbe8183d6058312b60d5b7e4b61d`.
The enclosed ZIP is
`c7399871093ab5a50fc3bdb4b573f03485865daf5e357202243d8e59e9db7808`,
with JAR `d0bedb4db10e102b598d4cd015d6a43f5eb970e6e0b3bba9bd907391975e38da`.
Its exact source/docs/manifests and native provenance pass; actual Java 21
focused checks and twenty native producer lifetimes pass. This hosted JAR is
separately identified from the earlier local package.

Final independent gate evidence is retained under the external-function worktree:
`build/external-inventory-package-audit/independent-final-gate-40126794530.json`,
SHA-256 `6b9bda98a927409353b12691d132d8209b383aa089804c44e6afa65f214b4fa2`.
It binds the package receipt and eight peer receipts, including final GUI/artifact
acceptance `f676bc744172d4a7aadde5c95067ccfc4b7156ad3d1c77900006ec60db990344`.
Archive omissions, recorded runtime provenance and Windows validator/runtime
limits remain explicit; artifact inspection is not fresh execution.

Root independently rehashed the reviewed sources and receipts and checked live
head/base, strict required-validation protection and unresolved reviews. Normal
merge `0d2cbc5ad1ca10eb98077f67675bfc8a1927c11d` at `2026-10-24T20:22:37Z`
has the tested tree. Separate main push `40129499500` passes all twelve jobs
and independent both-GUI/native Windows 23 review. Its target job conclusions
are a separate CI scope from the detailed PR artifact reviews above.
Published releases and optional attachment remain unchanged.

### Host-observation research integration (2026-10-24)

**CONFIRMED:** PR #43 head `bdc3502059beb2e91180293dfcb5abd0cabc2ad0`
passes all twelve jobs in `40130322553`. Exact source/package review, the
separate two-host inspection trial, both GUI journeys and native Windows 23
checks pass. The production runtime payloads equal the accepted PR #42 package;
five target job successes are CI evidence, not newly attributed detailed target
artifact audits. Normal merge `0f1abdc1cadeae5ffc17ca5a732a26fe766bd7f7`
preserves the tested tree. Its distinct main push `40132729633` passes all twelve
jobs and fresh independent both-GUI/native Windows 23 review. Acceptance receipt
`294de8d9908c5028c4a28c94e0ca288abad6bcda0913f0e8dab179546d8e83ff`
binds that separate push; target job conclusions remain CI scope.
The probes do not implement optional attachment or publish a release.

### Bounded ARM/Thumb mode symbols: local acceptance (2026-10-24)

**CONFIRMED locally; hosted gate pending:** the new production path restores
ELF function-mode cues for a mixed ARM/Thumb ET_EXEC whose static symbol table
was stripped. It leaves DWARF code addresses even, emits exact-size synthetic
local ELF symbols, and checks actual instruction coverage/context and original
code bytes. Synthesis is restricted to ET_EXEC without named defined dynamic
symbols. Existing symbol tables and uncertain cases receive conservative
omission diagnostics. See [the scope and initial failure](research/ARM-THUMB-MODE.md).

The local interim runtime ZIP has SHA-256
`1794aa0724786bdb8605ddb509608af76099c49ee0edb58cc89a3891e50b3ba3`,
with JAR `e0888311f678f281f9288a7cb4c09213b8717bf04197e3a520052ebbd2bd684b`
and production script
`eb636d3abc2c3f43aac6a4593b1c25ef53dcbe05a1cdb190d75d44550ec068b6`.
Its 49 production sources, 220 Java-21-compatible classes, five manifests and
native provenance pass author verification. Only JAR/script differ among the
28 earlier runtime payloads. Documents changed after that interim assembly;
the initial exact-document audit failure is retained and final package equality
remains required.

Actual Java 21 focused checks pass: 132 planner/serializer assertions with a
64 MiB heap and 38 Ghidra extraction assertions. The extraction test is compiled
with JDK 25 `--release 21`; the local Gradle run's test classes are Java 25. Existing
ELF inherited-debug, extended-numbering, reader and cancellation regressions
also pass. Independent GNU readelf checks accept ordinary, extended and mixed
symbol section indexes. Source/focused evidence review
`build/thumb-mode-review/gui-frozen-source-review.json` has SHA-256
`04daeb0df067a52badc35028cbb40e408c9268aa3de1bf4a04b38a760845280b`.

Final installed run `build/test-results/arm-thumb-mode/run.nkBwUuYA` uses the
real packaged exporter on a stripped, source-built three-unit fixture. GNU,
LLVM and strict libdwarf checks pass with zero unexplained errors. Two exports
of the same saved program produce identical sidecar/source/report bytes.
Four compiler/Forge GDB sessions prove static Thumb disassembly, an adjacent ARM
function in the same section, direct and indirect calls, source stepping,
typed global values and an exact-entry stop from an ARM caller. The report
remains `PARTIAL`/`NOT_RUN`; four parameter location omissions remain explicit.
Eleven protected source/input/installed paths remain unchanged. This headless
run uses Java 25.0.4.1, separately from the focused Java 21 tests.

The old accepted exporter fails the same static-disassembly assertion after
passing GNU/LLVM/strict checks, establishing a nonvacuous regression. Retained
setup failures include an initially incorrect focused-test guard expectation,
an inclusive GDB disassembly endpoint, and a tracing file descriptor inherited
by a child shell. Their corrected runs are separate. This is not broad Thumb,
PIE/rebase/shared-object, sectionless-mode, or native breakpoint-encoding
acceptance; the current supported ARM-state profile remains unchanged.

The first hosted attempt at head `02a4bfa` (`40135704323`) is not accepted.
Its package precheck passes exact source/docs/manifests and downloaded-JAR-first
Java 21 planner132/extraction38 checks. The x86-64 and ARM target jobs then fail
the existing exact fixture-source inventory: the three new `arm-thumb-*.c`
files were not registered. Both stop before exporter/GDB/GUI work. Their logs
and digest-verified artifacts are retained in
`gui-script-manager/build/hosted-gui-review/run-40135704323/`; first-failure review
SHA-256 is `8c6ddb95fad75451976f93fdba74a1c2e700751cec0bc6c7262cc1b13d5519de`.
The correction adds only those three reviewed names to the inventory, preserving
the exact guard and existing Makefile behavior. Local x86-64 fixture inventory
and all thirteen byte-identical rebuild checks pass. A fresh complete hosted
gate remains required; the successful component package checks do not substitute
for it.

### PR #44 shared-object correction (2026-10-24)

**CONFIRMED:** the second run `40136340620` at `5c4f14c` is not accepted.
The x86-64 job fails standalone compilation because `large-elf-sidecar.sh`
omits the new `ElfLocalFunctionSymbol.java` dependency. The ARM job reaches its
existing shared-library GDB oracle, where a partial SHT_SYMTAB suppresses
dynamic minimal symbols and `break recovered_add` also selects the driver's
PLT entry. AArch64 and both MIPS jobs pass; Windows is skipped and the required
gate fails. The failed-run independent receipt has SHA-256
`c5c9072749254b8ab0bdc1cbc566d0a8b67b253cdac9a628fae99d9b0288120e`.

Owned reproduction `build/thumb-mode-review/arm-shared-regression/run.2k3c1bhy`
uses the installed interim `e0888311...` JAR, distinct from hosted `f0670a27...`.
The unchanged shared GDB script fails with its generated artifact and passes
with a diagnostic copy that nulls only the added 40-byte SYMTAB section-header
row. All other bytes, including every DWARF/dynsym payload, are identical.
Minimal-symbol dumps prove loss/restoration of the global `recovered_add`.
Independent causal review SHA-256 is
`03d1434f455e50935f7109ead0d09b1106cae4c6e5f1d7ae6eee6baa7fe777dc`;
eight source/module and four fixture hash/size/mtime observations remain equal.
This is a diagnostic experiment, not an accepted production sidecar.

The correction restricts synthesis to ET_EXEC without named defined dynamic
symbols, including nonoverlapping code, data and absolute definitions. Undefined
imports keep their existing handling. The standalone build lists the new record.
Gradle passes 231 planner/serializer and 38 extraction checks and builds the
extension. The corrected standalone large-ELF oracle passes on a 2,147,487,745-byte
input with a 64 MiB heap, GNU/LLVM verification, strict libdwarf and actual GDB
values/source/stepping/exit checks. Strict validation records two corroborated
inherited frame diagnostics and zero unexplained errors. Its evidence is
`build/test-results/large-elf-sidecar/run.wR6fH7ii`.

An always-run capture step retains only the explicit primary fixture/output
allowlist, at most 16 MiB each, with streamed hashes and missing/error states.
Local controls cover actual fixture copies, all-missing output, preserved old
receipts, rejected links/FIFO/oversize files, an exact-limit file and exclusion
of an unlisted 40 GiB sparse file. These are end-of-job diagnostic snapshots,
not invocation-time provenance.

**CONFIRMED corrected local runtime:** interim ZIP SHA-256
`6008d117ed3bd4a4374e1e2808d0010c27eee66abf07c1a51883ecd589a2c96d`
contains JAR `5faafc7397d101308bd68742ec25309b307169a765e6d8fa1a9081d03df0d292`
and the unchanged production script. Independent JAR-first actual Java 21
checks pass planner231 at 64 MiB and extraction38 at 256 MiB. All 49 production
sources, 220 Java-21-compatible classes, five inventories and unchanged native
payloads match; review SHA-256 is
`906d9ebaa5f559e84392b5ff31f90ed5818fb41145f0c1f69655484560fbd19d`.

The private installed exporter passes three real cases. The checked-in Thumb
harness (`run.dVVInSY5`) retains its static and four compiler/Forge runtime GDB
checks, validators and deterministic repeat. An owned copy adding only the
linker's `--export-dynamic` switch (`run.Tq1um02E`) passes those same GDB checks
with original dynamic symbol/string bytes preserved, an explicit omission and
no synthesized static table. A clone of the saved shared-library program now
passes the unchanged shared GDB oracle and GNU/LLVM/strict validation through
the corrected production exporter. The latter two are local controls, separate
from the checked-in CI Thumb harness. Their receipt is
`build/thumb-mode-review/arm-shared-regression/corrected.0zon9mad/result.json`,
SHA-256 `442cdcb96b6a728323d6c6e3ce4bc9ba4cb3f7de9a73241ec5083e3d1629fba3`.
All 74 selected earlier evidence/project files and four shared inputs retain
their observed bytes/size/mtime. Headless execution uses Java 25; actual Java 21
focused checks are separate. Initial package-auditor layout assumptions stopped
before runtime and remain retained. Final exact-document packaging and a fresh
full hosted gate are still required.

### PR #44 hosted acceptance and integration (2026-10-24)

**CONFIRMED:** exact head `c16628574dbb7546f70fd666187f8f1a522686d3`
passes all twelve jobs in pull-request run `40138005382`, attempt 1. Normal
merge `f359d1831f9a6923d0a60c07fc4c7bd1fa2a32ba` preserves tested tree
`e79d012213dba9c7a5208fab53acd055d33d000c`. Distinct main-push run
`40140510117` subsequently passes all twelve jobs and separate fresh artifact
reviews. Its acceptance receipt SHA-256 is
`e519d1728f3c90746ea76cf29514d975ce96735838e803e0d285be0a987617d6`.
Both actual GUI hosts, native Windows 25/231/38, ARM Thumb/shared/primary capture
and the x86 strict24 subset are independently clear; other cross-target suites
retain CI-execution scope. No PR #45 acceptance is implied.

The fresh downloaded extension ZIP has SHA-256
`eca4dae30812df5239915d2ba699cc30cbc587f4dd0eeb73249754cc5ae959fa`;
its production JAR has SHA-256
`58defbacc721af249ca0ce27dddcf2864e15e2a31e19ad576ab208ab866178e6`.
The package audit binds all 49 Java sources, two scripts, 220 Java-21-compatible
classes, current documents/support files, five manifests and both native
provenance records. Downloaded-JAR-first actual Java 21 passes 231 planner
checks at 64 MiB and 38 extraction checks at 256 MiB.

Independent artifact review verifies both actual GUI journeys, native Windows
25 suites, the five-language external-function inventory, the exact ARM/Thumb
regression, and the unchanged shared-library GDB oracle. The retained primary
fixture capture has all 28 requested files and no errors. The shared sidecar
has no synthetic SHT_SYMTAB, preserves dynamic symbol/string metadata and bytes,
and resolves the real recovered function with the expected value and normal
exit. A named 24-case x86 strict-validation subset also passes. Other target
suites have CI-execution evidence; they were not all independently re-audited
at artifact level in this gate. Windows lacks independent libdwarf and does not
run Linux ELF GDB or the Linux large-file/FIFO cases.

Final acceptance receipt
`gui-script-manager/build/hosted-gui-review/run-40138005382/acceptance-scope.json`
has SHA-256 `7a9c8eab00ebcc9f008203f95a79b9755a335c3eeb4e487c527cc406dbc4da96`.
The independent package receipt SHA-256 is
`fe3567aba8e84871eb45e0aaa6eba0005b5b4142c62842afcf402c315b1416c5`.
The root integration gate freshly checked all job conclusions, protected-branch
requirements and exact head/base, and rehashed the retained evidence before
normal integration. The failed earlier gates remain historical failures.
No general Thumb PIE/shared/rebase or new release claim follows.

### Effective dynamic parameter storage: local controls (2026-10-24)

**CONFIRMED locally; hosted acceptance pending:** the correction changes only
the `stableParameter` unassigned-storage guard. It uses effective Ghidra storage
instead of the persisted symbol's assignment flag and preserves all remaining
validity, lifetime, prefix, local-variable and cancellation policies. The pinned
API investigation and initial saved/reopened old-exporter omission evidence
are retained in `thumb-mode-cues/build/next-abi-profile-review/`.

Interim runtime ZIP SHA-256
`c2e70b3a2c7f487405280de5caf7aa8b91fa37c545fa3819968b430eb8cd9b5d`
contains JAR `2fb0d5e41ca6507e4f65e2f1b5dfde5ce61d8d00f541d1355519c43f8c691600`
and unchanged production scripts. Private installation verifies all 49 embedded
production sources, two scripts, 220 major-65 classes and five manifests.
This package predates the dynamic-storage documentation; final exact-source
packaging remains required.

Focused actual Java 21 run `build/dynamic-parameter-review/java21.x0e43r3e`
passes 154 assertions across five language profiles, including saved/reopened
programs and public type/location extraction. Tests are compiled with JDK 25
`--release 21` and run with a 256 MiB heap, packaged JAR first; class-load logs
bind the actual storage/type extractor. The same compiled test against the
earlier `5faafc73...` JAR fails on its first x86-64 computed parameter with the
expected `UNASSIGNED` reason (`old-jar-negative.5v5kspsd`). It does not reach
later targets or reopening. The Gradle focused and existing variable-storage,
prefix, alias, register-copy, stack-first-use and opaque-effect suites also
pass, as does the extension build.

Installed ARM run `build/test-results/arm-dynamic-pcs/run.pWyLkH3o` uses
ordinary compiler-produced code with explicit per-function base/VFP conventions
and dynamically computed Ghidra parameter storage. GDB verifies four correctly
typed float entry values, distinct incoming register bits, two honest modified
parameter omissions and natural program exit. The compiler checks named values
after its prologue; its raw argument carriers are checked at entry. Both modes
retain the real `bx lr` and `setISAMode` behavior. The test does not inject calls
or claim nonvoid return-value ABI support. GNU and LLVM checks are quiet; strict
libdwarf reports zero errors. Saved/reopened output/source/report bytes repeat
identically and all ten protected inputs/module/harness files remain unchanged.
The report is correctly `PARTIAL`/`NOT_RUN` with two `REGISTER_MODIFIED` entries.
Headless Ghidra uses Java 25, separately from the actual Java 21 focused process.
Independent retained-evidence review SHA-256 is
`35c830564af0424f929adcecdf59a2833b771528195ce5efe4ce558a3263dc0d`.

Initial failed ARM harness runs remain separate: `run.5S6U4JHq` used an
unsupported GDB Python property before export; `run.StDEybjl` used global-only
lookup for curated static Forge definitions; `run.x1TRuEE2` passed real GDB but
its checker assumed two hex digits for every GNU readelf byte token. Only
harness assumptions changed between those runs and the passing case. The
fresh full hosted gate remains separate work.

**CONFIRMED local five-target integer control:** the same interim packaged
runtime passes ten real exports and ten compiler/Forge GDB sessions with the
unchanged generic fixture/harness sources. Its author receipt
`build/dynamic-parameter-review/generic/acceptance.json` has SHA-256
`2257ac4bf25fc84f244dba36b2f872139be115afc1d652f6499b82fc35c8f40d`.

| Target | Retained run | Strict inherited frame errors | Unexplained errors |
|---|---|---|---|
| x86-64 | `x86_64.fO8iPZNl` | 2 | 0 |
| AArch64 | `aarch64.bDI7auHO` | 4 | 0 |
| ARM32 | `arm32.tOErmevw` | 0 | 0 |
| MIPS32 BE | `mips32be.msCw0QDS` | 0 | 0 |
| MIPS32 LE | `mips32le.N5zfjRR7` | 0 | 0 |

Runs reside under `build/test-results/dynamic-parameter-storage/`. All show
effective dynamic storage before/after saved-project reopen and deterministic
sidecar/source/report output. GNU and LLVM are quiet; inherited strict
diagnostics are corroborated against each original. Eleven preservation records
per case cover 19 unique paths across the suite. At 167 actually observed Forge
PCs, 268 typed parameter observations have correct values and 66 are unavailable
with matching report intervals. All ten mandatory store-function entry values
are positive. The ARM integer-return function's first parameter remains wholly
unavailable under the existing modified-register/prefix policy. These counts
do not claim unexecuted paths or individual delay-slot stops.

An isolated earlier-JAR x86-64 run fails the same real harness with `UNASSIGNED`.
A separate GDB probe confirms correct raw incoming bits but both named integer
parameters optimized out at entry, then normal exit. The negative receipt
`generic-old.vfara7c8/result.json` has SHA-256
`58aea92d143b709382eee8fc039454b600ce31d6e23d3de1632832433fd5b0d4`.
Its initial audit-side traceback-format assumption failed separately and is
retained. No fixed generic runtime or setup run failed. Root rehashed all 355
files bound by the author receipt. Independent full source/runtime review is
clear, recorded in `independent-source-package-review/result.json`, SHA-256
`90c8cfae3036eba3a8068f339df930b5e27cf4c764ceab40a0c85d19c1848147`.
Final committed package equality remains required before hosted integration.

The inherited Thumb oracle exposed one stale expectation after this fix:
`run.7UrqpknP` passes validators and all four GDB sessions, but its final checker
still expects `UNASSIGNED`. The recovered right parameter now has a defensible
R1 location and reads 7/3 on the two calls; left remains unavailable because R0
is modified. The revised oracle requires exactly that availability, no right
omission, and a full-body `REGISTER_MODIFIED` left omission. It does not accept
either outcome permissively or alter production lifetime rules.

Fresh final runs `arm-thumb-mode/run.KBDtCyM1` and
`arm-dynamic-pcs/run.kRKyZbBc` pass four/two compiler/Forge GDB sessions, all
validators with strict zero errors, deterministic repeats and 11/10 protected
paths. The four shared helper definitions are unchanged; the second run binds
the latest helper-file bytes explicitly. Thumb retains its exact synthetic
LOCAL mode symbols and static adjacent ARM boundary; mixed PCS retains four
float values and two honest omissions. Independent final-pair review SHA-256 is
`abcc7cccf93757761b9473186ae018400d817f80c13e79f7a6d73689c4596a64`.
The initial passing/failed receipts remain historical exact-source evidence.

Final local commit `ad2b556073c3996ab9c9b5be25cbdf11c62ed2ce` is packaged in
ZIP SHA-256 `c8f9a07fd0115f33fd6592a65215a057b4b00cca59e3bf763b391a53e7f1928c`.
Its exact source/document/native review binds all 28 runtime payloads as
byte-identical to the installed `2fb0d5e4...` JAR package used above. Independent
final evidence review SHA-256 is
`929a41af3eeec6d25f12596a683e6d3b1fbd2a818af575b31b81e4d3ae20ccdf`;
root independently rehashed all 547 bound files. The subsequent normal merge
of accepted main `f359d18` preserves that source tree. Documentation now records
PR #44 acceptance; final package rebinding and the dynamic fix's own fresh
hosted gate remain required before its integration.

### PR #45 scalar gate and newly exposed composite-order defect (2026-10-24)

**CONFIRMED, not accepted for integration:** exact head
`f46712fd393efcde283528456e8205fddfb34b60` passes all twelve jobs in
`40141054093`, attempt 1. Its fresh downloaded package passes actual Java 21
planner231, extraction38 and dynamic154 checks. Independent artifact review
verifies the five scalar target cases, ARM mixed PCS/Thumb/shared, both GUI
hosts and native Windows 26 suites. These remain bounded component evidence.
Receipt `gui-script-manager/build/hosted-gui-review/run-40141054093/component-evidence-only.json`
has SHA-256 `08816e0d83d3cbaac97a0eae12cef05524489f9fcb7c75e5e18816ec77e705f3`;
no final acceptance receipt was issued.

Later ordinary by-value `{int first; int second;}` comparisons expose wrong
values on ARM32 and MIPS32 little endian. The compiler's incoming carriers and
named fields are `{-19, 37}`; Forge gives `{37, -19}` without an omission.
Computed Ghidra storage lists the second register first, and the generated
DW_OP_regx/DW_OP_bit_piece sequence copies that order. MIPS big endian's
object-order sequence passes all 16 visited PCs. The x86-64 single-register
case passes all 11 visited PCs; AArch64 has four correct available PCs and
nine honest unavailable PCs after overwrite. Both compiler and Forge AArch64
research sessions retain a file-transfer setup warning and a compiler-correlated
VDSO warning; this is not quiet-GDB evidence.

All ten research exports repeat identically and independently validate. Strict
libdwarf records two/four corroborated inherited frame errors for x86/AArch64
and zero for ARM/MIPS, with zero unexplained errors. The ARM and MIPSLE GDB
failures stop at the first wrong-field assertion and remain failures. Selected
inputs/module/test files retain their hashes, sizes and recorded modification
times, including on failure; owned QEMU processes and socket paths are gone.
The five-case receipt under
`truncated-space-stores/build/next-aggregate-review/five-contrast-binding.json`
has SHA-256 `90bf63bf113755d583428c1500dbf939e209efc8f25035a02d7d80dce58b14bd`.
Independent raw DIE/expression/member-offset/carrier review has SHA-256
`d9f80cb6f8bdcbd809b62dacb311d68424c1e60195a8dbd2848522498452000d`.
Method hashes and the exact production diff show the separate truncated-STORE
change does not cause this equal-width ARM/O32 ordering defect.

**HISTORICAL attempted correction:** normalize only proven attached computed
joins after the original piece/lifetime proof, leaving custom/local joins
unchanged. Its component checks below pass, but the subsequent custom-conversion
probe exposes the remaining wrong value. This candidate is not accepted.

### PR #45 computed-only correction: historical component checks (2026-10-24)

**HISTORICAL, incomplete correction:** the frozen production source
has SHA-256 `78da242b10100fa5fc56aae71c0016349d53f71aef08379bf4bfd3bd682f5974`.
Actual Java 21/256 MiB passes 603 focused checks, with exact five language
markers, real saved/reopened compound parameters, scalar/aggregate and unequal
piece cases, explicit custom/local/direct-model isolation, origin negatives,
first-omission precedence and cancellation. The old `2fb0d5e4...` JAR fails the
intended actual ARM object-order assertion. Initial test-only constructor and
overlapping-local setup failures are retained separately. Independent final
source/focused review SHA-256 is
`5b37406b61959e67a7094958ebfeee47cc07778848429eaaf2f25fd57a7e34e9`;
a second independent closure is
`c43a9b3af169864db0fada355ac3364d3f84f2260b7313e69ab134de416cbb87`.

The eight Gradle focused tasks and extension build pass, including the new603,
existing154 and six storage/lifetime controls. Workflow/architecture guards
and the exact 26-file fixture inventory pass; all 13 x86-64 Makefile artifacts
remain reproducible. Initial assembled ZIP SHA-256 is
`dd7cb3981411afae4926efee85003f4c706ffb2aabaf24168409942648e28837`,
containing JAR
`97018b02251b37e1f1f2a414b35456eed30e1c43435767be7caf7e71298573e7`.
Author package verification binds 49 sources, two scripts, 220 major65 classes,
five manifests, pinned native provenance and exact initial documents; all 28
runtime payloads equal the private installation and 27 non-JAR payloads equal
the earlier dynamic package. The downloaded/assembled JAR itself passes603 on
actual Java21 with production origins verified. Author receipt SHA-256 is
`d07cee6132a6a27aa3bbee1f22c06d6e617da734e2680bcdccc7d6263bc89590`;
independent package peer review is
`d354798e941228d5d4c044ff6a54d0d5abdb7dbb4d2b36796146d8985b81931e`.

Final driver `build/dynamic-composite-review/installed.pjp4y3ue` runs the exact
final harness on x86-64, AArch64, ARM32 and both MIPS32 byte orders. All ten
exports and ten compiler/Forge GDB sessions pass. The five aggregate entries
and three non-MIPS scalar entries have correct typed values. Across 105
actually visited Forge PCs, 76 parameter observations are available and correct
and 29 are explicitly unavailable. Both MIPS scalar functions copy the incoming
word and then overwrite a0 using LUI: the raw input instruction bytes, report
full-body `REGISTER_MODIFIED`, absent location and actual unavailability agree.
The preselected O1 scalar body and the original failing aggregate C are unchanged.
There is no positive MIPS scalar-runtime claim or new composite-prefix support.

GNU/LLVM and strict validation pass with inherited totals2/4/0/0/0 and zero
unexplained errors. One VDSO warning in each AArch64/ARM compiler and Forge
session is retained and matched; current runs do not retain the initial missing-
sysroot file-transfer notice. Source/sidecar/report pairs repeat identically.
All85 per-case protected records (37 unique paths) and12 global records retain
their bytes/metadata, and all eight owned QEMU processes/sockets are cleaned up.
Independent all-five review SHA-256 is
`3492a51b42ba6294ab48ff9c0bb1e1ea9dd8ae1c3e2f843d723e8e916cb6e431`.

Targeted driver `primary.hteyr_ee` makes three fresh owned ARM/MIPS imports and
uses unchanged existing primary export/GDB scripts. All three exports, GDB
sessions and strict-zero sidecars pass. Stack/shifted-stack values stay42;
both MIPS explicit custom/local composites retain `0x1122334455667788`.
Twenty-eight protected source/input/mirror/module paths, including executable
modes, remain unchanged. Independent primary review SHA-256 is
`4c2d82e4347b6dab486f64e2731f53068da3128e2d01ddf62f270f9f67afab68`.
No old accepted projects or artifacts were overwritten.

Initial harness failures remain distinct: Ghidra's unsigned type name is
`ulonglong`, so an overly literal spelling assertion was replaced by an actual
unsigned cast/type check; the two MIPS scalar positive assertions were corrected
to require the observed precise omissions without changing code or optimization.
The first primary mirror copies lacked execute permission, so QEMU exited before
GDB connected; new copies preserve the original mode. Final exact-source runs
above pass. No production or fixture-body workaround conceals these failures.

Final author receipt `final-local-acceptance.json` has SHA-256
`585cbd82da6318fbb63306e016b0563b3caad85029aeff6a6077782f804b0b7c`.
Local headless execution is Java25; actual Java21 checks are separate. Final
committed-document packaging and the corrected head's fresh full hosted gate
remain required before integration.

### PR #45 computed-to-custom semantic regression (2026-10-24)

**CONFIRMED blocker:** an owned clone of the passing ARM aggregate project is
exported before conversion, after `setCustomVariableStorage(true)`, and after
saving/reopening. The two field offsets, r1/r0 storage sequence, signature and
actual decompiled member uses stay identical. Only the effective storage class
and persisted-assignment flag change. With the computed-only `97018b02...` JAR,
GDB changes from correct fields `{-19,37}` to `{37,-19}`. Raw incoming carriers
and the compiler oracle remain unchanged. GNU/LLVM and strict validators pass;
structural validity does not establish value correctness.

Pinned `MappedEntry`, `AddressXML`, `JoinSpace` and `JoinRecord` source establishes
most-significant-first join serialization for custom/local as well as computed
storage. The old injected-local fixture only tested memory-order byte assembly:
its unused local had no decompiled semantic use. Correcting that fixture's
Ghidra register order must preserve its C executable and expected GDB value.

Receipt `custom-history.exrqsykm/observation-result.json` under
`build/dynamic-composite-review` has SHA-256
`820442806d7a87cc60b7d3c65104f85200f173ebef845454ca8a5fee8374e269`.
It binds all three successful headless calls, two actual QEMU/GDB sessions,
raw DIEs, source traces and preservation of the original project/module/inputs.
An incorrect footer comparison across differently named sidecars is retained
as an audit failure; no successful runtime call was repeated to conceal it.
The shared extraction correction and new acceptance remain in progress.

### PR #45 shared join correction: local validation (2026-10-25)

**CONFIRMED locally; integration pending:** the correction normalizes completed
Ghidra register joins at the shared extraction boundary. Little-endian pieces
are reversed into object memory order; big-endian pieces retain their order.
Every original piece/lifetime proof runs first in its original order, preserving
first-omission precedence. Per-register LSB slices, single-register/stack paths,
the neutral model, expression encoder and native producer are unchanged.

Production source SHA-256 is
`39eb0a1d4d76554187102e78f2c0c7504438d80918e7b602698388c96e01cdcb`;
focused source SHA-256 is
`6cf48e24abcbbe5ab7974bc805cab53c0c2fa48ea8c38d276f15c3c67b68e6b2`.
Actual Java 21 at 256 MiB passes 1,480 checks across all five real language
models, including computed-to-custom conversion, immutable reopening, explicit
custom/local joins, unequal widths, actual AddressXML serialization, direct
neutral-model order and existing malformed/omission/cancellation controls.
The `97018b02...` computed-only JAR fails the intended converted-custom ARM
assertion. Focused receipt SHA-256 is
`dbda0b6242c82ad40623199bf911b5beeef8c840ef6b7cab3a021091804095cd`;
independent review is
`073d6a609eab4dfc9255777c91170afddc572e7c49fe54ebba688bbbe55c964c`.

Eight Gradle storage/lifetime tasks and the extension build pass, along with
workflow and architecture guards. Initial assembled ZIP SHA-256 is
`f40335382d2603d61f46468c37440480b455d3f3fb117acb7838a473d988f118`;
its JAR is
`8303348fe3b78a152bec19480beda458459f117ac316bafaf73f05d450f7d219`.
The package audit verifies 49 sources, two scripts, 220 Java21-compatible
classes, five manifests, native provenance, initial documents and all 28
installed runtime payloads. The 27 non-JAR payloads equal the previous package.
Fresh actual Java21 runs the packaged JAR first and passes 1,480 checks with
all production class origins bound. Author/independent receipts are
`892c63c3ca89b70c28ad4591c9ed3ddfc09e5bf16a780a307976f2781acb36fc` and
`f2bef3f7f30d2007210893943850e8dcc7aabf1a619724cb52bfa250b0c6b164`.

Driver `build/join-order-review/installed.xo97n145` passes x86-64, AArch64,
ARM32 and both MIPS byte orders: twenty exports, fifteen compiler/computed/custom
GDB sessions and five plain executions. Each Forge variant visits 105 PCs,
with 76 available correct observations and 29 unavailable observations. Each
has five aggregate and three scalar entry positives; both MIPS scalar cases
retain exact whole-body REGISTER_MODIFIED omissions from the original LUI.
The signatures, storage pieces, typed fields, decompiled member uses and
high-symbol storage survive computed-to-custom conversion and reopening.
Both sets of source/sidecar/report pairs repeat identically. GNU/LLVM and strict
validation pass on both outputs with inherited totals2/4/0/0/0 and no unexplained
errors. Matching AArch64/ARM VDSO warnings remain explicit. Seventeen protected
files per case and twelve global records remain unchanged.

The first expanded x86 case, `x86_64.aYzXkK7j`, exposed an overly narrow test
assertion after its four successful exports. Ghidra uses an adjacent temporary
for each field assignment. The corrected checker accepts only the bounded
direct or single-temporary dataflow with unique field read/global write and no
intervening temporary mutation; unchanged full decompiled text is also required
across conversion/reopen. The failed attempt remains retained. No fixture body,
compiler flag or production workaround changed the outcome.

Driver `build/join-order-review/primary.yhrwsh1d` passes five fresh primary
exports and five existing scripted GDB sessions. Stack/shifted-stack values
remain42 on all targets; x86/AArch64/both MIPS recover the expected
`0x1122334455667788`, while ARM retains its modified-register omission. The
Ghidra fixture alone now supplies significance-order registers; C inputs and
GDB expected values are unchanged. Strict inherited totals3/5/0/0/0 have zero
unexplained errors. Thirty-six protected source/input/mirror/module records
preserve bytes, size, modification time and mode. Old projects are untouched.
This remains an injected-local assembly control, distinct from the real
computed/custom aggregate semantic test.

Independent final raw runtime and primary-control reviews pass. Committed
packaging and the fresh full hosted gate remain required before integration.

The shared correction's installed headless/GDB corpus uses Java 25.0.4.1;
the actual Java21 checks above are separate source/packaged focused tests.
Final local evidence receipt SHA-256 is
`07c73b0f85d28ddb830ffab91f364c6de20c814178b5329a879dc5cc3a5cc86d`.
Independent computed/custom runtime review SHA-256 is
`4939adbb7367d73ab6777698a00745d9c503995faf5b538320f947a486bec14d`;
independent five-primary review is
`4a803df13f60a9418ca10732f8731112ec579af2eab895bdd824dcd039667229`.

### Explicitly truncated memory stores: local acceptance (2026-10-24)

**CONFIRMED locally; full hosted gate pending:** the correction preserves
incoming register facts across well-framed STOREs into an explicitly truncated
SLEIGH RAM space. It requires exact physical-space identity and bounds the wider
offset to `Long.BYTES`. Equal-width behavior, register/memory-mapped clobber checks,
call/write/opaque precedence, local assignment policy and cancellation remain
unchanged. It does not establish a memory location, address validity or an ABI
classifier. See `docs/TRUNCATED-MEMORY-STORES.md` for the pinned semantic proof.

`GHIDRA_INSTALL_DIR=... ./gradlew --no-daemon truncatedSpaceStoreSmoke
 dynamicParameterStorageSmoke variableStorageSmoke registerPrefixSmoke
 registerAliasSmoke registerCopySmoke stackFirstUseSmoke opaqueRegisterEffectsSmoke
 buildExtension` passes all eight focused tasks and the extension build.
The workflow linter, architecture guard and exact 25-file fixture inventory pass;
all 13 existing x86-64 Makefile outputs remain reproducible. Actual Java 21 at
256 MiB separately passes 182 focused checks, including both real N32 languages.
The old `2fb0d5e4...` production JAR fails the intended actual-decoded positive
assertion. One initial test control accidentally used equal OTHER-space widths;
its failure is retained and the corrected mismatch control passes.

Initial ZIP SHA-256
`b34cfc4114eb489ef1b80d6f63f93d2fc0a0f094fef883f189aa1248f07da16b`
contains production JAR
`325926ee3bc06a6e270015512ac3c830f8187212270f54abb307f449eff2d42d`.
The author's package verification binds 49 production sources, two scripts, 220
Java-21-compatible classes, five manifests and pinned native provenance. All
28 runtime payloads equal the private installation; the 27 non-JAR payloads
are unchanged from the dynamic-parameter parent. The packaged JAR itself passes
the 182 checks on actual Java 21 with production class origins verified.
Package review SHA-256 is
`5bba1f51ebefda069b10d05116b5c6a17ed78fb82b93ccbf1c4b4ddb914b58ae`.
Separate independent package peer review has SHA-256
`ec406146c69c4aae6425a1ed141ddbcf1c0accf9cadc9bca091620ab407e2347`.
Two audit-footer assumptions were corrected using the retained successful
execution evidence; no Java run was silently replaced.

The new harness runs O32 and N32 for each MIPS byte order. Cases under
`build/test-results/mips-truncated-space/` are
`mips32be.o32.4ZmdzQq2`, `mips32be.n32.TmzpyLFH`,
`mips32le.o32.7JC13t89` and `mips32le.n32.1Nwblikq`.
All eight exports, four plain QEMU runs and eight compiler/Forge GDB sessions
pass. GNU/LLVM and all four strict libdwarf checks report zero unexplained errors
(strict totals are zero). Source/sidecar/report pairs repeat deterministically.
At 194 actually visited Forge PCs, 864 typed observations have correct values
and 30 are explicitly unavailable. Both N32 cases expose all seven parameters
at entry; O32 preserves six integer values including stack arguments five/six,
while the overwritten wide pair remains `REGISTER_MODIFIED` and unavailable.
Normal returns, global results and all program exits pass. No claim covers
unvisited delay slots, debugger-injected calls or new source-next/step semantics.

The current fixture C/startup sources and all four stripped executables match
the earlier `2fb0d5e4...` contrast byte-for-byte. That retained old evidence shows
N32's exact former `UNKNOWN_LIFETIME` omissions without another old-runtime run.
Forty unique case-protected files and eleven additional global records retain
their recorded bytes; all QEMU children/sockets are cleaned up. The ignored
launcher initially failed on a missing configuration key before executing a
compiler/JVM; its source/error are retained. All four actual harness runs pass
on their first execution. Headless Java 25 is distinct from the Java 21 checks.

Author runtime receipt SHA-256 is
`7f8bab70170b2f9fcc90ff4f741919838bd1d65ee8c92491a5c8249c9ee573c5`;
independent raw review SHA-256 is
`34252ee04fbf5113786bfc2a70fe6e82941b251a6ab3de1b072e20f761426337`.
Root rehashed 348 referenced current/runtime evidence files. Independent final
production/focused review SHA-256 is
`3796ee04524b9f001ff7ba56fa6410870b418fe816749afafab38d2f538acad8`.
Final committed-document packaging and full hosted acceptance remain required.
The bounded freestanding tests do not establish libc, floating/aggregate,
PIE/shared, O64/N64 or broad N32 support.

### Combined truncated STORE follow-up (2026-10-25)

**CONFIRMED locally; hosted acceptance pending:** normal merge `70ba319` has
parents `18c0d0f` and `5e2ea7d`. The source delta from the corrected join parent
retains exactly the 16-file STORE follow-up. Conflict resolution retains both
focused tasks, both runtime steps and both evidence histories. The combined
fixture inventory is 28. The configured native Windows suite list has 28 entries;
native Windows acceptance remains pending. Shared join
normalization matches the parent bytes; the STORE predicate matches the earlier
follow-up bytes. Source SHA-256 is
`c4c5e8985349e0a917ffa7a3fb5296250874816553ddd729b068d69de14a4968`.

Nine Gradle storage/lifetime suites and the extension build pass, including
182/1480/154 controls. Workflow/architecture guards and the exact 28-source
fixture inventory pass. Initial assembled ZIP SHA-256 is
`cd057db40dd267244903d1eadcaf5005c4c55612d910aa1d8422c9464632ed81`;
production JAR is
`2d787e338390810c8452f4a743aba41905f8440d619a99a06358a607fec465f9`.
Exact-commit packaging verifies 49 source files, two scripts, 220 class-version-65 classes,
five manifests and pinned native provenance. All 28 runtime payloads match the
private installation; 27 non-JAR payloads equal both preceding packages. Author
package receipt is
`013fd8c7f1e1ef965a6046b9d569f1c18b612bbae0b92847b0be77241aba04d2`;
independent source/package review is
`695bd49d6e58eaa9c574967171a5d9960b654fd94abc44ac9eebb97cb87db5f6`.

Actual Java 21 at 256 MiB passes source and packaged runs for 182/1480/154. Each
packaged run resolves production classes from the selected combined JAR. The
shared-parent `8303348f...` JAR fails the exact actual-decoded truncated RAM
STORE assertion. A final audit's literal file-URI spelling comparison failed;
retained logs and parsed-URI verification close that audit without repeating
JVM execution. Focused evidence SHA-256 is
`3c29840980910059724534b3136bf6c60cdd67c1cfb9f1471d6f2e9efdea0d46`.

Fresh four-case O32/N32 runtime validation uses unchanged fixtures and oracles:
eight deterministic exports, eight compiler/Forge GDB sessions and four plain
QEMU exits pass. At 194 actual Forge PCs, 864 parameter observations are available
and correct and 30 are explicitly unavailable. Both N32 cases have seven positive
entry values; both O32 cases have six integer positives including stack arguments,
with their modified wide pair honestly unavailable. Four strict validators
report zero errors. Forty unique per-case protected paths and eleven global
records retain their bytes/metadata. The runtime receipt SHA-256 is
`66b5d82365138116807ff54b2800691c777719b0391b6280557cb12e2438b4c3`;
root independently rehashed all 332 referenced witnesses. Installed headless/GDB
execution is Java 25.0.4.1, distinct from the actual Java 21 focused checks.

Independent final raw runtime and focused reviews pass. Committed acceptance
packaging and the full fresh hosted gate remain required. Earlier `325926ee...` component results and the
shared-join correction's rejected candidates remain separate historical evidence.

Independent focused review SHA-256 is
`03aa07a318c2174589ab98453ce238cee43e4643d96bb3be80c08641001b54be`;
independent raw four-case review is
`125f134d13a016df39e94c64ca52107b2913fd882ffa2ceef167fb04e3ff7e0f`.

### PR #45 exact hosted acceptance and normal merge (2026-10-25)

**CONFIRMED:** corrected head `5e2ea7dfc4911c89e42c7b486d08c10a445e8fe7` passes
all twelve jobs in run `40145554731`, pull_request attempt 1. Fresh package
precheck receipt SHA-256 is
`80301b5dc8618953290ab8055da7ce74953ac7a4ed4a8ac53330bc9e2af408c4`.
Hosted JAR `10e3cd67...` matches the exact committed sources and passes fresh
actual Java 21 checks 231/38/154/1480 with bound production origins. The four
focused source snapshots and all 29 relative package-evidence records were
independently rebound to the tested head.

Independent acceptance receipt SHA-256 is
`ace468102fcd6f929d3e0b2347b5853a89c4aacccb3b88207a6809b2285dfdfe`;
final artifact bindings are
`05867502822bbf51fc3e3a16de40cf232d4372c46f4a14b988da26163939bc94`.
All five computed/custom and generic parameter artifacts pass raw audits.
Computed/custom variants each retain 105 visited PCs, 76 available values and 29
honest omissions, with five aggregate and three scalar entry positives. Both
GUI hosts and native Windows 27 suites pass. All 212 selected target-workflow
steps succeed; 108 unselected platform conditions remain explicit skips.
All 22 Windows steps succeed. There are no unexplained strict errors. Root
rehashed all 27 final binding witnesses and independently verified the exact
run/head/event/attempt and twelve successful job records before merge.

Normal merge `96fa0a826429e0b9dbfacd028e6caa02bcf2934e` occurred at
`2026-10-25T00:38:23Z`; its tree equals the tested head. Distinct main-push
run `40147478153` independently passes all twelve jobs. Fresh main target,
all 27 native Windows suites and both-GUI artifacts are reviewed; only package-focused
actual Java 21 results are inherited after exact 28 runtime/four test-source
equality. Acceptance receipt SHA-256 is
`fb2731ee04644ae947b5e2225ba419e879e054055a3984fb57643f6b84b643e5`;
final bindings are
`f43ff1e6155abe827a27faee46e878bf31cf3dfea96e33ce158cafb03511c9f8`.
Root rehashed all 27 final witnesses and confirmed fresh API success. The rejected
`f46712f` scalar-only run and computed-only `97018b02...` package remain
historical component evidence. Published releases are unchanged.

The truncated-STORE branch's subsequent normal parent merge `732356f` preserves
its exact prior `0b5d216` tree, including all locally tested combined runtime
bytes. Only acceptance documentation changes afterwards; final exact-head
packaging and a separate hosted follow-up gate remain required.

### Composite incoming-register source checkpoint (2026-10-25)

**CONFIRMED source/focused; packaged runtime and hosted acceptance pending.**
The bounded composite prefix uses the existing interval and location-list path.
Actual Java 21 at `-Xmx256m` passes 469 checks, including decoded x86-64/AArch64
computed/custom/reopened storage, whole-body rejection controls, exact raw
location-list bytes and cancellation. A real big-endian language supplies the
storage for a controlled p-code test; this does not prove a MIPS runtime prefix.
The old `2d787e33...` package fails the intended existing-public-API positive
assertion. Source-focused receipt SHA-256 is
`12c327069437ea65e220acc4aa3a1fab28e75c86d3c22711f9eaba91d4120194`;
independent source/focused review is
`482e90ef75397406fec5a89bca0f0422afca83794051bfb93a8510d20fca2ace`.

The following command passes under Java 25, producing Java 21 bytecode:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 \
./gradlew --no-daemon compositeRegisterPrefixSmoke dynamicCompositeOrderSmoke \
    dynamicParameterStorageSmoke truncatedSpaceStoreSmoke variableStorageSmoke \
    registerPrefixSmoke registerAliasSmoke registerCopySmoke stackFirstUseSmoke \
    opaqueRegisterEffectsSmoke buildExtension
```

All ten requested smoke tasks execute and pass; the build reports 15 executed
tasks. Workflow lint, architecture neutrality, whitespace checks and the exact
29-file fixture-source inventory pass. Source-only reviews of the durable
ET_EXEC harness and private driver pass. The fixture C and compiler flags equal
the independently reviewed baseline probe. No fresh packaged-exporter/GDB or
hosted acceptance is claimed at this checkpoint.

### Composite prefix installed-runtime checkpoint (2026-10-25)

**CONFIRMED locally; full hosted acceptance pending:** initial committed head
`6397e06` builds ZIP `6d281838...`, containing production JAR `3f9e46b5...`.
Exact committed sources, scripts, documentation, native provenance, five
manifests and 220 Java 21 classes pass the strict package audit. All 27 other
runtime payloads match the preceding combined package. Independent package
review passes. The private Python installer initially omitted archived modes;
the owned module's 108 entries were corrected to their archived modes with
unchanged file bytes/mtimes. The initial mode-check failure and a partial
correction attempt remain recorded. Independent mode closure is
`01d836dc1f8dd94d20bb582ef0453a0e0d34d29f4cca01c6ac60cf1405092659`.
This correction changed no production or fixture bytes and required no JVM
rerun.

Actual Java 21 at 256 MiB passes the installed-JAR checks 469/1480/154/182,
with JAR-first classpaths and every loaded production class bound to that JAR.
Receipt SHA-256 is
`c9ae84ab6c8d1f169af6dded8a6aeecf70839af154fc8dc582a4f67675e613e3`;
independent packaged-focused review is
`d600d8257fc288e5d47282018494f72581666c1f278ca351cadfa35fcc6ef9c8`.

The exact installed package then passes the two durable harness commands:

```bash
src/test/integration/composite-register-prefix-export.sh "$GHIDRA_INSTALL_DIR" x86_64
src/test/integration/composite-register-prefix-export.sh "$GHIDRA_INSTALL_DIR" aarch64
```

Here `GHIDRA_INSTALL_DIR` selects the private `runtime.ua_d0osz/ghidra`
installation, not the source checkout's base platform. Actual headless Java
is 25.0.4.1. Eight exports, six compiler/computed/custom GDB sessions and two
plain executions pass on the first runtime attempt. Computed and custom
variants each visit sixteen PCs across the targets, with six complete correct
values and ten explicitly unavailable tail values. The raw DIEs and location
lists have the correct member offsets, object-order register pieces and exact
first-write boundary. Compiler DWARF retains correct values at all sixteen PCs.
Both stripped inputs equal the prior omitted-location baseline byte-for-byte.

Strict output reports four inherited original-frame findings on x86-64 and six
on AArch64, all corroborated with zero unexplained errors. Each AArch64 GDB
session has the same one known vDSO warning as its compiler oracle. Repeated
and reopened outputs are deterministic; 267 global protected records and
thirteen per-case paths remain unchanged, and all owned sessions/endpoints
are released. The final author receipt binds 244 witnesses; independent raw
review also checks all 229 retained case files without rerunning the exporter
or debugger.

Runtime receipt SHA-256 is
`703fc5ba467cb9a61fdd3bfaf089a54ef8d107ebc54dd7f77e9b266f76c8b77c`;
independent raw review is
`1bebf993bc534ad0af0113d1e920ee9b93eddfa5219476c2b0cee348aae46a12`.
Final committed packaging and the full five-target/two-host gate remain
required before integration. Composite PIE/rebase, additional targets,
surviving pieces, backup migration, calls and delay slots remain outside this
new bounded runtime claim.

### PR #46 hosted acceptance and normal merge (2026-10-25)

**CONFIRMED:** exact head `ea4f9c0` passes all twelve jobs in run
`40148228012`, including all 214 selected target steps and 22 Windows steps.
The 111 excluded platform conditions are explicit skips. Independent downloaded
package checks run actual Java 21 suites 231/38/154/1480/182. Fresh artifact
review accepts all five target chains, the four O32/N32 cases, 28 native Windows
suites and both GUI journeys. The new MIPS cases retain 194 visited PCs,
864 correct values, 30 unavailable values and 26 positive entries; all four
strict validators report zero errors. Other reviewed strict reports have zero
unexplained errors.

Acceptance receipt SHA-256 is
`948b3d183f174cbb068e3a55bd2488df037059a056ae33d6e0fa85b9f890c8a7`;
final artifact bindings are
`d2b6b9d393afc8fd2aac7ecafc7f2453acd591f1dc2d93e89f38ed71e3aba8cb`.
Root rehashed all 30 binding witnesses and reread exact CI identity, head/base,
mergeability and enforced `required-validation` protection. Normal merge
`800081f7d8dd22280e9d360c2c2a0e5e7ffc343c` at `2026-10-25T01:23:22Z`
preserves the tested tree. Distinct main-push run `40150436365` also passes all
twelve jobs and independent fresh target, 28-suite native Windows and both-GUI
artifact review. Only five package-focused Java 21 observations are inherited
after exact 28-runtime-payload/five-test-source equality; all main runtime
artifacts are fresh. Acceptance SHA-256 is
`495edcaf7420c832156bebecbc1fa661a1c8f20a53424925ee3f286ec58572b8`;
final bindings are
`be9656b1839133ebbebb5fc574c7a76bca77c746e527ff7409a9e504d39d6c52`.
Root rehashed all 30 main witnesses and confirmed fresh API success.

The composite-prefix branch's normal parent merge `b9ba06f` has exactly the
prior `eb10b6c` tree. Its local source/package/runtime evidence therefore retains
the same runtime bytes. Subsequent changes record parent acceptance only;
final committed packaging and a separate prefix hosted gate remain required.

## Formal aggregate function returns — local acceptance (2026-10-25)

**CONFIRMED locally; hosted validation pending.** The concrete signature
extractor now uses the curated formal return type instead of the effective ABI
carrier. See `FORMAL-FUNCTION-RETURNS.md`. The old source fails the new real
ProgramDB aggregate-return assertion; the corrected source passes 312 checks
across x86-64, AArch64, ARM32 and both MIPS32 byte orders on actual Java 21 with a
256 MiB heap. Scalar/pointer/void, custom conversion, hidden parameter identity,
forced-indirect inputs, cancellation and immutable reopen are covered. The
existing dynamic parameter suite also passes all 154 checks.

The installed production JAR
`a7bb363ef5eb1944b917f43f4c8e93a960de2144ae77f9e6381a3134183ef180`
passes `formal-function-return-export.sh` in owned case `x86_64.Io1OFFWL`:
three headless invocations, two byte-identical exports and two actual GDB
sessions. The observed headless runtime is Java **25.0.4.1**, despite the caller's
JAVA_HOME setting; the Java 21 model test is separate. Compiler and Forge both
report a 24-byte structure with three unsigned 64-bit members at offsets 0/8/16.
The compiler's two arguments are correct at all ten callee instructions. Forge's
hidden destination and seed remain correct at all ten; delta is correct at seven
and unavailable at the final three, matching raw locations and the omission
report. Both normal calls return the expected bytes and caller globals and exit
zero. No inferior call was injected.

LLVM reports no errors. Strict validation reports four inherited frame findings,
all corroborated against the unchanged input, and zero unexplained findings.
Original ELF and protected source/module bytes and mtimes are unchanged.
The result SHA-256 is
`926ab4b8a167334e85e46524c5dd70b15df0494e71f6da60dff650e42a06701f`.
This is one x86-64 SysV ET_EXEC runtime profile, not broad aggregate ABI support.

Retained development failures are distinct from acceptance: the first harness
attempt included a DWARF end-of-children marker as a member; the next pure check
incorrectly expected scalar `DW_OP_bit_piece` instead of `DW_OP_regx`. Both
checker assumptions were corrected before the fresh accepted run. An initial
Java 21 launcher rejected test classes compiled at Java 25's default level;
explicit `--release 21` corrected the test compilation. None of these failures
required changes to the production fix, the fixture C, or its compiler flags.

Commands: `formalFunctionReturnSmoke`, `dynamicParameterStorageSmoke`,
`buildExtension`, the installed `formal-function-return-export.sh`, actionlint,
`architecture-neutrality.sh`, Python/shell syntax checks and `git diff --check`.
Hosted checks and a separately packaged Java 21 test are recorded independently.

The separately compiled test-only classes also pass against the installed JAR
on actual Java 21/256 MiB (`packaged.vl7adtvd`, 312 checks), with class-load logs
binding the production extractor to that JAR. The same compiled test rejects
the retained old JAR `3f9e46b5...` at the aggregate return assertion. Receipt
SHA-256: `95697de837b17880d330d33891de8db54579066bb2aad00c7217f33783313a74`.
A post-run URI spelling check was corrected to compare parsed file URIs;
the successful fixed JVM was not repeated. The final rebuilt extension's JAR
is byte-identical to the runtime-tested JAR above. The 30-file fixture inventory
and 13-artifact x86-64 reproducibility check pass.

## Composite prefix integration (PR #47)

**CONFIRMED:** exact head `2c8d4fa6bb57e64978ceb656c67036e48104a089`
passes all twelve jobs in run `40200733276`, six fresh packaged Java 21 focused
suites, native Windows's 29 suites, both GUI hosts and independent target
artifact checks. The two new prefix cases cover 16 compiler-positive PCs;
computed and custom variants each expose six correct values and ten unavailable
tails. Prior five-target chains, all four bounded MIPS store cases and strict
validation remain clear. The accepted receipt is `a00839e5...`, with final
bindings `4d4cdb49...` and packaged JAR `c04913f8...`. Normal merge
`ffc16713cc1be34924519544356b5d6f57e851f1` retains the tested tree. Its distinct
main push `40204254359` is pending separately; no release was published.

## Curated external declarations — local acceptance (2026-10-25)

**CONFIRMED locally; hosted gate pending.** Curated external signatures now
have a separate addressless declaration model and producer path. Default
prototypes remain omitted even when their names are imported/user-defined.
The existing five-language inventory suite additionally proves distinct keys for
same-display-name declarations, library/nested names, unreferenced signatures,
unknown-prototype omission and separation from memory thunks/definitions.
Native-free type graph controls validate ordering, duplicate identities and
missing return types. These suites and the 312 formal-return checks pass
against the installed JAR on actual Java 21/256 MiB; class-load logs bind the
model to that JAR. Receipt `271f7c6a838f282d76636abea5fb2f35b005ad5dbbbafcffbf0a2eb4a5944b3a`
is retained in `packaged.o1n6sfx_`.

Installed JAR `ee02307991bafe40546cd7cc14de5717dcb76e0b49dcbd6809a865957646db8a`
passes the real x86-64 caller/library regression `x86_64.VWBADEl4`. Two headless
exports, including read-only saved-program reopen, produce identical source and
sidecar bytes and identical extraction models. The observed headless runtime is
Java25.0.4.1. The actual imported signature and an unreferenced variadic/no-return
signature appear as typed declarations, without any code address, location,
frame base or fabricated source attribution. The unknown signature remains
absent. The imported return/parameter sizes and signedness match GCC's DWARF.

Compiler and Forge GDB sessions both retain real definition lookup/prototype,
source listing, `next`/`step`, the expected normal library result and exit zero.
Both ignore unlocated declaration symbols, an explicit debugger limitation
rather than evidence of resolved external prototypes. LLVM passes. Strict
validation has two corroborated inherited frame findings and zero unexplained
errors. Caller inputs, library and protected source/module files remain
unchanged. Result SHA-256:
`beb24d5b202428fb1de4f972d452e6ecb6120ea40df3fcd0079e16585bda0871`.

The first harness attempt `x86_64.K0GCLJho` installed its return breakpoint after
source stepping and could pass the caller return before checking it. That GDB
control failed; its evidence is retained. The corrected harness installs the
return breakpoint before navigation and conditionally continues only when not
already stopped there. Production code and fixture C were unchanged.

Commands: `externalFunctionInventorySmoke typeGraphSmoke formalFunctionReturnSmoke
buildExtension`, installed `external-function-declarations-export.sh`, the three
packaged Java21 suites, actionlint, architecture neutrality, Python/shell syntax
and whitespace checks. This does not complete P1.7/P3.3's linkage, aliases,
classes, lexical scopes or external-code debugging.

## Formal return correction — PR #48 hosted acceptance

**CONFIRMED:** head `e588d607dcc8d01a1a045cd41d1fe5641e3b0621` passes
all twelve jobs in `40205151874`, including all five target lanes and both
hosts. The downloaded package passes exact source/manifests/native provenance
and Java 21 bytecode checks. Its JAR
`a82e898e96b03e6032af51736b5740a246c0f9df76baae0ce3d04f7ff8a76bc9`
passes fresh actual Java 21/256 MiB inventory, graph and 312 formal-return
checks. Native Windows passes thirty smoke suites, including the same 312
checks across all five Ghidra language models.

The hosted x86 case `x86_64.Kih5iWd1` runs on Java21.0.12.1. Downloaded raw
DIEs, hidden-pointer references, input hashes and GDB records confirm the
24-byte aggregate/member layout, ten correct compiler argument observations,
ten correct Forge seed observations and seven correct delta observations with
three unavailable tail PCs. Original inputs and repeated outputs match. LLVM
passes; all four strict frame findings are corroborated, with zero unexplained
errors. Result SHA-256:
`41910a898fa458ac48d85a384fbb81b72350f0a0a0ba65e76cc25eb4b6f855cb`.

Normal merge `a162b0c2b4b9add6689b05efac63c5e78c32ec4f` retains the tested
tree. Its distinct main push `40208082901` is pending separately. PR #47's
separate main push `40204254359` has now passed all twelve jobs and independent
fresh target/both-host artifact review. No release was published. This record
supersedes the pending PR #48 and main #47 labels above.

## Default scalar return recovery — local acceptance (2026-10-25)

**CONFIRMED locally; hosted acceptance pending:** 645 five-profile ProgramDB
checks and the installed `recovered-default-returns-export.py` regression pass.
The ordinary compiler/Forge GDB calls return -41/41/1.75; the prior package
displays void returns. Inferred unsigned width is explicitly distinguished
from compiler provenance. Repeated artifacts, input/module/program bytes,
LLVM, strict seven-frame corroboration and actual decompiler failure/cancel
controls pass. Detailed result/JAR hashes and retained development failures are
in `docs/RECOVERED-DEFAULT-RETURNS.md`. This is not full original signature or
new architecture/ABI coverage.

## Recovered parameter metadata (2026-10-25)

**CONFIRMED locally; full hosted acceptance pending:**
`recoveredParameterSmoke` passes 550 checks on five Ghidra language models,
including immutable reopen. Actual Java 21 packaged checks and the real
x86-64 `recovered-parameter-types-export.py` compiler/previous-package/GDB
regression pass. The three inferred types have no DWARF location; GDB reports
their arguments as unavailable while ordinary calls return the expected values.
Incomplete lists are omitted, analyst metadata survives, validators have no
unexplained findings and repeat artifacts/input-preservation checks pass.
The pipeline adds the model on both hosts and the runtime test on x86-64.
See [RECOVERED-PARAMETER-TYPES.md](RECOVERED-PARAMETER-TYPES.md) for exact
receipts, the retained initial harness failure and remaining scope.

## Direct leaf call backup local checkpoint (2026-10-25)

**CONFIRMED locally; full hosted gate pending:** 140 decoded/ProgramDB call
controls, the existing register-prefix/copy/composite/opaque/dynamic-storage
regressions, extension build, architecture-neutrality guard, actionlint and
x86 fixture inventory/reproducibility pass. Five focused suites execute on
actual Java 21 from the installed candidate JAR. Native x86-64 and QEMU AArch64
compiler/current/preceding-exporter runs compare three signed inputs at five
PCs, retain an honest unavailable restore tail, and pass raw DIE/location-list,
GNU/LLVM/strict-validator, source-navigation and preservation checks.

Final full runs are `x86_64.xuhk8nrq` and `aarch64.dte1c21b`; root raw-evidence
receipt SHA-256 is
`10cdcda14ed175faf6fbe848aa57b20ad0d8c9035090cbb4f52220f8cd7ae1ae`.
Local headless Java is 25.0.4.1; separate packaged tests use actual Java 21.
See [the bounded contract and retained failures](DIRECT-LEAF-CALL-BACKUPS.md).
The new workflow requires both runtime lanes and native Windows model checks;
this local checkpoint does not claim those hosted results or a new release.

## Combined recovered signatures and stack analysis accepted (2026-10-25)

**CONFIRMED:** PR53 head `47970c8558ca9e4ba9933470a5ddd77cb814adef` passes
all twelve jobs in `40218743315`. Exact package/manifests/native provenance,
seven actual Java 21 focused tests, raw parameter/return/declaration GDB/DWARF,
stack exec/PIE/rebase preservation and 32 Windows smoke tasks pass review.
Combined receipt SHA-256:
`f43a469f3dd2d381cc8610d3211c9a3eb80b6165135972f27eeb076f8e1ed90c`.
The enforced strict gate remained enabled; normal merge
`5eeefb76cfcefa2ed501bdd59676048081b5e9bc` preserves the tested tree. Main run
`40221601223` is pending. Component commits remain intact, local timing claims
stay separately scoped, and no release is published.
