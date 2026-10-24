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
