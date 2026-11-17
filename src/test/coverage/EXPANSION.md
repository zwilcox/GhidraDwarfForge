# Combined Java coverage and behavioral gaps

Issue #209 remains **incomplete**. The accepted targets are 85% lines / 80%
branches overall, 95% / 90% for **each** critical group, and 90% lines / 85%
branches minimum for substantially changed Java logic (90% branches preferred).
A passing coverage percentage does not replace independent debugger, validator,
input-preservation, determinism, cancellation and recovery assertions.

## Raw intra-instruction flow admission

The existing `intraInstructionFlowSmoke` now invokes 140 additional assertions
for raw p-code admission. Independently constructed arrays check exact forward
targets at the first, middle and last operation, using both unconditional and
conditional branches. Exactly 4,096 operations remain eligible; 4,097 are
refused. Ordinary operations remain marked as non-branches, and a branchless
instruction does not acquire an internal-flow proof.

Null/empty arrays, null operations, missing/extra branch inputs, null targets or
conditions, wide conditions, self/backward branches and out-of-range distances
must be refused without crashing. Cancellation at entry and during classification
must allow a clean retry. Classification preserves operation descriptions and
the program modification counter. These synthetic p-code cases do not establish
new processor support; the existing real ARM/BE8 predication suite still passes.

The guarded task passes 140 new assertions plus 598 existing checks. Six compiled
faults are detected by behavioral assertions: rejecting the exact operation cap,
accepting wide conditions, dereferencing null operations, admitting self-branches,
inventing branchless proofs and using the next operation as the displacement base.
The unchanged baseline passes. No production code was changed.

Evidence: `.forge-work/scratch/intra-instruction-boundaries-first.log`,
`intra-instruction-boundary-mutants/result.json`, and
`coverage-recovery/intra-instruction-boundaries/`. The verified diagnostic union
contains 1,399 sessions, 901 unchanged production classes and all 255 production
sources. It adds seven branches: 28,846/29,802 lines and 22,236/25,902 branches
overall; critical binary/location 16,067/18,750 branches (808 short of 90%). File
operations remain 50 short. Historical cohorts remain, so full current-head
hosted acceptance is still pending.

## Custom scalar storage and finite compiler-model input regions

The existing `customCallStorageSmoke` now invokes 688 additional assertions on
actual x86-64, i386, AArch64, ARM32, MIPS big-endian and MIPS little-endian programs.
Integer, floating, boolean, pointer and enum signatures are checked directly and
through one or 65 typedef wrappers. Ghidra resolves the typedef base; these cases
do not claim to exercise a cyclic/over-budget alias guard. Unsupported aggregate
and undefined types are applied explicitly to saved custom parameter/return
storage and must remain restricted. Nondefault model selection and cancellation
partway through classification are also checked. Repeated observations preserve
formal types, parameter/return storage and the program modification counter.

The pinned x86-64 GCC model provides six integer argument registers and a finite
500-byte stack input region aligned to eight bytes. A 68-integer signature reaches
the last proven slot (four bytes at offset 496); parameter 68 in a 69-argument
signature is unassigned and must cause refusal. A 4,096-argument signature still
requires refusal for that storage gap, while 4,097 exceeds the separate count
budget. Count eligibility is not evidence of a callable signature.

The guarded suite passes the 688 new and 486 existing checks, including the
existing saved/immutable-program observations. Six compiled faults are detected
by assertions with a passing baseline: rejecting enums, pointers, floating types
or typedefs, bypassing scalar classification, and accepting unassigned storage.
The initial fixture used the wrong enum constructor; subsequent fixture attempts
incorrectly expected full allocation at 4,096 arguments and passed an aggregate
through Ghidra's dynamic-to-custom conversion, which can convert an indirect
return to a pointer. Those test premises were corrected using the pinned model
and explicit saved types. Production code was not changed.

Evidence: `.forge-work/scratch/custom-scalar-call-storage-explicit.log`,
`custom-scalar-call-mutants/result.json`, and
`coverage-recovery/custom-scalar-call-storage/`. The verified diagnostic union
has 1,398 sessions, 901 unchanged production classes and all 255 sources. It adds
three lines and nine branches: 28,846/29,802 lines and 22,229/25,902 branches
overall; critical binary/location 18,609/19,213 lines and 16,060/18,750 branches
(815 short of 90%). File operations remain 50 branches short. Historical cohorts
remain, so this is not current-head hosted acceptance. An empty additional
custom-storage restriction does not certify general ABI or debugger-call support.

## Sectionless unwind framing and exact record limits

The existing `sectionlessUnwindSmoke` now invokes an independent CIE/FDE and
search-table fixture suite. It validates versions 1, 3 and 4 across ELF32/ELF64
and both byte orders, including the minimum accepted version-4 CIE length.
Three-entry controls reject repeated/descending PCs, repeated FDE references,
FDEs before or beyond the bounded frame extent, backward-reference underflow,
unindexed FDEs and a short version-4 CIE. Successful inventories must retain
exact section/file extents and each FDE-to-initial-PC association, and expose an
immutable map. Input bytes, identity and modification time remain unchanged.

The exact record-cap control includes one CIE and 262,143 FDEs: all 262,144
records are accepted and every association is checked independently. Adding one
FDE remains within the search-table count limit but must fail the total record
limit. The largest fixture is about 8 MiB; the suite owns and deletes its input.
These are framing/discovery tests, not an assertion of runtime CFI behavior or
new architecture support.

The guarded Gradle task passes 262,343 helper assertions (mostly the complete
large-table coordinate check) plus 9,172 existing checks. Six compiled faults are
caught by Java assertions, with a passing unchanged baseline: both directions
of the record-cap boundary, allowing equal PCs, allowing a short version-4 CIE,
rejecting version 3 and shifting stored initial PCs.

Evidence: `.forge-work/scratch/sectionless-unwind-boundaries-first.log`,
`sectionless-unwind-boundary-mutants/result.json`, and
`coverage-recovery/sectionless-unwind-boundaries/`. The verified local diagnostic
has 1,397 sessions, the unchanged production JAR with 901 classes, and all 255
production sources. It adds 11 branches. Totals: 28,843/29,802 lines and
22,220/25,902 branches overall; 16,051/18,750 critical binary/location branches,
824 short of 90%. File operations remain 50 short. Historical cohorts remain;
full current-head hosted acceptance is pending. Production code is unchanged.

## Relative-pointer provenance, admission and candidate bounds

`elfRelocatedPointersSmoke` passes 569 assertions for the existing AMD64 and
AArch64 little-endian relocation profiles. The expanded cases distinguish RELA
relative candidates from REL, RELR, NONE and absolute relocations; reject missing,
partial or duplicate RELRO coverage; and reject unreadable slots, ambiguous or
unreadable targets, and slots without complete file backing. Target values at
file/BSS boundaries remain link-time candidates, not runtime observations.
Adjacent loader writes ending exactly at the slot or starting at its end remain
non-overlapping. Every fixture inspection preserves original bytes, file identity
and modification time on both success and refusal.

Unsorted tables of 1, 63 and exactly 64 candidates must produce address-sorted,
immutable lists retaining each original relocation-record offset, explicit addend,
file offset and independently computed SHA-256 of its original eight bytes.
65 candidates are refused. The bounded fixtures use at most 16 KiB each.

The guarded Gradle task and six compiled behavioral mutations pass. Mutations
cover an off-by-one candidate cap, retained record order, fabricated source-byte
hashes, duplicate protection ranges, ambiguous targets and write-only slots.
The first cap mutation escaped as an uncaught exception; the positive-boundary
oracle now explicitly asserts that valid input must be accepted. An initial
write-only fixture also had an unreadable target and did not distinguish the
slot-read check. Giving the target its own readable segment isolates that check;
the complete final mutation run detects all six faults. Neither earlier attempt
is credited as a passing mutation run.

Evidence: `.forge-work/scratch/relocated-pointer-boundaries-isolated.log`,
`relocated-pointer-boundary-mutants-isolated/result.json`, and
`coverage-recovery/relocated-pointer-boundaries/`. The same-production diagnostic
union has 1,396 sessions, 901 classes and all 255 production sources, adding ten
branches. Overall totals are 28,843/29,802 lines and 22,209/25,902 branches;
critical binary/location is 16,040/18,750 branches, 835 short of 90%. File
operations remain 50 short. Production is unchanged; this adds no ABI/runtime
immutability claim. Historical cohorts remain, so current-head hosted acceptance
is still pending.

## Firmware capture consistency and original-file provenance

The existing `ghidraFirmwareMemoryMapSmoke` task now invokes 21 additional
assertions using real ProgramDB/FileBytes, a 131,073-byte mapped region and
nonzero import/source offsets. The exact file span and whole-input SHA-256 are
independently checked. Analysis-byte edits immediately before/after a 64 KiB
boundary and in the final chunk are refused. Duplicate FileBytes, duplicate
logical input IDs, foreign FileBytes and a one-byte-short original extent are
also refused; restoring the explicit edits restores the exact captured map.

A monitor calibrated from the unchanged capture injects an edit to an unmapped
input byte immediately before the second digest pass. The final whole-input
comparison must refuse it. A separate edit changes block permissions at the
last capture cancellation poll; the program modification check must refuse it
without undoing the analyst edit. These are deterministic consistency controls,
not claims of an atomic snapshot or exhaustive concurrent-filesystem protection.
The caller's pre-publication consistency obligation remains unchanged.

The guarded Gradle task passes these 21 assertions and the original 20 checks.
Four compiled faults are caught by behavioral assertions: ignoring the final
input mismatch while still reading its digest, ignoring a program modification,
dropping the import file offset, and trusting altered analysis bytes. Baseline
passes. The first fixture attempt had a one-byte-short FileBytes range and was
rejected by Ghidra before capture; that setup failure is not credited as passing
validation. The corrected fixture crosses the intended chunk boundary.

Evidence: `.forge-work/scratch/firmware-capture-consistency-second.log`,
`firmware-capture-consistency-mutants/result.json`, and
`coverage-recovery/firmware-capture-consistency/`. The verified diagnostic union
has 1,395 sessions, 901 unchanged production classes and all 255 production
sources. It gains five lines and six branches: overall 28,843/29,802 lines and
22,199/25,902 branches; critical binary/location 18,606/19,213 lines and
16,030/18,750 branches (845 short of 90%). File operations remain 50 branches
short. Historical cohorts remain, so full current-head hosted acceptance is
still pending. Production and emitted artifacts are unchanged.

## ARM floating-aggregate admission and exact classification bounds

The existing `armHfaParameterAllocationSmoke` now runs 226 additional assertions
on actual little-endian and BE8 programs, alongside 948 existing assertions across
216 scenarios. Controls cover image/profile disagreement, foreign programs,
unknown conventions, hidden return pointers and exact parameter limits
(4,096 accepted; 4,097 refused). Nested structures exercise the real 64-visit
classification budget: 61 wrappers plus the base structure and two floating
leaves are accepted; a further wrapper is refused. Positive corrections require
exact S0/S1 member ordering for the target byte order, with no modification of
saved types/storage, the program modification counter or original ELF bytes.

The guarded Gradle task passes. Six compiled faults are detected by behavioral
assertions, with a passing unchanged baseline: both directions of the type-budget
boundary, the parameter-count boundary, incorrectly including the hidden pointer,
accepting an unaudited compiler, and reversing big-endian member order. Evidence
is under `.forge-work/scratch/arm-hfa-admission-first.log` and
`arm-hfa-admission-mutants/result.json`; no production code was changed.

The verified local diagnostic addition is
`coverage-recovery/arm-hfa-admission/`: 1,394 sessions, unchanged production JAR,
901 classes and all 255 production sources. It adds seven branches, yielding
28,838/29,802 lines and 22,193/25,902 branches. Critical binary/location branches
are 16,024/18,750 (851 short of 90%); file operations remain 50 branches short.
This is a mixed historical/current diagnostic, not full current-head hosted
acceptance or a new debugger-support claim.

## ARM BE8 aggregate correction admission

The existing `armCompositeParameterAllocationSmoke` task now invokes a focused
saved-program admission suite. It passes 118 new assertions alongside the
existing 2,592 checks on Ghidra 12.0.3. Real ProgramDB functions prove refusal
for mismatched ELF metadata, unaudited language/compiler profiles, another
program, unknown calling conventions, and signatures exceeding 4,096 parameters.
The exact 4,096 boundary remains accepted. A large aggregate return introduces
an actual hidden return pointer; correction applies only to the explicit
three-byte stack aggregate, with the corresponding shifted stack offset.

Every observation checks unchanged saved storage, formal types, program
modification count and ELF bytes. Nested typedef inputs at depths 63, 64 and
65 resolve through Ghidra's actual base-type API and retain the justified
correction. These cases do **not** claim to exercise a typedef traversal cap:
Ghidra resolves the base structure directly. Initial test attempts incorrectly
expected a correction for an already-correct register argument and refusal for
the flattened alias chain. Those fixture assumptions were corrected; production
code was not changed. The positive fixture uses a stack argument whose padding
really needs adjustment.

Five compiled faults are detected by Java assertions: accepting an unaudited
compiler, accepting invalid EABI metadata, rejecting the exact parameter cap,
including the hidden argument in the explicit signature, and retaining incorrect
stack padding. The unchanged-source baseline passes. This is a selected-fault
check, not a repository-wide mutation score.

Commands (through `support/storage-guard.py run`):

- `./gradlew --no-daemon armCompositeParameterAllocationSmoke`
- `python3 src/test/coverage/mutation-check.py` with the five
  `arm-composite-*` selectors and pinned Ghidra dependencies.
- The local diagnostic collector against the unchanged production JAR,
  followed by raw execution/source hash and complete-denominator verification.

Evidence: `.forge-work/scratch/arm-composite-admission-final.log`,
`arm-composite-admission-mutants/result.json`, and
`coverage-recovery/arm-composite-admission/`. The diagnostic union contains
1,393 sessions with all 255 production sources and 901 production classes.
It adds ten branches: nine in aggregate allocation and one in ARM ABI metadata
admission. Totals are 28,838/29,802 lines and 22,186/25,902 branches. Critical
binary/location coverage is 16,017/18,750 branches, 858 short of 90%; file-operation
coverage remains 3,775/4,250, 50 short. Historical cohorts remain, so this is not
full current-head hosted acceptance. This test-only change makes no new emitted
DWARF, debugger or architecture-support claim.

## ARM/MIPS context sessions reconciled with the diagnostic union

The nine previously validated local context-boundary sessions are now included
in the combined diagnostic: import plus two exports for ARM32, MIPS32 big endian
and MIPS32 little endian. All use the same production JAR. Receipt hashes, raw
execution hashes, oracle hashes and session identities were checked; each target's
headless report regenerated exactly, including per-source counters and XML hashes.
The producing local commit is `7f663d1a33fc906c398be7b6e00945f529431c14`; production
source remains unchanged since that commit.

Retained evidence was also rechecked: output and saved-project hashes, repeated
generation equality, protected inputs, GNU/LLVM and strict libdwarf reports, and
successful compiler/Forge GDB results with QEMU exit status. The runtime cases
exercise ARM/Thumb transitions and MIPS delay slots. Incomplete context retains
diagnostic source without fabricated executable line mappings. This was evidence
revalidation, not a new runtime test execution. The cached Ghidra installation
was restored after the original run; its tested JAR identity is checked against
the preserved matching production JAR, not against the restored installation.

The union now has 1,392 sessions and gains nine lines and 15 branches: nine lines
and 13 branches in instruction-context extraction, plus one branch in each of
the MIPS aggregate/floating call policies. Totals are 28,838/29,802 lines and
22,176/25,902 branches. Critical binary/location branches are 16,007/18,750,
868 short of 90%; file operations remain 3,775/4,250, 50 short. No classification
or denominator changed. Historical cohorts remain; this does not establish
complete current-head hosted acceptance or resolve the hosted MIPS collector
failures before the queued workflow fix runs.

Evidence: `.forge-work/scratch/coverage-recovery/verify-context-addition.log`,
`verify-context-oracles-final.log`, and `context-current-diagnostic/` (regenerated
target reports, retained-oracle recheck, receipts, union, counters and gaps).
The first oracle recheck incorrectly expected QEMU's status file to contain
`0`; the runner records `exit=0`. Correcting that format assertion produces the
passing final recheck without changing the retained evidence.

## Loader write ranges and file-backed intersections

`elfRelocationEffectsSmoke` now checks an independent interval oracle over COPY
write sizes 0, 1, 7, 8, 37 and 256 at four locations spanning ordinary file bytes,
the file/BSS boundary and BSS. Exact write records, protected-address queries and
protected-file queries must match the fixture's declared LOAD boundaries. Tests
include interior zero-length file queries, exact endpoints, overflow and negative
extents. Every fixture inspection, successful or rejected, preserves input bytes,
file identity and modification time.

Both existing AMD64 and AArch64 metadata profiles additionally check global/weak
COPY objects, refused local/reserved bindings and section indices, profile-specific
alignment, REL/RELA prefix counts, duplicate ordinary tags versus repeated
`DT_NEEDED`, `DF_TEXTREL`, and empty versus unqualified nonempty `.sframe`. These
are bounded hand-built metadata tests, not new native-loader or debugger support
claims. Existing compiler/runtime oracles remain separate and unchanged.

The guarded final suite passes 2,269 assertions. Six compiled mutations are
detected: assigning file bytes to BSS, refusing weak COPY, rejecting an empty
file query, inventing a zero-size write, refusing a zero prefix count without
a table, and trusting unqualified SFrame. The first mutation attempt exposed
a missing test: empty queries only touched write endpoints. It was not credited;
the added interior query detects the fault in the final passing run.

Production-only measurement adds 18 critical branches, with no line-count change.
The mixed diagnostic now has 1,383 sessions, 28,829/29,802 lines and
22,161/25,902 branches. Binary/location coverage is 16,005/18,750 branches,
870 short of 90%; file operations remain 3,775/4,250, 50 short. Production code,
critical classification and the full denominator remain unchanged. Complete
current-head hosted validation is still pending.

Evidence: `.forge-work/scratch/relocation-write-boundaries-final.log`,
`relocation-write-boundary-mutants-final/result.json`, and
`coverage-recovery/relocation-write-boundaries/`.

## Saved-program unwind capture admission

The existing `ghidraUnwindInstructionsSmoke` task now includes 67 additional
assertions using real ProgramDB instructions and saved function edits. Capture
refuses length/fallthrough overrides, changed flow references, external and
thunk functions, an oversized body, unresolved computed jumps, and MIPS delay
slots in both byte orders. A controlled policy callback changes the body during
capture; the stale graph must be refused. Refusals preserve code bytes and the
saved state they inspect, and transaction rollback restores identical capture
evidence for the small accepted fixture.

A bounded x86 fixture proves admission of exactly 65,536 decoded instructions
and refusal of the first excess. Its explicit disassembly region avoids Ghidra's
default repeated-byte stopping heuristic. The initial test attempt stopped
decoding the repeated NOPs and was correctly rejected; that fixture setup failure
is retained separately from the final passing run.

The guarded full task passes, including the existing 1,849 unwind checks and
882 call-site checks. Three compiled mutations are detected by Java assertions:
trusting a thunk body, accepting a body changed during capture, and rejecting the
valid instruction-count boundary. The initial mutation attempt surfaced an
uncaught exception for the last case; it was not credited. Accepted-fixture
assertions now explicitly distinguish that regression, and the final baseline
and all three mutation checks pass.

The new helper's production-only measured execution adds one line and nine
critical branches. The diagnostic union has 1,382 sessions, 28,829/29,802 lines
and 22,143/25,902 branches. Critical binary/location branches are 15,987/18,750
(888 short of 90%); file operations remain 3,775/4,250 (50 short). No production
code, target, denominator or critical classification changed. These decoder and
admission tests do not claim new exported CFI or architecture support. Complete
current-head hosted acceptance remains pending.

Evidence: `.forge-work/scratch/unwind-capture-boundaries-final.log`,
`unwind-capture-boundary-mutants-final/result.json`, and
`coverage-recovery/unwind-capture-boundaries/`.

## Dynamic symbol count sources and exact inventory limits

`sectionlessDynamicSymbolsSmoke` now checks an independently encoded named
`SHT_DYNSYM` alongside `PT_DYNAMIC` across ELF32/64 and both byte orders. The
original-record reader must preserve the raw records, accept the exact 262,144
record cap, and reject its first excess. Disagreements in address, record width,
size, allocation/compression flags, file mapping, duplicate tables and SysV
count evidence are rejected with specific diagnostics. Unrelated sections do
not change the count or records. These metadata fixtures use bounded files of
at most about 6 MiB; they are not new executable architecture fixtures.

Additional mirror controls preserve absolute/common indices and reject duplicate
dynamic segments, partially file-backed string extents and an excluded GNU bucket
index. Existing malformed-input checks also exercise alias omission and preserve
the original input and prior output. The task now removes its owned fixture tree
on both success and failure.

The final guarded task passes 3,430 assertions. Five compiled mutations are
detected by behavioral assertions: ignored named record width, accepted compressed
records, ignored file mapping, rejection of the exact cap, and ignored count
disagreement. The unmodified baseline passes. Production Java is unchanged.

Matching-production measurement adds one line and 13 branches. The diagnostic
union now has 1,381 sessions: 28,828/29,802 lines and 22,134/25,902 branches.
Critical binary/location coverage is 15,978/18,750 branches, leaving 897 to
reach 90%; file operations remain 3,775/4,250, leaving 50. The full denominator
and existing critical inventory are retained. Historical cohorts remain in
this diagnostic; full current-head hosted acceptance is still pending.

Evidence: `.forge-work/scratch/dynamic-count-boundaries-final.log`,
`dynamic-count-boundary-mutants-final/result.json`, and
`coverage-recovery/dynamic-count-boundaries/` (raw execution hash, test source
hashes, command, union manifest, report, counters and remaining gaps).

## Current-run AArch64 coverage independently regenerated

The AArch64 job in [CI run 44105084385](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44105084385)
passed at remote head `6104599a775cddad303078a92de00ed3052bc099`, using producing
merge `8f9d946cedee0ca8ad370c6daf45057514534c3e`. Artifact `14351816980` was downloaded
under the storage guard; its byte count and GitHub SHA-256 digest were verified
before bounded extraction. Its 26 sessions comprise 14 headless and 12 native-Java
sessions across all four required suites: bitfields, stack transitions, location
widths and namespace globals.

Every raw collection receipt passed validation against the unchanged production
JAR. Local report regeneration reproduces the hosted layer data exactly, including
per-source counters, receipt hashes and XML hashes. All 901 production classes
and 255 sources remain represented. The verification also checks the successful
AArch64 job, producing cohort and unchanged production source since its head.

The diagnostic replaces the 26 older AArch64 sessions instead of accumulating
duplicate runs, and admits the final formatter admission session. Its total is
1,380 sessions, with **28,827/29,802 lines (96.7%) and 22,121/25,902 branches
(85.4%)**. Replacement of the AArch64 cohort changes no covered counters; the
nine-branch increase comes from the formatter task. Both critical-group branch
targets remain unmet. Other historical sessions remain in the diagnostic, and
the queued local changes have not passed full current-head hosted validation.
x86-64 and ARM32 were still running; both MIPS coverage-report failures have a
separately validated collector fix queued for the next run.

Evidence: `.forge-work/scratch/coverage-recovery/fetch-aarch64-current.log`,
`verify-aarch64-current.log`, and
`current-44105084385/aarch64-current-diagnostic/` (job identity, regenerated layer
reports, union manifest, full report and updated gaps).

## Formatter type-name admission before native production

The existing `formatterPlanSmoke` task now runs 60 additional assertions against
the exporter admission path. It rejects malformed or duplicate formatter witness
names, missing type models/keys, and collisions with recovered function, type
or global names. The negative exports use an independently encoded ARM ELF and
regular-file placeholders that cannot be loaded as producer libraries. Each
case must reach the specific admission diagnostic before native loading.

Both absent and existing sidecar destinations are checked. The original ELF and
library placeholders retain their bytes; an existing destination retains its
bytes, file identity and modification time. No source or staging artifact is
left behind. The existing owning task removes its entire disposable fixture
directory. Linux and Windows CI already run this task; fresh hosted validation
of the additional cases is pending.

The guarded task and matching-production measurement pass. The full task adds
two lines and eight branches in `MinimalDwarfSidecarExporter`, plus one branch in
`Arm32CallPolicy`, against the 1,379-session spill diagnostic. This tests rejection
before native production, not successful DWARF serialization or debugger use.
No new mutation-control result is claimed. Production code and coverage scope
remain unchanged.

Evidence: `.forge-work/scratch/formatter-witness-admission-test.log` and
`coverage-recovery/formatter-witness-admission/`.

## 32-bit stack spill displacement and input admission

`StackSpillSmoke` adds real decoded x86-32 spills of 1-, 2- and 4-byte values and
an ARM32 spill of a 4-byte value. Each fixture checks the exact stack-pointer
DWARF register, negative displacement and end of availability. Analysis must
preserve the saved function body, program modification counter and code bytes.
The 4-byte fixtures additionally refuse absent/non-register incoming nodes,
zero-width and high-byte slices, mismatched extents and the stack pointer itself.

The existing independent finite-width p-code evaluator now runs for both 32-bit
and 64-bit pointers. It checks stored values and addresses near signed and
unsigned wrap boundaries. Exact minimum/maximum signed displacements are
accepted; their first excesses and negation of the signed minimum are refused.
These controlled p-code transfers supplement the real decoder fixtures; they do
not claim that every synthetic operation sequence comes from an instruction or
establish a new full debugger/architecture support profile.

The final guarded suite passes 2,202 checks. Four compiled mutations are detected
by behavioral assertions: lost displacement sign extension, missing narrow-width
overflow refusal, incorrect subtraction and incorrectly commuted subtraction.
The measured task adds one line and eight branches against the 1,377-session ARM
admission diagnostic. Production Java and the coverage denominator are unchanged;
complete current-head hosted acceptance and critical branch targets remain unmet.

Evidence: `.forge-work/scratch/stack-spill32-admission-test.log`,
`stack-spill32-admission-mutants/result.json`, and
`coverage-recovery/stack-spill32-admission/`. The earlier arithmetic-only
measurement adds one branch and is superseded by the final task; do not count
both sessions as separate coverage gains.

## Complete ARM section allocation boundaries

`GhidraArm32SectionModesSmoke` checks allocations that begin inside an ARM
instruction, end inside a defined literal, or extend beyond the initialized
ProgramDB memory. NOBITS allocations are refused as lacking file backing. A
256-MiB NOBITS extent reaches that backing check, while the first excess is
refused by the byte budget; these are tiny metadata fixtures, not large payloads
or successful 256-MiB exports. A virtual selection list tests the first comparison
budget excess without allocating millions of entries.

The actual saved literal block is also split and converted to uninitialized
memory. Selection-address overflow, removal of the selected mixed-mode function,
and unknown current instruction mode all have explicit outcomes. Refusals preserve
the ELF bytes and saved program modification counter; retries against the original
allocation reproduce the exact baseline mapping. Owned temporary ELF fixtures
are removed after the task.

The guarded task passes 126 checks. Three compiled mutations fail behavioral
assertions: accepting a partial code unit, ignoring file backing, and rejecting
the exact byte-budget boundary. The matching-production diagnostic adds four
lines and ten branches against the 1,377-session ARM admission baseline.
Production Java is unchanged, and complete hosted acceptance remains outstanding.

Evidence: `.forge-work/scratch/arm-section-boundaries-test.log`,
`arm-section-boundary-mutants/result.json`, and
`coverage-recovery/arm-section-boundaries/`.

## Saved ARM mode evidence after analyst edits

`GhidraArm32FunctionModesSmoke` now retains an extracted function selection while
the actual ProgramDB function is renamed, removed, marked as a thunk, or shortened
to another completely decoded body. It requires the precise stale-evidence
diagnostic, unchanged unrelated cues, and an unchanged program modification
counter. Transaction rollback restores the exact original evidence. Rejection
of the last usable Thumb cue also drops the otherwise valid ARM-only supplement.

Additional cases exercise out-of-range analysis addresses, invalid ELF32
coordinates that rebase into valid saved instructions, misaligned link-time
coordinates, and the exact 65,536-alias limit followed by its first excess.
Both primary and alias mode extraction must refuse invalid coordinates without
altering the saved program.

The guarded task passes 423 checks. Four compiled mutations are detected through
behavioral assertions: skipping name agreement, skipping body-size agreement,
accepting thunks, and rejecting the valid alias-count boundary. The initial
mutation invocation lacked the Ghidra dependency/argument registration for this
test; that compilation failure was not counted as detection. The corrected
baseline and all four controls pass, as do the eight mutation-outcome tests.

Production code remains unchanged. The measured task adds five lines and 13
branches. Together with the preceding ARM inventory test expansion, the refreshed diagnostic
contains 1,377 matching-production sessions, adding 15 lines and 41 branches to
the preceding inventory diagnostic. It retains all 255 production sources and
901 classes. This mixed historical/current union is still not full current-head
hosted acceptance, and neither critical-group branch target has been met.

Evidence: `.forge-work/scratch/arm-saved-mode-test-final.log`,
`arm-saved-mode-mutants-final/result.json`, `arm-mode-mutation-outcomes.log`,
`coverage-recovery/arm-saved-mode-boundaries/`, and
`coverage-recovery/current-44105084385/arm-admission-diagnostic/`.

## ARM mode symbol admission boundaries

`Arm32ModeSymbolsSmoke` now checks malformed dynamic-table framing and links,
extended-index framing, irrelevant index tables, unnamed non-code definitions,
out-of-section dynamic symbols, ARM/Thumb alignment, 32-bit address limits and
wrapping allocations. It accepts exactly 262,144 dynamic rows and a 16,777,216
allocation/cue comparison budget, then refuses the first excess. Recovered-cue
checks preserve analyst names, reject excessive cue counts, and require an
eligible Thumb cue after byte/owner validation. All three reserved symbol-section
names are covered. Accepted and refused planning preserve original input bytes.

The final guarded task passes 13,613 checks. Four compiled mutations are detected
by behavioral assertions: tightening either exact resource limit, accepting an
odd Thumb extent, and accepting malformed extended-index framing. Production
Java is unchanged. The fixture tree is owned by this task and removed in its
`finally` block. These metadata fixtures do not claim runnable ARM or valid DWARF
payloads; independent architecture/runtime acceptance remains a separate gate.

The matching-production diagnostic union adds 10 covered lines and 28 branches
to the preceding 1,375-session inventory diagnostic. This is a **partial mixed
historical/current collection**, not complete current-head hosted acceptance.
The full production denominator and critical classification remain unchanged.
The first fixture draft mistakenly overlapped an invalid huge extent with its
positive control; another draft expected an incomplete diagnostic string. Both
test expectations were corrected without changing production behavior.

Evidence: `.forge-work/scratch/arm-mode-boundaries-admission-final.log`,
`arm-mode-admission-mutants/result.json`, and
`coverage-recovery/arm-mode-admission-boundaries/` (raw execution, source hashes,
command, test log, verified union and coverage deltas). CI run `44105084385`
still had x86-64, AArch64 and ARM32 running at this checkpoint. The separately
validated ARM/MIPS collector fix remains queued for the next hosted run.

## Static ELF symbol inventory limits

`LocalSymbolMergeSmoke` adds malformed table links, partial records, excess local
counts, empty or incorrectly terminated strings, addressed index sections, and
zero extended indices in ELF32/ELF64 with both byte orders. Existing refusal
checks require unchanged source bytes, unchanged destination sentinels and no
partially published files. Positive merges compare original symbol records and
string bytes exactly, including their positions after local-symbol insertion.

The name-size boundary accepts 65,536 bytes and rejects 65,537. A compact string
table with overlapping suffixes also exercises the decoded-work budget: 256
unique suffixes remain below 16 MiB, while the 257th exceeds it. These tests use
independently constructed ELF records; their placeholder debug payload is not
claimed to be valid DWARF or a runnable architecture fixture.

Guarded `localSymbolMergeSmoke` passes **3,636 checks**. All three compiled mutants
are detected by Java assertions, with the baseline passing (3.640 seconds): an
oversized name, excessive aggregate decoded names, and a zero extended index.
The suite now removes only its freshly created temporary fixture tree in
`finally`; the measured run leaves no `forge-symbol-merge-*` tree behind.

Production-only measurement adds **1 line / 10 branches** in
`MatchedElfSidecarWriter` against the 1,373-session partial diagnostic. Production
code and accepted targets are unchanged. Evidence:
`.forge-work/scratch/symbol-inventory-boundaries-test.log`,
`symbol-inventory-mutants/result.json`, and
`coverage-recovery/symbol-inventory-boundaries/result.json`.

## Preserve explicit analyst call overrides during allocation correction

`AllocationDecompilerSmoke` starts with Ghidra's actual encoded i386 function and
analyst call override. Controls replace a parameter tag with an unexpected element,
add child metadata to a return/parameter address without attributes, and duplicate
those address elements. Each must be rejected without changing the captured tree
or saved function. A separate control rejects an allocation view that requests
omission of an explicit analyst parameter. Positive assertions retain the formal
return type and the intended omission of only the automatic return parameter.

Every observed override-encoding cancellation poll is exercised, with immediate
failure, unchanged captured data and a deterministic valid retry. The first test
attempt counted `checkCancelled()` calls, while this encoder uses `isCancelled()`;
correcting the monitor to observe the actual API made the cancellation test valid.
No production cancellation defect is claimed.

Guarded `allocationDecompilerSmoke` passes **60 checks**. The canonical mutation
harness detects all three compiled faults (unexpected parameter acceptance,
explicit address-child loss, and explicit-parameter omission) through Java
assertions; the unmodified baseline passes (9.025 seconds). Production-only
measurement adds **2 lines / 5 branches** in `GhidraAllocationDecompiler` against
the 1,373-session partial diagnostic baseline. This does not update the complete
hosted coverage figure or claim a new end-to-end debugger profile.

Evidence: `.forge-work/scratch/allocation-override-boundaries-test-final.log`,
`allocation-override-mutants/result.json`, and
`coverage-recovery/allocation-override-boundaries/result.json`.

## Sidecar comparison detects changing candidate lengths

`SyntheticSourceSidecarSmoke` now rejects an empty staging channel whose position
is nonzero, without writing or repositioning it. Two owned-file controls change
the candidate length after its initial size check: appending must fail the final
size comparison, and truncation must fail when the required comparison read cannot
complete. Both require the specific diagnostic and independently verify that the
intended size change occurred. These synchronized controls do not establish
protection against every possible concurrent filesystem mutation.

Guarded test compilation and real producer-sidecar smoke runs pass for ARM32 and
MIPS32 in both byte orders. Each transformed artifact passes readelf inspection,
LLVM verification, the strict libdwarf checker, and the existing QEMU/GDB context
oracle, including source lookup from another directory, exact branch/mode/slot
behavior and normal exit. Original inputs remain unchanged. Production Java is
unchanged; no malformed fixture is passed off as a valid debugger artifact.

Unioning the three production-only sessions with the previous 1,370-session
diagnostic produces 1,373 compatible sessions and adds **2 lines / 16 branches**
in `SyntheticSourceSidecar`. This is the gain from the full refreshed smoke tasks,
not an isolated attribution to the three new controls. Production identities and
the complete 255-source denominator remain unchanged. It is still mixed partial
evidence, not a full current-head acceptance report.

Evidence: `.forge-work/scratch/source-comparison-compile.log`,
`verify-source-comparison.log`, `coverage-recovery/source-comparison-validation.json`,
and `coverage-recovery/current-44105084385/source-comparison-diagnostic/`.
The individual `source-comparison-boundaries*` directories retain measured test,
validator and debugger logs. No new mutation run is claimed for these controls.

## Enable required context collection in ARM/MIPS CI

**CONFIRMED failure and local correction; hosted verification pending:** run
`44105084385` MIPS little-endian job `134145563389` passed the context-boundary
harness at 15:54 UTC, but its final report failed with
`required integration coverage suite did not run: ['context-boundaries']`.
The collector is opt-in; the step lacked its agent/output environment variables.
Only x86-64 receives those variables job-wide. The shared ARM32/MIPS context step
now explicitly exports both variables, matching other measured target steps.
The required-suite and hosted cohort checks remain unchanged.

The guarded local verification uses the current production JAR
`58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`,
Ghidra 12.0.3 and Java 21.0.12.1. ARM32 and MIPS big/little endian each pass
three measured import/reopen JVM sessions, unchanged input/project checks,
deterministic outputs, GNU/LLVM/strict validators, and compiler/Forge QEMU-GDB
oracles. Each real integration report requires `context-boundaries` and validates
all 901 production class identities. These nine sessions establish the local
collector path, not a complete hosted architecture cohort or a new coverage gain.
The agent-owned cached installation JAR and launch properties were restored.

`actionlint .github/workflows/ci.yml` and all 304 coverage-admission tests pass.
Evidence: `.forge-work/scratch/ci-44105084385-mips32le.log`,
`context-ci-wiring-final/`, `verify-context-ci-wiring-final.log`, and
`context-ci-wiring-checks.log`. The first local attempt passed the MIPS behavior
harness but could not start report generation because its Java path omitted the
extracted package's `usr/lib/jvm` directory; the corrected Java-21 run is the
accepted evidence. The first attempt is retained and is not reported as a fully
passing collection/report run.

## Call-site inventory admission and instruction boundaries

The real Sleigh/ProgramDB fixture now checks explicit fallthrough replacement and
removal on x86-64/AArch64, decoded fallthrough outside the retained function body,
x86 length overrides, and an x86 branch into the middle of its own instruction.
Capture must report unavailable instructions or incomplete inventory as appropriate;
an interior branch destination must not become a decoded instruction boundary.
Foreign Program functions are rejected. Bodies at 1,048,576 bytes proceed to the
ordinary undecoded-body diagnostic; the first excess byte triggers the size
refusal before scanning. Budget checks also assert unchanged program state.

Guarded `callSiteEvidenceSmoke` passes **527 checks** (six seconds). All five
compiled mutants are detected through Java assertions, with the unmodified
baseline passing (18.989 seconds): foreign ownership, escaping fallthrough,
interior branch destination, length override, and the exact body-budget boundary.
The first fixture attempt incorrectly reused a Program-bound compiler spec;
using the language's corresponding base compiler spec corrected that test setup.
Production code remains unchanged.

A production-only measurement adds **2 lines and 5 branches** in
`GhidraCallSiteEvidence` against the refreshed 1,367-session diagnostic union.
Evidence: `.forge-work/scratch/call-evidence-boundaries-test-corrected.log`,
`call-evidence-boundary-mutants/result.json`, and
`coverage-recovery/call-evidence-boundaries/result.json`. This is a listing and
original-byte inventory test, not a new emitted call-site or debugger acceptance
claim. Full current-head combined coverage and hosted acceptance remain pending.

## Parameter storage refusals across seven profiles

`DynamicParameterStorageSmoke` now rejects missing register maps, unnamed slices
whose byte extent disagrees with the saved formal, cross-register spans, RAM and
void storage, oversized stack allocations, and values wider than their assigned
register. Positive three-byte slices retain byte-order-aware offsets. All cases
use actual Ghidra storage objects and assert that extraction leaves the program's
modification number unchanged; the existing immutable reopen and file hash checks
remain. The task puts temporary database fixtures under the guard's `TMPDIR`.

Guarded `dynamicParameterStorageSmoke` passes 325 checks across x86-64, AArch64,
ARM32, and both byte orders of MIPS32/MIPS64. An initial test expected the unnamed
slice diagnostic for a span that Ghidra resolves through a named register; the
expectation now distinguishes those paths. This was a test correction, not a
production fix. The canonical mutation harness detects all three compiled faults
(removing the unnamed-width check, removing the named-register width check, and
allowing a byte slice across its container) through Java assertions, with both
unmodified source baselines passing. Elapsed time: 11.904 seconds.

A production-only measurement against the refreshed 1,367-session diagnostic
union adds **3 lines and 6 branches** in `GhidraVariableStorage`. The unchanged
production JAR and full class identities validate. This remains a mixed
current/historical/local diagnostic cohort, **not** final hosted acceptance.
Evidence: `.forge-work/scratch/parameter-storage-refusal-test-corrected.log`,
`parameter-storage-refusal-mutants/result.json`, and
`coverage-recovery/parameter-storage-refusals/result.json`. Production code is
unchanged; this test does not newly validate emitted DWARF or debugger behavior.

## Windows privilege restoration replies — PRESENT, UNVERIFIED

`WindowsPrivilegeReadbackControls` adds 12 cases after actual constructor
admission. Real token restoration runs before controlled adjustment failures,
ERROR_NOT_ALL_ASSIGNED, invalid previous-state lengths/counts/LUID, or a runtime
exception is reported. A readback control changes only the returned attributes.
Close-error controls perform the actual `CloseHandle` successfully before
reporting failure. Combined restoration/close errors must preserve the primary
checked or unchecked exception and retain the secondary close error as suppressed.

Each case independently observes the real original token attributes, requires
one restoration and one successful native handle release, and rejects later use
of the closed scope. The native interfaces are restored in `finally`; ordinary
scope cleanup runs even when a fixture assertion fails. Warmed repetitions and
the existing process-handle count enclose the controls. Python requires all 12
named results, original-state restoration and handle-release evidence; PowerShell
requires the new control marker alongside the original acceptance marker.

Guarded Java `testClasses` compilation passes, including the final returned-buffer
bounds assertion (`windows-privilege-close-final-compile.log`). Python harness
AST parsing passes. **Actual Windows execution, stable handle counts, PowerShell
execution and coverage gains remain unverified** until CI includes this change.
The current run's successful Windows-host and debugger follow-up jobs use the
older remote commit and do not validate these queued cases. Production code and
native interfaces are unchanged.

## Validator helper changes during provenance observation

`ValidatorLaunchBoundarySmoke` uses owned executable fixtures and synchronizes
actual file changes at digest cancellation polls. Identity replacement preserves
bytes/size/mtime; a size change preserves mtime; a timestamp change preserves
identity/bytes. A fourth case appends before the digest read and restores the
original bytes/size/mtime before EOF, so equal metadata snapshots still must
reject a mismatched observed byte count. Each case requires the specific
provenance error, verifies the intended filesystem control, and requires an
empty evidence directory. These are Linux prelaunch refusal tests; they do not
claim hostile-race protection against undetectable change-and-restore attacks.

Guarded `gcc -std=c11 -O2 -Wall -Wextra -Werror` builds the current native Linux
supervisor. The full `validatorSupervisorSmoke` task passes with that helper:
270 status checks, 69 launch checks, 15 negative helper-protocol controls, and
38 supervisor checks, including real child cleanup, cancellation and interruption.
Four compiled mutations independently removing identity, size, modification-time
or observed-byte-count verification are detected by behavioral assertions;
the unchanged baseline passes (3.004 seconds total mutation run).

Diagnostic measurement against the refreshed mixed-cohort baseline adds
**1 line / 4 branches** in `ValidatorSupervisor`. Production code is unchanged.
Evidence under scratch: `provenance-supervisor-build.log`,
`validator-provenance-test.log`, `validator-provenance-compile.log`,
`validator-provenance-mutations/result.json`, and
`coverage-recovery/validator-provenance/`. No new Windows runtime evidence or
complete-current coverage percentage is claimed.

## Refreshed diagnostic evidence from CI 44105084385

**CONFIRMED, diagnostic only:** completed artifacts from the run at `6104599a`
contain the unchanged production JAR `58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`.
The producing merge is `8f9d946cedee0ca8ad370c6daf45057514534c3e`; its parent
identity and exact task inventory were checked through GitHub. Artifact IDs:
`14341438049` (JavaExec), `14344971281` (Windows attachment), `14341788394`
(Linux host), and `14341049022` (firmware). Downloads were guarded, archive
SHA-256 verified, extraction paths/size bounded, and raw collection/oracle
receipts plus class/probe identities validated.

The first diagnostic union was correctly refused because the old JavaExec test
class versions differed. Replacing old JavaExec sessions with the current 212
sessions, while retaining compatible production-only historical integration
sessions, produces 1,359 diagnostic sessions. Current completed Windows/Linux
host/firmware collections contribute 57/45/4 sessions. This reconciliation adds
39 lines and 170 branches relative to the previous diagnostic baseline, largely
removing stale apparent gaps in class, lexical-scope and vtable models. These
are previously implemented tests becoming visible, not newly added tests.

Adding eight already verified local smoke sessions produces 1,367 diagnostic
sessions and a further **25 lines / 59 branches**, using probe union rather than
summing individual test gains. The local contributions include mapping parser
refusals, transaction recovery, type collisions, register completeness, target
agreement, switch guards and lock-publication boundaries. The refreshed critical
gap inventory now guides further work.

Evidence is under guarded scratch `coverage-recovery/current-44105084385/`:
`diagnostic-result.json`, `queued-diagnostic/result.json`,
`queued-diagnostic/gaps.json`, and their raw manifests/XML/receipts. Local
`diagnose-current.py` and `diagnose-queued.py` record the verification procedure;
`diagnose-current.log` retains the rejected mixed-test-version attempt, and
`diagnose-current-retry.log` records the corrected pass. The measurement helper
now compares against this refreshed diagnostic baseline. **No complete-current
coverage percentage, target completion, or hosted acceptance is claimed**: the
architecture and Windows-host jobs were still running at this checkpoint.

## Saved local mapping encoding boundaries

`LocalMappingsSmoke` captures actual `HighSymbol.encodeMapSym` output for curated
register and stack/register identities on x86-64, AArch64, and MIPS BE/LE. The
original typed tree is a positive control. `LocalMappingEncodingSmoke` changes
one storage/range field or structural relationship at a time and replays through
the private mapping collector's public `Encoder` interface. Reflection only
constructs the collector and observes its acceptance state; malformed trees are
explicit parser-boundary inputs, not claims that Ghidra emits them.

The cases reject missing fields, unresolved/constant storage spaces, nonpositive
or overflowing sizes, nested/duplicate/orphan/dangling storage, absent or multiple
register definition ranges, non-point ranges and invented stack definition
ranges. Every observed encoder cancellation checkpoint retains its cancellation
cause and stops promptly. A separate real-listing case sets two saved variables
to the same definition PC, requires refusal, restores distinct PCs and verifies
the original group returns unchanged.

Guarded `localMappingsSmoke` passes (92 listing checks plus 592 encoding checks).
Four compiled malformed-encoding faults and one duplicate-PC fault are detected
by behavioral assertions; both unchanged-source baselines pass. Logs and results
are under scratch: `local-mapping-encoding-test.log`,
`local-mapping-definition-test.log`, `local-mapping-encoding-mutations/`, and
`local-mapping-definition-mutation/`.

Diagnostic `coverage-recovery/local-mapping-encoding/` verifies the unchanged
production JAR/class/probe identities and adds **5 lines / 23 branches** in
`GhidraLocalMappings` against the historical partial cohort. This is a measured
local gain, not a refreshed complete-cohort percentage or hosted acceptance.
Production behavior and the coverage denominator are unchanged.

## Build-ID lock acquisition interruption boundaries

`BuildIdFileLockSmoke` now cancels acquisition at each of its four observed
checkpoints and changes actual file modification time at each of the two
verification observations. Every refusal leaves record bytes intact and allows
a separate process to acquire the lease, proving resource release. The metadata
fixture restores its original timestamp after each case. The same test is wired
into the existing Windows host harness; that platform's new cases remain
**PRESENT, UNVERIFIED** pending hosted execution.

Guarded Linux `buildIdFileLockSmoke` passes. Two compiled mutations removing the
initial/final metadata check are detected by behavioral assertions, with the
unchanged baseline passing (7.514 seconds total). The first mutation invocation
omitted required class-directory arguments and failed argument parsing; the
corrected invocation passed. Evidence under scratch: `lock-interruption-test.log`,
`lock-interruption-mutations-retry.log`, `lock-interruption-mutations/result.json`.

Diagnostic `coverage-recovery/lock-interruptions/` verifies the same production
JAR/class/probe identities against the historical cohort. It adds **zero** lines
or branches beyond `installation-lock-publication`; the task's two-line/two-branch
historical gain remains attributable to that earlier batch. These are behavioral
regressions, not new progress toward the critical branch percentage. Production
sources, denominator and targets remain unchanged.

## Windows rename replies — PRESENT, UNVERIFIED

The existing Windows rename lifetime probe now forwards real kernel calls with
five controlled replies: null/invalid stage handles, failed rename, a close error
after the real handle was released, and cancellation immediately after successful
rename. Assertions distinguish unchanged and published namespaces, retain exact
file identity/bytes/preservation metadata, and balance opened/closed handles.
Exceptional test cleanup releases any retained owned handles. Controls run before
and during the existing warmed lifetime measurement; the PowerShell harness
requires their success marker and independently rechecks the final stage.

Guarded `testClasses` compilation passes (`windows-rename-replies-final-compile.log`
under scratch). Windows execution, handle-count stability and coverage gains
are **unverified** until a new hosted run includes this commit. PowerShell is
unavailable locally; no runtime or parser pass is claimed. Production code is
unchanged.

## Target descriptors and complete register mappings

`RegisterProfileAgreementSmoke` uses actual pinned language registers to reject
an unresolved register, a half-width request for a complete MIPS pair, and two
correct PowerPC children that cover only part of their parent. The PowerPC case
is refusal evidence, not a new supported ABI. The register-alias suite passes;
165 profile checks and one compiled missing-completeness mutation pass with its
baseline. Diagnostic measurement adds two lines/two branches in
`GhidraVariableStorage`. Evidence: guarded scratch
`register-pair-completeness-test.log`, `register-pair-completeness-mutations/`, and
`coverage-recovery/register-pair-completeness/`. The guard refused an overlapping
measurement launch; the measurement was retried after the first command ended.

`DwarfTargetSmoke` rejects malformed public target descriptors and independently
changes each identity field against a real, header-only ELF. Instruction, call
ABI, call-origin, alias, and mode planners must reject disagreement before
downstream work. Matching metadata remains accepted; ordinary x86 has no ARM
mode-symbol output. Input bytes remain unchanged. These are metadata admission
checks, not executable/native producer or debugger validation. The suite passes
and three compiled faults are detected. Diagnostic measurement adds six lines/
fourteen branches in `DwarfTarget`. Evidence: `target-descriptor-admission-test.log`,
`target-descriptor-admission-mutations/`, and
`coverage-recovery/target-descriptor-admission/` under guarded scratch. Its Gradle
task now uses the guard's temporary directory when supplied. Production code,
coverage denominator and acceptance targets are unchanged; hosted results for
these additions remain pending.

## Imported type identity and switch index controls

`defaultTypeIdentitySmoke` now reserves and converts actual Ghidra structure
objects with the same persistent ID but different sizes. Equivalent imports
deduplicate, distinct layouts retain distinct deterministic identities, and an
ambiguous third layout fails without replacing either accepted aggregate.
Reflection accesses the existing private extractor, as in the prior identity
test; this is component evidence, not a new headless export claim. The test and
two compiled identity-merging/ambiguity mutations pass. Diagnostic comparison
with the recovered historical cohort adds eight lines and six branches in
`GhidraTypeGraph`. Evidence: guarded scratch `type-identity-collision-test.log`,
`type-identity-collision-mutations/`, and `coverage-recovery/type-identity-collisions/`.

`boundedSwitchProofSmoke` adds real x86 encodings for an unbounded addend,
unknown byte/word index overwrites, and a known high-byte extraction. Both
original and rebased programs must reject unbounded dispatches and retain the
exact expected target addresses and original table witnesses for the known
case. All 106 cases/981 checks pass. Three compiled faults are detected: the
new high-byte case catches a wrong-byte calculation; existing index-clobbered
and same-read cases catch the other two faults. This batch adds **zero** measured
lines/branches, so it is regression coverage rather than percentage progress.
Evidence: `switch-partial-index-test.log`, `switch-partial-index-mutations/`, and
`coverage-recovery/switch-partial-index/` under guarded scratch. Production code
is unchanged and current hosted validation remains pending.

Five further switch guard shapes use a register bound, stale flags, a signed
comparison, an index-changing subtraction, or an unproved memory bound. The
original and rebased forms are refused at their appropriate proof stages and
preserve the original ELF. The full suite passes 116 cases/1,041 checks and adds
one line/five branches to the historical diagnostic cohort. Initial diagnostic
expectations for the signed and destructive guards were too late in the proof;
both were corrected to the observed earlier refusals. A proposed mutation of
the later index-overwrite guard was discarded: the unchanged-source baseline
failed the stale expectation, and the final fixture never reaches that guard.
No mutation detection is claimed for this batch. Evidence: guarded scratch
`switch-guard-input-test-final.log`, `switch-guard-input-mutations.log` (failed
baseline), and `coverage-recovery/switch-guard-inputs/`.

## Request admission and stack controls awaiting hosted measurement

Build-ID lock publication tests now cover an absent destination after a failed
publication, a valid competing lock, and a same-length foreign lock record.
They verify the original error or independent validation result, unchanged
competing bytes, no state/registration publication, and successful retry after
failed admission. The existing real-host lease smoke passes on Linux; its Windows
lane will exercise the same cases after push. Diagnostic measurement against the
historical cohort adds two lines/two branches in `BuildIdInstallation`; this is
not current hosted acceptance. Evidence: guarded scratch
`installation-publication-test.log` and
`coverage-recovery/installation-lock-publication/`.

Transaction request admission now rejects each missing explicit role, unknown
roles, all completed phases and a PREPARED recovery journal presented as a new
transaction, for both initial attachment and refresh. The fixture verifies that
selected file snapshots remain unchanged and no receipt/recovery/restore outputs
are created. The normal request remains accepted. These are controller admission
checks using filesystem fixtures, not ELF/DWARF or native Windows validation.
Guarded `attachmentTransactionSmoke` passes 1,330 checks, including its existing
eight abrupt process exits. Three compiled admission faults are detected by the
new assertions; the unmodified baseline passes. Diagnostic raw-probe verification
adds four lines and seven branch outcomes in `AttachmentTransaction` relative to
the recovered historical 1,252-session cohort. Current hosted acceptance and the
full critical-group targets remain pending. Evidence is in
`.forge-work/scratch/transaction-admission-mutations/` and
`coverage-recovery/transaction-admission/` under the same scratch directory.

Refresh controls additionally alter the previous image's hash, byte count and
metadata claims while keeping the prior receipt internally valid and rebinding
its outer hash. Each case preserves the selected target and changed receipt and
creates no new transaction outputs. The controller suite passes 1,348 checks;
two compiled faults omitting prior-image hash/size agreement are detected.
The refreshed diagnostic comparison adds three branch outcomes beyond the
admission batch (ten branches/four lines over the historical cohort in total).
Evidence: `transaction-refresh-mutations/` and
`coverage-recovery/transaction-refresh/` under guarded scratch. Production code
is unchanged; current hosted acceptance is still outstanding.

Recovery-journal controls exercise failure before/after preparation and terminal
publication, disappearance of the published record, and a valid terminal record
with foreign claims, for initial attachment and refresh. They check fresh target
and receipt observations, preserved backups, and `RECOVERY_REQUIRED` whenever
durable journaling failed. The controller suite passes 1,540 checks; both faults
that accept a foreign terminal record or discard an owned published preparation
are detected. Diagnostic measurement adds **one branch** beyond the refresh batch
(four lines/eleven branches over the historical cohort). Evidence is in guarded
scratch `transaction-journal-mutations/`, `transaction-journal-test-configured.log`
and `coverage-recovery/transaction-journal/`. An initial build invocation lacked
`GHIDRA_INSTALL_DIR` and failed before tests; the configured invocation passed.

Eight new x86-64 component cases use actual decoded byte/word stores immediately
before, after, or across either edge of four- and eight-byte saved parameters.
An independent byte-memory oracle determines whether the saved value survives.
Both `StackValueFlow.prove` and the public parameter-location path must retain
adjacent writes and omit locations after destructive overlapping writes; the
pre-instruction location remains available. Existing ARM64 cases also pass.

Guarded `./gradlew --no-daemon stackValueFlowSmoke` passes. Two registered
slot-invalidation mutations incorrectly retire a value at the lower or upper
touching boundary; both compile and fail behavioral assertions, while their
baseline passes. Logs are under `.forge-work/scratch/stack-boundary-test.log`
and `stack-boundary-slot-mutations/`. Earlier mutations of the general overlap
helper also failed, but the retained registration targets slot invalidation
specifically. No production code changed. These are extraction component checks,
not new emitted-DWARF or debugger acceptance.

A subsequent guarded measurement uses the unchanged `58bd7a71` production JAR,
instruments only its production classes, and verifies class/probe identities
before combining the new session with 1,252 recovered historical sessions.
It adds **zero line or branch outcomes** to that diagnostic cohort: the new
assertions cover additional boundary inputs along already executed branches.
The two detected faults establish their regression value. The historical cohort
lacks ARM32 and current test additions, so this comparison is neither current
hosted acceptance nor a replacement for the preceding full partial measurement.
The command, source hashes, raw execution, log and comparison are under
`.forge-work/scratch/coverage-recovery/stack-boundaries/`.

Four further cases decode real x86-64/AArch64 two-byte loads from saved four-
and eight-byte parameters. The intact stack slot remains the complete location;
after a partial overwrite of that slot, the short register read cannot stand in
for the original parameter. Both internal and public location APIs are checked.
The existing smoke task passes, and a compiled fault that retires memory on a
short read is detected by the new assertion. Guarded measurement in
`coverage-recovery/stack-narrow/` again adds zero line/branch outcomes to the
historical diagnostic cohort. This is additional behavioral coverage only.

## Current partial measurement after integration refresh

**CONFIRMED, local:** the current `58bd7a71` production JAR has 1,164 verified
sessions: 212 JavaExec, 689 native-Java, 206 headless and 57 Windows. Every available view
retains all 255 production sources / 901 class files. The remaining integration cohort is still incomplete; hosted acceptance is
false. Native C, Python and shell are outside these Java counters.

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 28,610 / 29,802 (96.0%) | 21,868 / 25,902 (84.4%) |
| Binary and location correctness | 18,492 / 19,213 (96.2%) | 15,749 / 18,750 (84.0%) |
| File transactions and validation | 6,383 / 6,677 (95.6%) | 3,732 / 4,250 (87.8%) |

Commit `c613b980` adds 37 GDB companion identity-policy cases using independent
ELF metadata fixtures. Exact immutable header/payload hashes, both ELF widths
and byte orders, 1,024 accepted LOADs/probes and their first refused excesses,
writable or absent executable evidence, and the runtime hashing budget are
checked without modifying inputs. The over-budget test uses a two-MiB file
with repeated views. These metadata fixtures are not runnable programs and do
not establish new architecture or DWARF support. Seven compiled faults are
detected by behavioral assertions; the unchanged baseline and eight mutation
outcome controls pass. CI's existing companion workflow and mutation harness
both invoke the expanded tests.

A fresh live companion run passes the native executable, PIE and shared-object
workflows, including validator checks, real GDB symbol/source/variable values,
ASLR/reload behavior, explicit registration, refusal controls and preserved
inputs. Its three native-Java sessions are admitted after raw receipt, committed
harness, production JAR, protected artifact and mutation-log verification.
The isolated metadata session is not additionally counted in this union.
The initial metadata attempt expected the no-LOAD fixture to reach the LOAD
count check, but missing allocation evidence correctly refused it earlier.
That setup failure is retained separately; the corrected test requires the
actual conservative refusal and does not bypass correspondence validation.

Current immutable partial summary:
`.forge-work/scratch/coverage-expansion/stable-memory-hosts-companion-identity-partial/summary.json`,
SHA-256 `d3be55a2d09bf99dcc1ceb904f3a72f8a4de779ed72b65fa3ca5264c3fef27b6`.
This batch adds four lines and nine branch outcomes; critical branch deficits
remain 1,126 binary/location and 93 file-operation outcomes.

Hosted run `44042799768` is now terminal. x86-64, AArch64, both MIPS and Windows
jobs passed. ARM32 failed before integration execution when Maven Central
returned HTTP 429 for JaCoCo preparation; its missing coverage artifact then
failed upload. Required validation failed and combined coverage/publication
were skipped. The bounded preparation retry in `eac13854` was not in that run;
it retries dependency preparation only, not behavioral failures. The full
updated revision still needs hosted validation, and a dependency retry does
not establish that the critical coverage targets pass.

The preceding batch adds build-ID reader boundaries and refreshed ELF32 source
relocation measurements. Commit `fc45754e` tests independently constructed
ELF32/ELF64 note views in both byte orders. Individually valid views must be
rejected when their physical record intervals overlap or wider alignment padding
extends into a following record, without changing the input. It also tests 21
invalid normalized provenance records, accepted upper bounds and defensive list
ownership. The five compiled faults (two overlap checks, container overflow,
oversized descriptor and invalid hex) all fail behavioral assertions; the
unmodified baseline and eight mutation-outcome controls pass. These mutants are
registered in the existing CI mutation harness. This is reader-component
validation, not a new architecture support claim.

Six source-relocation cases reuse current-production serializer fixtures for
ARM32, MIPS32 big endian and MIPS32 little endian, each plain and gABI zlib
compressed. The existing smoke test checks deterministic/idempotent output,
14 plain or 26 compressed refusal controls, every observed cooperative
cancellation point, exact candidate bytes and unchanged inputs. Independent
ELF byte comparisons restrict edits to the selected section offset/size fields
and appended payloads. LLVM/GNU validation and fresh compiler/relocated GDB
runs under QEMU pass; both expected variable values (42 then 43), addresses and
the retained source path are asserted. This exercises the serializer and
relocator with an explicit compiler fixture model, not fresh Ghidra extraction,
installer transactions or LLDB.

The first local driver completed both ARM32 cases, then stopped before MIPS on
an old fixture's harness-hash mismatch. Its failure log remains retained. The
historical MIPS source is authenticated against snapshot `652fe943`, and its
artifact/native/JAR hashes still match. The only intervening harness changes
add ARM toolchain/sysroot handling. The four MIPS cases ran in a separate root;
the two already completed ARM cases were admitted separately. A subsequent
local manifest-generation variable collision was rejected by admission, fixed,
and reverified without rerunning or relabeling the tests. Neither failed attempt
is represented as a successful complete run.

The resulting immutable partial summary is
`.forge-work/scratch/coverage-expansion/stable-memory-hosts-source32-partial/summary.json`,
SHA-256 `4a36405c558b90184ae91e910738e6951786b93a81a05166713b58ee461038f5`.
The preceding 1,155-session build-ID checkpoint has SHA-256
`88b01cd17432f7f1eab23504612866c8e17e612d3962eea874bad1e54ea95c6c`.
Together these measurements add eight covered lines and 42 branch outcomes.
`ElfBuildId` now measures 155/156 lines and 134/140 branches;
`SyntheticSourceSidecar` measures 199/200 lines and 154/180 branches.
Critical-group branch deficits remain 1,135 binary/location and 93 file-operation
outcomes. The complete current hosted cohort, protected merge and actual-main
publication are still outstanding.

Across all four production sources changed from PR base `c6265e1`, all 30
changed executable lines and 50/54 branch outcomes are covered (100% / 92.6%).
The latest relocation fix is a subset covering 14/14 lines and 14/14 branches;
its 100% branch figure does not describe the entire PR. Both overall numerical targets are met in this
partial measurement. The critical-group targets and complete hosted cohort
remain unmet. Both critical-group line targets are now met in this partial report;
their branch targets are not.

The file-operation refresh verifies 43 Linux host sessions and 220 build-ID
sessions. It checks real metadata/directory operations, installation/update/
removal, recovery, identity refusal, fresh GDB discovery and command cancellation.
Sixteen deliberate process-halt controls remain unmeasured and are reported
separately. Local privileged visibility is **NOT RUN**. The separately authenticated Linux
CI host artifact now supplies both privileged and unprivileged visibility
results; the verified Windows artifact remains a separate origin.

The expanded measurement also includes 28 native producer-failure sessions
with validated retries, 17 attachment sessions on the limited Linux test host,
one actual interactive Linux GUI session with nine GDB workflows, four raw
Cortex-M3 headless sessions, 29 annotation/equate/source-failure sessions, and
108 inheritance/vtable sessions. The firmware cases validate both input layouts,
41 refusal controls and MSP/PSP runtime behavior. Inheritance tests reject six
structurally valid but behaviorally incorrect object layouts. GUI, firmware and
annotation harnesses restore the cached Ghidra installation after testing.

The latest additions are 104 frame-encoding/composition sessions, four source
relocation sessions, three companion-loader sessions and four ARM32 memory
sessions. Unwind tests cover both address widths and byte orders structurally,
plus real x86-64/AArch64 executable and PIE backtraces with plain, gABI and GNU
compressed original frames. Source relocation checks executable/PIE inputs,
plain/zlib DWARF and 32 debugger scenarios plus source lookup. Companion loading
checks executable, PIE and shared-object mappings and rejects a validator that
prints a diagnostic despite exiting successfully. These source/attachment
fixtures may be preserved historical inputs; measured production Java is the
current JAR. Native-C coverage and a complete hosted cohort are not claimed.

The immutable partial summary is
`stable-memory-hosts-call-mmio-partial/summary.json` in the coverage workspace, SHA-256
`9bdc59b07d982d487f969c6e5f5d1af2cd18585a04d75465d665ea3f7fa489f5`.
It replaces the smaller 1,152-session partial baseline for current progress
reporting. It does not combine execution data from the older production JAR.

## Call-parameter admission and MMIO failure refresh

**CONFIRMED, local:** commit `6d03d027` adds 36 assertions to the existing
call-argument smoke. Real x86-64/AArch64 ProgramDB fixtures reject missing proof,
stale function IDs/addresses, duplicate snapshots, invalid or missing storage
pieces and hidden return carriers. An actual extraction-correction callback
maps two real formals onto one register; both ambiguous arguments must be omitted.
Qualified integers preserve the recovered value, and refusals leave retry results
unchanged. This tests normalized entry evidence without fake Ghidra API objects.

The full smoke passes 612 assertions across its existing 25 decoded instruction
cases. All 240 expression vectors pass the independent DWARF evaluator. Five
compiled faults are detected by behavioral assertions: accepting a stale owner,
accepting duplicate snapshots, assigning overlapping carriers, rejecting qualified
integers and binding a hidden return carrier as an argument. The mutation baseline
also runs the independent vector evaluator; all eight mutation-outcome controls
pass. No production Java or support claim changes. The one measured native-Java
session authenticates source, raw receipt, both 18-check target groups, vectors
and mutation results. `GhidraCallParameters` now has 143/144 measured lines and
108/140 branch outcomes. Remaining decisions are still visible in the report.

The existing x86-64 MMIO reference/export/failure workflows also pass against the
current JAR. Compiler/Forge static GDB values, alias values, GNU/LLVM/strict
validation, deterministic outputs, unchanged input/project/output bindings and
16 cancellation/failure controls are independently rechecked. Deliberately
changed reference bytes are rejected by the value oracle. Only the completed
failure-control analyzer session is newly measured; the positive export is its
validated dependency. This is a file-backed fixture, not real-device access,
LLDB evidence, or a new architecture claim. The isolated Java 21 script cache
avoids incompatible cached classes; the installed JAR, native manifest and
supervisor metadata are restored. The applied admission verifier is authenticated
against the recorded and committed source.

The 1,154-session union adds 37 covered lines and 26 branch outcomes over the
preceding checkpoint. `GhidraMmioProfile` reaches 88/92 measured lines. Critical
branch deficits remain 1,177 binary/location and 93 file/validation outcomes.
All 255 production sources and 901 classes remain in each available view; the
full current hosted cohort, protected merge and actual-main publication remain
unfinished. Evidence under guarded coverage-expansion scratch:
`call-parameter-boundaries-stable-memory/`, `call-parameter-boundaries-mutations/`,
`mmio-stable-memory/` and `stable-memory-hosts-call-mmio-partial/`, with corresponding
run/verify drivers. The intermediate `stable-memory-hosts-call-parameters-partial/`
report is retained separately. Storage is READY at 16.244/100 GiB scratch,
2.200/10 GiB cache and 6.728/10 GiB evidence. No local heavy process remains.

## Target replacement boundaries and stack transition refresh

**CONFIRMED, local:** commits `61862fc0` and `9e95aa3e` extend the existing
`AttachmentTargetStoreSmoke` with 76 assertions, for 139 total. The tests use
actual owned files and the existing limited Linux metadata host. They check
post-replacement byte, metadata and inode changes independently; both replaced
parent directories; rejection of the target itself or a metadata-mismatched
backup as recovery material; exact retained recovery paths; and directory
flushes when source and destination share or do not share a parent. Original
backups remain unchanged and explicit recovery restores the original bytes and
metadata where supported. Existing cancellation and two abrupt process-exit
controls still pass; the halted children are not counted as measured sessions.

Five compiled mutations are detected by behavioral assertions: omitted byte
readback, omitted fingerprint readback, accepting the target as its own backup,
accepting a metadata-mismatched backup, and skipping destination-directory sync.
The metadata-refusal test checks that no restore file was created before checking
diagnostic wording; removing the guard fails on the unexpected file. The baseline
and all eight mutation-outcome controls pass. This is not evidence of privileged
host support or ELF validation, and no production source changes were needed.

The final one-session collection authenticates the committed test source at
`9e95aa3e`, raw receipt, protected JAR, all four new assertion groups and the
mutation logs. `AttachmentTargetStore` now measures 52/53 lines (98.1%) and
22/24 branch outcomes (91.7%). The earlier run is retained separately; only the
final run contributes to the new combined measurement.

Six real stack-value transition profiles also pass on x86-64 and AArch64:
non-PIE, PIE and rebased PIE for each target. Twenty-four headless sessions retain
instruction-by-instruction compiler/Forge GDB observations with signed inputs,
an independent DWARF location-byte oracle, GNU/LLVM/strict validators, saved
model and project checks, deterministic outputs and unchanged protected inputs.
AArch64 runtime checks use QEMU. The driver uses an isolated Java 21 script cache
and restores the installed JAR, native manifest and supervisor metadata. No LLDB
claim is made. The current hosted admission oracle/cohort checks also pass on
these local results; hosted acceptance remains false.

The revalidated 1,152-session union adds seven covered lines and eight branch
outcomes. Critical groups still need 1,203 binary/location and 93 file/validation
branch outcomes to reach 90%. Full current CI, protected merge and actual-main
publication remain outstanding. Evidence in guarded coverage-expansion scratch:
`target-store-boundaries-final/`, `target-store-boundaries-final-mutations/`,
`transitions-stable-memory/` and `stable-memory-hosts-target-transitions-partial/`,
with corresponding run/verify drivers. Storage is READY at 16.186/100 GiB scratch,
2.200/10 GiB cache and 6.728/10 GiB evidence. No local heavy process remains.

## Measured call-site task and calling-convention/signature refresh

**CONFIRMED, local:** the existing `callSitePlanSmoke` ran in the target CI jobs
but was absent from the extension-build measured cohort. Commit `9515363f` adds
it to that job and its required JavaExec receipt inventory. It does not change
production Java, remove a target test or exclude production classes. The fresh
212-task cohort passes in 4 minutes 52 seconds; its production JAR is byte-for-byte
identical to `58bd7a71`. All 901 production classes and 683 current test classes
are authenticated, with a source snapshot at `9515363f`. The 212 fresh sessions
replace the previous 211-session JavaExec baseline in this partial measurement.

The call-site smoke passes all 69 checks, including stale formal identities,
duplicate instruction/return keys, discontiguous owner boundaries, ELF32 return
address limits, hidden return carriers, ordinary recursion versus excluded
self-tail entries, immutable snapshots and stable ordering. Its 60 executable
lines and 86 branch outcomes are now measured. These are Java model/admission
checks; they do not substitute for the separate native/debugger tests.

Nine actual headless calling-convention/custom-storage profiles pass for x86-64
non-PIE, PIE and rebased PIE, including GCC and Windows compiler profiles on the
Linux host. The compiler/Forge GDB comparisons, GNU/LLVM/strict validators,
repeatability, saved model equality and unchanged protected inputs are rechecked
before admitting their 27 sessions. The Windows compiler profile does not imply
a Windows host run. Three additional workflows pass for recovered return types,
recovered parameter types and curated external declarations, adding eight
headless sessions with the same independent validators and debugger observations.
No LLDB evidence is claimed by these runs.

The initial rebased import failed before export because a shared cached script
had Java 25 class-file version 69 while the chosen Java 21 runtime accepts version
65. That incomplete collection and its log/hash inventory remain under
`call-abi-stable-memory/failed-collections` and are excluded from measurement.
Only the three remaining rebased profiles were rerun, using an isolated Java 21
settings/cache directory. All passed. Both drivers restore the installed JAR,
native checksum manifest and supervisor metadata after completion or failure.
The signature refresh also uses an isolated Java 21 cache.

Workflow syntax passes `actionlint`; all nine JavaExec collection-integrity and
11 coverage report/publication controls pass. The complete 212-task run and
independent call-value checker pass. The refreshed union authenticates every
prior admitted raw session and source snapshot again, preserves all 255 sources
and 901 classes in each view, and adds 17 covered lines / 40 covered branch
outcomes overall. It is still a partial cohort with hosted acceptance false.
The critical groups still need 1,205 binary/location and 99 file/validation
branch outcomes to reach 90%. Full updated CI, protected integration and actual
main publication remain required.

Evidence under guarded coverage-expansion scratch:
`call-abi-stable-memory/`, `call-abi-rebased-stable-memory/`,
`signatures-stable-memory/`, `measured-task-refresh-build/`,
`javaexec-measured-task-refresh/` and
`stable-memory-hosts-call-signatures-partial/`. The corresponding run/verify
drivers retain exact commands, source hashes, raw receipts, logs and report
hashes. Storage is READY at 16.116/100 GiB scratch, 2.200/10 GiB cache and
6.728/10 GiB evidence. No extra worktree or local heavy process remains.

## Object bindings, lexical visibility and preservation of saved associations

**CONFIRMED, local:** fifteen object-parameter/return profiles pass against the
current JAR: inferred, explicit, stale, conflicting and aggregate-return cases
for x86-64 non-PIE, PIE and rebased PIE. The 45 measured headless sessions retain
compiler/Forge GDB observations, independent validators, deterministic output,
project-change inventories, failed-source fallback and explicit cancellation
checks. Current object-oracle and full-role admission pass. A separate four-run
lexical fixture passes discontiguous blocks, calls, shadowed locals and partitioned
source, including exact source inventory and compiler/baseline/Forge comparisons.
Both runs restore the cached installed JAR and native metadata. No LLDB execution
or new architecture-support claim follows from these local runs.

Commit `a5df91cd` extends the existing static-association smoke test. Saving an
unknown block in an otherwise valid lexical tree must preserve the old binding;
a defined, loaded overlay object in a different address space must not acquire
an association with the image function. Existing associations remain readable.
All 505 assertions pass on five real ProgramDB language profiles (x86-64,
AArch64, ARM, MIPS big-endian and MIPS little-endian), including saved/reopened
programs, rebasing and cancellation. This adds 45 assertions to the prior suite.
A compiled fault accepting a missing lexical block is detected; the unmodified
baseline and eight mutation-outcome tests pass. Production source is unchanged.

The 50 new measured sessions pass committed harness, raw-receipt, oracle and
protected-input verification. They add fourteen lines and thirty branch outcomes
to the prior matching union. Critical branch deficits remain 1,245 binary/location
and 99 file-operation outcomes. Evidence roots are `object-stable-memory`,
`lexical-stable-memory`, `static-binding-boundaries-stable-memory` and
`static-binding-boundaries-mutations` in the bounded workspace. Full updated CI,
protected merge and actual-main publication remain incomplete.

## Refreshed static recovery and isolated class scopes

**CONFIRMED, local:** the current production JAR passes the existing x86-64
non-PIE lexical/static/recovered-static workflow with 37 measured sessions:
one native producer and 36 actual headless Ghidra runs. The five raw collections
cover ordinary static objects, lexical shadowing, recovered static types and
negative/failure/cancellation controls. Current per-suite and whole-role
admission checks pass, along with exact output pairs, independently retained
GDB observations, structural validation, source provenance and input hashes.
The temporary installed JAR, native manifest and supervisor metadata are restored.

The isolated class-scope producer also passes five variants: normal, failed
source generation, collision, ambiguous binding and unbound collision. Each
artifact passes GNU/LLVM/pinned-libdwarf and DIE-reference checks. Four variants
add 26 cold GDB queries; the failed-source variant retains its separately checked
symbol/type behavior. This contributes one native session and reuses the existing
matching module without copying another build tree.

The refreshed measurements add 56 executable lines and 50 branch outcomes.
`GhidraStaticRecovery` improves to 85/87 lines and 91/116 branch outcomes; the
exporter reaches 1,138/1,206 lines and 626/742 branch outcomes. These results
identify missing measurement against the current JAR; no production or test
source changed in this refresh. Evidence roots are `statics-stable-memory` and
`class-scopes-stable-memory` in the bounded workspace.

The combined report now evaluates changed-code scope against the full PR base,
verified through GitHub as `c6265e1c657c9ffc7a4d9cb71017cca1e1bc5786`, rather than
only the latest exporter-fix parent. Full-PR changed-code coverage meets both the
minimum and preferred targets: 30/30 lines and 50/54 branches (92.6%). Four
remaining changed branch outcomes are in the i386 allocation correction.
Critical-group branch deficits remain 1,269 binary/location and 99 file-operation
outcomes. Complete current hosted acceptance, protected merge and actual-main
publication remain incomplete.

## Validator refusals, sectionless frame validation and MIPS little-endian CI

**CONFIRMED:** commit `30fbf0d0` adds four live negative controls for the
production attachment validator. Replayed tools exit successfully but omit an
LLVM unit check, omit final success, duplicate the success marker, or write a
strict-checker diagnostic to stderr. Each is rejected for the expected reason,
without publishing success evidence or changing protected inputs. These are
explicit faulty-tool controls, not observations that real validators misbehave.
The refreshed attachment bridge passes all 21 measured sessions, actual GDB
association/runtime checks, CRC rejection, commit and rollback. It uses the
documented limited Linux test host, not privileged public attachment.

The current exporter also passes two deterministic exports of an actual
sectionless x86-64 fixture. The live attachment validator corroborates three
inherited-frame diagnostics against the original program-header bytes and
checks its temporary non-loadable frame view with GNU, LLVM and pinned libdwarf.
The view preserves the original payload; the original ELF remains unchanged.
GDB resolves the generated source, resolves the recovered type, advances with
`next`, and exits normally. A second evidence publication is rejected without
overwriting the first. Two native validation sessions are measured; the two
headless exports are behavioral evidence only in this collection. Cached
installed JAR/native metadata are restored. The export script conservatively
refused its own temporary-directory cleanup under the storage guard; the guard
removed its owned per-run temporary directory on completion.

Completed MIPS little-endian job `133915220868` from run `44042799768` passed.
Artifact `14317104428` contains eight matching raw sessions (four headless and
four native), ZIP size 549,795 bytes / expanded 6,248,338 bytes, SHA-256
`ff9c6cba3f68e8d2712f07f70a0f4876b673fc689b9dc88da90bdce0a649c648`.
API-authenticated job/source tree, committed harness hashes, raw receipts,
current per-suite behavioral admission and exact report regeneration pass.
Whole-job admission correctly rejects the older artifact because it lacks the
new `context-boundaries` suite. It remains partial evidence, not an updated-gate
pass. The verified origin digest is
`614555a2e2372e26d8db16214ad7b2f204406bb2440d8206fa26a641d8bf6a97`.

The resulting 1,003-session union adds sixteen lines and ten branch outcomes to
the previous report. Critical branch deficits remain 1,319 for binary/location
correctness and 99 for file operations. Evidence roots are
`sectionless-validation-stable-memory`, `attachment-validator-boundaries-stable-memory`
and `hosted-mips32le-44042799768` in the bounded workspace. Current hosted
acceptance, protected integration and main publication remain incomplete.

## Composite lifetimes across decoded body gaps

**CONFIRMED, local:** commit `bc3650c7` adds four actual decoded ProgramDB
fixtures: x86-64, AArch64, ARM little-endian and ARM big-endian. Each jumps over
a non-body gap into a small loop. Two unchanged incoming register pieces must
retain memory order and exact executable intervals on either side of the gap.
The proof must neither emit a gap interval nor merge equal locations across it.
Foreign program/function/storage, absent or invalid storage, single-piece
storage, stack-pointer pieces and explicitly unmapped registers are refused.

The new fixture passes 1,088 assertions, alongside the existing 1,032 composite
flow checks. Cancellation is exercised at every observed checkpoint: 112 each
for x86-64/AArch64 and 137 each for the two ARM profiles (498 total). Every
cancelled proof permits an identical retry; machine bytes, function body and
attached storage remain unchanged. These are decoded API tests, not new runtime
architecture-support claims.

Two compiled faults are detected by exact interval assertions: emitting an
unavailable interval inside the body gap and coalescing equal locations across
the gap. The original baseline and eight mutation-outcome tests pass. No
production source changed. The added measured session passes committed-source,
raw-receipt and oracle verification, with only the two test classes excluded.
It adds three lines and eleven branch outcomes to the prior matching union.
`CompositeValueFlow` now measures 87/87 lines and 86/114 branch outcomes. Critical
branch deficits remain 1,321 for binary/location correctness and 107 for file
operations. Full current hosted acceptance and publication remain incomplete.
Evidence: `composite-boundaries-stable-memory` and `composite-boundaries-mutations`
in the bounded coverage workspace.

## Owned canary safety and multi-file build-ID refresh

**CONFIRMED, local:** commit `dc12574c` extends the actual Linux metadata
visibility smoke test. It rejects five invalid nonce lengths and three owned
file states (nonempty, hard-linked and non-private), checking that rejected
files retain their bytes and metadata. An explicit input-policy matrix rejects
158 unsupported inode-policy values and accepts the documented ordinary flags.
These policy values are test inputs, not claims about features on this host.
The full unprivileged run passes 359 checks. No local privileged run is claimed.

Four separately compiled faults are detected by behavioral assertions: bypassed
canary link checks, and accepted extent-size, project-ID or copy-on-write extent
policies. The unmodified baseline and eight mutation-outcome harness tests pass.
This new session excludes only the compiled test class from instrumentation;
all production classes remain in the report population.

The existing x86-64 non-PIE multi-file exporter workflow also passes against the
same production JAR. Both single/multi-file outputs pass strict libdwarf and
LLVM validation and ten GDB observations each. Source-bundle binding and build-ID
installation contribute eighteen authenticated native sessions. The binding
controls use their documented test metadata host; installation uses the actual
Linux build-ID host. Installed cached exporter files were restored after the run.

Both collections pass source-snapshot, raw-receipt and oracle verification before
admission. Together they add thirteen lines and eighteen branches to the prior
952-session report. File operations now need 107 additional branch outcomes to
reach 90%; binary/location correctness still needs 1,332. Full current hosted
acceptance, protected integration and actual-main publication remain incomplete.
Evidence is under `metadata-canary-stable-memory`, `metadata-canary-mutations`
and `build-id-multifile-stable-memory` in the bounded coverage workspace.

## Authenticated Linux-host and partial MIPS CI measurements

**CONFIRMED:** completed `extension-build` job `133902228908` from run
`44042799768` passed. Artifact `14311029718` contains 45 matching native-Java
sessions: 39 file-metadata, one directory-sync and five metadata-visibility
sessions. Both privileged and unprivileged visibility checks passed. This is
isolated host-component evidence, not public attachment acceptance.

The ZIP is 277,431 bytes (3,164,153 extracted bytes), SHA-256
`2f0709a31cd3af905643eb494cc3801b7cba1890266012b9da363c2d37435542`.
Download digest, bounded extraction, run/job/source-tree identity, raw receipt
hashes, current admission checks and exact regenerated report/README all passed.
These older host receipts do not carry harness hashes: harness provenance was
instead checked against the API-authenticated merge tree and completed job's
source-build workflow. The first verification attempt stopped because the merge
revision was unavailable locally; the successful check uses locally available
head blobs and verifies each against the authenticated merge-tree blob ID.
No failed attempt contributes measured sessions.

Completed MIPS big-endian job `133915220959` also passed. Its artifact
`14316685268` contains four headless O32/N32 truncated-space sessions and four
native memory-location sessions. Current behavioral admission checks and exact
report regeneration pass, as do committed harness hashes. The 549,739-byte ZIP
has SHA-256 `0a0eb5e07bb2ddbe5609f9ef4c05175574c8a87f522a4108db683d19fcf2d56b`.
It is deliberately admitted as **partial** evidence: current whole-job admission
rejects it for lacking the newly added `context-boundaries` suite. The policy was
not weakened, and the old job does not satisfy the updated hosted gate.

The combined 952-session measurement includes these 53 distinct sessions with
unchanged production bytecode and denominator. Linux-host evidence adds 119
lines and 40 branches; MIPS adds one further branch. File-operation line coverage
now meets 95%, while both critical groups still miss their 90% branch target.
Evidence is under `hosted-linux-host-44042799768` and
`hosted-mips32be-44042799768` in the bounded coverage workspace.

## Refreshed instruction context, qualified types and namespace lookup

**CONFIRMED, local:** five fresh measured JVMs reran the existing instruction/
source-context pipeline against the current production JAR. Read-only saved
program observations, byte and instruction bounds, repeated output and staged
cancellation passed; the cached installation was restored afterward.

`context-boundaries.py` now uses the standard opt-in collector for its import and
two repeated headless runs. Its receipt is finalized only after the existing
structural and debugger checks pass. ARM32 and both MIPS byte orders passed,
adding nine authenticated sessions and ten compiler/Forge QEMU-GDB workflows.
Tests cover ARM/Thumb context, full MIPS delay slots, gaps and partial bodies,
real native decompilation failure, deterministic outputs and preserved input/
project state. GNU/LLVM/strict validators pass with only the harness's explicitly
corroborated compiler warnings permitted. The checked harness snapshot is
`30db26c0`. CI and hosted cohort admission now require this suite on all three
targets (`933306ca`); 61 existing admission tests and actionlint pass. Hosted
execution of the new requirement remains unverified.

The qualified-type producer refresh adds one current native session, with
compiler/exported GDB type/value checks plus symbol-only and source-only output
checks, independent validators and input preservation. The namespace/global
refresh adds 16 native sessions across x86-64 and AArch64: eight variants each,
cold debugger lookups, compiler/selected runtime checks, independent validators,
artifact hash checks and restored packaged-library metadata. This refresh does
not claim LLDB coverage or rerun historical mutation checks.

Raw receipts, committed harness hashes, unchanged production bytecode and local
admission checks passed for all four refreshes. Evidence directories are
`context-stable-memory`, `context-boundaries-stable-memory`,
`qualified-type-stable-memory` and `namespace-stable-memory` under the bounded
coverage workspace. The combined 899-session report adds 86 lines and 107
branches over the 868-session baseline, with unchanged production denominators.
Critical-group targets, complete hosted acceptance, merge and main publication
remain outstanding.

## AArch64 composite allocation and cancellation boundaries

**CONFIRMED, local:** the expanded `Aarch64ParameterAllocationSmoke` passes
1009 assertions using actual pinned Ghidra programs. Its 48 new composite cases
cover sizes 1 through 24 with and without saved typedef wrappers. After seven
integer arguments, the oracle requires 9–16-byte composites wholly on the stack,
with the following integer at offset 16. Smaller composites remain in the final
argument register; larger ones use an indirect pointer, with the next integer
at stack offset zero. Saved signatures/storage remain unchanged.

Staged cancellation reaches 25 internal checkpoints. Every cancelled attempt
leaves the saved signature intact and allows an identical successful retry.
Three compiled mutations (dropping typedef resolution and excluding either the
9-byte or 16-byte boundary) fail behavioral assertions. The unchanged baseline
and mutation classification tests pass.

The guarded final collection `aarch64-boundaries-stable-memory-final` records
committed harness `4934bae5` and unchanged production JAR. Two preliminary helper
compilations failed on the typedef API spelling/constructor; neither generated
an admitted session. Final collection validation and combined regeneration pass.
This adds one line and three branches, bringing the current partial to 868
sessions. These compiler-model tests do not replace AArch64 runtime/GDB checks.

## Saved class and vtable evidence boundaries

**CONFIRMED, local:** `ClassEvidenceBoundarySmoke`, called by the existing
`classScopeModelSmoke` task, adds 155 assertions. These check malformed saved
identities, a cross-product of class owner / explicit-versus-inferred binding /
ABI, hash and text bounds, address and file extent overflow, the 4096-table
limit, deterministic ordering and immutable snapshots. The existing 51 class
scope assertions also pass. No production code changed.

Four compiled mutations are detected by behavioral assertion failures:
accepting inferred ownership, ignoring ABI disagreement, and suppressing either
address or file-offset overflow. Both unchanged production baselines and the
mutation outcome classification tests pass. These model checks do not claim
original-ELF identity validation or debugger behavior.

The `class-evidence-stable-memory` collection records the frozen production JAR,
raw JaCoCo receipt and committed test snapshot `42dc9c1c`; its test classes are
excluded from measurement. The checked collection and combined-report drivers
passed through the storage guard. Adding this session covers one previously
missed line and 43 branches without changing any denominator. `ClassScopeModel`
has 133/134 lines and 145/146 branches covered; `VtableEvidence` has 11/11 lines
and 42/42 branches. That checkpoint contained 867 combined sessions.

## Matching Windows artifact and completed host job

**CONFIRMED:** run `44042799768` published Windows coverage
artifact `14313128001` (414,544 compressed bytes; 3,524,218 extracted bytes).
Its SHA-256 is
`a89ce2752893028e046e9b8f7c49c8f0a60c0abb45480fc15ac05379afa5a8e4`.
The 57 sessions use the exact current `58bd7a71` production JAR and cover
Windows attachment, build-ID installation/recovery and host primitives.

Raw execution validation, current admission controls, committed harness hashes
(including the recorded Windows CRLF transformation), and regenerated coverage
counters all pass. The artifact's source is PR merge commit
`4d3960f95ae97c433d204a7d6b383ad62018e109`, whose parent includes branch head
`9e0cc53a79f3a20394da831cd270deefa42375ef`. The entire Windows job `133916861927` subsequently completed successfully,
including its remaining formatter, GUI and clean installed-release checks.
The 57 sessions are now included in the partial summary above. Adding them
contributes 689 covered lines and 400 branches relative to the Linux-only
808-session report. This does not establish a passing full architecture gate;
ARM32 failed dependency setup and the other target lanes remain in progress.

Evidence is in `hosted-windows-44042799768/`, including `artifact.json`, the
bounded ZIP, source-tree authentication, regenerated report and
`raw-verified.json` and final `verified.json`. Its independently verified
865-session union has summary SHA-256
`254668536b7dff95cae1073b538d7fbe592dad16d871c8de401c42781e3e7876`.
No old-production Windows execution data is reused.

## Finite lexical visibility oracle

**CONFIRMED, local:** `LexicalScopeBoundarySmoke`, called by the existing
`lexicalScopeModelSmoke` task, checks all 12,096 combinations of six-address
visibility/storage masks at three address bases, including above 32 bits and
near the signed-address ceiling. It compares each output address against an
independent pointwise oracle, checking exact scope visibility, preserved storage
and provenance, unavailable gaps, immutable input and idempotence. Malformed
saved identities, missing entry/owners and ambiguous local ownership are refused.

The oracle passes 267,867 assertions, alongside 105 existing lexical/range-byte
checks. Two compiled controls detect an extended location endpoint and a missing
unproved prefix. The latter initially survived a matrix with singleton visibility
ranges; the final matrix includes contiguous visibility extents with interior
proof gaps and detects both faults. The unchanged-source baseline passes.

Sources are committed at `8de94232`. Final raw execution and verified receipt
are in `lexical-boundary-stable-memory-verified/`; mutation evidence is in
`lexical-boundary-mutations-verified/`. This adds one covered line and 19 branches:
`LexicalScopeModel` now has 88/88 lines and 93/96 branches in the combined report.
This is model and range-encoding evidence, not a new runtime debugger claim.

## Attachment paths changed during commit and recovery

**CONFIRMED, local:** the expanded `AttachmentTransactionSmoke` passes 1,293
assertions. Eight additional cases cover initial and refresh operations when
the real target parent is replaced after preparation or target replacement,
and when an installed target is replaced by a directory or dangling symlink.
The parent cases retain the file inodes, content and modeled metadata beneath
a new parent inode, so file-only checks cannot stand in for traversal identity.

The controller reports `RECOVERY_REQUIRED`, preserves original/prior backups,
leaves foreign objects untouched and avoids writing a restore image through a
changed parent. An unobservable target has no reported snapshot. Two compiled
mutations are caught by outcome/snapshot assertions: ignoring the commit's
parent check reports `COMMITTED`, while substituting the original snapshot for
an unobservable current target fabricates an observation. Both unchanged-source
baseline and eight mutation-outcome classification checks pass.

This uses the existing limited Linux test metadata host with real owned files;
it does not claim a validated production native host, Windows or ELF/DWARF
validation. The suite's eight deliberate child-process exits remain unmeasured.
Sources are committed at `3657242c`. Raw execution, snapshots and verified
receipt are in `transaction-path-stable-memory/`; selected mutation evidence is
in `transaction-path-mutations-verified/`. The preceding exploratory mutation
that removed a recovery check was detected only through its diagnostic and is
not part of this selected pair. Coverage gains are three lines and four branches
in file transactions, with no production or denominator changes.

## Saved parameter provenance and character layout

**CONFIRMED, local:** the expanded `CuratedTypeBoundarySmoke` passes 469
assertions through the existing floating-layout task, whose 73 checks also pass.
Seven real Ghidra language/compiler profiles cover x86-32 GCC/Windows, x86-64,
AArch64, ARM32 and both MIPS32 byte orders. Windows here describes a target
compiler model on Linux, not execution on a Windows host.

For every profile, five saved parameters exercise USER_DEFINED, IMPORTED, AI,
ANALYSIS and DEFAULT sources. Extraction preserves their names, available
register storage and exact confidence labels. A selected function with no saved
signature produces a diagnostic instead of an invented signature. Character
signedness/width follows the target data organization. Extraction leaves the
saved program unchanged. Four compiled mutation controls detect changed AI or
imported provenance, inverted character signedness and a hidden missing-signature
diagnostic; the unchanged-source baseline passes.

Sources are committed at `d7f873e5`; `type-evidence-stable-memory/` holds the raw
session, verified receipt and source snapshots. `type-evidence-mutations/`
records the four controls. This adds five covered lines and four branches over
the preceding partial report, with no production change or denominator change.

**CONFIRMED CI failure:** run `44042799768`, ARM32 job `133915220887`, failed
`prepareHeadlessCoverage` because Maven Central returned HTTP 429 for the pinned
JaCoCo 0.8.16 POM. Its isolated producer checks passed before coverage setup.
The workflow now gives Linux target and Windows coverage preparation the same
three-attempt limit used by extension-build, waiting 15 then 30 seconds. Only
dependency preparation is retried; test failures remain failures. Actionlint and
four Linux command-control cases pass, including permanent-failure propagation.
PowerShell retry execution and the hosted retry remain **PRESENT, UNVERIFIED**.

## Conditional transfers and saved delay-slot references

**CONFIRMED, local:** `ClosedFlowBoundarySmoke`, invoked by the existing
`outsideBodyFlowSmoke` task, passes 16 real ProgramDB cases and 122 assertions.
ARM cases distinguish ordinary and conditional returns, direct and conditional
calls, and computed calls. MIPS cases cover both byte orders, data references
and saved jump/call references attached to a decoded NOP delay slot. Assertions
check the control-flow proof, public stable-parameter availability, and proof
recovery after removing saved references. No fake instruction objects are used.

The complete measured task also passes 17,419 existing entry-contract checks
and 85 outside-body checks. This adds one covered production line and four
covered branches to the preceding partial report; rounded percentages remain
unchanged. The production JAR and all denominator entries are unchanged.

Two compiled controls in `mutation-check.py` prove that removing terminal-flow
validation or ignoring saved delay-slot references triggers the intended Java
assertion. The unchanged-source baseline passes, and compilation/class-loading
failures do not count as detection. They run in the normal Ghidra-enabled
mutation suite; `--only closed-flow-accepts-conditional-return --only
closed-flow-ignores-slot-references` selects this pair and its baseline for a
focused local replay. All eight mutation-outcome classification checks pass.

Evidence: `closed-flow-stable-memory/` contains the raw execution data, source
snapshots and verified receipt; `closed-flow-mutations/result.json` records both
controls. Test sources are committed at `1f6db49c`. The existing JavaExec data
remains attributed to its original source snapshot, while this new native-Java
session records the expanded tests. This is control-flow/storage evidence;
it does not claim a new ELF export or runtime debugger validation.

## Stable and listed memory locations under PIE relocation

**CONFIRMED, local:** `stable-location-pie-verified/` passes twenty profiles
against the unchanged production JAR `58bd7a71`: the four stable/listed and
direct/indirect forms on x86-64, AArch64 and both MIPS byte orders, plus all four
forms on an x86-64 PIE executable. Forty compiler/Forge GDB workflows check the
program counter, object address, type size and live value at two instruction
boundaries. PIE checks require a nonzero runtime load bias and the expected
relocated object address. The indirect cases read through a loader-relocated
pointer. The fixture changes its value from 42 to 43; its original constant-only
form let GCC emit `DW_AT_const_value`, which was insufficient evidence of a live
memory read. No production change was needed for PIE.

Every profile passes GNU, LLVM and strict-libdwarf validation, deterministic
reruns and original-input preservation. Strict validation retains the existing
policy for byte-identical inherited-frame diagnostics. The MIPS cases retain
32 address-overflow refusals and validated retries in total. Both selected
compiled mutation faults are detected with the revised fixture; compilation or
class-loading failure is not accepted as detection. All 304 coverage-policy
tests and workflow lint pass.

CI now requires the four x86-64 PIE cases as well as the existing executable
cases on all five targets. Admission checks the ELF role and two runtime address
checks per debugger, rejecting missing or duplicate profiles. ARM32 is now
verified locally using a checksum-verified Ubuntu cross toolchain extracted
under the shared cache, without changing system packages. The four ARMv7-A
ARM-state hard-float profiles pass eight compiler/Forge QEMU/GDB workflows,
sixteen overflow refusals with retries, structural validators, deterministic
reruns and input preservation. The harness explicitly selects that instruction
profile and accepts a runtime sysroot for cached toolchains. A separate compiler
default-mode check also selected ARM state; this is fixture normalization, not
a reproduced product bug. These tests use
an explicit fixture model through the real native exporter; they do not claim
Ghidra variable-extraction coverage or a completed combined coverage goal.

The twenty native sessions are independently authenticated against committed
harness snapshot `652fe943` and matching production classes. Their local manifest
is `stable-location-pie-verified/measurements.json`, SHA-256
`ea2b3af6de42318365bdfe8874dc22a75d66a033d9e998cba25e5d34da4b28bf`.
Hosted acceptance is still pending; this measurement does not supply Windows
or the rest of the required integration cohort.

**CONFIRMED:** the earlier hosted run `44024881065` failed its AArch64 isolated
function-relationship scenario during Java compilation. A local reproduction
reported the missing `ScopeRelationshipBoundarySmoke` helper. Its explicit
source list now includes that dependency. The complete scenario passes locally
against the current production JAR for x86-64 and AArch64, both executable and
PIE: twelve compiler/plain/related GDB workflows and twenty-eight native exports
with structural validation, serialization rejection controls and preserved
inputs. This run is behavioral evidence, not an additional measured Java session.

## Stable memory locations: regression found and corrected

**CONFIRMED:** extending the native location fixture to one stable interval exposed
a valid-export failure. The producer created a relocation for a local variable's
absolute memory address, but the relocation validator expected only function,
scope, call-site and global/static-object addresses. The original JAR rejected
the valid MIPS fixture with `producer address relocations do not match requested
functions, scopes and objects`. The retained reproduction is
`stable-location-mips-pilot-4bd11/producer.stderr` in the coverage workspace.

The validator now includes addresses from the exact variable expressions that
were emitted. It excludes omitted and list-based locations, whose bytes are
handled separately. Stable address operands are checked against the target
pointer width before passing them to libdwarf; oversized direct and indirect
32-bit addresses fail without replacing an existing output or leaving a partial
final artifact. No JNA signature, native dependency or default input behavior
changed.

**CONFIRMED, local:** `stable-location-verified/` passes sixteen profiles:
x86-64, AArch64, MIPS big-endian and MIPS little-endian, each with stable/listed
and direct/indirect memory. Every profile validates the real sidecar with GNU,
LLVM and strict libdwarf, checks compiler and exported values in GDB (QEMU for
cross targets), repeats production deterministically and preserves inputs.
The MIPS profiles additionally reject 32 oversized-address exports across both
output-present and output-absent cases, then retry successfully. These explicit
compiler fixture models test native serialization, not Ghidra extraction.
ARM32 was unverified at that earlier checkpoint. Its four forms are now verified
locally with the cached compiler/runtime described above and remain in CI.

Both compiled mutation controls pass: removing the stable relocation expectation
or the width check triggers the specific regression assertion; compilation,
loading errors and native crashes do not qualify. Mutants are unmeasured and
their temporary compiled files are removed. Coverage-policy tests pass 304
checks; `actionlint` and `git diff --check` pass. The location-emission,
location-list and variable-storage Java checks pass. An additional invocation
of `indirectStorageSmoke` stopped at setup because its required fixture/native
Gradle properties were not supplied; it is not reported as a passing test.

The corrected production JAR is
`58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`.
**The preceding 96.0% / 83.9% combined measurement is now historical for JAR
4bd11717.** Those raw exporter probes must not be presented as coverage of this
changed bytecode. A fresh JavaExec baseline and matching integration/host data
are required; current full combined coverage and hosted acceptance are
**UNCERTAIN**. The full denominator and all original targets remain unchanged
as policy. Pipeline reporting now requires all four location forms on each of
the five targets, with ARM32 retained as a separate measured origin.

The fresh baseline at source commit `86b5a34b` is now **CONFIRMED** locally:
all **211 measured JavaExec tasks** passed (4m43s), followed by sixteen native
location profiles, the callable metadata fixture, and eight real headless
exports across x86-64, AArch64 and both MIPS byte orders. The latter retain
compiler/Forge GDB bit-field values and restore the prior cached installation.
The two native fault mutations pass their behavioral assertions. Source hashes,
artifact receipts and every raw class/session identity were verified before
combining these **236 current-JAR sessions**. No historical-JAR probes are used.

The local partial measurement is **25,014/29,802 lines (83.9%)** and
**19,609/25,902 branches (75.7%)**. Binary/location correctness is 91.6% lines /
79.8% branches; file transactions/validation is 69.0% / 65.7%. These are not
comparable to the preceding broader union: current Windows and most integration
origins remain absent. All 255 production sources and 901 classes remain in
each measured view, including the unexecuted Windows classes. The fix itself
has **14/14 changed executable lines and 14/14 branches covered**, meeting the
changed-logic gate. Full issue #209 acceptance remains incomplete.

The strict checker reports two inherited compiler-frame alignment diagnostics
on x86-64 and five on AArch64; MIPS has none. Verification compares the original
and sidecar `.eh_frame` bytes, complete section identity and exact diagnostic
sets, and reruns the checker's log assertions. No uncorroborated error is
accepted. A first local verifier incorrectly demanded zero total diagnostics;
it was corrected to enforce this existing corroboration policy. The hosted
reporter also refused to construct a complete report without current Windows
data. Its requirements were preserved; the separate local audit explicitly
records four measured views and no Windows origin, with publication disabled.

Evidence: `stable-location-verified/`, `stable-location-mutations/`,
`javaexec-stable-memory-baseline-64/`, `callable-type-stable-memory/`,
`bitfields-stable-memory/` and `stable-memory-baseline-verification/` in the
bounded workspace. The latter's `report/summary.json` has SHA-256
`10067ce11c259d76c9f5a51a9eaa3b2583de8b954a838512763c24ade0479d2b`.
Local verification processes are terminal; storage is READY at
14.104/100 GiB scratch, 2.059/10 GiB cache and 6.728/10 GiB evidence. The headless
fixture deletes its owned projects, and mutation compilation directories were
removed. Hosted run `44024881065` now has thirteen passing jobs (both MIPS lanes
included), three running architecture jobs, and no failures observed; it still
predates this fix and does not prove current-head acceptance.

## MIPS STORE regression measurement

**CONFIRMED:** the existing freestanding O32/N32 integer STORE regression now
supports opt-in per-export coverage without changing its fixtures or oracle.
Local run `85546` passed for big- and little-endian MIPS: four source-built
fixtures, eight measured exporter JVMs, compiler and Forge QEMU/GDB observations,
GNU/LLVM/strict validation, identical repeated sidecar/source bytes, and unchanged
protected inputs. The original installed JAR and native metadata were restored.
This remains a bounded ET_EXEC integer-storage test, not a broader N32 libc,
floating-point, PIE/shared or debugger-call ABI support claim.

The wrapper leaves initial analysis unmeasured and instruments the curated and
read-only repeated exports separately. New admission checks require both ABIs,
all four exporter sessions, compiler/Forge values and normal exits, zero strict
errors, artifact hashes and harness provenance. Each MIPS CI lane now reports
its own cohort. Both cohorts are required by combined reporting and publication;
one endian lane cannot substitute for the other. Coverage source inventory and
targets are unchanged. No production Java code changed.

Validation: guarded full coverage-policy suite passed **301 tests**; after adding
the hosted-lane substitution/omission test, the focused suite passed **six tests**.
`bash -n`, `actionlint` and `git diff --check` passed. Raw execution data is retained
under `mips-truncated-current-4bd11/` in the bounded coverage workspace. New hosted
collection remains **PRESENT, UNVERIFIED** until CI runs
this revision. Run `44024881065` still has eleven passing jobs and five live
architecture lanes; it predates this change and has not been cancelled.

Guarded verification `55718` passed against source snapshot `7fa5b0d6` and JAR
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.
It checked source hashes against committed blobs, artifact/oracle bindings,
native/script restoration, the existing 1,292 raw sessions and the eight new
sessions before regenerating all five coverage views. Each view retains all
255 production sources and 901 classes. The verified partial union is now
**1,300 sessions**: 211 JavaExec, 638 native-Java, 394 headless and 57 Windows.

Combined results are **28,609/29,792 lines (96.0%)** and **21,732/25,888 branches
(83.9%)**. The MIPS regression adds one branch to the preceding union. Binary
and location correctness is **18,506/19,203 lines (96.4%)**, **15,641/18,736
branches (83.5%)**; file transactions and validation remain **6,377/6,677 lines
(95.5%)**, **3,714/4,250 branches (87.4%)**. Each critical 90% branch target is
still unmet. `hostedAcceptance` and `completeCombinedCohort` remain false.

The union is `mips-truncated-refresh-4bd11/summary.json`, SHA-256
`c0edf50f3878c69b6bf11d3ab3cb4da2ff16cba93935aeff8c8d873b8cbf4a30`.
After verification, guarded cleanup `48223` removed only the four owned fixture
projects (4,526,152 bytes), preserving hashes of 1,077 retained files including
all eight raw sessions, fixture artifacts, source snapshots and debugger logs.
Scratch/cache/evidence usage is 13.923/2.059/6.728 GiB, within the 100/10/10 GiB
budgets. No additional worktree or `/dev/shm` workspace was created.

## Verified Windows measurements and callable producer behavior

**CONFIRMED:** Windows-host job `133854290162` passed in
[run 44024881065](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44024881065).
Its authenticated coverage artifact `14304952661` has SHA-256
`73b7c95c3a05cf73fa2ec60edff6f6f17226c18372041947d33519d98242fa2c`;
the 414,396-byte download expands to 3,523,735 bytes. Its production JAR exactly
matches the current local measurement. The verifier checks the successful job,
CI merge commit `35630411a00470eeb2a72149823494e23b180222`, source tree, native
Windows test-source hashes (including the checkout's CRLF transformation),
collection hashes, current behavioral admission policy and production class IDs.
Regenerating the Windows report reproduces its counters and report contents.

The 57 Windows sessions cover host primitives, attachment and build-ID
installation. Actual Windows APIs are exercised with controlled failure replies
for metadata, directory sync, security, backup streams and privilege readback;
the receipts retain handle-count and state-preservation checks. Fourteen deliberate
process halts remain behavioral evidence only: they do not contribute fabricated
JaCoCo sessions. Nested lock contenders remain explicitly unmeasured. The
Windows GUI job passed, but this artifact's coverage scope remains the three
named suites. No GUI coverage is inferred from the job's success alone.

**CONFIRMED:** `86158ec3` adds an explicit C callable fixture through the production
native exporter. Three deterministic variants preserve variadic function and
function-pointer types, unnamed parameters, and address-free `noreturn` external
declarations with normal, unknown and explicitly blocked calling conventions.
Compiler-reference and exported-artifact GDB runs check pointer targets, sizes,
signatures and program execution; GNU readelf, LLVM and the strict standalone
checker accept every variant. Twenty-one parsed-DIE corruption controls and three
separately compiled producer faults are detected. This tests serialization of an
explicit fixture model, not recovered parameter locations or injected-call ABI
support. Native library/JAR/source/input hashes and raw probes are retained.

CI requires this suite and its evidence; 82 admission/hosted-report/publication
unit tests and workflow lint pass. The ordinary Gradle test compilation passes.
No production bytecode changed. The new suite adds two covered lines and eight
branches before incorporating Windows; Windows contributes another 689 lines and
400 branches. The verified combined report is
`.forge-work/scratch/coverage-expansion/hosted-windows-44024881065/union/summary.json`,
SHA-256 `5716a0ad77ebe093e9ceb16708e90c6cde32aa75c25817e110be886a6f587b40`.
Its 1,292 sessions comprise 211 JavaExec, 638 native-Java-path, 386 headless and
57 Windows sessions. Each view retains all 255 production sources / 901 classes;
production JAR SHA-256 remains
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 28,609/29,792 (96.0%) | 21,731/25,888 (83.9%) | 85% / 80% |
| Binary/location correctness | 18,506/19,203 (96.4%) | 15,640/18,736 (83.5%) | 95% / 90% |
| File transactions/validation | 6,377/6,677 (95.5%) | 3,714/4,250 (87.4%) | 95% / 90% |

**INCOMPLETE:** both critical groups still require 90% branch coverage. The full
architecture/role inventory, privileged Linux attachment measurements, validation
of the queued commits, protected merge and actual-main publication remain open.
This mixed-origin report has `hostedAcceptance=false` and
`completeCombinedCohort=false`; it does not replace the published badge. The
architecture jobs in the current earlier-head CI run are still advancing.

## Earlier line-program boundaries and ARM aggregate shapes

**CONFIRMED:** `fea5d401` extends the existing line-table smoke task with 900
complete program decodes. Expected rows are derived from the supplied source
evidence, including forward/backward signed line changes around LEB128 limits,
line zero, large line numbers, high ELF32/ELF64 addresses, both byte orders,
discontiguous sequence reset and exact end addresses. Reordered evidence must
produce identical bytes. Tests also reject invalid filenames, duplicate partition
names, mismatched partition counts, negative positions and unsupported address
widths, and verify that returned bytes and file tables cannot mutate the result.
Five separately compiled faults fail behavioral assertions: unsigned line deltas,
premature signed-LEB termination, address truncation, embedded NUL acceptance and
mutable section bytes. The ordinary `dwarfLineTableSmoke` task passes in three
seconds. These are encoder tests, not additional end-to-end debugger claims.

**CONFIRMED:** `7e602fe8` extends the actual Ghidra ARM aggregate allocation test
with 144 array and typedef scenarios. Both byte orders and audited conventions
cover register-only, register/stack split and exhausted-register allocations.
The independent byte-placement oracle remains unchanged. New checks preserve
formal types and saved storage through cancellation, variadic refusal and retry;
explicit analyst storage remains authoritative. The isolated and ordinary
`armCompositeParameterAllocationSmoke` runs pass 2,592 checks; the Gradle task
takes four seconds. Three faults are detected using only the new scenarios:
skipped typedef unwrapping, skipped array correction and variadic correction.
This tests existing allocation policy without extending runtime ABI claims.

No production code changed. Mutant bytecode is excluded from coverage and was
removed. Source snapshots, test classes, logs and raw session receipts bind both
successful measurements to their committed tests. The current verified partial
union is `.forge-work/scratch/coverage-expansion/arm-composite-shapes-refresh-4bd11/summary.json`,
SHA-256 `58c9988892b5fc38e16d515d3985db628b310366e30567057a33f84bb73a6c3c`.
All 255 production sources / 901 classes remain included, against production JAR
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.
The 1,234 sessions comprise 211 JavaExec, 637 native-Java-path and 386 headless
sessions. These additions cover three more lines and seventeen more branches.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 27,918/29,792 (93.7%) | 21,323/25,888 (82.4%) | 85% / 80% |
| Binary/location correctness | 18,504/19,203 (96.4%) | 15,632/18,736 (83.4%) | 95% / 90% |
| File transactions/validation | 5,688/6,677 (85.2%) | 3,314/4,250 (78.0%) | 95% / 90% |

**INCOMPLETE:** critical-group thresholds, fresh Windows and remaining complete
hosted measurements, protected integration and actual-main publication are still
required. CI `44024881065` is advancing on the earlier remote head `1437e340`;
these local test commits require their own validation before integration.

## Earlier stack coordinates and actual ARM literal memory effects

**CONFIRMED:** `208efbca` adds `StackCoordinateProjectionSmoke`, invoked by the
existing `truncatedStackDepthSmoke` Gradle task. Its 13,483 checks independently
evaluate effective addresses with BigInteger across eight existing register maps,
including signed displacement limits, unknown-depth intervals, instruction gaps,
missing register mappings and immutable inputs/results. This tests the coordinate
stage's contract; it does not claim those arithmetic extremes arise in recovered
programs or establish new target support. The isolated and Gradle runs also pass
the existing 996 decoded MIPS stack-depth checks. Six separately compiled faults
are rejected by the new assertions: reversed displacement, wrapped overflow,
invented known depth, altered interval bounds, mutable results and a hard-coded
stack-register name. Mutated bytecode is not measured and was removed.

**CONFIRMED:** `b9bdd725` extends `mixedParameterPrefixSmoke` with four actual
ARM little-/big-endian decoded cases. A PC-relative store ends the conservative
mixed register/stack prefix; a load into an unrelated register preserves it.
Assertions check the independently calculated literal address in raw p-code and
the listing's write result, along with the existing byte/parameter preservation,
cancellation and ownership controls. The isolated and Gradle task pass 364
checks. Two compiled faults are caught by the new literal cases alone: ignoring
the listing's fixed-address write, and treating a load as a write.

The first literal test incorrectly expected reference-table entries immediately
after disassembly. An unmeasured probe established that this decoder exposes the
literal address in p-code and result objects while the reference table is still
empty. The corrected test asserts those actual contracts; the failed collection
is excluded and retained for diagnosis. No production behavior was changed.

Each Gradle task passes independently in six seconds. Production JAR SHA-256
remains `4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.
The verified partial union is
`.forge-work/scratch/coverage-expansion/stack-literal-refresh-4bd11/summary.json`,
SHA-256 `4cd2084de3e4419cef621ba2e9d27b7ee6ffea3483e94c4e3b9c12475795be9b`.
Its 1,232 sessions comprise 211 JavaExec, 635 isolated Java/native-path and 386
headless sessions, with all 255 production sources and 901 classes included.
The new tests add seven covered lines and eleven branches over the preceding
1,230-session report. Individual receipts bind the tested source snapshots,
committed harness versions, compiled test classes, mutation outcomes and raw probes.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 27,915/29,792 (93.7%) | 21,306/25,888 (82.3%) | 85% / 80% |
| Binary/location correctness | 18,501/19,203 (96.3%) | 15,615/18,736 (83.3%) | 95% / 90% |
| File transactions/validation | 5,688/6,677 (85.2%) | 3,314/4,250 (78.0%) | 95% / 90% |

**INCOMPLETE:** the critical-group targets and complete hosted acceptance remain
unchanged. Run `44024881065` has now passed extension-build, release-package and
the initial Linux/Windows host jobs; architecture jobs and Windows-host validation
are advancing at this checkpoint. These queued test commits are not part of that
run and will require their own protected CI validation before integration.

## Earlier frame, entry, class, relocation and GUI-loader checkpoint

**CONFIRMED, local validation:** the following existing suites now have verified
measurements against production JAR
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`:

- CFI encoder and explicit/plain/gABI/GNU compiler-frame composition: 104
  isolated sessions. Ten encoder cases include ELF32/ELF64 and both byte orders,
  large gaps, compression, deterministic repeats and malformed CIE-pointer
  rejection. Four x86-64/AArch64 non-PIE/PIE runtime profiles compare generated
  unwinding to compiler frames in GDB; all four composition modes preserve the
  compiler prefix and validate the combined stack trace. These explicit plans
  do not establish additional production frame-recovery support.
- Function entries and aliases: twelve real headless exports cover non-PIE/PIE,
  rebasing, deterministic repeats, backward/discontiguous function bodies,
  true-entry breakpoints, gaps, values and stepping. Original files and the
  cached installation remain unchanged after the run.
- Isolated class scopes: one measured producer session emits five variants
  covering normal bindings, failed source, collisions, ambiguous aliases and
  unbound collisions. Independent DIE checks, strict/LLVM validation and 26
  queries in fresh GDB processes pass.
- Source relocation and derived binding: ten sessions exercise current Java
  transformations and validators on hash-bound historical x86-64 non-PIE/PIE
  fixture inputs. Old producer execution data is not included. GDB and LLDB
  resolve retained source while the old source is hidden; the source is restored
  afterwards. Each profile passes eleven binding refusals and seven sampled
  cancellation points. Derived validation uses an explicit test metadata host,
  not a privileged installation or attachment claim.
- GUI companion loader: one measured JVM performs actual Swing export selection,
  cancellation and attachment preparation. Both independent GDB workflows and
  structural validators pass, including `forge-load` on the exported companion.
  Geometry calibration, report CLI and nested attachment helpers remain
  explicitly unmeasured. The cached module is restored after execution.

All runs use `support/storage-guard.py run --cwd <repository> -- ...`, existing
repository harnesses and the same compiled production classes. Raw receipts,
source snapshots or committed source bindings, tool/input hashes, debugger logs
and individual verification records are retained under
`.forge-work/scratch/coverage-expansion/`. No production code or target threshold
changed. The CFI consumer has zlib support; the isolated class test uses the
existing atomic-type-capable consumer.

The first GUI attempt failed at geometry calibration because the cached headless
JDK lacks `libawt_xawt.so`; it contributes no coverage. The retry uses the existing
desktop OpenJDK 21.0.13 runtime. A local verification-script path mistake was
also corrected: loader flags belong to `select/result.txt` and `cancel/result.txt`,
not the top-level result. The successful GUI execution was verified without
rerunning it or weakening its assertions. Failed-attempt logs remain retained.

The verified partial union is
`.forge-work/scratch/coverage-expansion/gui-loader-verified-refresh-4bd11/summary.json`,
SHA-256 `335fcc6e2add7b2b47b30d73d1df99ad5c94e3a194b3333cdeb3d18e560998ed`.
Its 1,230 sessions comprise 211 JavaExec, 633 isolated Java/native-path and 386
headless executions. All 255 production sources and 901 classes remain included.
This adds 15 covered lines and 19 branches over the 1,102-session checkpoint;
additional executions also establish missing behavioral/profile evidence.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 27,908/29,792 (93.7%) | 21,295/25,888 (82.3%) | 85% / 80% |
| Binary/location correctness | 18,494/19,203 (96.3%) | 15,604/18,736 (83.3%) | 95% / 90% |
| File transactions/validation | 5,688/6,677 (85.2%) | 3,314/4,250 (78.0%) | 95% / 90% |

**INCOMPLETE:** the required suite-name inventory still lacks production Linux
attachment (exec, PIE, and no-build-ID) and all three Windows suites. Presence of
the other suite names is not a full required-profile audit. Fresh hosted results,
critical-group targets, complete same-run coverage, protected merge and actual-main
publication remain required. Local noninteractive privileged execution is
unavailable; no host checks or privileges were simulated to count those branches.
At this checkpoint, run `44024881065` on `1437e340` has passed native Linux,
native Windows and workflow lint; extension-build is still running. The Windows
companion preflight now passes, with the unavailable identity-only `fileKey`
race still explicitly `NOT_RUN`, not claimed as validated. The completed Windows
job log confirms `companion-observation-recovery=PASS checks=63` and
`companion-observation-identity=NOT_RUN reason=basic-file-key-unavailable`.

## Earlier formatter consumers and measurement checkpoint

**CONFIRMED, local validation:** the three existing x86-64 formatter profiles
pass through the production wrapper with both GDB CLI/MI and LLDB 18.1.3:
non-PIE with companion loaders/unwind evidence, compressed PIE, and compressed
PIE with a multi-file source bundle and companions. The 27 measured headless
sessions include preparation, default/enabled/repeated/restored exports,
cancellation recovery, and missing-key/wrong-kind rejection. Tests assert typed
values and bit fields, signed/high-bit flags, child expansion, formatter unload,
unchanged input/selection hashes, retained outputs after rejection, deterministic
reruns, and independent DWARF validation. Unicode/quoted sidecar paths are retained.
This measurement does not add an AArch64 or Windows formatter claim.

The local LLDB prerequisite is now available in the shared tool cache. Unmodified
Ubuntu packages `lldb-18`, `liblldb-18`, `python3-lldb-18`, and `liblldb-18-dev`, all
`1:18.1.3-1ubuntu1`, were checksum-verified and extracted there. A cache-only
wrapper selects their relocated library, Python and server paths. A native
fixture launch, Python API value assertion and normal exit pass before the
formatter suites. No system package installation was performed; downloaded
archives were removed after verification. The initial extraction attempt stopped
on an APT epoch-encoded filename; the existing authenticated downloads were
reused without repeating the download or changing the version pin.

The validator supports the exercised zlib sections. Verification checks source
and package inventories, tool hashes, raw coverage identities, all three profile
receipts, emitted file/source-bundle hashes, export reports, strict/LLVM results
and raw GDB/LLDB transcripts. The local validation package and cached installation
are restored. Original source/bytecode and previous immutable JavaExec receipts
remain unchanged.

The verified partial union is
`.forge-work/scratch/coverage-expansion/formatters-refresh-4bd11/summary.json`,
SHA-256 `59c1dfd4131e9ee769041389583868c9837f4c8d3dcb51ec959f5704f43c9b38`.
Its 1,102 sessions comprise 211 JavaExec, 517 isolated Java/native-path and 374
headless executions. All 255 production sources and 901 classes remain included.
These formatter profiles add 40 lines and 46 branches over the prior checkpoint.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 27,893/29,792 (93.6%) | 21,276/25,888 (82.2%) | 85% / 80% |
| Binary/location correctness | 18,481/19,203 (96.2%) | 15,587/18,736 (83.2%) | 95% / 90% |
| File transactions/validation | 5,686/6,677 (85.2%) | 3,312/4,250 (77.9%) | 95% / 90% |

**INCOMPLETE:** critical targets, fresh Windows execution, remaining full-cohort
measurement, exact-head hosted acceptance, protected merge and actual-main
publication. This is a verified partial matching-bytecode union, not the published
coverage badge or a completed CI acceptance run. Hosted run `44020062360`
subsequently finished extension-build successfully but failed its Windows
companion preflight; its downstream acceptance jobs were skipped. The later
run and correction are recorded above.

## Saved inheritance, C++ ABI bounds and hosted Linux measurement

**CONFIRMED, local validation:** `02f18a4d` adds 8,883 independent C++ ABI checks
and invokes them through the existing `inheritanceModelSmoke` task. BigInteger
encoding verifies signed 64-bit offset-to-top decoding at primary and secondary
address points; complete-header enumeration rejects truncated/misaligned table
views. Unbounded interval arithmetic checks vptr containment and distinguishes
virtual-base slots from RTTI and offset-to-top entries. The matrix also rejects
unsupported processor, ELF machine, pointer-width and byte-order combinations.
Both explicitly supported C++ profiles are exercised; this adds no architecture
support claim. Production code and JAR remain unchanged.

The isolated run and Gradle task pass the new checks plus the previous 131,136
admission, 1,879 expression and 80 model assertions. Six separately compiled
mutations fail the intended new assertions: reversed byte order, a narrowed
signed displacement, reading the wrong header word, rejecting a vptr ending
exactly at the object boundary, admitting the RTTI slot as a vbase slot, and
admitting a misaligned vptr. Compilation/setup failures are not accepted as
mutation detection. Mutants are unmeasured and their compiled files were removed.
`CxxAbiProfile` now measures 26/26 lines and 39/39 branches in this partial union.

Additional current-JAR integrations and measurement verification pass:

- Six stack-control-flow profiles (32/64-bit locals, non-PIE/PIE/rebased PIE)
  retain their complete compiler/Forge debugger observations, independent
  validators, deterministic outputs and input/project preservation. The first
  run's pretty JSON exceeded the coverage reader's 1 MiB bound. `83c48201`
  writes the same observations as compact JSON and checks that bound before
  writing; it does not enlarge the reader limit or discard trace fields. The
  complete rerun passes and contributes 18 direct headless sessions. The first
  over-limit collection remains excluded. A local verifier initially used the
  wrong export-prefix filename; correcting that path admitted the actual rerun.
- Packaged call-site workflows pass for non-PIE and PIE, each in original and
  rebased views. Four measured headless sessions use the production entry point,
  verify the installed package inventory and preserve the reopened saved
  program. Compiler and recovered-plan prerequisites, raw debugger observations,
  strict/LLVM results, output hashes and repeatable exports are checked before
  admission. The locally assembled package is explicitly validation-only.
- All 68 saved-inheritance profiles pass across x86-64 and AArch64, with QEMU
  debugger execution for AArch64. Each target has 34 cases covering non-PIE/PIE,
  RTTI/no-RTTI, rebasing, adjustment thunks, missing/stale/conflicting evidence,
  recovered/qualified/duplicate names and retained symbols. The 136 measured
  JVMs include curation and ordinary-wrapper read-only reopening. Reopening
  preserves the full saved program and produces identical source/sidecar bytes;
  original executable hashes, actual GDB observations and independent validators
  agree. Existing verified compiler references/models are reused with hashes,
  not counted as fresh producer executions. The cached installation is restored.

**CONFIRMED, completed hosted Linux job:** 45 isolated Java sessions from
[run 44015264480](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44015264480)
are admitted from its successful `extension-build` job. The production JAR
matches the current `4bd11717` bytecode. Verification authenticates the artifact
hashes, source merge commit/tree, exact source copies, raw receipts/probes and
regenerated report. Selected diagnostic files corroborate real `sudo -n` JVM
invocations, distinct target/backup inodes, non-root ownership, byte preservation,
mode, timestamps and xattrs. Expected cancellation/refusal subprocess exits are
checked against their exact labels and diagnostics, rather than mistaken for
failed test cases. This is isolated host-test evidence, not full public attachment
or power-loss acceptance. These sessions add 119 lines and 40 branches to the
preceding 893-session union.

That checkpoint's verified partial report is
`.forge-work/scratch/coverage-expansion/saved-inheritance-abi-refresh-4bd11/summary.json`,
SHA-256 `c4f040a6ffd56084c2f94e0e14cfefadf55ea0f97af2149ffa45ec192c223991`.
It unions 1,075 distinct sessions: 211 JavaExec, 517 isolated Java/native-path and
347 headless sessions, retaining all 255 production sources and 901 classes.

| Scope | Lines | Branches | Required |
| --- | --- | --- | --- |
| Overall Java | 27,853/29,792 (93.5%) | 21,230/25,888 (82.0%) | 85% / 80% |
| Binary/location correctness | 18,441/19,203 (96.0%) | 15,541/18,736 (82.9%) | 95% / 90% |
| File transactions/validation | 5,686/6,677 (85.2%) | 3,312/4,250 (77.9%) | 95% / 90% |

The denominator is unchanged; no native C coverage is claimed. Fresh Windows,
remaining integrations, the complete hosted acceptance gate, protected merge and
actual-main publication are still outstanding. Both critical groups remain below
their branch targets, and file-operation line coverage remains below its target.

**PRESENT, Windows-unverified correction:** current CI run `44020062360` passed
workflow lint and native Linux but failed the Windows companion test before the
native build. The earlier compile-dependency correction worked. The next failure
was the identity-only fixture assuming a non-null Java `fileKey()`. `362ce60a`
explicitly reports that probe as `NOT_RUN` when the provider supplies no key,
retaining content, size, timestamp, publication and recovery checks. The exact
workflow source subset compiles and passes on Linux; Windows execution of this
correction is pending. Windows identity-only race detection is not proven by this
change. The extension-build job remains in progress at this checkpoint.

After verification, 47,242,159 bytes of owned per-run Ghidra caches were removed.
Raw probes, logs, source snapshots, saved programs, compiler references and
selected artifacts remain. No additional worktree or unaccounted workspace was
created.

## C++/stack transition refresh and decoded call-site effects

**CONFIRMED, local validation:** `2579948b` adds 34 actual decoded instruction
cases across x86-32, x86-64, ARM32 and AArch64 to the existing
`ghidraUnwindInstructionsSmoke` task. The new 882 assertions check conditional
destination invalidation, independent register/stack preservation, ordinary
copy/add/subtract effects, and conservative rejection of unproved calls,
computed jumps, repeated stores and floating operations. Cancellation at every
observed poll must stop promptly, preserve program bytes/state, and allow a
deterministic retry. This is component evidence, not a new CFI or architecture
support claim. Production source and JAR are unchanged.

An initial ARM conditional-load expectation failed. The diagnostic rerun showed
actual Sleigh p-code containing conditional address arithmetic, for which this
decoder deliberately returns a whole-instruction omission. The corrected test
requires that conservative result and verifies that no register/memory facts
survive. Both failed collections remain excluded. The passing run is
`callsite-effects-verified-4bd11`; four separately compiled mutations are rejected
by its new assertions: retaining a conditional destination, ignoring opaque
effects, treating subtraction as addition, and retaining a copy's destination.
Mutation executions do not contribute coverage. The existing Gradle task passes
the new 882 plus 1,849 prior assertions; no full JavaExec rerun is claimed.

Existing production integrations also pass against current JAR `4bd11717`:

- Fifteen C++ profiles cover inferred/explicit object bindings, stale/conflicting
  class evidence and aggregate returns for non-PIE, PIE and rebased PIE. Compiler
  and Forge GDB, independent validators, deterministic artifacts and preservation
  checks pass. Their 45 direct headless sessions are measured; nested real
  decompiler-failure and copy-cancellation controls remain behavioral evidence
  only and are explicitly excluded from this measurement.
- Six x86-64/AArch64 stack-transition profiles cover non-PIE, PIE and rebased PIE.
  Each checks twelve 32/64-bit functions with three signed input values at every
  instruction, raw register/stack observations, availability gaps, return values,
  source stepping, exact serialized location intervals, validators and repeatable
  outputs. All 24 direct headless sessions are measured, including QEMU-backed
  AArch64 debugger execution. Both original bytes and saved programs are preserved.

Raw receipts, actual harness snapshots and installed JAR/native metadata
restoration are verified. The original run checkout is `19524e34`; the new test
snapshot is `2579948b`. The two owned Java 21 script caches (21.9 MB total) were
removed after verification; raw measurements and selected artifacts remain.

The current-JAR partial union is **871 sessions** (211 JavaExec, 471 isolated
Java/native-path, 189 headless), with all 255 production sources/901 classes:

| Scope | Covered lines | Covered branches |
| --- | ---: | ---: |
| Overall Java | 27,722 / 29,792 (93.1%) | 21,149 / 25,888 (81.7%) |
| Binary/location correctness | 18,430 / 19,203 (96.0%) | 15,504 / 18,736 (82.7%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

Relative to the prior MMIO checkpoint, this adds 16 lines and 25 branches. The
new instruction tests account for three lines/four branches in
`GhidraUnwindInstructions`; the other gains come from the integration refresh.
Evidence is under `.forge-work/scratch/coverage-expansion/`, including
`object-current-4bd11`, `transitions-current-4bd11`,
`callsite-effects-verified-4bd11`, `callsite-effects-mutations-4bd11`,
`callsite-effects-gradle.log` and `callsite-effects-refresh-4bd11/summary.json`.
The final summary SHA-256 is
`95ed0fa4e04cffe017f4bbf388ccb98b0de2f27da1cba9b7cabe2113b70e580c`.

Issue #209 remains **incomplete**: the unchanged critical-group 95%/90% targets,
fresh Windows/privileged/full-hosted measurements, protected integration and
actual-main publication remain required. Run `44015264480` still has its
extension build in progress; its known native-Windows compilation dependency
failure is fixed locally in `b41c3d20`, awaiting the next CI revision.

## Existing ELF MMIO cancellation/failure measurement

**CONFIRMED, local validation:** `294ccb43` instruments the existing ELF MMIO
control process, retaining its 16 cancellation, late-failure, collision,
saved-project and output-preservation checks. The collection closes only after
those checks pass and module/harness/artifact hashes remain unchanged. Hosted
Linux coverage now requires this suite. Raw firmware keeps its separate parent
measurement contract; this does not add a device-access support claim.

The new admission policy binds the exact analyzer session, source/native/JAR
identity, unchanged saved program, compiler/Forge static GDB values, deterministic
baseline output hashes and strict validator result. It requires the precise
post-control inventory, including the deliberately incompatible formatter input.
The first admission attempt rejected that intentional `formatters.json` input;
`afd5a903` corrects the expected inventory by requiring its exact known contents,
while still rejecting extra files or changed outputs. It also rejects boolean or
floating-point values in integer debugger observations. All **291 coverage-policy
tests pass**; workflow lint and whitespace checks pass.

The current-JAR x86-64 run builds its compiler reference, verifies raw register
bytes and the changed-bytes negative control, imports/curates/exports/repeats,
checks LLVM/readelf/strict libdwarf, compares static GDB layouts/values/qualifiers
and alias values, then runs all 16 failure controls. The saved program and all
four original/output artifacts remain unchanged. The one control JVM contributes
coverage; preceding reference/export checks establish its artifact baseline.
The installed JAR/native metadata are restored afterward. The owned 9.0 MB
Java 21 script cache was removed; raw coverage and selected artifacts remain.

The verified partial current-JAR union is now **801 sessions** (211 JavaExec,
470 isolated Java/native-path, 120 headless), with all 255 sources/901 classes:

| Scope | Covered lines | Covered branches |
| --- | ---: | ---: |
| Overall Java | 27,706 / 29,792 (93.0%) | 21,124 / 25,888 (81.6%) |
| Binary/location correctness | 18,418 / 19,203 (95.9%) | 15,484 / 18,736 (82.6%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

This adds 33 lines/13 branches in `GhidraMmioProfile` and one exporter branch.
Evidence is under `.forge-work/scratch/coverage-expansion/mmio-current-4bd11`
and `mmio-refresh-verified-4bd11`. The final summary SHA-256 is
`0f2f62b1743f09a889176abf9f734c8ecdba0ee3337546800772f7a06f4ba3e4`.
The original run checkout is `c71e513a`, with executed harness code committed in
`294ccb43`. Verification binds runtime sources to `afd5a903`. The admission module
was captured as unexecuted context before its inventory correction: its original
hash/copy are retained separately from the applied admission hash and snapshot.
No runtime source provenance is rewritten. The failed initial admission report
remains under `mmio-refresh-4bd11`; it is not an accepted measurement.

Issue #209 remains **incomplete**: the unchanged per-critical-group targets,
fresh Windows/full hosted cohort, protected merge and actual-main publication
still apply. CI `44015264480` is finishing its extension build; the Windows
preflight dependency fix and this measurement await the next revision's run.
Storage is READY: 12.42/100 GiB scratch, 2.03/10 GiB cache, 6.73/10 GiB evidence.

## ARM32 alias boundary contracts and Windows preflight dependency

**CONFIRMED, local component validation:** `c456355f` adds 321 assertions using
actual ARM32 ProgramDB instructions. ARM, Thumb and mixed-width Thumb bodies are
placed at low addresses, `0x80000000`, and the top of the 32-bit address space.
Thirty-six address/rebase combinations verify exact byte hashes, function extents,
mode tags, saved-body/input preservation and the intentionally silent ARM-only
primary-symbol path. Invalid analysis rebases are omitted without wrapping or
contaminating a later valid extraction.

Real analyst edits cover a changed body with the same range count, cleared
instructions, changed/redecoded bytes and a removed owner. Stale aliases must be
omitted with the specific diagnostic; fresh evidence must bind the changed code.
No impossible Ghidra return values or proxy-based inconsistent metadata are used
in these new cases. This is component evidence, not an additional emitted-DWARF
or debugger support claim.

The existing Gradle `ghidraArm32FunctionModesSmoke` task passes **380 checks**
(321 new plus 59 existing). Five isolated, compiled mutations are each caught by
the new assertions: ignoring a rebase, narrowing an analysis address to 32-bit
signed, ignoring a changed body size, accepting stale code hashes and dropping
the Thumb tag. Mutation executions do not contribute coverage. Production source
and the JAR remain unchanged.

The current-JAR union now contains **800 sessions** (211 JavaExec, 470 isolated
Java/native-path, 119 headless), still all 255 production sources/901 classes:

| Scope | Covered lines | Covered branches |
| --- | ---: | ---: |
| Overall Java | 27,673 / 29,792 (92.9%) | 21,110 / 25,888 (81.5%) |
| Binary/location correctness | 18,385 / 19,203 (95.7%) | 15,470 / 18,736 (82.6%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

All five additional covered branches are in `GhidraArm32FunctionModes`.
Evidence under `.forge-work/scratch/coverage-expansion/` includes
`arm32-alias-boundaries-4bd11`, `arm32-alias-mutations-4bd11`, the successful
`arm32-alias-gradle.log`, and `arm32-alias-refresh-4bd11/summary.json`, SHA-256
`2cba45107556689cad33f370be3527ba965b2e274ea7ea2ad79945bbcf79a260`.
The run checkout was `6589d929`; the verified harness snapshot is `b41c3d20`,
which contains test commit `c456355f`. Original run/source provenance is retained.

**CONFIRMED CI failure, fix awaiting Windows validation:** run `44015264480`
failed its native-Windows preflight compilation because the explicit `javac`
source list omitted `CompanionObservationRecoverySmoke`, now called by
`CompanionArtifactPublisherSmoke`. Commit `b41c3d20` adds that dependency.
The exact six-file workflow list compiles under Java 21 and both publication
and recovery workflows pass locally on Linux (including 68 recovery assertions);
workflow lint passes. A first local wrapper used incorrect expected output
markers after the tests passed; corrected marker verification passes separately
in `windows-companion-source-list-verified`. No Windows runtime pass is claimed.
The failed CI log is retained as `ci-44015264480-native-windows.log`.

Issue #209 remains **incomplete**, with unchanged 85%/80% overall and 95%/90%
per-critical-group targets, full hosted/Windows measurement, protected merge and
actual-main publication requirements. Storage remains READY within its budgets.

## Current-JAR signature and calling-convention refresh

**CONFIRMED, partial local measurement:** the existing recovered-return,
recovered-parameter and external-declaration workflows pass with production JAR
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.
Their eight headless sessions preserve curated/inferred signature distinctions,
omit unproven parameter locations, and keep external declarations unlocated.
Compiler/Forge GDB, independent validators, saved-program/input preservation and
repeatable artifact pairs pass. Both existing admission policies accept the
complete cases; no historical-package probes contribute.

All nine calling-convention/custom-storage cases also pass: non-PIE, PIE and
rebased PIE, each with explicit alternate conventions, GCC custom storage and
Ghidra's Windows compiler profile on the Linux ELF fixture. Their 27 headless
sessions retain ordinary arguments/return values while GDB rejects unsupported
injected calls. This is ABI-profile validation, not a native Windows-host claim.
Both compiler and exported artifacts pass LLVM and strict libdwarf checks.

One initial rebased import **failed before export**: the shared Ghidra script
cache contained a Java 25 `RebaseFixtureProgram` class, incompatible with the
selected Java 21 runtime. Its incomplete receipt and raw execution data remain
under `call-abi-current-4bd11/failed-collections` and are excluded from coverage.
The three rebased profiles then passed with an isolated Java 21 cache. The
original failure and retry remain separately recorded; no failed test was
converted into a passing receipt. Installed JAR/native metadata restoration was
verified, and the retry's 9.3 MB disposable script cache was removed afterward.

The verified union now contains **799 sessions**: 211 JavaExec, 469 isolated
Java/native-path and 119 headless. All **255 production sources / 901 classes**
remain in the denominator:

| Scope | Covered lines | Covered branches |
| --- | ---: | ---: |
| Overall Java | 27,673 / 29,792 (92.9%) | 21,105 / 25,888 (81.5%) |
| Binary/location correctness | 18,385 / 19,203 (95.7%) | 15,465 / 18,736 (82.5%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

Relative to the preceding namespace checkpoint this adds nine covered lines and
16 branches. Evidence is under `.forge-work/scratch/coverage-expansion/`:
`signatures-current-4bd11`, `signatures-refresh-4bd11`,
`call-abi-current-4bd11`, `call-abi-rebased-current-4bd11` and
`call-abi-refresh-4bd11`. The final summary SHA-256 is
`e432493510a61acb8ca98324e5261f099fccd66cff29a9aff138b01383ab1d90`.
Executed harness snapshots bind to `78af6ca8`; original run provenance is retained.
Guarded signature verification, ABI execution/retry and final union verification
all completed successfully after the recorded cache failure. The union checks
raw class identities, source population, artifact hashes and complete behavioral
receipts. Production code and coverage targets are unchanged.

Issue #209 remains **incomplete**: each critical group's 90% branch target,
file/validation's 95% line target, fresh Windows/remaining integration data,
exact-revision hosted acceptance, protected merge and actual-main publication
remain required. These are local measurements, not a new published badge.
Storage is READY: 12.38/100 GiB scratch, 2.03/10 GiB cache, 6.73/10 GiB evidence.

## Namespace/global producer measurement on both target lanes

**CONFIRMED, local validation:** commit `518f2718` instruments the existing eight
namespace/collision variants on x86-64 and AArch64. Each producer JVM has its own
raw session; the test class is explicitly excluded and every production class
remains included. Collection completes only after the existing structural,
cold-lookup and runtime assertions pass.

The new admission policy requires exact sessions and variants, all cold GDB
queries, validator inventory, source/native provenance, compiler/selected global
values and addresses, return value 140 and normal process exits. The hosted
report requires this suite on both target lanes; AArch64 now includes its native
Java layer. The workflow supplies the measurement environment on the namespace
command without instrumenting unrelated AArch64 suites.

Validation: **286 coverage-policy tests pass**, including incomplete/mismatched
receipt rejection and the updated synthetic AArch64 bundle; workflow lint passes.
Two initial metadata-test failures were corrected before native execution: the
synthetic bundle needed the new layer, and the measurement wrapper needed the
collector's existing status format. Neither policy nor the behavioral test was
weakened.

Actual runs passed **16 producer JVM sessions**, **54 cold GDB lookups**,
independent validation of all 16 artifacts, and compiler-versus-exported runtime
checks on native x86-64 and QEMU AArch64. Emulator endpoints were removed after
normal exits. Cached extension files were restored and checked. Production Java
and native libraries are unchanged.

The verified union now includes **764 sessions** (211 JavaExec, 469 isolated
Java/native-path, 84 headless), all **255 production sources / 901 classes**:

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall | 27,664 / 29,792 (92.9%) | 21,089 / 25,888 (81.5%) |
| Binary/location correctness | 18,376 / 19,203 (95.7%) | 15,449 / 18,736 (82.5%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

This adds 15 lines and 14 branch outcomes in `MinimalDwarfSidecarExporter`.
Evidence: `.forge-work/scratch/coverage-expansion/namespace-current-4bd11` and
`namespace-refresh-4bd11`; final summary SHA-256:
`c15165e5e8ff4fe2a92da4343efdd125857b2c477c74c5a317b0184b2c9b56ed`. Executed harness snapshots bind to `518f2718`; the original
pre-commit run identity is retained. The captured but unexecuted workflow is
context evidence, not proof of hosted execution.

Issue #209 remains **incomplete**. Both critical branch targets, file-operation
line target, remaining integration/Windows measurements, exact-revision hosted
acceptance, protected merge and actual-main publication remain required.

## Current instruction context, static objects and lexical composition

**CONFIRMED, partial local measurement:** refreshed existing integration suites
against the unchanged production JAR, with harness source snapshot `78611660`.
No production code or native libraries changed.

- Five instruction/source-context JVMs verify repeatable saved-program reads,
  cancellation and bounded context composition. These are component checks;
  annotation export has separate end-to-end validator/debugger evidence.
- Thirty-seven static-object JVMs cover x86-64 non-PIE explicit/recovered static
  ownership, lexical shadowing, stale/conflicting evidence, failure isolation
  and cancellation. The existing admission policy verifies the complete five
  collection types for this role. Compiler, isolated-producer and exported GDB
  observations exercise nine execution boundaries, values, addresses and types.
- Four lexical JVMs combine discontiguous visibility, inspected calls and split
  source. Baseline and split-source GDB observations/calls match. Output pairs
  and source inventory are deterministic; target inputs remain unchanged.

The static and lexical artifacts pass readelf, LLVM and strict libdwarf checks.
Fresh raw probes are admitted only after checking class identity, behavioral
receipts, harness snapshots, retained output hashes and debugger observations.
Temporary cached-extension changes are restored and checked.

The verified union contains **748 distinct sessions**: 211 JavaExec,
453 isolated Java/native-path and 84 headless. All **255 production sources /
901 classes** remain included:

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall | 27,649 / 29,792 (92.8%) | 21,075 / 25,888 (81.4%) |
| Binary/location correctness | 18,361 / 19,203 (95.6%) | 15,435 / 18,736 (82.4%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

This adds **97 lines and 112 branch outcomes** to the preceding attachment
checkpoint. Evidence is under `.forge-work/scratch/coverage-expansion/` in
`context-current-4bd11`, `statics-current-4bd11`, `lexical-current-4bd11` and their
respective `*-refresh-4bd11` directories. Final summary SHA-256:
`aa669f97bdda2bbce33a3d0bdf881a8841e894fc17d23a2a65ec04cc6390ebba`.

Issue #209 remains **incomplete**. These local profiles do not replace the
remaining roles, fresh Windows measurement, full hosted cohort, critical-group
95%/90% targets, protected merge or publication from actual `main`. Original
JavaExec collection snapshots remain intact; a full suite rerun is not claimed.

## Incoming-reference contracts and attachment validation refresh

**CONFIRMED, partial local measurement:** test commit `6d290908` adds an actual
Ghidra listing-reference matrix to `outsideBodyFlowSmoke`. Across x86-64,
AArch64, ARM32 and both MIPS byte orders, 3,544 cases check instruction entries,
offcuts, external predecessors, delay slots, and flow/data references. Unsafe
entries must omit incoming parameter locations without fabricating a prefix;
removing each reference restores the proof. Target bytes and function bodies
remain unchanged. All **17,419 new assertions plus 85 existing checks pass**.

Three compiled production mutants are rejected by the new matrix's behavioral
assertions: accepting alternate entries, allowing outgoing delay-slot flow, and
treating data references as flow. Compilation failures are not credited. Mutants
are not instrumented and their disposable compiled classes were removed.
The existing Gradle task also passes. Production source/JAR/native libraries
are unchanged. This test uses actual Ghidra ProgramDB objects; it does not claim
new native DWARF or runtime-debugger validation.

A separate current-JAR attachment refresh measures **17 JVM sessions** covering
live validation success, 14 rejection/cancellation controls, commit and rollback.
It runs independent readelf/LLVM/libdwarf checks and actual GDB discovery/runtime
and CRC rejection. Historical exported fixtures are preserved inputs to the
current Java implementation, not a source of old execution data. The limited
Linux test host does not establish privileged production-host acceptance or
public-launcher recovery coverage.

The verified union now contains **702 distinct sessions**: 211 JavaExec,
452 isolated Java/native-path and 39 headless. All **255 production sources /
901 classes** remain included:

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall | 27,552 / 29,792 (92.5%) | 20,963 / 25,888 (81.0%) |
| Binary/location correctness | 18,303 / 19,203 (95.3%) | 15,380 / 18,736 (82.1%) |
| File transactions/validation | 5,566 / 6,677 (83.4%) | 3,271 / 4,250 (77.0%) |

This checkpoint adds ten lines and nine branch outcomes to the prior CFI
checkpoint. `AttachmentValidator` has 204/204 measured lines;
`StrictDwarfCheck` has 63/66. Original JavaExec receipt/test-bytecode snapshots
are retained; the full suite was not rerun merely for this focused change.

Evidence under `.forge-work/scratch/coverage-expansion/`:
`flow-entry-contract-4bd11`, `flow-entry-mutations-4bd11`,
`flow-entry-refresh-4bd11`, `attachment-current-4bd11`, and
`attachment-refresh-4bd11`. Source snapshots, behavioral receipts, raw probes,
class IDs, complete population, protected inputs, expected failure outcomes and
validator logs are checked before admission. Final summary SHA-256:
`7ce5ba489cd22bf9e8115210e160af9d323c396ff5f720a9266ea25b226ed3e7`.

Issue #209 remains **incomplete**. Critical-group targets, fresh Windows and
remaining integration measurement, exact-revision hosted acceptance, protected
merge and publication from actual `main` remain required. The earlier CI cycle
is still running and uses different production bytecode.

## Independent frame-state encoding boundaries

CONFIRMED: commit `5342ccd7` adds `CallFrameEncodingBoundarySmoke` through the
existing `callFrameEncoderSmoke` task. The test independently decodes complete
CIE/FDE instruction streams with ByteBuffer and BigInteger LEB operands, then
compares the resulting CFA/register state with the explicit input plan at each
modeled instruction boundary. It covers both byte orders, 32/64-bit addresses,
extended register numbers, signed-long offset limits, high addresses crossing
the signed-long boundary, and row gaps at and above the 32-bit advance limit.
Negative CFA-value expressions retain their signed addition semantics.

The standalone and Gradle paths both pass 7,992 new assertions plus 362 existing
checks. Six separately compiled faults trigger the intended behavioral
assertions: truncated wide row gaps, wrong negative-CFA operations, erased saved
register displacements, truncated return-register numbers, narrowed frame
addresses and omitted CFA transitions. Compilation failures are not credited;
mutants are excluded from coverage and their owned compiled directories removed.
Production code and the `4bd11717` JAR remain unchanged.

`DwarfDebugFrame` now measures **172/173 lines (99.4%) and 112/121 branches
(92.6%)**. This adds five previously unmeasured lines and branch outcomes to the
current union. The isolated `native-java` collection explicitly describes pure
Java model checks; it does not claim recovered unwind evidence or new debugger
validation. The original JavaExec collection retains its original test snapshot.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union, 684 sessions | 27,542 / 29,792 (92.4%) | 20,954 / 25,888 (80.9%) |
| Binary/location | 18,303 / 19,203 (95.3%) | 15,378 / 18,736 (82.1%) |
| File/validation | 5,556 / 6,677 (83.2%) | 3,264 / 4,250 (76.8%) |

All 255 production sources/901 classes remain included. Evidence under
`.forge-work/scratch/coverage-expansion/`: `frame-encoding-boundaries-4bd11`,
`frame-encoding-mutations-4bd11`, `frame-encoding-gradle-4bd11.log`, and the
independently regenerated union `frame-encoding-refresh-4bd11`. Source snapshots,
behavioral receipts, raw identities/probes and all prior current-JAR collections
were rechecked before unioning.

Issue #209 remains **incomplete**: both critical-group branch targets,
file/validation line coverage, fresh Windows/full hosted evidence, protected
merge and actual-main publication are outstanding. The older CI run now has a
passing ARM32 job; AArch64 and x86-64 are still active, and its probes belong to
old bytecode. Storage is 11.888/100 GiB scratch, 2.033/10 GiB caches and 6.728/10 GiB
evidence. No extra worktrees or local heavy processes remain active.

## Lexical range boundary tests and current GUI unwind measurement

CONFIRMED: commit `679ea5d1` adds `RangeListScopeBoundarySmoke` through the existing
`dwarfRangeListsSmoke` task. Its independent ByteBuffer decoder checks lexical
visibility point by point when a contiguous function contains a discontiguous
block. It covers both byte orders, 32/64-bit addresses, near-width limits,
visibility gaps, absent/ambiguous/mismatched owners, duplicate scope identities,
invalid address widths, deterministic reruns and defensive output ownership.

The new test passes 18,832 assertions and the existing Gradle smoke task passes.
Four separately compiled faults are rejected by the intended behavioral
assertions: omitting lexical-only lists, filling a lexical gap, accepting
ambiguous owners and accepting duplicate scope identities. Compile failures do
not count as detections. Mutant execution is excluded from coverage and owned
compiled mutant directories were removed after verification. Production source
and the `4bd11717` JAR remain unchanged.

`Dwarf5RangeLists` now measures **94/95 lines (98.9%) and 53/54 branches (98.1%)**.
The additional focused JVM is recorded as an isolated `native-java` collection
with an explicit pure-Java scope; it makes no native producer or debugger claim.
The original 211-task JavaExec collection remains bound to its original test
snapshot rather than being relabeled as a rerun of the new tests.

The actual Linux GUI unwind workflow also passes all seven choices, four exports
and three cancellations. Independent compiler/GDB instruction-boundary and
return-frame comparisons pass for conditioned modes; off/strict modes correctly
omit unproven plans in this fixture. All four outputs pass structural validation.
Its one measured main JVM is separate from unmeasured helper processes. The
cached installation and compiler fixture inventory are restored/preserved.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union, 683 sessions | 27,537 / 29,792 (92.4%) | 20,949 / 25,888 (80.9%) |
| Binary/location | 18,298 / 19,203 (95.3%) | 15,373 / 18,736 (82.1%) |
| File/validation | 5,556 / 6,677 (83.2%) | 3,264 / 4,250 (76.8%) |

All 255 sources/901 classes remain included. Evidence under
`.forge-work/scratch/coverage-expansion/`: `range-scope-boundaries-4bd11`,
`range-scope-mutations-4bd11`, `gui-unwind-current-4bd11`, and the verified union
`range-unwind-refresh-verified-4bd11`. Two initial local verifier attempts stopped
before admission because the default-GUI marker and Python import path did not
match the unwind harness. After checking the actual unwind script/receipts, the
verifier was corrected; the passing behavioral tests were not rerun or weakened.

Issue #209 remains **incomplete**. Critical branch targets, file/validation line
coverage, fresh Windows and complete hosted evidence, protected merge and
actual-main publication remain outstanding. Storage is 11.872/100 GiB scratch,
2.033/10 GiB caches and 6.728/10 GiB evidence; no extra worktrees or active local
heavy processes remain.

## Current compressed GUI, sectionless ELF and bit-field refresh

CONFIRMED: the fixed `4bd11717` JAR has 681 verified raw sessions: 211 JavaExec,
431 native Java and 39 headless. All 255 production sources/901 classes remain
included, with no old-JAR execution data admitted.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union | 27,508 / 29,792 (92.3%) | 20,908 / 25,888 (80.8%) |
| Binary/location | 18,269 / 19,203 (95.1%) | 15,333 / 18,736 (81.8%) |
| File/validation | 5,556 / 6,677 (83.2%) | 3,263 / 4,250 (76.8%) |

The real compressed Linux Swing workflow passes cancellation, attachment
preparation, strict validation and both GDB checks, contributing one measured
main JVM. Unmeasured helper/CLI/calibration processes remain identified separately.
Inherited frame diagnostics are corroborated against the original input.

Fresh sectionless ELF exports are deterministic and preserve the original input.
GDB resolves the expected breakpoint and source, displays types, steps and exits
successfully. Live attachment validation obtains original-frame evidence from
program headers and rejects an already-existing evidence destination. Both
native validator sessions pass the hosted admission checks for this suite; the
limited test host does not establish full privileged attachment acceptance.

Bit-field values pass compiler-reference and exported GDB comparisons for
x86-64, AArch64, MIPS32 big-endian and MIPS32 little-endian, together with strict
structural validation, deterministic outputs and protected-input checks.
The eight measured headless sessions are verified against the current JAR.
QEMU endpoints/processes are checked as cleaned up. LLDB was **NOT RUN** locally
and remains required in hosted validation; ARM32 was not included in this local
four-target invocation. Cached extension files and native metadata are restored.

Evidence under `.forge-work/scratch/coverage-expansion/`:
`gui-compressed-current-4bd11`, `sectionless-validation-current-4bd11`,
`bitfields-current-4bd11` and the latest union `validation-refresh-checked-4bd11`.
All prior current-JAR sessions were revalidated with the new collections before
regenerating the union. No production/test-source changes or target reductions
were made in this refresh.

Issue #209 remains **incomplete**: both critical branch targets, file/validation
line coverage, fresh Windows and full hosted evidence, protected merge and
actual-main publication remain outstanding. Storage is 11.805/100 GiB scratch,
2.033/10 GiB caches and 6.728/10 GiB evidence. No extra worktrees or local heavy
processes remain active.

## Current source, GUI, firmware and debugger measurement refresh

CONFIRMED: the unchanged fixed `4bd11717` JAR now has 670 verified raw sessions:
211 JavaExec, 428 native Java and 31 headless. All 255 production sources/901
classes remain included. Old-JAR execution data is excluded.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union | 27,476 / 29,792 (92.2%) | 20,882 / 25,888 (80.7%) |
| Binary/location | 18,256 / 19,203 (95.1%) | 15,316 / 18,736 (81.7%) |
| File/validation | 5,537 / 6,677 (82.9%) | 3,254 / 4,250 (76.6%) |

Both overall targets and the binary/location line target are now met in the
verified partial measurement. Critical branch targets and the file/validation
line target remain unmet. Fresh Windows and remaining integration measurements
are still missing, so these are not final coverage-gap counts or hosted acceptance.

The four source-relocation sessions pass boundary/cancellation controls,
readelf, LLVM and strict libdwarf validation, retained-source lookup and 32 GDB
runtime scenarios across non-PIE/PIE and uncompressed/zlib inputs. They use
preserved exported fixtures as inputs to the current relocation code.

The real Linux Swing workflow passes source-context selection, split-source
exports, attachment preparation and nine GDB checks. Its one measured main JVM
is identified separately from unmeasured calibration, report-CLI and helper
processes. Strict validation corroborates inherited frame diagnostics against
the original input. This is the default GUI mode, not a claim for all GUI modes.

Fresh Cortex-M3 raw exports pass single-input and separate-RAM layouts, including
20 and 21 failure controls, unchanged inputs/saved projects, deterministic
outputs, structural validation and QEMU/GDB observations of source stepping,
values and both MSP/PSP exception stacks. The four measured headless sessions
are imports and direct export controls; wrapper exports are behavioral evidence.

The three GDB companion sessions pass non-PIE, PIE and shared-library mapping,
preservation, invalid-path and cancellation checks. The independent consumer
also rejects an injected warning despite a successful validator exit status.
All temporary cached-extension changes were restored and package inventories
rechecked. These local validation packages are not published release artifacts.

Evidence is under `.forge-work/scratch/coverage-expansion/`:
`source-sidecar-current-4bd11`, `gui-desktop-current-4bd11`,
`firmware-current-4bd11`, `companion-strict-current-4bd11`, and the latest union
`consumer-refresh-checked-4bd11`. The earlier `source-firmware-refresh-checked-4bd11`
union measured 667 sessions at 91.8% lines / 80.4% branches. Every collection and
all prior current-JAR data were revalidated before unioning raw probes.

Issue #209 remains **incomplete**: remaining critical targets, fresh Windows and
complete hosted evidence, protected merge and actual-main publication are still
required. No production/test-source changes or threshold relaxations were made
in this refresh. Scratch usage is 11.737/100 GiB, caches 2.033/10 GiB and evidence
6.728/10 GiB. No additional worktrees or local heavy processes remain active.

## Current installation and Linux metadata measurement refresh

CONFIRMED: the fixed `4bd11717` JAR now has 658 independently verified raw
sessions: 211 JavaExec, 420 native Java and 27 headless. All 255 production
sources/901 classes remain in the denominator. No old-JAR execution data was used.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union | 26,932 / 29,792 (90.4%) | 20,638 / 25,888 (79.7%) |
| Binary/location | 17,992 / 19,203 (93.7%) | 15,154 / 18,736 (80.9%) |
| File/validation | 5,534 / 6,677 (82.9%) | 3,254 / 4,250 (76.6%) |

The fresh multi-file exporter passes strict libdwarf/LLVM validation and GDB
source observations. Its retained-source build-ID lifecycle and source-binding
refusals contribute 18 native sessions. Build-ID operations use the actual Linux
host; the owned-copy source-binding controls use their explicitly limited test
metadata host. The cached extension JAR and native metadata were restored.

Linux metadata, directory sync and unprivileged visibility contribute 43 native
sessions. Independent native observations and the complete 28 read-failure and
12 application-failure controls pass, including balanced resource release,
unchanged source, checked stage effects and successful retries. Privileged
visibility is **NOT RUN** locally; these receipts do not satisfy the complete
hosted visibility requirement.

The build-ID installation/command suites contribute another 220 native sessions:
157 non-PIE installation, seven PIE installation, 13 identity-refusal and 43
command sessions. Real Linux installation, idempotence, update, removal, source
retention, cancellation, crash recovery and fresh GDB discovery pass. Sixteen
intentional process halts are behavioral evidence only and are excluded from
coverage. This suite reuses preserved exported fixtures as inputs to the current
installation code; the separate multi-file run above exercises fresh exports.

Every collection was checked against the fixed JAR, recorded source snapshot,
raw session identities, protected-input hashes and behavioral receipts before
regenerating the full-denominator union. Evidence under
`.forge-work/scratch/coverage-expansion/`:
`build-id-multifile-current-4bd11`, `linux-host-current-4bd11`,
`buildid-current-4bd11` and `installation-refresh-checked-4bd11`.
The intermediate 438-session union in `file-refresh-checked-4bd11` measured
90.0% lines / 79.3% branches and is superseded by the result above.

These are measurement refreshes, not new production changes. Fresh Windows and
remaining integration data, both critical-group targets, exact-head hosted
validation, protected merge and actual-main publication remain **incomplete**.
The active older CI run is still advancing; its old-JAR data is not admitted.
Storage after this refresh is 11.650/100 GiB scratch, 2.033/10 GiB cache and
6.728/10 GiB evidence, with no extra worktrees or local heavy processes retained.

## Current producer, inheritance and annotation measurement refresh

CONFIRMED: the fixed `4bd11717` production JAR now has 377 verified raw sessions:
211 JavaExec, 139 native Java and 27 headless sessions. No old-JAR probes were
admitted. All 255 production sources/901 classes remain included.

| Scope | Lines | Branches |
| --- | --- | --- |
| Partial current-JAR union | 25,811 / 29,792 (86.6%) | 20,076 / 25,888 (77.5%) |
| Binary/location | 17,800 / 19,203 (92.7%) | 15,053 / 18,736 (80.3%) |
| File/validation | 4,605 / 6,677 (69.0%) | 2,793 / 4,250 (65.7%) |

Fresh native runs pass all 28 producer fault/cleanup/retry cases, qualified scalar
types and optional source-only/symbol-only exports, and the existing x86-64/AArch64
inheritance/vtable matrix. The inheritance evidence includes 48 compiler-reference
observations, eight producer cases, 40 naming variants and six runtime rejection
controls. Structural validators and debugger receipts are checked before admitting
the corresponding raw execution data.

The saved-annotation pipeline also passes against the installed fixed JAR:
comments and equates, placement, context exports, deterministic reruns, cancellation
and limit failures, failed-decompilation output, and multi-file source failures.
It preserves the original project and restores the cached extension JAR afterward.
Its current instrumentation records 29 sessions, including two native constant
sessions and three retained-name headless sessions; the older local verifier's
24-session assumption was corrected after checking these additional receipts
against the current equate admission policy and GDB results.

The fresh partial union is retained in
`.forge-work/scratch/coverage-expansion/annotation-refresh-checked-4bd11/`.
Supporting evidence is in `producer-failures-current-4bd11`,
`qualified-type-current-4bd11`, `inheritance-current-4bd11` and
`annotations-current-4bd11`. Raw class IDs, probe lengths, session identities,
source hashes, protected inputs and the full source denominator were rechecked.
This refresh adds no production changes. It is **not** a complete hosted cohort:
fresh Windows and remaining integration measurements, critical targets, protected
merge and actual-main publication are still outstanding.

## Location-list narrowing fix and initial new measurement baseline

CONFIRMED: boundary tests found that `Dwarf5LocationLists` silently serialized
`0x100000007` as `0x7` for 32-bit targets. The old production JAR reproduces this
through the real native exporter on both MIPS byte orders. The encoder now
rejects fixed-width values that cannot fit, covering live-range bounds and
absolute addresses inside direct or indirect memory expressions.

The new `LocationListBoundarySmoke` passes 8,358 checks through the existing
`dwarfLocationListsSmoke` task: independent address/LEB decoding, both byte orders,
32/64-bit boundaries, signed-long offsets, long composite expressions, exact
range gaps, cancellation at every observed callback and deterministic retry.
It fails against the old JAR with the intended overflow assertion. The changed
production guard has both executable lines and all four branch outcomes covered.

All 211 JavaExec tasks and 53,432 independent call-value vectors pass in the
fresh build. `Dwarf5LocationLists` measures 119/124 lines and 62/67 branches.
The new production JAR SHA-256 is
`4bd11717ce1ff8e46eba3b0f7091517c4dd90e4e0c82472613f8fd66ca31390c`.
Its JavaExec-only measurement is **23,928/29,792 lines (80.3%) and
18,996/25,888 branches (73.4%)**, with all 255 sources/901 classes retained.
The previous 96.2%/83.7% combined result belongs to the old JAR and is now
**HISTORICAL**. Old execution data must not be silently reused as current-JAR
coverage. Current combined coverage and hosted acceptance need revalidation.

The new native harness passes on x86-64, AArch64, MIPS32 big-endian and MIPS32
little-endian: readelf, LLVM and strict libdwarf validation; compiler-reference
and exported GDB reads before/after a real instruction boundary; deterministic
reruns; unchanged original input/source; and four rejected overflow exports per
32-bit target with existing/absent final artifacts preserved. Native probes use
explicit compiler-fixture models and do not claim Ghidra extraction coverage.
ARM32 is wired into CI but was not run locally because its compiler is unavailable.
Workflow lint passes. The new native runs are behavioral evidence, not added
JaCoCo sessions. Evidence roots under `.forge-work/scratch/coverage-expansion/`:
`location-width-repro`, `location-width-build`, `location-width-native` and
`location-width-old-native`. The previous JAR/build remains intact for auditing.
The 211 raw JavaExec sessions were separately collected and verified against the
new JAR's class IDs/probe lengths. The source snapshot binds to `6fa6a270`; the
build receipts retain their original checkout commit `7d5c1152` because the fix
was tested before committing. Verification is retained in
`location-width-javaexec-verification/`, with no old-JAR sessions admitted.

## Historical completed Windows job verification (previous JAR)

CONFIRMED: the `windows-host` job in run `43991284160` passes at PR head
`6bf2352c` (tested merge `731fae2d`). Artifact `14291317448` contains 55 raw
sessions from attachment, build-ID installation and host-primitive tests.
Its 411,214-byte archive has SHA-256
`64a07d4ea9f683929e98db24f85e2c788e00a920982d2f5c0c0e8572cb14ea40`.
The independently regenerated report exactly matches the hosted report. Source
provenance is checked against the authenticated merge tree; seven recorded Java
source hashes match the Windows checkout's LF-to-CRLF conversion of those blobs.

The job passes its original admission policy. Today's stronger policy additionally
requires the queued security, backup and privilege controls, so this is not current
hosted acceptance. Revalidating and unioning its raw data with all prior sessions
gives 1,912 distinct sessions with **no additional covered lines or branches**.
The percentages and remaining critical gaps below are unchanged. Evidence is in
`.forge-work/scratch/coverage-expansion/hosted-windows-43991284160/`.

## Queued Windows privilege readback checks

PRESENT, UNVERIFIED on Windows: commit `5de11c17` adds thirteen
`WindowsPrivilegeReadbackControls`
controlled failures to the existing isolated privilege probe. Each case first
opens a real Windows x64 token scope with an already-owned privilege. Only the
subsequent readback replies are changed: sizing status/error and length bounds,
read errors, returned lengths, privilege counts, duplicate entries and a missing
entry. No platform flags are spoofed and no missing privilege is granted.

Each case requires the intended rejection, exactly one injected fault, an
independent native query proving unchanged token attributes, a successful retry,
and restoration when the real scope closes. Warmed process handle counts must
remain equal. These controls do not claim constructor or adjustment-failure
coverage. Both explicit Windows compilation harnesses include the new helper;
the coverage harness requires its full behavioral receipt in the existing
privilege session, retaining eight direct host-primitive JVM sessions.

CONFIRMED locally: Java 21 compilation of all six sources used by the PowerShell
attachment harness and all 281 coverage-policy tests pass. The first local
policy run failed because its test imported an incorrect module filename; the
corrected run is retained separately in
`.forge-work/scratch/coverage-expansion/windows-privilege-harnesses-preflight-2f181/`.
Native Windows execution remains pending. No new probes are admitted and the
verified coverage totals below are unchanged.

## Current unreachable local-definition checkpoint

CONFIRMED: commit `1682df53` adds `UnreachableLocalDefinitionSmoke` through
`localDefinitionFlowSmoke`. Sixteen real Ghidra ProgramDB fixtures cover x86-64
and AArch64, 32/64-bit locals, low/above-4-GiB addresses, and dead predecessor
blocks or dead cycles. Every byte is decoded into actual instructions; the
saved function body explicitly retains the unreachable blocks. A pointwise
oracle requires unavailable locations before the real definition completes
and throughout dead blocks, with valid locations at the reachable join/return.
An unreachable recorded definition and an external entry into the previously
dead block both cause refusal. Removing the extra entry restores the original
proof. Extraction leaves saved program state and machine bytes unchanged.

The focused run passes 808 new assertions and 508 existing local-definition
checks. Four compiled faults trigger intended behavioral assertions: initializing
dead blocks as reachable, letting a dead predecessor suppress a live value,
publishing the definition before execution, and assigning locations to unvisited
blocks. No production source/JAR changes or new emitted-DWARF/debugger claims.

The verified JVM adds three binary/location branch outcomes. All prior raw
receipts, hashes and class/session identities were rechecked before unioning.
`RegisterDefinitionFlow` now measures 169/171 lines and 208/263 branches.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,857 distinct sessions | 28,665 / 29,790 (96.2%) | 21,665 / 25,884 (83.7%) |
| Binary/location | 18,454 / 19,201 (96.1%) | 15,583 / 18,732 (83.2%) |
| File/validation | 6,485 / 6,677 (97.1%) | 3,701 / 4,250 (87.1%) |

Evidence: `.forge-work/scratch/coverage-expansion/unreachable-local-definitions-2f181/`
and `unreachable-local-mutations-2f181/`. Mutant probes are excluded and compiled
mutant classes removed after verification. All 255 production sources/901 classes
remain included. **Still incomplete:** 1,276 binary/location and 124 file/validation
branch outcomes for the critical targets, current hosted acceptance, protected
merge and actual-main publication. The queued Windows security/backup controls
remain unverified on their native host and contribute no measured coverage yet.

## Earlier function relationship and class witness checkpoint

CONFIRMED: commit `e0dd5325` adds `ScopeRelationshipBoundarySmoke` through
`functionRelationsSmoke`. The focused run passes 22 boundary assertions and
13 existing checks. Shared external targets retain exact saved identities;
same-named declarations cannot substitute for one another. A shuffled chain
of 65,536 edges retains every edge, evidence string and canonical order. A
larger graph and a long cycle within the capacity limit are rejected.
Caller-owned collections cannot change admitted graphs or class ownership.
Class layout inference requires an actual object-parameter witness; ordinary
pointer parameters, scalar receivers and same-named unions do not establish it.
Explicitly saved layout remains valid without an inferred receiver.

Seven compiled mutations fail their intended behavioral assertions: ignoring
origin or endpoint presence, allowing two saved IDs for an endpoint, admitting
excessive graphs or cycles, accepting unwitnessed layout inference, and accepting
a union as a class structure. These are pure Java model checks; production
source/JAR bytes are unchanged and no new native/debugger claim is made.

The verified session adds one line and eight critical branch outcomes. All
prior raw receipts, hashes and class/session identities were rechecked.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,856 distinct sessions | 28,665 / 29,790 (96.2%) | 21,662 / 25,884 (83.7%) |
| Binary/location | 18,454 / 19,201 (96.1%) | 15,580 / 18,732 (83.2%) |
| File/validation | 6,485 / 6,677 (97.1%) | 3,701 / 4,250 (87.1%) |

Evidence: `.forge-work/scratch/coverage-expansion/scope-relationship-boundaries-2f181/`
and `scope-relationship-mutations-2f181/`. Mutant probes are excluded; disposable
mutant classes were removed after verification. All 255 production sources/901
classes remain in the denominator. **Still incomplete:** 1,279 binary/location
and 124 file/validation branch outcomes for the critical targets, current hosted
acceptance, protected merge and actual-main publication. No full JavaExec rerun
or new Windows validation is claimed for this increment.

### Queued Windows backup stream failure validation

PRESENT, UNVERIFIED on Windows: commits `ef3cd584` and `824e263f` add 20 backup-stream
failure controls through the existing native Windows host primitive suite.
Actual Windows x64 admission happens before any injected replies. The controls
forward real file/context operations and test open/read errors, signed and
excessive read counts, invalid stream headers and UTF-16 names, premature EOF,
incomplete low/high seek results, cancellation and reported cleanup errors.
Aborting the backup context and closing its handle are independently counted;
a reported abort/close failure is injected only after the real release succeeds.
Each case requires the intended failure, one injected fault, unchanged payloads
and metadata, balanced native lifetime and a successful retry.

The native Python harness creates the owned alternate stream and independently
hashes all four fixture payloads before and after the JVM. Java inspects base
files through the production backup API; it does not construct colon-bearing
ADS Paths, which its Windows provider rejects. Admission requires the external
payload-preservation receipt as well as the Java case results.
Positive controls inspect an actual alternate data stream and an empty file.
A buffered-read control splits bytes actually returned by Windows into replies
of at most seven bytes, requiring the exact same inventory as normal reads.
The suite now requires eight direct JVM sessions; complete backup case receipts,
positive controls and stable process handle counts are required for admission.

Java 21 compilation and all 275 coverage-tool tests pass locally. Evidence:
`.forge-work/scratch/coverage-expansion/windows-backup-native-fixture-preflight-2f181/`.
Actual Windows execution is still pending; **no new native probes or percentage
increase are claimed**. The verified union above remains unchanged. Current CI
`43991284160` still runs its earlier revision; these controls are queued with the
security controls and GDB transport fix for the next complete cycle.

### Queued Windows security and CI transport validation

PRESENT, UNVERIFIED on Windows: `1199abc3` adds 18 controlled native security
failure cases, run only after actual Windows x64 host admission. They cover
sizing success/error inconsistencies, small/large/unsigned capacities and returned
lengths, native errors, invalid descriptor controls, inconsistent SACL presence
and changed readback. Each case requires the intended diagnostic, one injected
fault, balanced handles, unchanged source bytes/full security and a passing retry.
The existing isolated Windows suite gains a seventh direct JVM. Hosted coverage
admission requires the complete case inventory and preservation/cleanup receipts.
Local Java 21 compilation and all 267 coverage-tool tests pass; no Windows probe
or coverage gain is claimed before native execution. Evidence:
`.forge-work/scratch/coverage-expansion/windows-security-preflight-2f181/`.

CONFIRMED: CI `43991284160` failed MIPS big-endian preflight while downloading
GDB: all three attempts to GNU failed with network-unreachable errors, before
exporter validation. Commit `617f498f` adds the upstream Sourceware fallback to
bounded transport retries, preserving the exact release pin, size bound,
no-overwrite publication and refusal to retry integrity failures. All 16
downloader tests pass. A controlled primary outage followed by a real Sourceware
request retrieved 24,663,896 bytes matching the unchanged GDB 17.1 checksum.
The owned archive was removed without extraction. Evidence:
`.forge-work/scratch/coverage-expansion/gdb-source-fallback/`. This proves the
fallback locally; the hosted lane still needs a successful subsequent run.

## Earlier variable location contract checkpoint

CONFIRMED: commit `65bf9ae8` adds `VariableLocationContractSmoke` through the
existing `variableStorageSmoke` task. A deterministic point-by-point oracle
checks 32 shuffled lifetime inventories, including gaps, adjacent ranges,
changing storage and unavailable intervals. Sorting must preserve both the
half-open coverage and each interval's analyst evidence. Boundary cases also
reject overlapping lifetimes, incomplete/excessive composite pieces, ambiguous
variable identities and missing evidence. Caller-owned lists cannot mutate
admitted models. Register-piece width mismatches and untranslated Ghidra stack
coordinates remain omitted; omission reasons and diagnostics are retained.

The focused storage smoke passes 5,229 contract assertions and the existing
register-map checks. Eight independently compiled faults fail the intended
assertions: accepting overlap or excessive pieces, requiring every interval to
be available, identifying variables by function spelling, mutable model output,
ignoring register-piece width, inventing a frame-base translation, and replacing
omission reasons. These pure Java model/planning tests make no new native,
debugger or architecture-support claim. Production source/JAR bytes are unchanged.

One verified JVM session adds 12 lines and 27 critical branch outcomes.
`VariableStorageModel` now measures 102/103 lines and 74/78 branches; the
expression planner gains one branch outcome. All prior raw hashes, receipt
bindings and actual class/session identities were rechecked before the union.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,855 distinct sessions | 28,664 / 29,790 (96.2%) | 21,654 / 25,884 (83.7%) |
| Binary/location | 18,453 / 19,201 (96.1%) | 15,572 / 18,732 (83.1%) |
| File/validation | 6,485 / 6,677 (97.1%) | 3,701 / 4,250 (87.1%) |

Evidence is in `.forge-work/scratch/coverage-expansion/variable-location-contracts-2f181/`
and `variable-location-mutations-2f181/`. Mutant probes are excluded. All 255
production sources/901 classes remain included. **Still incomplete:** 1,287
binary/location and 124 file/validation branch outcomes for the 90% critical
targets, full current hosted validation, protected merge and main publication.
No full JavaExec rerun or current Windows result is claimed for this increment.

## Earlier companion observation and recovery checkpoint

CONFIRMED: commit `351e0f6e` preserves the existing
`CompanionPublicationFailureSmoke` byte-for-byte and adds the separate
`CompanionObservationRecoverySmoke` through the existing publisher smoke task.
The final focused run passes 68 new assertions, the publisher smoke and all
111 existing publication failure cases. The new cases use actual owned files
to distinguish inode replacement, size changes with restored timestamps, and
timestamp-only changes during observation. They also reject changed content or
a directory substituted before publication, and restore the prior generation
when the next stage disappears after the first file is installed.

Five independently compiled faults fail the intended assertions: ignored
identity, size or timestamp changes, ignored prepublication content changes,
and skipped restoration of a backup whose replacement was never installed.
Mutant probes are excluded. The final two verified JVM sessions add two covered
lines and six file/validation branch outcomes. `CompanionArtifactPublisher`
now measures 155/164 lines and 88/92 branches. No production code changed.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,854 distinct sessions | 28,652 / 29,790 (96.2%) | 21,627 / 25,884 (83.6%) |
| Binary/location | 18,441 / 19,201 (96.0%) | 15,545 / 18,732 (83.0%) |
| File/validation | 6,485 / 6,677 (97.1%) | 3,701 / 4,250 (87.1%) |

Evidence is in `.forge-work/scratch/coverage-expansion/companion-observation-recovery-2f181/`
and `companion-observation-mutations-2f181/`. An intermediate local test-name
collision was corrected before push; its superseded measurements are not
included. The original failure task and mutation-harness references are intact.
All 255 production sources/901 classes remain included. **Still incomplete:**
1,314 binary/location and 124 file/validation branch outcomes for the 90%
critical targets, current hosted validation, protected merge and main publication.
This increment does not claim a new full JavaExec run, Windows run, native
producer validation or debugger result. CI `43991284160` remains active at
`6bf2352c`; subsequent local test commits await the next cycle.

## Earlier Linux cohort and inheritance admission checkpoint

CONFIRMED: the completed Linux artifact from run `43952501473` has been
reverified against its authenticated merge-source tree and historical admission
policy. All 821 raw JVM sessions reproduce the original layer reports with the
current production JAR. The recorded harness hashes in 63 behavioral receipts
match 81 authenticated source files. Fifty-one sessions were already present;
their raw bytes match and they are counted only once. This adds 99 covered lines
and 147 branch outcomes, including the completed GUI loader/unwind workflows.
The current hosted admission policy has not been relaxed. The historical run
still failed its required gate because of the MIPS QEMU collision.

Commit `e6bfc25e` adds inheritance evidence boundary tests to the existing
`inheritanceModelSmoke` task. They accept exactly 65,536 entries, reject an
additional entry, preserve semantic declaration order independently of identity
order, and preserve admitted evidence after caller mutation. They also check
bounded identities/provenance and exact, non-wrapping vtable address/file ranges.
These are pure Java model tests, not claims about a real program with that many
bases. The existing inheritance model and expression smokes also pass.

Six independently compiled faults fail the intended behavioral assertions:
both excessive model capacities, sorting by parent identity, mutable admitted
evidence, and unchecked virtual-address/file-offset addition. Mutant execution
data is excluded. Production source and JAR bytes remain unchanged. The verified
new session adds two lines and 26 critical branch outcomes; `InheritanceModel`
now measures 95/95 lines and 115/118 branches.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,852 distinct sessions | 28,650 / 29,790 (96.2%) | 21,621 / 25,884 (83.5%) |
| Binary/location | 18,441 / 19,201 (96.0%) | 15,545 / 18,732 (83.0%) |
| File/validation | 6,483 / 6,677 (97.1%) | 3,695 / 4,250 (86.9%) |

All 255 production sources/901 classes remain included. Evidence is under
`.forge-work/scratch/coverage-expansion/hosted-linux-43952501473/` and
`inheritance-admission-checked-2f181/`, with mutation evidence in
`inheritance-admission-mutations-2f181/`. The earlier inheritance admission run
predates the stronger declaration-order assertion and is not included.

**Still incomplete:** 1,314 binary/location and 130 file/validation branch
outcomes are needed for the 90% critical targets. Updated hosted validation,
protected merge and actual-main publication remain outstanding. This increment
does not claim a new full JavaExec run or Windows validation. CI run
`43991284160` is validating pushed commit `6bf2352c`; the subsequent test commit
is local while that run continues.

## Earlier retained split-source build-ID workflow

CONFIRMED: commits `09cfc855` and `31ee8ee2` add the real Linux build-ID
installation lifecycle to the x86-64 non-PIE multifile integration workflow.
Fresh headless single/split/repeat exports pass independent GNU/LLVM/pinned strict
checks, deterministic reruns, semantic comparison and compiler/sidecar GDB
checks. The source binding controls still pass. The new workflow then installs
the split export using `LinuxBuildIdHost`, verifies an idempotent repeat, updates
to single source and back to split source, and explicitly removes registration.

All three installed generations pass the production supervised validator.
Four GDB workflows prove automatic build-ID discovery, source stepping between
two functions, the expected global value and normal exit, then lack of source
discovery after removal. Selected export inputs are temporarily unavailable and
source substitution disables fallback to the original export location. Retained
generation paths remain explicitly usable, including when CI places them below
the export fixture. All retained generation bytes survive updates and removal.
Changes to every retained dependency (one manifest and eleven parts) are refused
without changing registration; test changes are restored afterward.

The first standalone run passed. The first full rerun exposed an overly broad
test-only GDB substitution rule that also hid nested retained sources; its
incomplete collection is excluded. The corrected full rerun passes at
`build/test-results/multifile/x86_64-exec-p9sor8eh`. All **261 coverage-tool tests**
pass, including five new receipt-admission tests. No production bytecode changed.
The installed Ghidra JAR/native metadata were restored after local validation.

The latest verified union admits **18 JVM sessions** from the corrected full
run: seventeen real build-ID operation/refusal processes and one source-binding
probe. Its headless exporters are behaviorally checked but not instrumented by
this harness. The union gains four lines/one branch in `BuildIdInstallation` and
two branches in `ArtifactValidationBinding`. All prior raw hashes, receipts and
actual Java class/session identities were rechecked.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,081 sessions | 28,549 / 29,790 (95.8%) | 21,448 / 25,884 (82.9%) |
| Binary/location | 18,347 / 19,201 (95.6%) | 15,388 / 18,732 (82.1%) |
| File/validation | 6,480 / 6,677 (97.0%) | 3,691 / 4,250 (86.8%) |

Evidence is in `.forge-work/scratch/coverage-expansion/build-id-multifile-checked-2f181/`.
All 255 sources/901 classes remain measured. **Still incomplete:** another 1,471
binary/location and 134 file/validation branch outcomes are needed for the 90%
critical targets, followed by updated hosted validation, protected merge and
actual-main publication. No full JavaExec rerun, Windows result or new mutation
claim is made for this increment.

Historical CI run `43952501473` is now complete: its x86-64 lane and all Windows
jobs passed; the known MIPS big-endian QEMU collision prevented the required
gate and combined publication. The Linux raw artifact `14285999979` has been
downloaded within budget (5,561,709 compressed / 25,762,060 extracted bytes;
SHA-256 `8c1323313630c1cadb51fd8829e1a24030f06897946b3aa4fbc9a6ba784e359d`).
Its report identifies the same production JAR and 821 sessions. The newer
checkpoint above verifies and admits the distinct sessions; its older cohort
still lacks newly required suites and cannot establish current hosted acceptance.

## Earlier artifact-pair failure boundaries

CONFIRMED: commit `b5edd09e` adds 63 real owned-filesystem assertions to the
existing `artifactPairPublisherSmoke` workflow. It verifies callback admission,
cross-directory staging refusal, cleanup after each writer fails, and two
exclusive-rollback cases where another writer replaces or removes the first
installed artifact before the second installation collides. Concurrent files
remain untouched, the caller-owned staging files remain available, and the
primary failure retains the cleanup failure as a suppressed exception.

A separate case replaces the newly installed artifact with a nonempty directory
and then interrupts publication. Failed restoration preserves the concurrent
directory, unchanged original source, and the original artifact's backup bytes,
identity and timestamp. Disposable staging files are removed. These actions
operate only on the test's owned temporary files and are cleaned up afterward.

The focused Linux run and existing publisher smoke passed against unchanged
production bytecode. Four separately compiled mutations failed their intended
behavioral assertions: deleting a concurrent artifact, dropping the restoration
error, discarding the recovery backup, and leaking the source staging file.
Mutation probes are not admitted to coverage. Windows execution of the new
cases remains for the updated hosted cohort; no new ELF/DWARF/GDB claim is made.

`ArtifactPairPublisher.java` now measures **143/145 lines and 58/66 branches**.
The verified raw union gains 7 lines and 8 branch outcomes, preserving all 255
sources/901 classes. Evidence, exact test-source snapshots, mutation receipts and
class/session verification are under
`.forge-work/scratch/coverage-expansion/artifact-pair-failures-2f181/` and
`artifact-pair-mutations-2f181/`. Every prior raw execution hash and collection
receipt was rechecked before combining the measurements.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,063 sessions | 28,545 / 29,790 (95.8%) | 21,445 / 25,884 (82.9%) |
| Binary/location | 18,347 / 19,201 (95.6%) | 15,388 / 18,732 (82.1%) |
| File/validation | 6,476 / 6,677 (97.0%) | 3,688 / 4,250 (86.8%) |

**Still incomplete:** 1,471 binary/location and 137 file/validation branch
outcomes remain before both critical groups meet 90%. The updated hosted cohort,
protected merge and actual-main publication remain outstanding. This focused
filesystem increment does not claim a full JavaExec rerun or public badge update.

## Earlier type-graph contract boundaries

CONFIRMED: commit `d6c36ae8` adds 6,223 assertions to the existing
`typeGraphSmoke` task. The new tests exercise each half-open bit-field interval
for 1/2/4/8-byte component storage, signed-integer overflow boundaries, meaningful
value size versus floating ABI padding, hidden-return/object-parameter roles,
required model fields, recursive references, and immutable canonical ownership.
These are native-independent model contracts, not claims that very large model
boundary values describe an actual Ghidra type or a debugger-tested output.

The focused run compiles the current test sources against the unchanged
`2f18126b...` production JAR and passes the new checks plus existing declaration
and program-model tests. Five separately compiled mutations are rejected by
their intended assertions: overflowing the bit-field offset sum, allowing integer
padding, using padded object width for meaningful value size, allowing a dual
hidden-return/object role, and exposing the mutable type index. Mutation runs
are excluded from measured coverage.

Current `TypeGraph.java` coverage is **146/146 lines and 118/118 branches**.
The verified raw union gains **12 lines and 33 branch outcomes**. All prior raw
execution hashes and collection receipts were rechecked, followed by actual Java
class/session verification. Evidence is in
`.forge-work/scratch/coverage-expansion/type-graph-boundaries-2f181/`, with mutation
receipts in `type-graph-mutations-2f181/`. The normal Gradle task already invokes
the new test; no production logic or measurement exclusions changed.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,062 sessions | 28,538 / 29,790 (95.8%) | 21,437 / 25,884 (82.8%) |
| Binary/location | 18,347 / 19,201 (95.6%) | 15,388 / 18,732 (82.1%) |
| File/validation | 6,469 / 6,677 (96.9%) | 3,680 / 4,250 (86.6%) |

**Still incomplete:** 1,471 binary/location and 145 file/validation branch
outcomes remain before both critical groups meet 90%. Full updated hosted
validation, protected merge and actual-main publication remain outstanding.
This focused pure-model increment does not claim new native/GDB validation or
a full JavaExec rerun. All 255 sources/901 classes remain in the denominator.

## Earlier true-entry and alias integration measurement

CONFIRMED: commit `d943783f` instruments the existing real function-entry shell
oracle without changing its exporter, fixtures or GDB assertions. Each mode
measures six analyzer JVMs: non-PIE and PIE, each with baseline, rebase and repeat.
The alias mode additionally checks analyst secondary symbols. The real Ghidra
installation remains the source of the measured production JAR; single-use
adapters inject JaCoCo only into each analyzer JVM. Incomplete shell workflows
cannot finalize a coverage collection.

All **12 actual headless exports** passed with the current `2f18126b...` JAR.
GNU/LLVM/pinned strict validation, original preservation and byte-identical
repeats passed. GDB checks true function-entry breakpoints, every body range,
absence of function/source ownership in gaps, backward branches into earlier
body addresses, parameter values, global writes, source stepping and exit zero.
The non-PIE strict-checker frame diagnostics were corroborated against the
original input; no uncorroborated errors were accepted. Aliases also passed the
independent ELF symbol check. Both modes are now required by hosted admission.

The first local attempt failed because the shared Ghidra script cache contained
Java 25 bytecode while the selected runtime was Java 21. It contributes no probes.
A fresh run used isolated application settings/cache under the storage guard's
temporary directory, retained Java 21, and restored the installed extension JAR
after completion. This did not require a production or baseline change.

The coverage-tool suite passes **256 tests**, including five new admission tests
with negative controls for missing cases, wrong hosts/layers, missing validators
or GDB receipts, incorrect aliases and inconsistent repeat/rebase identities.
These synthetic receipt controls are not treated as runtime behavior evidence.

The verified raw union adds **8 lines and 8 branch outcomes** across 12 sessions:
8 lines/6 branches in the exporter, plus one branch each in equate reservations
and coverage claims. Latest evidence is under
`.forge-work/scratch/coverage-expansion/function-entry-java21-2f181/`, including
`provenance/verification.json`, `measurements.json`, `verified/`, and `union/`.
Every prior execution hash/collection and actual Java class/session identity was
rechecked before union. All 255 sources/901 classes remain in the denominator.

| Scope | Lines | Branches |
| --- | --- | --- |
| Overall, 1,061 sessions | 28,526 / 29,790 (95.8%) | 21,404 / 25,884 (82.7%) |
| Binary/location | 18,335 / 19,201 (95.5%) | 15,355 / 18,732 (82.0%) |
| File/validation | 6,469 / 6,677 (96.9%) | 3,680 / 4,250 (86.6%) |

**Still incomplete:** the critical groups need another 1,504 binary/location and
145 file/validation branch outcomes to reach 90%. The updated hosted cohort,
protected merge and actual-main publication remain outstanding. These are local
diagnostic measurements, not hosted acceptance or a refreshed public badge.

## Earlier native-producer failure measurement

CONFIRMED: the existing 28-case isolated producer-failure suite now passes against
the current `2f18126b...` production JAR and verified pinned libdwarf 2.3.2 native
pair. Its earlier local result used production JAR `3021d43e...` and correctly
could not contribute to the current union. This was a measurement refresh, not
a newly discovered upstream failure or a production change.

The shim compiles against the three exact headers extracted from the authenticated
release archive. Normal calls reach the real producer; each configured result
fault is introduced twice, once with an existing final output and once without
one. All 56 fault attempts preserve the original/source, preserve or leave absent
the final output as appropriate, leave no staging file, and finish every allocated
producer handle. All 28 retries are byte-identical to their baseline and pass
GNU/LLVM/pinned strict validation plus actual GDB function/type/source/breakpoint,
input-register, return-value and normal-exit checks. The suite's current admission
oracle confirms every mode, native lifecycle count, header/native/harness hash and
behavioral receipt. These synthetic faults are not claims of upstream defects.

The verified 28 JVM collections add **21 lines and 26 branch outcomes**. The
1,049-session diagnostic union measures **28,518/29,790 lines (95.7%) and
21,396/25,884 branches (82.7%)**. Binary/location reaches 18,327/19,201 lines
(95.4%) and 15,348/18,732 branches (81.9%). File/validation remains 96.9% lines /
86.6% branches. Both critical branch targets and the updated hosted/protected-main
requirements remain incomplete. All 255 sources and 901 classes remain included.
No historical-JAR execution data was mixed into this result.

Evidence: `producer-failures-current-2f181/` under guarded coverage-expansion
scratch retains focused Java compilation, source/header provenance, real shim,
28 validated output pairs, raw collection, regenerated report and the latest
`union/`. Verification rechecks all prior raw execution hashes and collections.
Drivers are `run-producer-failures-current-2f181.py` and
`verify-producer-failures-current-2f181.py`. No full JavaExec rerun, new mutation
run, or hosted acceptance is claimed by this refresh; existing tests/admission
source code are unchanged.

## Call-site admission and ARM dynamic interval boundaries

CONFIRMED: 1,021 verified sessions now measure **28,497/29,790 lines (95.7%)
and 21,370/25,884 branches (82.6%)**. Binary/location reaches 18,306/19,201
lines (95.3%) and 15,322/18,732 branches (81.8%). File/validation remains
6,469/6,677 lines (96.9%) and 3,680/4,250 branches (86.6%). The denominator
still includes all 255 sources and 901 classes. Both critical 90% branch targets
and full updated hosted/main acceptance remain outstanding.

The existing call-site plan smoke adds 57 checks for identity validation,
global instruction/return-key uniqueness, discontiguous owner boundaries,
ordinary recursion versus excluded self-tail entries, ELF32 return-address
limits, hidden return-storage formals, immutable input snapshots and stable
argument/function ordering. It passes 69 checks total. Four compiled mutations
are caught by behavioral assertions: omitted ELF32 return width, hidden-return
refusal, duplicate-return refusal and argument sorting. `CallSitePlan.java` now
has all 60 executable lines and all 86 branch outcomes measured. These are pure
Java admission/model checks before native production, not a debugger claim.

ARM mode-symbol tests add an independent byte-interval oracle for unnamed dynamic
NOTYPE/FUNC/IFUNC definitions. Six interval populations, six permutations, three
symbol types and two query widths produce 6,588 cases. They exercise touching,
separated, bridged, nested and equal-start ranges, unknown sizes extending to the
section end, empty end labels and Thumb-bit normalization. Every query checks
exact retained mode-symbol identity or the specific dynamic-conflict omission;
every table remains byte-identical. The new matrix passes 13,284 assertions;
the entire existing smoke passes 13,515. Three compiled mutations are caught:
treating adjacency as overlap, shrinking a containing interval, and retaining
the Thumb tag in a code address. These byte-built ELF tests do not execute ARM
instructions or add an architecture support claim.

The two matching-production-JAR sessions add 15 lines and 47 branches to the
preceding union. Mutation execution is unmeasured. Every prior raw execution
hash/native collection is revalidated before union. No production source or JAR
changed. Evidence roots under guarded coverage-expansion scratch:
`call-site-plan-boundaries-2f181/`, `arm-dynamic-intervals-2f181/`,
`call-site-plan-mutations-2f181/`, `arm-dynamic-intervals-mutations-2f181/`, and
`call-and-arm-boundaries-2f181/union/`. The tests remain in their existing Gradle
smoke tasks; no full JavaExec rerun or hosted acceptance is claimed this turn.

## Split-source binding and recovery-request boundaries

CONFIRMED: the latest diagnostic union has **1,019 sessions, 28,482/29,790
lines (95.6%) and 21,323/25,884 branches (82.4%)**. File/validation reaches
6,469/6,677 lines (96.9%) and 3,680/4,250 branches (86.6%). Binary/location
remains 18,291/19,201 lines (95.3%) and 15,275/18,732 branches (81.5%). Both
critical 90% branch goals, updated hosted validation and protected main
publication remain incomplete. All production sources/classes remain measured.

The existing x86-64 multi-file integration cases now run a read-only attachment
binding probe on owned copies of their actual exporter outputs. It binds the
manifest and every source part, including an index retained under a private name.
For every dependency it rejects changed bytes with restored mtime, missing files,
and identical bytes with a new inode. It also rejects a valid bundle describing
a different input, a valid bundle whose source names differ from DWARF, and a
source part changed between inventory validation and host observation. The host
uses actual Linux file identities but controlled metadata; this is not privileged
attachment approval. New hosted admission preserves that distinction and requires
all dependency checks and protected-input/log hashes.

A fresh current-JAR x86-64 executable passes the existing single/multi/repeat
export journey, semantic comparison, unchanged input/project checks, strict
libdwarf, GNU/LLVM and actual GDB source-stepping checks. The binding probe passes
79 assertions across twelve dependencies. Three compiled mutations are rejected
by their intended behavioral assertions: omitted dependency recheck, omitted input
binding and omitted post-observation inventory verification. The new measured
session adds nine lines and seven branches; the headless export processes were
not instrumented in this run. Coverage-tool schema tests pass 251 checks.
Evidence: `source-bundle-binding-2f181/`, `source-bundle-binding-mutations-2f181/`
and `build/test-results/multifile/x86_64-exec-6y1joqf5/`. The temporary installed
JAR/native metadata are restored and verified. This local run covers executable
layout; the existing hosted task also invokes the probe for PIE/rebased PIE.

Recovery-request smoke tests add 100 assertions across initial/refresh modes and
prepared/committed receipts. They reject malformed or absent pinned hashes,
missing/unknown roles, relative/oversized path strings, excessive UTF-8 transport,
mismatched receipt roles or selected path, and recursive recovery receipts.
Exact path-length boundaries and both accepted pinned hashes have positive
controls. The long paths are transport inputs only, never files to create.
Receipt bytes and absent recovery outputs are checked after each refusal.
All 304 smoke assertions pass. Four compiled mutations are caught: omitted
committed-hash syntax, transport limit, receipt-path agreement and recursive
recovery refusal. These admission-only tests claim no native transaction approval.
Their verified session adds two lines and nine branches. Evidence:
`recovery-invocation-boundaries-2f181/` and `recovery-invocation-mutations-2f181/`.
Both new unions revalidate previous execution hashes and native collections;
mutation probes are excluded and production source/JAR bytes are unchanged.

## Sectionless validation, hosted AArch64 and recovery publication

CONFIRMED: the diagnostic union now contains 1,017 verified sessions with
**28,471/29,790 lines (95.6%) and 21,307/25,884 branches (82.3%)**.
Binary/location has 18,291/19,201 lines (95.3%) and 15,275/18,732 branches
(81.5%). File/validation has 6,458/6,677 lines (96.7%) and 3,664/4,250
branches (86.2%). All 255 sources and 901 production classes remain included.
Both critical branch targets and updated hosted/main acceptance remain pending.
Evidence paths below are relative to the guarded coverage-expansion scratch root.

The existing sectionless attachment-validator harness now measures its two native
Java processes and checks their independent validator receipts before completing
collection. A current x86-64 sectionless fixture passes two deterministic headless
exports, unchanged-input checks, strict/GNU/LLVM validation and actual GDB source,
type, breakpoint and stepping checks. Three inherited frame diagnostics are
corroborated against original program-header bytes. Exclusive evidence publication
refuses an existing destination without changing it. Parameters are optimized out;
no variable-value claim is made. The metadata host is a test host, not privileged
attachment approval. The two measured validator sessions add 15 lines and six
branches. `sectionless-validation-2f181/` retains results and verified raw data;
247 coverage-tool tests pass. Updated hosted policy requires this collection;
older hosted runs cannot satisfy the new requirement.

The completed AArch64 job in run `43952501473` supplies artifact `14282028785`.
Its authenticated ZIP digest, successful job, historical source merge/harness
hashes and current production class identities verify. Twelve measured sessions
cover stack transitions in executable, PIE and rebased PIE cases, with compiler
and exported GDB values, stepping, complete range/availability assertions,
input preservation and deterministic repeat output. Regeneration matches the
published artifact report. This adds one line and one branch; the historical
artifact lacks the newly required bitfield collection and does not establish
current full hosted acceptance. Evidence: `integration-aarch64-43952501473/`.

Five new real-filesystem recovery-selection failure cases cover directory identity
failure, cancellation before writing, changed staging bytes, replacement of the
staging directory and replacement of the staged file during cleanup. Each refuses
transaction entry and preserves the original target/backup; unverified replacement
files survive, and cleanup failures remain attached to the primary failure.
These cases use the existing test host/validator seam, not a privileged host
claim. The operation smoke passes 274 assertions including 51 new assertions.
Two separately compiled mutations are caught by behavioral assertions: accepting
changed staged content and deleting a replacement without rechecking identity.
Mutants contribute no probes. Production source and JAR hashes are unchanged.
`recovery-publication-final-2f181/` contains the final one-session collection and
verified union; `recovery-publication-mutations-2f181/` retains the mutation
results. This session adds nine lines and eight branches. Earlier superseded
four-case runs are excluded. No full JavaExec rerun is claimed; the tests remain
wired into the existing operation smoke task for the next hosted cycle.

## Current interactive GUI and ARM aggregate boundaries

CONFIRMED: the existing Linux Script Manager journey passes with the current
production JAR in a local validation package, using actual Swing interactions
on owned Xvfb/Openbox. It verifies script discovery, export choices, cancellation,
report presentation, all four source-context choices, split/repeated/default
source layouts, attachment preparation and original preservation. Nine output
pairs pass structural checks and GDB name/type/source lookup, next/step and
normal-exit assertions. Inherited frame diagnostics remain separately
corroborated; none is silently ignored. This run does not claim Windows, the
privileged GUI attachment mode, or a published release package.

The first attempt stopped during geometry setup because the cached headless JDK
lacks `libawt_xawt.so`. The successful run uses the installed desktop Java
21.0.13.0.3, retains its version, verifies the exact current production JAR and
restores the original cached installation byte-for-byte. Its one main-JVM
collection passes raw class/session verification; geometry, report CLI and
attachment-helper children remain explicitly unmeasured. Evidence is under
`gui-desktop-current-2f181/`, with raw desktop outcomes in
`build/test-results/gui-script-manager/run.gWy9yZCF/` and the bound oracle log in
`build/test-results/gui-coverage/gui-script-manager-twrswbkv/`. The failed
headless-JDK attempt contributes no coverage. This adds 278 lines and 86 branch
outcomes to the preceding verified union.

The existing ARM HFA allocation task now adds 48 real ProgramDB scenarios:
mixed floating widths, interior/trailing padding, bit fields, extended floats,
one/five-member aggregates, nested excessive member counts, deep typedefs and
deep structures. Both byte orders and four/eight-byte floating members retain
exact accepted register pieces, unchanged saved storage and prompt cancellation.
All 216 scenarios and 948 assertions pass on Java 21. The first fixture wrongly
expected deep typedefs to exhaust recursive member traversal; Ghidra flattens
their base type. The corrected fixture asserts that API behavior and preserves
the accepted HFA. Actual nested structures separately test the traversal limit.
An isolated mutation omitting that limit compiles and is rejected by the
deep-structure behavioral assertion. It contributes no coverage, and production
source/JAR hashes are unchanged. Evidence is under
`arm-hfa-boundaries-final-2f181/` and `arm-hfa-depth-mutation-2f181/`; earlier
driver/fixture failures are retained separately and excluded.

The verified 1,001-session diagnostic union measures **28,446/29,790 lines
(95.5%) and 21,292/25,884 branches (82.3%)**. Binary/location is 18,290/19,201
lines (95.3%) and 15,272/18,732 branches (81.5%). File/validation is 6,434/6,677
lines (96.4%) and 3,652/4,250 branches (85.9%). All 255 production sources and
901 classes remain included. The two critical 90% branch targets, full updated
hosted validation, protected integration and main publication are still pending.

The separate compressed-output GUI journey also passes with the current JAR,
strict/GNU/LLVM validation, compressed-section flags, GDB stepping and unchanged
inputs. Its raw session verifies successfully but adds no new probes beyond the
above union: 1,002 sessions retain the same percentages. Evidence is under
`gui-compressed-current-2f181/`. This demonstrates the compressed UI workflow;
it is not counted as an increase in coverage or as completion of other GUI modes.

## Verified privileged Linux attachment sessions

CONFIRMED: 51 measured production attachment/recovery sessions from CI run
`43952501473`, artifact `14277061512`, pass current receipt, class-identity and
raw-probe verification. These are completed steps of the still-running x86-64
job at `74436b6e`; they are not acceptance of the full job or newer local tests.
The authenticated artifact digest and merge-tree/source provenance are retained
under `hosted-attachment-43952501473/` in bounded scratch. Its source merge tree
matches the recorded head, and its production JAR matches the current 901-class,
255-source denominator. No percentages were added or averaged.

Real privileged Linux execution verifies live validators, debugger discovery,
CRC rejection, consent refusal, cancellation, unchanged backups and rollback
restoration. Eight measured recovery children follow deliberate unmeasured
`Runtime.halt` processes. Their missing shutdown probes are not fabricated.
Strict validator receipts contain no uncorroborated errors; inherited frame
diagnostics retain their original-byte corroboration. The no-build-ID case uses
an intentionally unusual installed basename, `literal λ ;$[quoted].dbg`. The
first verifier incorrectly assumed that basename matched the source artifact;
its failed attempt is retained and excluded. The corrected verifier binds the
installed name to the existing oracle receipt and passes.

The 999-session diagnostic union measures **28,168/29,790 lines (94.6%) and
21,197/25,884 branches (81.9%)**. Binary/location remains 95.3% lines / 81.5%
branches. File/validation reaches **6,433/6,677 lines (96.3%) and 3,652/4,250
branches (85.9%)**. Both critical line targets are now met locally; both 90%
branch targets and the updated full hosted cohort remain outstanding. These
results do not update the published main badge or establish issue completion.

## Validator helper evidence refusals

CONFIRMED: fifteen new Linux executable-helper protocol controls exercise
rejection of helper diagnostics, missing status, inconsistent stdout/stderr
counts, over-limit streams, changed helper/tool bytes, incomplete cleanup,
cancellation status, contradictory exit/signal records and launch failure.
Each control requires the intended refusal and retained evidence state; none
claims that a simulated helper establishes actual native cleanup. They run from
the existing `validatorSupervisorSmoke` task after its real native lifecycle,
cancellation, timeout, output-limit and descendant checks. Windows explicitly
reports these script-specific protocol controls as not run; its real native
supervisor tests remain in place.

The current production JAR passes 270 status-boundary checks, 40 launch checks,
38 native smoke assertions and all 15 new controls. Three isolated mutations
(ignore helper diagnostics, output counters or executable changes) are rejected
by the specific behavioral assertions, not by compilation or class-loading
failures. Mutated classes never contribute coverage. Source/JAR/native-helper
hashes remain unchanged. Evidence in bounded scratch:
`validator-evidence-checked-2f181/`, `validator-evidence-mutations-2f181/` and
their run logs. The first driver wrongly expected at least 40 native smoke
assertions instead of the existing 38; its incomplete collection is excluded.
The corrected full smoke run and raw union verification pass. One new native
Java session adds eight lines and thirteen branch outcomes. The 948-session
diagnostic union measures 28,045/29,790 lines (94.1%) and 21,160/25,884 branches
(81.7%); file/validation rises to 6,310/6,677 lines (94.5%) and 3,615/4,250 branches
(85.1%). The production JAR is unchanged. The measured checkout `fb5645ae` and
committed test snapshot `07d22b94` are recorded separately. The new tests will
run in the existing hosted task; updated hosted acceptance remains unverified.

## Measured packed bit fields through the installed exporter

CONFIRMED: the existing real Ghidra bit-field fixture now measures two exports
per target. The shell oracle still checks one-byte component storage with a
four-byte base integer, exclusive `DW_AT_data_bit_offset`, independent compiler
and Forge GDB values `{a=5,b=17}`, aggregate sizes, normal exits and unchanged
input bytes. Repeat sidecar/source equality is now required for every target.
The harness uses the shared private QEMU socket helper instead of a PID-derived
TCP port. The measurement wrapper changes only launcher selection, preserving
the installed exporter and packaged-native route.

Local x86-64, AArch64, MIPS32 big-endian and MIPS32 little-endian runs pass GNU,
LLVM, strict libdwarf, GDB and repeatability checks. All emulator sockets are
removed after successful runs. These local runs do not claim LLDB results:
LLDB 18 is unavailable locally. Hosted x86-64/AArch64 admission still requires
the actual compiler/Forge LLDB value and layout observations. Both lanes now
require the bit-field collection. Five new receipt tests reject missing
measurement/preservation, nondeterminism, wrong GDB values/exits and matching
but incorrect LLDB offsets. The AArch64 cohort fixture includes both suites;
all 241 coverage-tool tests, actionlint and shell syntax checks pass.

The cached installation lacked its native checksum manifest and held different
supervisor build metadata. The first export correctly refused missing metadata;
a subsequent pre-run check refused the metadata mismatch. Neither failed attempt
contributes coverage. The successful run temporarily used the exact retained
release manifest/metadata after verifying every native binary hash, then restored
the previous installation state and production JAR. Evidence in bounded scratch:
`bitfields-packaged-2f181/`, `bitfields-packaged-2f181-run.log` and
`bitfield-measurement-tests-passing.log`. All eight sessions pass raw union
verification. They add 13 lines and 15 branch outcomes: the 947-session local
union measures 28,037/29,790 lines (94.1%) and 21,147/25,884 branches (81.7%).
Binary/location is 95.3% lines / 81.5% branches, with file/validation unchanged at
94.4% / 84.8%. The measured harness snapshot is `2cc92e88`; the earlier checkout
identity remains recorded separately. The local verifier explicitly excludes
any LLDB/hosted-acceptance claim. Full hosted acceptance and critical coverage
targets remain open.

## Current producer inheritance and vtable-name evidence

CONFIRMED: the existing compiler-backed inheritance and renamed-class harnesses
pass against the current production JAR on x86-64 and QEMU AArch64. Eight target/
role combinations cover executable/PIE, with and without RTTI. Forty name cases
cover readable controls, renamed mangled names, aliases, qualified aliases and
duplicate short names. The compiler reference supplies 48 separate debugger
observations. All six deliberately incorrect fixed/virtual-base models remain
structurally valid and are rejected by runtime GDB assertions.

The production-artifact checks now use `check-dwarfdump.py` with its full native
checker options and original-input corroboration, replacing ordinary dump-output
scans. All 48 positive production artifacts pass strict libdwarf, LLVM, GNU and
GDB checks. Native frame-alignment diagnostics are accepted only when the strict
checker matches them to byte-identical inherited `.eh_frame` and the original's
diagnostics; every artifact has zero uncorroborated errors. The strict parser's
regression controls also pass, including its
historical zero-exit error output. Original input hashes remain unchanged.
This validates a compiler-supplied model through the producer and ELF writer;
it does not claim new Ghidra extraction coverage. All 108 measured JVM sessions
pass raw matching-bytecode verification, adding 144 lines and 80 branch outcomes.
The 939-session diagnostic union measures 28,024/29,790 lines (94.1%) and
21,132/25,884 branches (81.6%). Binary/location reaches its line target at 95.2%,
with 81.4% branches; file/validation remains 94.4% / 84.8%. Neither critical branch
target nor full hosted acceptance is complete. Evidence in bounded scratch:
`inheritance-current-2f181/`, its `-run.log` and `-verification.log`. The first
verification incorrectly required zero total diagnostics instead of checking the
existing corroboration policy; that failed attempt is retained separately and
contributes no coverage measurement.

## Measured equate constants and retained names

CONFIRMED: both existing equate harnesses now collect their production JVM
sessions. The isolated producer runs twice and checks 52 constants with 104 GDB
lookups, including signed/unsigned extrema, unusual widths, type-name collisions
and absence of fabricated addresses. The headless C++ fixture records setup and
two exports, preserves saved analyst renames, and checks 20 constant lookups plus
actual stops at both retained function names and process exit zero. Repeated
sidecars/source are identical; input and saved-project preservation checks pass.
GNU readelf, LLVM verification and the strict libdwarf validator pass.

CI now requires both measured suites. Hosted admission checks session identities
by label and layer, debugger-result hashes, preserved-input hashes, deterministic
generations and observed runtime stops. Six new receipt tests reject omitted
measurement, wrong layers, absent consumer/preservation evidence, changed exports
and incorrect stops. All 236 coverage-tool tests and workflow lint pass.
These are additional measurements of existing behavior, not broader architecture
claims. All five collections' sessions pass raw matching-bytecode verification
and hosted receipt admission. They add 33 covered lines and 27 branch outcomes:
the 831-session diagnostic union measures 27,880/29,790 lines (93.6%) and
21,052/25,884 branches (81.3%). Binary/location is 94.4% / 80.9%; file/validation
remains 94.4% / 84.8%. Critical targets and full hosted acceptance remain unmet.
Evidence: `equates-measured-2f181/`, `equates-measured-2f181-run.log`,
`equate-instrumentation-tests.log` and `equate-actionlint.log` in bounded scratch.
The temporarily installed exporter JAR was restored and its original hash checked.

## Measured build-ID identity refusal controls

CONFIRMED: the existing identity harness now records its 13 child JVM sessions
through the shared collector. Production classes remain included; only explicit
test probe classes are excluded. The positive installation and missing, malformed,
conflicting, reused, aliased and noncanonical identity controls pass on the real
Linux host. Original input hashes remain unchanged. This adds measurement to
existing behavioral checks, not new target support.

CI report generation and hosted cohort admission now require `build-id-identity`.
Admission rejects a model-host claim, missing/unmeasured refusals, failed positive
baseline, unexpected errors and missing input-preservation evidence. Five new
receipt controls join the existing suite: all 230 coverage-tool tests pass in
8.956s, and actionlint passes. The actual 13-session collection also passes this
admission policy and raw matching-bytecode verification.

The 826-session diagnostic union adds three branch outcomes and no new lines:
27,847/29,790 lines (93.5%), 21,025/25,884 branches (81.2%). Critical binary/location
is 94.3% lines / 80.9% branches; file/validation is 94.4% / 84.8%. These remain
below the critical 95% / 90% targets. Hosted run `43952501473` predates this new
required measurement and cannot establish acceptance of the updated policy.
Evidence: `buildid-identity-measured-2f181/`,
`buildid-identity-measured-2f181-verification.log` and
`buildid-identity-instrumentation-tests.log` in the bounded workspace. The manifest
preserves the measured checkout and binds the subsequently committed harness
snapshot `79237f42` separately.

## Current-bytecode Linux build-ID lifecycle and launcher

CONFIRMED: real Linux-host installation, identity and public-launcher checks now
run against the current JAR using private copies of retained export fixtures.
Non-PIE/PIE install, update, idempotence, removal and recovery preserve inputs,
ordinary metadata, visible user xattrs and access ACLs. Fresh GDB processes find
retained source and values while previous export sidecars/source files are hidden.
These are tests of current installation behavior on validated retained inputs,
not a new headless-export or Windows execution claim.

The non-PIE transaction suite passes 173 checks, including 16 intentional process
halts, record/generation corruption, alias refusals and successful recovery after
restoring controlled changes. PIE passes seven lifecycle checks. The public
launcher passes 27 checks with ten GDB observations, including stdin/file
cancellation and metadata preservation. The separate identity suite passes its
13 controls but was uninstrumented in this refresh. Forced-halt processes remain
explicitly unmeasured; recovery sessions are measured normally.

All 207 measured sessions pass raw verification. The 813-session diagnostic
union is 27,847/29,790 lines (93.5%) and 21,022/25,884 branches (81.2%).
File/validation rises to 6,302/6,677 lines (94.4%) and 3,600/4,250 branches
(84.7%). Binary/location remains 94.3% / 80.8%. Full critical-group targets,
hosted acceptance, integration and publication are still outstanding.
Evidence: `buildid-current-2f181/` and `buildid-current-2f181-verification.log`
in the bounded workspace; exact commands, tool hashes, input metadata and probe
class provenance are retained there.

## Current-bytecode source relocation boundary checks

CONFIRMED: four current-JAR sessions exercise source relocation for x86-64
non-PIE/PIE with plain/zlib debug sections. The existing Java fixture checks
malformed section attributes and compression envelopes, exact planned bytes,
deterministic/idempotent output, refusal of nonempty stages and cancellation
through planning, writing and candidate comparison. Independent GNU/LLVM/strict
validation and all eight call-site runtime scenarios pass for each combination.
GDB resolves `cs_leaf` to the new retained-source path and lists its contents.
Input ELF, sidecar and source hashes remain unchanged.

The first added source-path assertion incorrectly used global-symbol lookup for
a file-local function. That attempt failed and is excluded. The passing assertion
uses GDB's line resolution; no production behavior was changed. Retained artifacts
are inputs to current transformation tests, not old execution probes or a claim
that the current Ghidra exporter generated those inputs.

Four verified native-Java sessions add 52 lines and 63 branch outcomes. The
606-session diagnostic union is 27,727/29,790 lines (93.1%) and
20,961/25,884 branches (81.0%). Binary/location is 18,104/19,201 lines (94.3%)
and 15,144/18,732 branches (80.8%); file/validation remains 92.6% / 83.3%.
Both critical targets and full hosted acceptance remain outstanding.
Evidence: `source-sidecar-current-checked-2f181/`,
`source-sidecar-current-checked-2f181-run.log` and
`source-sidecar-current-checked-2f181-verification.log` in the bounded workspace.

## Strict companion validation and current loader measurement

CONFIRMED: `gdb-loader-mappings.py` now runs the strict checker instead of invoking
`dwarfdump` without its checking options. It requires a PASS receipt and validates
inherited frame diagnostics against byte-identical original ELF frame data.
An initial supplementary check without the original correctly rejected inherited
alignment diagnostics. That attempt is retained and is not admitted to the union.
The corrected harness passes non-PIE, PIE and shared-library cases, GNU/LLVM/strict
checks, eight unsafe-path refusals per case, cancellation at every observed
checkpoint, deterministic generation and unchanged protected files.

Live GDB checks confirm relocated function/global addresses, parameter values,
source listing and stepping, repeated load idempotence, cleanup on process exit,
shared-library unload/reload and distinct PIE ASLR biases. Compiler DWARF supplies
the independent input to the production writer/companion generator; these results
do not claim new Ghidra extraction. A separate diagnostic-injection control runs
the real validator, appends a warning while returning zero, and proves the harness
rejects it without changing either ELF. The strict-checker test suite also passes.

Three verified native-Java sessions add 122 lines and 69 branch outcomes. The
602-session diagnostic union measures 27,675/29,790 lines (92.9%) and
20,898/25,884 branches (80.7%). Binary/location is 18,052/19,201 lines (94.0%)
and 15,081/18,732 branches (80.5%); file/validation remains 92.6% / 83.3%.
Neither critical group meets its 95% / 90% target. The denominator is unchanged,
and full hosted acceptance and actual-main publication are still required.
The measured worktree harness was subsequently committed as `4926cec2`; the
manifest preserves the actual checkout commit and separately binds that snapshot.
Evidence: `companion-strict-current-2f181/`,
`companion-strict-current-2f181-verification.log`,
`companion-strict-diagnostic.log` and `companion-strict-checker-tests.log` in the
bounded workspace. The three live fixture trees are recorded in its provenance.

## Current-bytecode saved annotations and failure isolation

CONFIRMED: the complete existing x86-64 non-PIE annotation pipeline passes with
the current production JAR. Independent saved-program reopens retain all 50
comments and 14 equates. Default and source-context exports retain 35 synthetic
lookup constants, preserve executable line mappings, pass GNU/LLVM/strict
validation and GDB source/value checks, and produce identical repeated artifacts.
Seven default and eleven context cancellation stages preserve the previous
outputs and permit recovery. Four invalid/over-budget annotation requests in
each mode also preserve those artifacts.

Real native decompilation failures are checked in all-failed, mixed and empty
selection cases, including single/multiple source files. Failed functions acquire
no invented signature, local or executable source row. Mixed exports retain
usable successful functions; single/multiple source artifacts compare
semantically, and GDB verifies their behavior. Separate constant-width and
retained C++ name checks pass but their child JVMs are not instrumented by these
existing harnesses and are not credited as measured coverage.

All 24 measured sessions in six collections pass raw-bytecode verification.
The 599-session diagnostic union reaches 27,553/29,790 lines (92.5%) and
20,829/25,884 branches (80.5%), meeting the overall numerical targets locally.
Binary/location remains 17,930/19,201 lines (93.4%) and 15,012/18,732 branches
(80.1%); file/validation remains 92.6% / 83.3%. Each critical group's 95% / 90%
target, complete hosted acceptance, protected integration and actual-main
publication remain outstanding. Evidence: `annotations-current-2f181/` and
`annotations-current-2f181-verification.log` in the bounded workspace.

## Current-bytecode instruction and native source context

CONFIRMED: five headless sessions rerun the existing instruction/source-context
pipeline against the same current production JAR. Saved instruction fixtures cover
split, truncated, overridden, unmapped, uninitialized and undecoded observations,
with cancellation at every checked point and identical independent readbacks.
A real instruction-limit decompiler failure exercises native diagnostic collection.
Assembly/p-code modes and trigger/function/export limits preserve executable line
mappings, function inventory and omission diagnostics. Fresh-process source
composition is byte-identical. The cached extension JAR is restored afterward.

Raw collection verification adds 328 lines and 202 branch outcomes. The diagnostic
575-session union covers 27,179/29,790 lines (91.2%) and 20,575/25,884 branches
(79.5%). Binary/location counters are 17,870/19,201 lines and 14,977/18,732
branches; file/validation counters remain 6,182/6,677 and 3,539/4,250. This is
component evidence, not a new production-export or cross-architecture claim.
The broader hosted cohort and critical-group targets remain incomplete.
Evidence: `context-current-2f181/{results,provenance,collections,verified,union}/`
and `context-current-2f181-verification.log` in the bounded coverage workspace.

## Current-bytecode frame encoder and composition verification

CONFIRMED: the existing CFI integration harnesses now have verified execution
against production JAR `2f18126bf76e63325bd0af6b006b6ac2a645e1608b21feeea2ab3b58739138b6`.
Ten encoder cases cover 32/64-bit little/big-endian layouts, large row deltas,
and x86-64/AArch64 non-PIE and PIE. Sixteen composition cases preserve compiler
frame records with explicit, plain, GABI and GNU-compressed inputs. Output is
checked independently by the Python decoder, GNU/LLVM tools, strict libdwarf
validation and compiler-reference GDB backtraces, with deterministic reruns and
input hashes. Missing-frame controls check unwinder selection; AArch64 can still
unwind through debugger heuristics, so missing frames are not claimed to make
every backtrace fail. These tests exercise explicit frame plans and packaging,
not new Ghidra unwind extraction behavior.

The first refresh failed because the selected atomic-capable validator had no
zlib/zstd support. Its incomplete collection is excluded. The successful refresh
uses the existing pinned, compression-capable validation-only libdwarf build;
its source revision, binary/configuration hashes and dependencies are recorded.
No validation warning was waived and no production code changed.

All 104 sessions from five collections pass behavioral and raw-bytecode checks.
The 570-session diagnostic union covers 26,851/29,790 lines (90.1%) and
20,373/25,884 branches (78.7%): 31 lines and 34 branch outcomes beyond the
previous 466-session union. Binary/location coverage is 93.1% lines / 79.9%
branches; file/validation remains 92.6% / 83.3%. All 255 sources / 901 classes
remain in scope. This is not a completed hosted cohort or published acceptance.
Evidence under `.forge-work/scratch/coverage-expansion/`:
`cfi-current-compressed-2f181-{encoder,explicit,plain,gabi,gnu}/`,
`cfi-current-compressed-2f181-collections/`,
`cfi-current-compressed-2f181-provenance/verification.json`,
`cfi-current-compressed-2f181-verified/`,
`cfi-current-compressed-2f181-union/` and
`cfi-current-compressed-2f181-verification.log`.

## Exhaustive location refinement over finite address domains

CONFIRMED: a pointwise oracle now checks how additional storage evidence refines
unavailable lifetime spans. Both input maps are valid, ordered, nonoverlapping
interval lists. Each of four cells can be absent, unavailable, register-backed or
stack-relative; differing cell boundaries exercise clipping and partial overlap.
All 256 by 256 map pairs run at ordinary addresses, above 4 GiB and near the
signed 64-bit boundary: 196,608 cases and 5,535,745 assertions.

The oracle selects expected storage independently at each address. Existing
available locations must win; new unavailable evidence must not replace the
original omission reason; gaps outside the original lifetime must stay absent.
Outputs must remain ordered, disjoint, coalesced and deterministic. This checks
the interval-refinement rule, not new architecture extraction or debugger support.
It runs within the existing stackValueFlowSmoke task; production is unchanged.

All nine selected compiled mutations are detected in 6.835s: overwrite existing
locations, accept unavailable evidence, extend before/after the original span,
drop unavailable prefixes/suffixes, retain a stale cursor, erase existing ranges
when extra evidence is empty, or discard newly proved storage. Mutated execution
is excluded from coverage. Evidence: `storage-refinement-focused.log`,
`storage-refinement-mutations.log` and `storage-refinement-mutations/result.json`
in the bounded workspace.

Baseline62 at `56ef319a` passes 211 JavaExec tasks in 276.770s, 53,432
independent DWARF-expression vectors and 225 coverage-tool tests in 9.031s.
The denominator and production JAR are unchanged. Raw verification attributes
two additional branch outcomes and no additional lines to this matrix; the
independent oracle and mutation detections provide the broader behavioral value.
JavaExec covers 23,859/29,790 lines and 18,818/25,884 branches. The 466-session
diagnostic union covers 26,820/29,790 lines (90.0%) and 20,339/25,884 branches
(78.6%). Binary/location coverage is 92.9% lines / 79.8% branches; file/validation
coverage remains 92.6% / 83.3%. Accepted targets and full hosted acceptance remain
outstanding. Evidence: `javaexec-baseline-62/`, `storage-refinement-javaexec-checked-62/`,
`storage-refinement-current-partial/`, `storage-refinement-hosted-partial-62/`
and `storage-refinement-verification-62.log`.

## Recovery record changes between independent observations

CONFIRMED: the attachment transaction task now changes actual receipt bytes,
inode or metadata between recovery's parsed-record read and its independent
artifact observation. Content changes preserve mtime; identity changes retain
the old inode and reproduce bytes/mode/mtime; metadata changes preserve bytes
and inode. Assertions prove those dimensions are isolated. Initial attachment
and refresh both report RECOVERY_REQUIRED, preserve the changed receipt, retain
the restored target/backups, and publish no recovery record based on mismatched
observations. Explicit receipt reconciliation permits a successful recovery retry.
These are controlled filesystem interleavings, not an adversarial-race guarantee.

Independent expected strings also check bounded recovery diagnostics, controls,
paired/unpaired UTF-16 surrogates and preserved ordinary Unicode, in both modes.
The first test attempt exposed an incorrect test expectation: Java regex matches
Unicode code points while the documented diagnostic sanitizer replaces UTF-16
code units. The oracle now uses explicit expected text; production is unchanged.

The task passes 1,167 assertions, including its existing eight abrupt-process
controls. All nine selected compiled transaction mutants are detected (43.037s).
The five new mutants remove the independent digest/fingerprint checks or the
control/surrogate/length diagnostic guards. Both observation mutants incorrectly
return ROLLED_BACK and fail the expected RECOVERY_REQUIRED assertion. Native
Windows behavior and ELF validation are outside this filesystem test's scope.
Evidence: `recovery-observation-focused.log` (initial failed oracle),
`recovery-observation-validation.log`, and `recovery-observation-mutations/`.
Baseline61 at `70e80ef3` passes all 211 JavaExec tasks in 277.009s,
53,432 independently interpreted expression vectors and 225 coverage-tool tests
(8.889s). Raw collection verification retains the unchanged production JAR and
255 sources / 901 classes. The new cases add one line and six branch outcomes;
`AttachmentTransaction` now covers 264/269 lines and 178/202 branches.

The 466-session matching-bytecode diagnostic union now covers 26,820/29,790
lines (90.0%) and 20,337/25,884 branches (78.6%). Critical file/validation
coverage is 92.6% lines / 83.3% branches. Binary/location coverage is unchanged
at 92.9% / 79.7%. This remains incomplete hosted acceptance, with all original
targets and architecture requirements retained. Evidence:
`javaexec-baseline-61/`, `recovery-observation-javaexec-checked-61/`,
`recovery-observation-current-partial/`, `recovery-observation-hosted-partial-61/`
and `recovery-observation-verification-61.log`.

## Current-bytecode verification after optional native exports

CONFIRMED: baseline60 at `889c26bd` passes all 211 JavaExec tasks in
278.033s, 53,432 independent expression vectors and 225 coverage-tool tests
(8.248s). Raw verification retains 255 sources / 901 classes and production JAR
`2f18126bf76e63325bd0af6b006b6ac2a645e1608b21feeea2ab3b58739138b6`.
The lexical tests add four lines and twelve branches to JavaExec. The new native
optional-source/type cases add eight lines and 26 branches to the native layer;
overlap makes the combined gain twelve lines and 36 branches. The 362-session
local partial result is 24,963/29,790 lines and 19,453/25,884 branches.

Completed Windows, Linux-host and firmware jobs from hosted run `43952501473`
provide another 104 matching-bytecode sessions (55/45/4). Their downloaded ZIP
hashes, extraction bounds, run/head/merge provenance, successful jobs, raw
execution and regenerated reports were checked. All three reports reproduce
exactly. The Windows primitive collection satisfies both current admission
policies: 40 metadata faults and 47 directory faults, with balanced resources,
preserved inputs and successful directory retries. The checked-out Java probe
hashes match the source commit, accounting explicitly for Windows line endings.

The resulting 466-session diagnostic union covers 26,819/29,790 lines (90.0%)
and 20,331/25,884 branches (78.5%). Critical binary/location code is 92.9% lines /
79.7% branches; critical file/validation code is 92.6% / 83.1%. This is NOT the
complete hosted cohort, protected gate or published badge. Architecture and
additional headless evidence are still outstanding, and the accepted overall
85/80 and each-critical-group 95/90 targets remain unchanged.

Evidence in the bounded workspace: `javaexec-baseline-60/`,
`report-native-javaexec-checked-60/`, `qualified-type-optional-checked-2f181-verified/`,
`report-native-current-partial/`, `report-native-verification-60.log` and
`integration-43952501473/` (three regenerated reports and `union/`).

## Native export with optional source and type models

CONFIRMED: the compiler-backed qualified-type fixture now also calls the public
symbol-only and source-without-types exporter overloads. Each is exported twice
with the real pinned producer. Independent DIE checks require exactly one CU
and one correctly addressed/sized function, without invented signatures,
variables or locations. Symbol-only output has no source/line table; source-only
output retains the expected file and declaration. GDB resolves the exact entry,
finds no invented globals, observes source presence/absence and the real return
value, and exits normally. GNU readelf, LLVM and the strict checker accept both.

Five invalid source names are rejected without changing the prior typed sidecar.
The final valid typed retry is byte-identical, and executable/source hashes are
preserved. All existing 13 typed C11 globals and their 59 DIE corruption controls
remain checked. Each untyped oracle rejects ten additional controlled output
corruptions. The admission policy now requires both variants, every debugger and
validator result, all 20 controls, source-name rejection and typed retry evidence.
Eight admission unit tests pass, including missing/reordered/falsified evidence.

All five compiled native mutations pass: the existing three qualifier/encoding
faults plus an incorrect subprogram extent and an invented prototype on the
untyped path. The new faults produce artifacts successfully and are detected by
the independent output oracle; compilation/native crashes are not credited and
mutant execution is excluded from coverage. Production code/JAR are unchanged.
This is explicit compiler-fixture serialization, not Ghidra extraction coverage.

Evidence in the bounded workspace: `qualified-type-optional-checked-2f181/`,
its `-collections/` directory, `qualified-type-optional-mutations/` and
`qualified-type-optional-full.log`. Raw admission and full-suite attribution
follow. Older qualifier-only collections do not satisfy the expanded policy.

## Report lexical boundaries through the streaming API

CONFIRMED: the existing report-value task now checks valid and malformed text
with 1/2/7-byte input chunks and 1/2/7/1024-character destination slices. It
rejects misspelled/extended/incomplete null tokens, unmatched or unfinished
containers, malformed UTF-8, unpaired escaped surrogates, oversized/noncanonical
integers and nonpositive resource budgets. Exact byte/UTF-16 ceilings remain
accepted. Empty reads must neither consume input nor change the destination;
all reads preserve slice boundaries and close their owned stream on failure.
This is lexical admission, not a replacement for full Gson/schema validation.

The focused task passes 2,364 new assertions. All twelve selected compiled faults
are detected by assertions (7.286s). The first mutation run was not credited:
a broken empty-read path threw IOException on valid input without an explicit
assertion. The positive-input helper now asserts that valid Reader operations
must succeed, and the complete mutation run passes. Production code is unchanged.
No private-reader internals or fabricated Ghidra states are used.

Evidence: `report-lexical-focused.log`, `report-lexical-verification.log` and
`report-lexical-mutations-2/` in the bounded workspace. The initial uncredited
mutation log remains retained. Full-suite coverage attribution follows.

## Primary QEMU oracle TCP collision

CONFIRMED: hosted run `43952501473`, MIPS32 big-endian job `133614218953`,
passed ordinary and sectionless GDB sidecar cases, then failed before the PIE
case could connect: QEMU could not bind TCP port 33530. This was a listener
collision, not an observed DWARF/debugger-value failure. Other live jobs were
left running. The old PID-derived-port harness reproduces the same refusal
locally while a controlled listener holds its exact historical port.

The primary oracle now uses the existing private UNIX-socket helper, including
bounded startup, child exit and cleanup checks. A new regression holds the old
TCP port throughout the actual GDB run, checks no connection reaches that
listener, preserves input hashes, and checks private endpoint cleanup and normal
QEMU exit. Every regression run owns a fresh log directory, so stale endpoint
records cannot satisfy its assertions. CI runs this control for all three
MIPS32 big-endian roles. GDB value/source/breakpoint/stepping assertions remain.

Local validation passes 12 real cases: x86-64, AArch64 and both MIPS byte orders,
each with ordinary, sectionless and PIE inputs. All 12 LLVM verifications pass;
the nine emulated cases run with their historical TCP port occupied. Existing
real socket startup, missing-executable, timeout and ready-child cleanup tests
pass, as does workflow lint. ARM32 was not run locally because
`arm-linux-gnueabihf-gcc` is unavailable; its hosted lane remains required.
This tests matched containers holding compiler DWARF, as in the failing CI step;
it does not replace production headless exporter acceptance.

Evidence in the bounded workspace: `mipsbe-43952501473-job.log`,
`qemu-oracle-old-collision-final.log`, `qemu-oracle-collision-final-result.json`,
`qemu-oracle-collision-final.log`, per-case `qemu-oracle-final-*` logs and
`qemu-oracle-socket-startup-final.log`. Hosted validation of this fix is pending.

## ELF changes during allocation observation

CONFIRMED: real-file controls change each input at public cancellation
checkpoints after attribute capture, after metadata parsing, or after the last
raw read. Across ELF32/ELF64 and both byte orders, growth with restored mtime,
mtime-only changes, same-bytes/same-mtime replacement, and broken first/last
section-name table bytes must produce the intended refusal. Assertions verify
the scheduled change occurred, the observer preserved both files, and restoration
permits deterministic successful retries. Both directory-input positions are
also rejected before parsing.

The file-identity control retains the old inode while creating its replacement.
It is explicitly unavailable when the host exposes no basic file key; Linux
exercised every case here. This is a controlled interleaving test, not a claim
that attribute checks provide a snapshot or detect every concurrent rewrite.
The focused allocation task passes 2,200 assertions. Seven selected compiled
faults are detected by assertions in 5.509s. Several layered guards can ultimately
reject the same input; exact diagnostics also enforce the intended early check.
No production code changed, and mutation execution does not enter coverage.

Evidence: `allocation-file-changes-focused.log`,
`allocation-file-change-mutations.log` and `allocation-file-change-mutations/`
in the bounded workspace. Full-suite measurement follows.

Baseline59 at `ed30f77b` passes all 211 JavaExec tasks in 277.224s,
53,432 independently interpreted expression vectors and all 222 coverage-tool
tests (8.531s). Raw verification retains the same 255 sources / 901 classes and
production JAR. The file-change tests add four lines and eight branch outcomes;
`MatchedElfAllocations` now covers 377/389 lines and 298/320 branches (93.1%).
JavaExec covers 23,854/29,790 lines and 18,798/25,884 branches. The current
362-session partial union covers 24,951/29,790 lines (83.8%) and
19,417/25,884 branches (75.0%). Full current Windows/headless acceptance and
publication remain outstanding; accepted targets are unchanged.
Evidence: `javaexec-baseline-59/`, `allocation-change-javaexec-checked-59/`,
`allocation-change-current-partial/` and `allocation-change-verification-59.log`.

## ELF allocation permissions and note boundaries

CONFIRMED: the allocation task checks all eight LOAD permission combinations
for ELF32/ELF64 and both byte orders. Independent expected section flags and
wrong-write/wrong-execute candidates check exact mismatch origins. Additional
cases cover inherited debug/index/link names, empty note views, an expired
nonallocated note preceding a disjoint segment, and reconstruction of the middle
of three complete note records in both section orders. Reconstructed address,
extent, alignment and bytes must agree. Cancellation at every observed checkpoint
is followed by a successful unchanged-input retry.

These are ELF metadata/relationship fixtures, with deliberately minimal debug
payloads; they do not claim executable behavior or validated DWARF for the dummy
payloads. The allocation task passes 1,684 assertions. The relocation task also
rejects zero and non-entry-aligned PT_DYNAMIC extents in all four encodings,
passing 1,636 assertions. Production code is unchanged.

All 15 selected compiled allocation/relocation faults are detected by assertion
failures (8.853s), including five new allocation faults and one dynamic framing
fault. Compiler/class-loading failures and mutated execution are excluded from
coverage. Evidence: `allocation-boundaries-focused.log`,
`allocation-boundary-selected-mutations.log` and
`allocation-boundary-selected-mutations/result.json` in the bounded workspace.
Full-suite coverage attribution follows this batch; targets remain unchanged.

Baseline58 at `678eddaa` passes all 211 JavaExec tasks in 276.680s,
53,432 independent expression vectors and all 222 coverage-tool tests. Strict
raw verification retains 255 production sources / 901 classes and the unchanged
production JAR. This batch adds ten lines and 29 branch outcomes over baseline57.
JavaExec now covers 23,850/29,790 lines and 18,790/25,884 branches. The same
362-session partial union covers 24,947/29,790 lines (83.7%) and 19,409/25,884
branches (75.0%). Windows and the other required integration suites remain
outstanding; this is not full-cohort acceptance or published coverage.
Evidence: `javaexec-baseline-58/`, `allocation-boundary-javaexec-checked-58/`,
`allocation-boundary-current-partial/` and
`allocation-boundary-final-verification-58.log` in the bounded workspace.

## ELF metadata combinations and malformed headers

CONFIRMED: the runtime relocation task now checks all eight presence combinations
of pointer/size/entry metadata for REL, RELA and RELR, plus all eight PLT metadata
combinations for both REL and RELA. Across ELF32/ELF64 and both byte orders this
is 160 presence cases. Additional controls cover standalone entry widths,
zero-sized and mixed empty/nonempty tables, overlapping roles with mismatched
record boundaries, negative ELF64 targets and an ELF32 RELR bitmap past the
address limit. Positive inventories check roles, formats, file/virtual addresses,
entry sizes, exact decoded records and empty-table SHA-256. Every inspection,
including rejection, must preserve the fixture bytes.

The expected tag dependencies follow section 8.3 and table 8.1 of the
[gABI 4.3 draft, September 4, 2025](https://gabi.xinuos.com/elf.pdf), including
RELR; the older HTML dynamic-section page omits that extension.
These are format-reader controls, not execution claims for every fixture machine
and byte-order combination. The task passes 1,612 total assertions. All nine
compiled selected faults are detected (4.245s). Initially the removed negative
RELR-address check was masked by a later bitmap rejection; a one-entry fixture
now tests that check independently. The first surviving-mutation result remains
retained and is not credited as a detection. Production code is unchanged.

The ELF reader task also adds 53 malformed-input controls: each magic byte,
unsupported class/byte-order values, section/program tables overlapping the
ELF header, absent section tables retaining a name index, and directory inputs.
Header rejection preserves the corrupted input bytes. The full focused reader
task passes, including existing large sparse/extended-count, source-identity,
writer-preservation and symlink cases. Three compiled header mutations are
detected (1.930s); no compilation failure is counted.

Evidence in the bounded workspace: `relocation-metadata-verification-2.log`,
`relocation-metadata-selected-mutations-2/`, `elf-header-verification.log` and
`elf-header-selected-mutations/`. Full coverage measurement follows this batch.

CONFIRMED: baseline57 at `2624cc3b` passes all 211 JavaExec tasks in 276.533s,
53,432 independent expression vectors and all 222 coverage-tool tests (8.897s).
Raw verification retains 255 production sources / 901 classes. Against the
same production JAR, JavaExec gains four lines and 32 branches over baseline56:
`ElfImage` reaches 268/271 lines and 186/198 branches; `ElfRuntimeRelocations`
reaches 165/166 lines and 206/230 branches. No production behavior changed.

The real Linux metadata suite was rerun against this JAR. Its 18 independent
filesystem observations and complete controlled read/application failure cases
pass, with all 39 JVM sessions admitted and their raw probes verified. The
current 362-session partial collection now measures 24,937/29,790 lines (83.7%)
and 19,380/25,884 branches (74.9%). The additional native execution is a refreshed
measurement of existing tests, separate from the new ELF test gain. Windows and
other required integration suites remain absent; this is not a complete cohort
or published badge. The full acceptance targets remain unchanged.

Evidence: `javaexec-baseline-57/`, `elf-metadata-javaexec-checked-57/`,
`metadata-current-2f181/`, `metadata-current-2f181-collections/`,
`metadata-current-2f181-verified/`, `elf-metadata-current-partial/` and
`elf-metadata-final-verification.log` under the bounded coverage workspace.

## Independent export-report outcomes

CONFIRMED: the existing report tasks now exercise all 32 combinations of five
independent partial-export causes for both 64-bit little-endian and 32-bit
big-endian report metadata. A failed decompilation, skipped function, unavailable
location, opaque type or diagnostic must each prevent `SUCCESS` on its own.
Every combination checks all 15 serialized counts, strict reader round-trip,
`NOT_RUN` validation status and immutable snapshots of caller-owned inventories.
These are report-model tests, not new architecture execution claims.

Boundary cases reject negative counts in every field, malformed artifact hashes,
empty/reversed omitted ranges, unsupported address sizes and missing completed
report inputs. Completed/terminal writers reject incompatible coverage inputs.
The focused tasks pass 1,470 new contract assertions across 64 status cases plus
the existing text/coverage checks. The first fixture expected one source mapping;
the actual builder correctly maps both its declaration and return statement.
The corrected expectation is two mappings; production behavior is unchanged.

All 11 selected report mutations compile and are detected by behavioral
assertions (9.072 seconds), including each hidden partial cause, invalid count,
hash, range and address-size admission, plus the existing JSON control-character
faults. Mutation output is excluded from coverage. Evidence is retained under
`report-contracts-focused-2.log` and `report-contract-selected-mutations/` in the
bounded workspace. A fresh full-suite measurement follows this test batch.

CONFIRMED: baseline55 at `c9b29310` passes all 211 JavaExec tasks in 277.993
seconds and 53,432 independent expression vectors. Raw probe verification
retains 255 production sources / 901 classes. JavaExec gains seven lines and
33 branches without changing production bytecode; `ExportReport` reaches
405/405 lines and 129/132 branches. All 222 coverage-tool tests pass (8.340s).
The refreshed qualified-type producer passes its real compiler/GDB/validator
oracle and raw probe admission against production JAR `2f18126b...`.
The resulting 323-session collection is explicitly partial: 24,850/29,790
lines (83.4%) and 19,248/25,884 branches (74.4%). It lacks Windows and other
required integration collections; these figures are not the published badge
or complete hosted acceptance. Evidence: `javaexec-baseline-55/`,
`report-contract-javaexec-checked-55/`, `qualified-type-current-2f181-verified/`,
`report-contract-current-partial/` and `report-contract-final-verification.log`.

## Register description admission and ownership

CONFIRMED: the existing storage-model task now checks invalid register-map
metadata, negative numbers, independent physical/logical slice bounds including
integer overflow, missing pair children/parents, repeated children, pair gaps
and overlaps. Valid aliases, reversed object-memory pair order and exact-end
slices remain accepted. Caller edits and attempts to mutate returned maps or
pair lists cannot alter retained descriptions. Unknown registers remain
explicitly unavailable; no location or architecture support is invented.

All 96 added checks pass. Eight compiled mutations are detected by assertion
failures in 3.093 seconds, covering both overflow calculations, paired extent,
child/parent admission, object order and list ownership. These are public model
contract tests using ordinary maps and lists; no impossible Ghidra objects or
duplicate-key map implementations are manufactured. Production code and the
coverage denominator are unchanged. Evidence: `register-map-contract-verification.log`
and `register-map-contract-selected-mutations/`; full measurement follows.

CONFIRMED: baseline56 at `74436b6e` passes all 211 tasks in 277.349 seconds,
the 53,432 independent expression vectors and all 222 coverage-tool tests
(8.527s). Raw verification preserves all 255 production sources / 901 classes.
Compared with baseline55, JavaExec gains eight lines and 38 branches;
`TargetRegisterMap` now covers 164/165 lines and 136/143 branches. Across both
report and register batches, the same production bytecode gains 15 lines and
71 branches. No earlier incompatible execution data is reused.

The 323-session current partial collection measures 24,858/29,790 lines (83.4%)
and 19,286/25,884 branches (74.5%). Windows and other required integration
collections remain absent; none of the complete-cohort gates is relaxed.
Evidence: `javaexec-baseline-56/`, `register-contract-javaexec-checked-56/`,
`register-contract-current-partial/` and `register-contract-final-verification.log`.
The code commits are pushed and CI run `43952501473` validates `74436b6e`.
The preceding run completed its ARM32/AArch64/MIPS/Windows lanes; x86-64 failed
before extension installation, leaving its coverage upload directories absent.
The new run includes the installation-order fix; hosted acceptance remains
unverified until it completes.

## Complete checker-report corruption controls

CONFIRMED: `StrictDwarfReportSmoke` now rejects duplicate categories in each
of the two retained real check tables, duplicate compiler/total/tag sections,
misordered summaries, contradictory arithmetic, zero completed checks, empty
tag inventories, unexplained trailing records and oversized/null reports.
Every text corruption starts from retained real libdwarf output; the unchanged
report must still pass after all corruptions. No parser behavior was changed.

The focused task passes 323 assertions. Four compiled behavioral mutations are
detected in 1.962 seconds: accepting duplicate categories, zero checks, trailing
records and duplicate final tag reports. Compiler failures are not detections.
Evidence: `strict-report-complete.log` and `strict-report-selected-mutations/`
in the bounded coverage workspace. Fresh full coverage measurement is pending;
this is not a repository-wide mutation score.

## Memory-local address spaces

CONFIRMED: the new real-ProgramDB regression fails on the previous exporter
because a function-owned local in an overlay is reduced to a plain ELF address.
Memory locals now reject overlay, mapped and non-default address spaces with a
diagnostic, matching the existing ordinary-global admission policy. Ordinary
saved and inferred memory locals retain their names, types, normalized addresses
and ownership. No location is invented for an unsupported mapping.

The existing static-recovery task now includes 90 extraction cases across
x86-64, AArch64, ARM32 and both MIPS byte orders (850 additional assertions).
Cases cover saved-type precedence, missing/stale inference, memory boundaries,
rebasing, first-use restrictions, rejected bindings/scopes, uninitialized objects
and unsupported mappings. Extraction preserves program state and object bytes,
is deterministic, and honors cancellation. These explicit recovery candidates
test extraction; they do not claim execution of the decompiler. One further
real dsPIC30F ProgramDB case (eight assertions) proves that distinct loaded
physical code/data spaces with equal numeric offsets cannot be collapsed.
Its unused register subset is checked against pinned Ghidra `PIC30.dwarf`;
this rejection-only fixture does not establish dsPIC export support.

All ten selected mutations are detected in 27.543 seconds, including incorrect
normalization, extent, provenance, saved-type precedence and mapping admission.
The first extent mutant failed to compile because it removed the only checked
address-overflow operation; that attempt is not credited. The corrected mutant
still performs address arithmetic and fails the intended behavioral assertion.

The real headless static-scope harness adds overlay and loaded mapped-memory
controls to the existing exec/PIE/rebased-PIE pipeline. It requires deterministic
output, unchanged inputs/project, independent GNU/LLVM/libdwarf validation and
GDB's correct fallback to the separate global object. Both controls are mandatory
for coverage admission, including their JVM sessions and debugger observations.
CONFIRMED: complete x86-64 non-PIE, PIE and rebased-PIE replays pass, including the existing
scope/recovery controls, cancellation, deterministic reruns, input/project
preservation, independent validators and all debugger boundaries. Fifteen complete
collections with 111 JVM sessions pass the stricter admission policy. AArch64
non-PIE also passes the full harness under QEMU; that run is behavioral evidence,
not included in these measured x86-64 collections. All 222 coverage-tool tests
passed in 8.912 seconds before the final mutation additions. Baseline52's 211
JavaExec tasks passed in 279.411 seconds with 53,432 independent expression
vectors. The separate-space follow-up requires a fresh JavaExec measurement.

The production JAR has changed: previous combined percentages remain historical
and must not be presented as coverage of this fix or merged with incompatible
probes. Evidence is in the bounded coverage workspace under
`memory-local-overlay-before.log`, `memory-local-overlay-fixed-cwd.log`,
`memory-local-fixed-mutations/` and the `memory-local-*` headless logs. The first
headless setup lacked package metadata; later fixture corrections distinguish
the saved name from its display name and ensure mapped storage is actually in
the loaded default address space. A stale Java 25 script cache blocked the first
rebased import; the successful replay uses the existing isolated Java 21 home
inside scratch. Retain those failures as diagnostic evidence. The raw Java
verifier accepts the 322 baseline52/integration sessions, but the full report
builder correctly requires Windows data. A partial local report must identify
that missing layer explicitly, without inventing Windows sessions or weakening
the full acceptance gate.

CONFIRMED final local checkpoint at `c5a31daa`: baseline54 passes all 211 JavaExec
tasks in 278.070 seconds, including 53,432 independently interpreted expression
vectors. All 222 coverage-tool tests pass in 8.570 seconds. The new memory guard
has 4/4 changed executable lines and 6/6 branches covered. Whole-PR changed code
has 14/14 lines and 32/36 branches (88.9%): the minimum passes, while the preferred
90% branch target remains unmet. No production sources or classes are excluded
(255 sources, 901 classes).

Raw verification accepts 322 current-bytecode sessions: 211 JavaExec and 111
native/headless static-scope sessions. The explicitly **partial** report measures
24,821/29,790 lines (83.3%) and 19,196/25,884 branches (74.2%). It has no current
Windows layer and does not include the other required Linux integration suites.
It is not comparable in scope to the previous 1,316-session diagnostic union,
and does not update the badge or establish hosted acceptance. The production
JAR is `2f18126bf76e63325bd0af6b006b6ac2a645e1608b21feeea2ab3b58739138b6`;
the previous JAR's probes are not reused.

In JavaExec alone, these changes add five covered lines and 33 covered branch
outcomes relative to baseline51, with four new production lines and six new
branches in the denominator. `StrictDwarfReport` increases from 88/116 to
102/116 branches; `GhidraTypeGraph` from 430/539 to 449/545. These are scoped
measurements, not estimates of the eventual complete combined percentage.

Final evidence: `javaexec-baseline-54/`, `memory-local-javaexec-checked-54/`,
`memory-local-current-partial/`, `memory-local-final-verification.log`,
`memory-local-harvard-mutations/` and `strict-report-selected-mutations/`.
Baseline53 stopped on an already-existing owned lock fixture; baseline54 uses
fresh lock/supervisor paths. That setup failure is retained. The original cached
extension is restored, and its redundant owned backup was removed only after
hash equality was verified. Issue #209 and PR #210 remain incomplete.

## Straight-line local ownership boundaries

CONFIRMED focused validation: `LaterLocalOwnershipSmoke` extends the existing
later-register-local task using actual decoded x86-64/AArch64 ProgramDB objects
and 32/64-bit locals. Every physical register byte conflicts with a second saved
owner, including bytes outside a narrower local; immediately adjacent bytes
must preserve the original proof. Separate stack objects and unassigned locals
cannot claim register ownership. A two-register composite whose second piece
overlaps must reject, and saved invalid storage must suppress the proof.

Unrelated omission reasons and already-proven locations cannot be replaced by
this fallback. A discontiguous body remains outside its straight-line contract.
After each reversible ownership change, the original exact intervals must return;
the proof leaves machine bytes, function body and program modification count
unchanged. No fake instruction graph or impossible variable-storage object is
used. Ghidra rejected the first attempted compound fixture's unnamed byte
varnodes; the final fixture uses two actual named registers of the required width.

Focused later/defined-local tasks pass. All six selected ownership mutants are
detected (17.954 seconds), including the three new straight-line mutations that
ignore overlap, confuse adjacency and ignore an invalid saved owner. Production
code is unchanged. Evidence under the bounded coverage workspace:
`later-local-focused-valid-pieces.log`, `later-local-selected-mutations/` and
`later-local-mutations.log`. Full JavaExec measurement follows separately.

CONFIRMED full measurement at `d00b0b1d`: all 211 JavaExec tasks pass in 275.728
seconds, including 53,432 independent expression vectors. All 221 coverage-tool
tests pass in 8.453 seconds; actionlint passes. Baseline51 and its matching raw
probes verify with the unchanged production JAR and 255-source/901-class scope.
Replacing the prior JavaExec sessions in the diagnostic union adds two lines and
seven binary/location branches: 28,465/29,786 lines (95.6%) and
21,138/25,878 branches (81.7%). Binary branches are 15,259/18,726 (81.5%).
Evidence: `javaexec-baseline-51/`, `later-local-javaexec-checked/`,
`later-local-union-verified/`, `later-local-baseline-result.json` and
`later-local-verification.log`. Changed production-code targets still pass;
no new production code or emitted artifact behavior changed in this batch.

## Hosted Windows metadata controls verified

CONFIRMED: Windows-host job `133524461073` in run `43926490219` passes at head
`117b6c66`, merge commit `52b46cd9c5d32b3ad5f278f4f3d2cd60787ed274`.
Artifact `14258784900` (`integration-java-coverage-windows`, 409,685 bytes),
SHA-256 `61046946652d89d6db6b6189b990169393aed32a3b86eed92f579b5140e6bede`,
has been downloaded with bounds and verified against GitHub's digest. All 54
sessions regenerate the original per-layer counters, source metrics, receipt
inventory and XML hash using the matching production JAR. README comparison
accounts only for Windows CRLF line endings. Protected Java test sources match
the exact Git blobs after verified LF-to-CRLF checkout conversion, recorded per
file; no source mismatch is ignored.

The host-primitives receipt proves all forty controlled metadata failures,
273 host checks and 275 transaction checks. Each fault retains its diagnostic,
one fault hit, balanced actual handles/allocations and unchanged source. Process
handle count is 283 both before and after the repeated batch. Eight deliberate
halt children and nested lock contenders remain explicitly unmeasured.

The audit uses the **unchanged historical five-session admission policy** at
`117b6c66`. Today's gate still requires six sessions, including the newer 47
directory controls; those are **PRESENT, UNVERIFIED** until a later CI run.
No acceptance rule was weakened to count this earlier result.

Adding only the five completed primitive sessions to the prior diagnostic union
gives 1,316 sessions, 28,472/29,786 lines (95.6%) and 21,173/25,878 branches
(81.8%). This adds seven file-operation lines and 35 branches. File-operation
coverage is 6,393/6,677 lines (95.7%) and 3,542/4,250 branches (83.3%);
binary/location branches remain 81.5%. Critical 90% gaps remain 1,595 binary and
283 file outcomes. This mixed-revision, matching-bytecode diagnostic union is
not a complete current hosted cohort or published main coverage.

Evidence: `windows-43926490219/{artifact.json,artifact.zip,job.json,merge-commit.json,
verified.json,regenerated-fixed/,union/}` under the bounded coverage workspace;
driver `verify-windows-43926490219.py` and its checkout-verification log retain
the exact artifact, policy and source hashes. The full goal remains incomplete.

## Qualified types and scalar encodings

CONFIRMED pilot: `qualified-type-producer.py` compiles a tiny Linux x86-64 C11
non-PIE reference with thirteen globals. An explicit compiler fixture model
drives the real native exporter twice. The sidecar is byte-identical on repeat;
input and source remain unchanged. GNU readelf, LLVM and the strict reader
validate the output. Compiler and exported GDB sessions check signed/unsigned
characters, Boolean, UTF-16/32, float/double, wide unsigned values, pointer
targets, object sizes, qualifiers, function return 42 and normal exit.
This tests serialization of an explicit model, not Ghidra type extraction.

The independent DIE oracle checks exact modifier chains, base encodings and
widths, pointer width, absolute object locations, and the absent terminal type
reference for const void. All 59 targeted oracle corruptions must fail. GDB
prints `void *` for both compiler and Forge `const void *`; the DIE oracle
therefore verifies the qualifier that debugger spelling alone cannot prove.

This exposed the pinned strict reader's omission of `DW_TAG_atomic_type` from
its permitted reference targets. The original compiler ELF reproduces the same
error. Validation-only patch 0009 corrects that omission, with an independent
compiler positive and a one-byte non-type-target negative. Production source
and native libraries are unchanged. See `support/validation/README.md`.

CI requires the new isolated suite and its complete compiler/debugger/DIE
oracle before admitting coverage. Schema tests reject omitted or changed
controls, incomplete sessions, invalid identity, missing input preservation,
missing native provenance or failed debugger/validator outcomes. Local pilot
evidence is in `qualified-type-pilot-5/` in the bounded coverage workspace.
The final pilot also validates the compiler reference through LLVM and the
strict reader; stripped input bytes corroborate inherited frame diagnostics.
All 221 coverage-tool tests pass. Three separately compiled production mutants
(atomic emitted as const, UTF emitted as unsigned, signed char emitted as
unsigned char) each produce an artifact successfully, then fail the independent
DIE oracle with the expected semantic mismatch. The unmodified compiled
baseline passes. Compilation errors, crashes and unrelated assertions cannot
count as detection; mutation executions contribute no coverage. Evidence:
`qualified-type-mutations/result.json`. Production sources remain unchanged.
CONFIRMED exact-commit measurement at `1816a8f9`: the final harness passes and
its completed native JVM session, source provenance, production class identities
and raw probes validate. The matching-bytecode union now contains 1,311 sessions:
28,463/29,786 lines (95.6%) and 21,131/25,878 branches (81.7%). This adds five
lines and seven branches, all in binary/location correctness, whose branches
are now 15,252/18,726 (81.4%). File-operation branches remain 3,507/4,250 (82.5%).
The critical 90% gaps remain 1,602 binary and 318 file outcomes. Production JAR,
255-source/901-class denominator and previous JavaExec baseline50 are unchanged.
This diagnostic union is not current hosted acceptance or published main coverage.
Evidence: `qualified-type-final/`, `qualified-type-final-collections/`,
`qualified-type-final-verified/union/` and `qualified-type-final-verification.log`.

## Linux metadata application failures

CONFIRMED locally: twelve additional cases exercise real owned-stage application
through `LinuxMetadataApplicationFailureControls`. Six controlled libc failures
cover opening the stage, temporary/final chmod, attribute removal/set and
timestamps. Three controls actually append to, hard-link, or change the mode of
the owned stage after timestamp application; independent Java filesystem reads
check those effects. Two controlled final-path statx identity replies exercise
source/stage disagreement without modifying the source. A close-error reply
follows actual descriptor release. These are explicit test faults, not claims
of observed kernel defects or full host admission.

Each case first proves unarmed forwarding, then requires its exact failure
diagnostic, one fault and balanced real descriptors (one for failed stage open,
two otherwise). Source metadata and bytes must remain unchanged. Discarding the
owned failed stage and retrying on a fresh stage must preserve stage bytes and
produce the source's supported preservation digest. Real writes are checked to
target only that owned stage. The Python integration oracle independently
rechecks source stat/xattrs/inode policy/content and retains its existing suite.

The hosted collector now requires the twelve application outcomes and their
completed isolated JVM session in addition to the existing 28 inspection
controls. Receipt/schema tests reject missing cases, altered cleanup or retry
claims, and omitted sessions, including a rebound-receipt regression.

The native integration pilot passes, test classes compile, all seven selected
Linux metadata mutations are detected (6.399 seconds), and all 216 coverage-tool
tests pass (8.884 seconds). The five added mutations remove stage size/link,
preservation readback, source-path and stage-path checks. This is a selected
mutation result, not a full repository mutation score. Production source/JAR
remain unchanged. Evidence is under `metadata-application-pilot/`,
`metadata-application-selected-mutations/` and the corresponding logs in the
bounded coverage workspace. Exact-commit measurement follows separately.

CONFIRMED exact-commit measurement at `a29cf82c`: the complete native harness
passes with 39 completed sessions. Receipts, preserved provenance, production
class identities and raw probes validate. Adding those sessions to the prior
verified union yields 1,310 sessions, 28,458/29,786 lines (95.5%) and
21,124/25,878 branches (81.6%). File-operation branches increase by three to
3,507/4,250 (82.5%); binary/location branches remain 15,245/18,726 (81.4%).
No lines, production classes, source denominator or production JAR changed.
The remaining critical branch gaps are 318 file-operation and 1,609
binary/location outcomes. Existing coverage overlaps most new failure cases;
no larger gain is inferred from case count. This diagnostic union is not
current hosted acceptance or published main coverage.

Exact-commit evidence: `metadata-application-final/`,
`metadata-application-final-collections/`,
`metadata-application-final-verified/union/`, and
`metadata-application-verification.log`. The prior JavaExec baseline50 is
retained; the new standalone native session is measured separately rather than
claiming a fresh full JavaExec run.

## Installed producer test ordering

CONFIRMED: hosted run 43926490219 at `117b6c66` failed its x86-64 producer-failure
step before invoking Java. The step resolved the installed source archive and
production JAR before the job's `Install extension` step had run, yielding
`FileNotFoundError` for the extension directory. Later missing-artifact upload
errors were consequences of that early failure, not validator failures.

The producer-failure and dependent mutation steps now follow installation.
Coverage preparation remains earlier; all assertions and mandatory suites remain
enabled. Actionlint and a dependency-order audit pass, including the absence of
installed-extension path consumers before installation in the target job.
Production source and test harnesses are unchanged. Hosted replay is pending;
the still-running earlier revision cannot validate this workflow correction.
Evidence: `ci-43926490219-x86.log` (215,514 bytes) and
`producer-ci-order-result.json` in the bounded coverage workspace.

## Windows directory failure and lifetime controls

PRESENT, UNVERIFIED on Windows: `WindowsDirectoryFailureControls` adds 47
controlled failures around actual Windows directory handles. The production
adapter admits the real Windows Intel 64-bit host before fixture creation.
Test-only forwarding wraps its existing native interface; production source,
bindings and bytecode are unchanged. Failed opens are intercepted before any
native allocation; close-error reporting follows an actual successful release.

Cases cover native open/information/flush errors; disk, directory and reparse
checks; filesystem-name and unsigned component limits; final-path size changes,
termination, UTF-16 and GUID validation; volume-root identity; and differing
file identities at each of five observations. Malformed replies are controlled
test inputs, not claims that the kernel produced those replies. Identity cases
2–5 run through inspection and exercise its revalidation points; they do not
claim a physical concurrent rename or a flush. Only the expected-identity and
flush-error cases request writable handles during injection.

Every case requires its specific diagnostic, exactly one injection, exact
successful-open and close counts, unchanged directory identity and sentinel
bytes, and an uninjected inspection/sync retry. A full warmup precedes repeating
all cases under stable process-handle accounting. Root directory handles remain
read-only and are never flushed. These tests do not establish power-loss durability.

The Windows host suite now requires six completed direct JVM sessions and retains
its eight unmeasured crash-child disclosures. The hosted collector requires all
47 ordered cases, cleanup counts, preservation, retry and stable handle counts;
missing, partial, reordered and corrupt evidence is rejected. The separate 40
metadata controls remain mandatory.

CONFIRMED locally: Java 21 compilation, actual non-Windows rejection before
fixture creation, all 212 coverage-tool tests (8.885 seconds), actionlint and
unchanged production JAR hash. Evidence is in
`windows-directory-controls-local/` under the bounded coverage workspace; command:
`python3 support/storage-guard.py run --cwd /home/ziggy/GhidraDwarfForge -- python3 .forge-work/scratch/coverage-expansion/verify-windows-directory-controls.py`.
Native Windows execution is **NOT_RUN locally**. No added production coverage
is claimed until matching Windows probes and their behavior evidence validate.

API contract references checked for this batch:
[final path lengths and GUID flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew),
[volume information and WCHAR component lengths](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew),
[flush return values and write access](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

## Known-zero facts at conditional value-flow joins

CONFIRMED at `39a8bc2d`: 96 raw-p-code cases exercise both branch arms, eight
byte placements and both operand orders for OR/ADD merges. The reference
interpreter executes bounded forward branches independently; direct BigInteger
expressions check its results for all 256 byte values and seven sign-boundary
inputs. Preserving paths retain the exact byte, while each corrupting path has
a concrete counterexample. An unreachable carrier overwrite must not add a
false predecessor or invalidate a valid location.

The focused register-byte suite passes 1,216,315 assertions. All ten selected
stack-value mutations are detected (53.045 seconds), including unioning zero-bit
facts across paths and retaining only the first path's facts. All 211 JavaExec
tasks pass (275.878 seconds), as do 53,432 independent DWARF vectors, 206
coverage-tool tests and actionlint. Baseline50 verifies 255 production sources /
901 production classes / 619 test classes. JavaExec measures 23,814 lines and
18,618 branches. Production bytecode and the measurement denominator are unchanged.

The verified 1,271-session diagnostic union adds two branch outcomes:
28,458/29,786 lines (95.5%), 21,121/25,878 branches (81.6%). Binary/location
branches are 15,245/18,726 (81.4%); file-operation branches remain 3,504/4,250
(82.4%). Critical 90% branch gaps remain 1,609 and 321. This is not current hosted
acceptance or main publication; the active hosted run covers the earlier pushed
revision `117b6c66`.

Evidence: `javaexec-baseline-50/`, `joined-zero-focused.log`,
`joined-zero-selected-mutations/`, `joined-zero-javaexec-checked/`,
`joined-zero-union-verified/`, `joined-zero-baseline-result.json` and
`joined-zero-verification.log` in the bounded coverage workspace.

## Complete hosted origins in the public renderer

CONFIRMED: CI run [43888754254](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43888754254)
passed every architecture/host lane, then failed while rendering the combined
report. The collector required the separate `linux_aarch64` origin, but the
renderer still expected the former five-origin inventory. The renderer now
requires all six origins, retaining exact commit/run/session checks. This does
not relax coverage targets or make a missing lane acceptable.

The collector-to-renderer contract test failed before the fix with the same
`mixed or incomplete origins` error. After the fix, all 206 coverage-tool tests
and actionlint pass. Each required origin is individually removed, duplicated,
replaced or assigned a different commit/run/session count in negative controls.

The actual CI report (1,094 sessions at merge commit `f1f3d0b8`) also renders
successfully using an exact-commit temporary checkout. Publication remains
rejected because critical targets are unmet. This check validates the retained
CI report and source history; it does not independently download/replay all raw
CI probes or publish anything. The temporary checkout was verified clean and
removed. Evidence: `ci-43888754254-combined/render-result.json`,
`aarch64-origin-regression-before.log`, `aarch64-origin-regression-after.log`
and `aarch64-origin-actual-report-verified.log` in the bounded coverage workspace.

## Byte preservation with overlapping untracked operand bits

CONFIRMED at `2cd66867`: 80 additional raw-p-code cases check both operand
orders, four input bytes and five byte placements against independent BigInteger
arithmetic. OR preserves the tracked byte despite overlap elsewhere. Higher-byte
ADD omissions have concrete carry counterexamples. Least-significant-byte ADD
is concretely safe here but remains outside the current disjoint-operand proof;
the test records that conservative omission without claiming value corruption.

The register-byte suite passes 642,363 assertions. All eight selected stack-value
mutations are detected (44.015 seconds), including losing either operand's byte
because unrelated bits overlap. All 211 JavaExec tasks pass (277.125 seconds),
as do 53,432 independent DWARF vectors. Baseline49 raw verification retains
255 production sources / 901 production classes; 619 test classes include the
new Windows-only probe. JavaExec measures 23,814 lines and 18,616 branches.

The verified 1,271-session diagnostic union adds two branch outcomes:
28,458/29,786 lines (95.5%), 21,119/25,878 branches (81.6%). Binary/location
branches are 15,243/18,726 (81.4%); file-operation branches remain 3,504/4,250
(82.4%). Critical branch gaps remain 1,611 and 321 respectively. Production
bytecode is unchanged. This is not current hosted acceptance or main publication.
Evidence: `javaexec-baseline-49/`, `overlapping-value-focused.log`,
`overlapping-value-selected-mutations/`, `overlapping-value-javaexec-checked/`,
`overlapping-value-union-verified/` and `overlapping-value-verification.log`.

## Windows native metadata failure controls

PRESENT, UNVERIFIED on Windows: `WindowsMetadataFailureControls` adds 40
controlled API replies around the actual Windows x64 production adapter. The
existing Windows host-primitives harness compiles and measures this as a fifth
isolated JVM, alongside the privilege, host, transaction and lock probes. It
retains the disclosure of eight unmeasured deliberate-halt children and nested
lock contenders. Production bindings, bytecode and source scope are unchanged.

The cases cover failed opens/information queries, inconsistent file facts,
descriptor/control/SID rejection, malformed stream names/chains/counts and
reported close/free errors. Forwarding without an injected reply must reproduce
the real snapshot. Every failure must hit once, produce its expected diagnostic,
balance actual handle/allocation ledgers, preserve source bytes/metadata and
allow a clean retry. A warmup precedes a second complete pass with unchanged
process handle counts. Failed allocating calls are intercepted before native
allocation; close/free error replies follow successful real releases. No invalid
pointer is passed to a native SID reader: descriptor bounds reject it first.
These are controlled replies, not claims that Windows returned malformed data.

The buffer layout and ownership audit uses Microsoft's
[FILE_STREAM_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info),
[FILE_STANDARD_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info),
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
and [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
contracts. This batch tests read-only inspection, not stage application or full
host admission.

CONFIRMED locally: Java 21 standalone compilation, rejection on a non-Windows
host before fixture creation, 204 coverage-tool tests and actionlint pass.
Strict hosted admission rejects missing/reordered cases, omitted faults,
unbalanced resources, changed source, false host claims, incomplete sessions
and missing nested-process disclosures. Local schema tests are not native
execution evidence. No coverage increase or Windows runtime pass is claimed
until the actual Windows job and raw matching-bytecode verifier pass.
Evidence: `windows-metadata-controls-local/` in the bounded coverage workspace.

## Inherited ARM mapping conflicts and allocation adjacency

CONFIRMED at `3797cb14`: adjacent allocated sections preserve exact mapping
output; overlapping allocations fail with the expected diagnostic. Inherited
ARM/Thumb function tags are checked for both ordinary and absolute symbols.
Markers at the exclusive section end cannot constrain preceding instructions;
matching inherited data markers suppress only the redundant mapping. Conflicting
intervals, wrong section/address evidence, misaligned ARM transitions and reserved
symbol names are rejected. Every fixture preserves its original bytes.

The focused suite passes 290 assertions; all eight selected ARM mutations are
detected (3.195 seconds). All 211 JavaExec tasks pass (276.567 seconds), as do
53,432 independent DWARF vectors, 197 coverage-tool checks and actionlint.
Baseline48 verifies 255 production sources / 901 production classes / 616 test
classes. JavaExec measures 23,814 lines and 18,614 branches.

The verified 1,271-session matching-bytecode diagnostic union measures
28,458/29,786 lines (95.5%) and 21,117/25,878 branches (81.6%). Binary/location
coverage is 18,350/19,197 lines (95.6%) and 15,241/18,726 branches (81.4%);
file operations remain 6,386/6,677 lines (95.6%) and 3,504/4,250 branches
(82.4%). This adds 15 branch outcomes and four lines. Critical branch targets,
current hosted acceptance and main publication remain incomplete. Production
bytecode and the measurement denominator are unchanged.

Evidence in the bounded coverage workspace: `javaexec-baseline-48/`,
`arm-conflicts-focused.log`, `arm-conflicts-selected-mutations/`,
`arm-conflicts-javaexec-checked/`, `arm-conflicts-union-verified/`,
`arm-conflicts-baseline-result.json` and `arm-conflicts-verification.log`.

## ARM section-mapping evidence and allocation boundaries

CONFIRMED at `91b4bae4`: evidence checks accept representable unsigned 32-bit
addresses/sizes whose exclusive end is 2^32, and exactly 65,536 ordered mode
boundaries. They reject invalid indices, negative/overflowing extents, malformed
hashes, missing/excessive boundaries, duplicate/nonincreasing offsets and invalid
or repeated mode values. Caller changes cannot mutate retained evidence.
Constructor acceptance alone does not prove matching ELF bytes or instruction modes.

Tiny ELF fixtures separately check unsupported machine/type/EABI/flag profiles,
ET_DYN mode/address stability, non-executable or compressed section exclusion,
zero-sized sections and executable NOBITS rejection. Planning cancels at every
observed checkpoint, preserves original bytes and retries with identical results.
These tests do not expand the supported architecture/ABI claims.

Focused ARM mapping smoke passes 213 assertions. Four selected address-overflow,
exact-limit, duplicate-offset and executable-flag mutations are caught in 1.761
seconds. All 211 JavaExec tasks pass in 275.891 seconds, 53,432 independent DWARF
vectors pass, and 197 coverage-tool checks plus actionlint pass. Baseline47
verifies 255 production sources / 901 production classes / 616 test classes;
JavaExec measures 23,810 lines / 18,599 branches.

The verified 1,271-session matching-bytecode diagnostic union measures
28,454/29,786 lines (95.5%) and 21,102/25,878 branches (81.5%). Binary/location
coverage is 18,346/19,197 lines (95.6%) and 15,226/18,726 branches (81.3%), adding
26 outcomes and four lines. File-operation branches remain 3,504/4,250 (82.4%).
Critical 90% branch targets, current hosted acceptance and main publication
remain incomplete. Production bytecode and scope are unchanged.

Evidence: `javaexec-baseline-47/`, `arm-mapping-focused-final.log`,
`arm-mapping-selected-mutations/`, `arm-mapping-javaexec-checked/`,
`arm-mapping-union-verified/`, `arm-mapping-baseline-result.json` and
`arm-mapping-verification.log` in the bounded coverage workspace.

## Attachment preview request, cancellation and response boundaries

CONFIRMED at `ffda4bf8`: the read-only helper test cancels at each of 1,931
observed preview checkpoints, requires CANCELLED/130 JSON and verifies unchanged
selected-file contents. It checks malformed JSON, wrong content pins, missing
argument values, the exact 256 KiB request limit and the next byte. Explicit
failed output streams cover help, successful preview, attachment cancellation
and recovery cancellation; a lost output stream must not be reported as success.
Restoring the original request bytes/time permits a fresh preview. These tests
are admission/transport checks, not native attachment or privileged-host proof.

Focused helper smoke passes 11,884 assertions. Three selected request-boundary,
preview-output and cancellation-status mutations are caught (3.413 seconds).
All 211 JavaExec tasks pass in 276.445 seconds, 53,432 independent DWARF vectors
pass, and 197 coverage-tool checks plus actionlint pass. Baseline46 verifies
255 production sources / 901 production classes / 616 test classes; the extra
test class implements the controlled broken output stream. JavaExec measures
23,806 lines / 18,572 branches. The production JAR and denominator are unchanged.

The verified 1,271-session diagnostic union measures 28,450/29,786 lines (95.5%)
and 21,076/25,878 branches (81.4%). Binary/location branches remain 15,200/18,726
(81.2%); file-operation branches increase to 3,504/4,250 (82.4%), adding 12
outcomes and four lines. The separate native/headless/Windows views remain
identifiable. Current hosted/main acceptance and critical 90% branch targets
remain incomplete.

Evidence: `javaexec-baseline-46/`, `helper-preview-focused-final.log`,
`helper-preview-selected-mutations/`, `helper-preview-javaexec-checked/`,
`helper-preview-union-verified/`, `helper-preview-baseline-result.json` and
`helper-preview-verification.log` in the bounded coverage workspace.

## Saved register ownership and deterministic source timestamps

CONFIRMED at `108311ab`: real x86-64/AArch64 ProgramDB fixtures with 4/8-byte
locals reject unsaved/noncurated identities, unrelated omission reasons,
unmapped registers and entry-time definitions. Saved byte aliases inside the
physical base register invalidate a lifetime, including a high byte outside a
32-bit alias; immediately adjacent bytes, separate stack storage and unassigned
variables preserve the existing proof. Invalid saved storage is rejected.
Restored controls preserve instructions, function body and modification count.
The intentionally bad row remains until its owned program is released: deleting
it in the pinned Ghidra version left a deleted row in the function's cached list.
This was a fixture-cleanup finding, not a passing restoration assertion.

Focused local-definition tests pass 508 checks. Publication checks set explicit
older/equal/newer sidecar times and verify exact source/loader times, unchanged
input/output bytes and no retained temporary files. Four selected provenance,
overlap, adjacency and source-freshness mutations are caught (9.850 seconds).
Initial constructor/provenance/cleanup development failures are not counted as
passing evidence. Final focused and full runs pass.

All 211 JavaExec tasks pass in 276.056 seconds, 53,432 independent DWARF vectors
pass, and 197 coverage-tool checks plus actionlint pass. Baseline45 verifies
255 sources / 901 production classes / 615 test classes; JavaExec measures
23,802 lines / 18,560 branches. The verified 1,271-session diagnostic union is
28,446/29,786 lines (95.5%) and 21,064/25,878 branches (81.4%). Binary/location
branches increase to 15,200/18,726 (81.2%), adding 16 outcomes and eight lines;
file-operation branches remain 3,492/4,250 (82.2%). RegisterDefinitionFlow itself
has 205/263 branches and 170/172 lines. No production bytecode changed.

Evidence: `javaexec-baseline-45/`, `local-ownership-focused-all.log`,
`local-ownership-selected-mutations/`, `local-ownership-javaexec-checked/`,
`local-ownership-union-verified/`, `local-ownership-baseline-result.json` and
`local-ownership-verification.log`. This is not current hosted/main acceptance;
critical 90% branch targets and issue #209 remain incomplete.

## Linux mount admission and cancellation

CONFIRMED at `49a7a0aa`: `LinuxAttachmentMountSmoke` adds synthetic parser cases
for the [kernel mountinfo fields](https://www.kernel.org/doc/html/latest/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts),
including no optional fields, shared/master/propagate-from/unbindable fields,
canonical unsigned IDs through 64 bits, overflow and malformed identifiers,
control bytes, and contradictory/empty write options on both mount and superblock.
Forge deliberately refuses unreviewed optional fields; these tests do not claim
that general-purpose mountinfo readers should reject them. The exact 2 MiB
parser boundary is accepted, the next byte rejected, and rejected bytes remain
unchanged. Synthetic parser cases do not establish host eligibility.

The default native session additionally uses real ext4 directory observation,
rejects virtual-thread inspection, cancels at every observed checkpoint, retries
against the same snapshot and checks file-descriptor balance. The session passes
341 checks. The harness independently compares mount ID/device with `findmnt`
and native directory identity with `stat`. Real unprivileged visibility/host
sessions pass; privileged modes are explicitly NOT_RUN locally. Three selected
mutations (contradictory read-only flag, empty option, noncanonical ID) are
caught by behavioral assertions in parser-only mode (2.081 seconds).

The final three native-Java sessions have verified receipts/oracles and original
provenance hashes. Their unchanged-production-bytecode union with baseline 44
has 1,271 sessions, 28,438/29,786 lines (95.5%) and 21,048/25,878 branches (81.3%).
Binary/location branches remain 15,184/18,726 (81.1%); file-operation branches
increase to 3,492/4,250 (82.2%), adding 21 outcomes and one line. All 197
coverage-tool checks and actionlint pass. Production scope remains 255 sources /
901 classes. This diagnostic union is not current hosted acceptance; no full
JavaExec rerun is claimed for native-only test changes after baseline 44.

Evidence: `mount-parser-final/`, `mount-parser-final-collections/`,
`mount-parser-final-verified/`, `mount-parser-selected-mutations/`, and
`mount-parser-verification.log` in the bounded coverage workspace. Initial
`mount-parser-local/` is focused development evidence, not the final cohort.
The critical 90% branch targets and issue #209 remain incomplete.

## Frame inventory budgets and compression metadata

CONFIRMED at `cee1a0ad`: exact 64 MiB / 262,144-record inventories are accepted,
while the next byte/record is rejected. Tests cover invalid address widths,
negative/oversized CIE references, section-address overflow and unexplained CIE
augmentation bytes. The large byte fixture stays in memory; no 64 MiB fixture
is retained on disk. This inventories extents, not CFI execution.

GNU/gABI tests cover every magic byte, negative decoded sizes and alignment,
zero alignment and unsigned ELF32 alignment, both ELF classes and byte orders.
Accepted metadata preserves the exact decoded frame bytes and original ELF.
Compressed EH frames are rejected before record interpretation. Focused tests
pass 18,914 parser and 1,884 source checks. Twelve selected mutation controls
pass, including four new off-by-one/alignment controls (5.532 seconds).

All 211 JavaExec tasks pass (275.746 seconds), 53,432 independent DWARF vectors
pass, and all 197 coverage-tool checks plus actionlint pass. Baseline 44 verifies
255 sources / 901 production classes / 615 test classes. The 1,268-session
matching-bytecode diagnostic union measures 28,437/29,786 lines (95.5%) and
21,027/25,878 branches (81.3%). Binary/location branches are 15,184/18,726
(81.1%); file-operation branches remain 3,471/4,250 (81.7%). This adds 14 union
branch outcomes; critical 90% targets remain unmet. This is not current hosted
acceptance or published main coverage.

JavaExec-only results are 23,793 lines / 18,543 branches. The one-line decrease
from baseline 43 is the timestamp normalization at CompanionArtifactPublisher
118–119: ordinary fixture write timestamps may be equal. The union retains
that path; deterministic timestamp controls remain useful follow-up work.

Local evidence: `frame-limits-focused.log`, `frame-limits-selected-mutations/`,
`javaexec-baseline-44/`, `frame-limits-javaexec-checked/`,
`frame-limits-union-verified/` and `frame-limits-verification.log` under the
bounded coverage workspace. Production JAR SHA-256 is unchanged.

## Exception-frame encoding and LEB128 boundaries

CONFIRMED: `OriginalFrameRangesSmoke` checks all 256 encoding bytes for each
LSDA, personality and FDE-pointer role, in both byte orders, both pointer widths
and both DWARF record widths: 6,144 cases. Scalar/application values follow
[LSB 5.0, tables 10-5/10-6](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.pdf).
Expected admission is explicit for this bounded reader: it skips supported
personality/LSDA fields, resolves only supported absolute/PC-relative FDE pointers,
and rejects aligned/reserved encodings. This is an extent inventory, not proof
of personality resolution, LSDA contents, CFI correctness or runtime unwinding.

Raw byte fixtures check every possible tenth LEB128 byte for signed and unsigned
values in both byte orders (1,024 cases). They distinguish overflow, unterminated
input and out-of-domain addresses, while accepting valid padded encodings and
signed negative PC-relative offsets. Additional controls cover maximum addresses,
negative sizes, relative/extent overflow, oversized augmentation lengths,
non-ASCII/excessive augmentation strings and unsupported augmentation contexts.
Cancellation is swept through a valid ten-byte scan; input bytes and fresh retry
results remain unchanged. The full parser suite passes 18,882 checks.

Three selected mutations are detected with a passing unchanged baseline in
1.45 seconds: admitting an unsupported aligned pointer, dropping the tenth-byte
overflow check and reading signed LEB128 as unsigned. The initial mutation run
correctly refused to count an uncaught rejection of valid input as an assertion
detection. The test now explicitly asserts that valid raw LEB frames are accepted;
the final three-fault run passes without weakening the mutation harness.

At `2576b7ea`, all 211 JavaExec tasks pass in 275.98 seconds, as do 53,432
independent DWARF-expression vectors, all 197 coverage-tool tests and actionlint.
Production code and the 255-source / 901-class denominator are unchanged.
JavaExec covers 23,794/29,786 lines and 18,530/25,878 branches. The verified
1,268-session diagnostic union covers 28,437/29,786 lines (95.5%) and
21,013/25,878 branches (81.2%), adding one line and 31 branch outcomes.
Binary/location branches reach 15,170/18,726 (81.0%); file operations remain
3,471/4,250 (81.7%). The remaining 90% gaps are 1,684 and 354 branch outcomes.
Current hosted acceptance and actual-main publication remain incomplete.

## Decoded MIPS stack arithmetic and original ELF object identities

CONFIRMED: `TruncatedStackDepthSmoke` now covers 17 middle instructions in each
MIPS byte order, with both the declared 32-bit address space and the ordinary
64-bit space. Twelve new encodings cover word/wide subtraction, commuted addition,
copies, reversed subtraction and shifts. Pinned Ghidra decoding was inspected
before defining the cases. Supported identities are compared with independent
low-address ISA arithmetic at carry/sign boundaries; unproved depths remain
unknown in the public profile. Zero-bit shifts are explicitly conservative
omissions, not claims that the concrete address changed.

Real function bodies with holes or instructions before the entry are rejected
by the bounded proof. Cancellation is swept across every observed checkpoint in
both byte orders; the exception identity, analyzed program and subsequent result
are preserved. The suite passes 996 checks. Two selected mutations are detected
in 8.16 seconds: commuting subtraction and ignoring the big-endian low-word
offset. These tests do not establish a new ABI or debugger support profile.

`LocalSymbolMergeSmoke` adds 48 original-object identity fixtures across ELF32,
ELF64 and both byte orders, plus long-name cancellation controls in all four
formats. They compare independently encoded symbol records with exact expected
matches/conflicts/absences, exercise repeated names and extended section indexes,
and retain an unsigned ELF32 address above `INT_MAX`. Earlier conflicting identities
must survive later matching entries. Reads and cancelled reads preserve input
bytes and create no artifacts; fresh retries reproduce the expected map.
The whole suite passes 2,288 checks. Two selected mutations are detected in
2.86 seconds: forgetting an earlier conflict and sign-extending an ELF32 address.

At `05487719`, all 211 JavaExec tasks pass in 276.50 seconds, as do 53,432
independent DWARF-expression vectors, all 197 coverage-tool tests and actionlint.
The production JAR and 255-source / 901-class denominator are unchanged.
JavaExec covers 23,792/29,786 lines and 18,498/25,878 branches. The verified
1,268-session diagnostic union covers 28,436/29,786 lines (95.5%) and
20,982/25,878 branches (81.1%), adding one line and 17 branch outcomes.
Binary/location branches reach 15,139/18,726 (80.8%); file operations remain
3,471/4,250 (81.7%). Their remaining 90% gaps are 1,715 and 354 branch outcomes.
Current hosted acceptance and actual-main publication remain incomplete.

## Stack-spill pointer expressions

CONFIRMED: `StackSpillSmoke` adds 48 raw-pcode expression cases across real x86-64
and AArch64 register definitions with 4- and 8-byte parameters. The cases cover
pointer/value copies, commuted addition, subtraction, negative constants and
chained address temporaries. Absolute addresses, constant-minus-pointer,
two-pointer sums and an unsupported XOR-zero identity conservatively receive no
spill location. These are transfer tests; the existing real-decoder positives
remain and no new decoded-instruction or ABI support is claimed.

For the supported expressions, an independent finite-width `BigInteger`
interpreter checks 384 concrete executions, including sign and unsigned-wrap
boundaries. It verifies the stored address and every parameter byte. The focused
suite passes 922 checks. Two selected mutations are detected with an unchanged
baseline in 6.64 seconds: adding instead of subtracting the displacement and
incorrectly commuting subtraction. These are separate from earlier mutation runs.

At `827d5465`, all 211 JavaExec tasks pass in 274.05 seconds, as do 53,432
independent DWARF-expression vectors, all 197 coverage-tool tests and actionlint.
Raw verification preserves 255 production sources / 901 production classes.
JavaExec covers 23,790/29,786 lines and 18,480/25,878 branches. The matching-bytecode
1,268-session diagnostic union covers 28,435/29,786 lines (95.5%) and
20,965/25,878 branches (81.0%). This batch adds one line and six branch outcomes
to the union. Binary/location branches reach 15,122/18,726 (80.8%); file operations
remain 3,471/4,250 (81.7%). The remaining 90% gaps are 1,732 and 354 branch outcomes.
Hosted acceptance, nested-recovery measurements and actual-main publication
remain incomplete; this is not a new published badge result.

## Linux metadata failure controls

CONFIRMED: the real Linux LP64 metadata suite now includes 28 controlled libc
failure/result cases. A test-only forwarding proxy calls the actual native
library and injects a single selected error or malformed reply. Cases cover
open/stat/attribute/inode/close failures, inconsistent identity and inode policy,
invalid timestamps, malformed attribute lists and bounded attribute counts and
sizes. The close-error case releases the real descriptor before returning the
injected error; actual Linux close errors are never retried.

Each case first passes an unmodified forwarding baseline, reaches its fault
exactly once, checks the expected IOException, proves all opened descriptors
were released, and compares real source metadata and bytes afterward. Python
independently compares the file before and after the whole failure suite. The
existing native header/layout contract and 18 metadata observations also pass.
These controls prove handling of injected API replies, not kernel failures,
complete privileged host admission or hidden namespace preservation.

The final suite produces 38 native-Java sessions. Provenance hashes, collection
receipts and raw JaCoCo data verify against the unchanged production JAR and
255-source / 901-class denominator. Their union with prior matching-bytecode
evidence contains 1,268 sessions: 28,434/29,786 lines (95.5%) and 20,959/25,878
branches (81.0%). File operations gain 16 branch outcomes, reaching 3,471/4,250
(81.7%); binary/location remains 15,116/18,726 (80.7%). This diagnostic union is
not current hosted acceptance or a published badge. The critical 90% targets
still require 354 file-operation and 1,738 binary/location branch outcomes.

Two selected mutations are detected in 2.11 seconds with an unchanged baseline:
omitting descriptor cleanup after an open-time failure and skipping final path
identity comparison. All 197 coverage-tool tests pass, including rejection of
an omitted fault case even when receipt hashes are rebound. Synthetic receipt
fixtures are schema tests only. New hosted admission requires the complete
failure inventory and its measured process; old receipts cannot satisfy it.

## Wide p-code value carriers

CONFIRMED: 54 additional raw p-code cases check tracked bytes in 8-, 9-, 16- and
32-byte temporaries, including byte positions on both sides of the 64-bit boundary.
Copies, sign/zero extension, high/low concatenation, extraction and destructive
shifts are checked using the independent finite-width `BigInteger` evaluator.
Each case enumerates all 256 tracked-byte values and seven sign/carry-boundary
nuisance values (96,768 additional concrete executions). Surviving locations must
name the expected register byte; dropped bytes must have a destructive example.

Wide OR with zero is deliberately distinguished from those supported transfers:
the independent evaluator proves its concrete identity, while the current
long-sized known-zero proof conservatively omits a location for widths above
eight bytes. This test does not expand production support or equate absence of a
location with a changed concrete value. The cases use raw p-code and real ARM-LE
register definitions; they do not establish a new machine-instruction or ABI lane.

The existing register-byte-slice task passes with the added cases. Two selected
mutations are detected with an unchanged baseline in 17.73 seconds: capping shifts
at the host's 64-bit width and wrapping tracked-byte offsets modulo eight. They
are separate from the previous full mutation run. Production code is unchanged.

At `32121f3f`, all 211 JavaExec tasks pass in 273.85 seconds and the independent
DWARF evaluator passes 53,432 vectors. All 191 coverage-tool tests and actionlint
pass. Raw verification preserves 255 sources / 901 production classes / 608 test
classes. JavaExec covers 23,788/29,786 lines and 18,473/25,878 branches.
The 1,230-session diagnostic union covers 28,434/29,786 lines and 20,943/25,878
branches: 95.5% / 80.9%, with **one** additional branch outcome beyond the previous
union. Binary/location branch coverage is 15,116/18,726 (80.7%); file operations
remain 3,455/4,250 (81.3%). The wide-value tests strengthen fault detection but
do not materially close the remaining branch-target gap. Hosted acceptance,
the new nested recovery measurements and final publication remain pending.

## Nested Linux attachment recovery measurement

PRESENT, UNVERIFIED: the production-host attachment controller now allocates a
separate Java measurement adapter for each of the eight existing recovery cases
(initial/refresh at prepared, replaced, before-commit and committed boundaries).
Only the normal `AttachmentHelper --recover` child selects the adapter. Each
deliberate `halt(89)` child retains the real JVM path and remains unmeasured.
The existing assertions for restored bytes/metadata, durable receipts, retained
inputs and exactly eight crash canaries are unchanged. Helper exit and rollback
outcome are also recorded per case.

Hosted admission now requires one completed parent, eight distinct completed
child sessions, one matching launcher invocation per child, exact case/session
bindings, successful rollback outcomes and all eight disclosed crashes. Missing,
duplicate, shared, mismatched, incomplete or merely claimed measurements are
rejected. Historical unmeasured attachment reports cannot satisfy this new
cohort policy; they remain historical evidence under their original policy.

CONFIRMED locally: updated Java test sources compile; all 191 coverage-tool tests
pass in 8.53 seconds, including nested-adapter receipt controls and negative
admission cases. Those receipt fixtures are not evidence of privileged native
recovery. The production JAR is unchanged. Local execution is unprivileged;
actual privileged recovery and new coverage gains await the next hosted run.
No additional sessions or percentages are claimed from this change yet.

## Build-ID command admission and cancellation

CONFIRMED: `buildIdHelperSmoke` checks real pinned request files without invoking
installation. It rejects malformed/duplicate options, invalid or encoded hashes,
unsafe debug-root names, aliased selections, malformed records, changed request
content and oversized input. Exactly 1 MiB remains accepted for a valid padded
request. Install/update/remove/recover previews stay explicitly unvalidated and
leave the debug root empty; selected input/tool bytes are preserved.

Cancellation is sampled at every observed request-read/parse checkpoint. A
pending cancellation also wins before opening a missing request. Changed
cancellation files and caller cancellation both stop preview. Closed response
pipes produce failure for help and preview. Linux tests use actual POSIX filenames
with line breaks; Windows does not pretend to support those forbidden filenames.
The task is registered in both host workflows; its Windows run is PRESENT,
UNVERIFIED until the next exact-head hosted execution.

Five selected mutations are detected with an unchanged baseline: ignored request
pin, omitted final request recheck, admitted carriage return in the debug root,
ignored response failure and skipped early cancellation. The initial mutation
attempt failed compilation because its dependency selection was incomplete; it
is not detection evidence. After that setup correction, the early-cancellation
mutant exposed a test weakness and survived. The missing-request cancellation
assertion fixes that weakness; the final five-fault run passes in 4.17 seconds.
This is separate from the previous full 177-fault and two native-fault results.
No production classes, targets or coverage exclusions changed.

At `ca16ccdc`, all 211 JavaExec tasks pass in 274.43 seconds, with 53,432
independent DWARF-expression vectors. All 187 coverage-tool tests and actionlint
pass. Raw verification retains 901 production classes / 255 sources and verifies
608 test classes. JavaExec covers 23,788/29,786 lines and 18,470/25,878 branches.

The 1,230-session matching-bytecode diagnostic union covers 28,434/29,786 lines
(95.5%) and 20,942/25,878 branches (80.9%). File operations reach 6,381/6,677
lines (95.6%) and 3,455/4,250 branches (81.3%). Binary/location remains
18,331/19,197 lines (95.5%) and 15,115/18,726 branches (80.7%). This adds two
lines and 25 branch outcomes beyond the previous union. `BuildIdHelper` itself
now covers 165/179 lines and 111/126 branches. These are diagnostic results,
not a current hosted acceptance or published badge; critical branch targets
remain unmet. The first local verification driver incorrectly used the
four-layer aggregator for JavaExec alone; raw verification passed but that
driver failed on the absent headless report. The corrected driver verifies
JavaExec separately before regenerating the complete matching-bytecode union.

## Isolated native-producer failure controls

CONFIRMED: `producer-failures.py` builds a test-only forwarding library against
headers extracted from the checksum-verified libdwarf 2.3.2 release archive. The
real pinned producer still allocates handles, emits the baseline and successful
retry, and releases its own state. The shim changes one API result at a time;
these controlled corruptions are **not** reports of upstream libdwarf defects.
Production code, JNA declarations and the packaged native libraries are unchanged.

All 28 fault profiles pass: initialization status/null handle, actual producer
string-form error and no-entry status, null DIE, transform status and buffer-count
bounds, section index/length/null/missing/duplicate data, relocation metadata,
group and record bounds, symbolic address completeness, and finish failure.
For each profile, the isolated JVM first exports a control, rejects two attempts
(existing sidecar and absent output), and exports a byte-identical retry in the
same JVM. Assertions require unchanged input bytes/identity and source bytes, no
partial final output or staging file, each fault actually reached, and matching
successful producer-init/finish counts. A finish failure is injected *before*
release, requiring the cleanup attempt; no freed handle is intentionally reused.
Handle counts do not constitute an ASan/Valgrind memory-leak audit.

Every resulting retry passes readelf, LLVM, the strict DWARF checker and GDB.
GDB checks recovered function/type/source lookup, an exact entry breakpoint,
the fixture's incoming argument register, return value and normal exit. The test
does not invent parameter locations. Initial harness setup attempts exposed an
ambiguous JNA glob, missing loader SONAME aliases, and a GDB prologue-skipping
breakpoint; those failed attempts are retained and are not passing evidence.
The corrected final run passes all 28 profiles and admits all 28 native-Java
sessions. Readelf stderr is also rejected rather than treated as harmless.

Two selected Java mutations pass with two unchanged baselines in 3.52 seconds:
removing failure cleanup leaves an unfinished real producer handle; removing the
buffer-count upper bound reaches an unexpected native read instead of the bounded
rejection. Both are detected by the intended Java assertion. Mutant classes and
JVMs contribute no coverage. The previous 177-fault suite remains separate
passing evidence; these are two additional controls, not a full179 replay.

CI now invokes the suite and its mutation checks on the x86-64 lane. The Linux
coverage contract requires 44 suites, including all producer failure profiles,
exact pinned header hashes, matched native identities, complete successful
session labels and independently validated retries. Six new admission tests reject
missing/reordered cases, unfinished lifecycles, skipped validators, changed
headers/native identities and incomplete preservation evidence. All **187**
coverage-tool tests and workflow lint pass. Hosted execution of this batch remains
PRESENT, UNVERIFIED; the running PR matrix predates it.

Strict raw verification adds 28 sessions to the matching-bytecode diagnostic union,
retaining all 255 sources / 901 classes and the unchanged production JAR. The new
1,229-session result is **28,432/29,786 lines (95.5%)** and
**20,917/25,878 branches (80.8%)**. Binary/location correctness measures
18,331/19,197 lines (95.5%) and 15,115/18,726 branches (80.7%); file transactions
remain 6,379/6,677 lines (95.5%) and 3,430/4,250 branches (80.7%). The exporter itself
moves from 1,110 to 1,127 covered lines and from 567 to 593 covered branch outcomes.
The accepted critical branch targets still require 1,739 and 395 additional
outcomes. Nothing was excluded or reclassified, and no threshold changed.

The existing JavaExec baseline38 remains unchanged; the new native probe's two
test classes are explicitly excluded from that integration JVM's instrumentation,
not from the production denominator. Its own execution therefore does not require
fabricating JavaExec sessions for a new test task. Evidence is under
`producer-failures-checked/`, `producer-failures-checked-collections/`,
`producer-failure-mutations-checked/` and `producer-failures-checked-verified/` in the bounded
coverage workspace. This mixed-commit union is diagnostic, not hosted acceptance
or publication. Issue #209 remains incomplete.

## Current matching-bytecode measurement after the Linux job

CONFIRMED: implementation `326326eb` adds a backup control that changes bytes
while applying metadata but preserves inode, size and metadata. It must fail
before publication, preserve the source and remove its owned stage. The test
passes 181 checks and four abrupt-exit controls. Export reports round-trip 35
cases covering every C0 control, Unicode, quotes/backslashes and injection-like
text, including valid POSIX path spellings. The strict report reader preserves
those strings; terminal failures preserve status and exception identity.

Seven selected mutations pass with two passing unchanged baselines: the five
backup readback faults and two report text faults. Removing the final backup
digest comparison now fails its intended rejection assertion. Unescaped control
characters fail the JSON assertion; dropping backspace fails the round-trip
assertion. An initial local runner attempt had a Python quoting error and ran no
mutants; the corrected replay detects all seven. The subsequent full configuration
passes **all 177 faults and 41 unchanged baselines in 394.0 seconds**. Every fault
is detected by its behavioral assertion or independent oracle, not setup failure.

The complete 210-task JavaExec baseline38 passes in 274.3 seconds, as do 53,432
independent DWARF expression vectors and all 181 coverage-tool tests. Production
JAR SHA-256 remains `3021d43ef8bcede78a4a87a7fe2c3f49bc15bb3b8cafb5121fb97fcd3a0cd8f6`.

Hosted run [43856734959](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43856734959)
completed its architecture/host jobs successfully. Its coverage gate correctly
fails the critical branch targets: the older hosted cohort reports 95.3% lines /
80.3% branches overall, with 80.2% binary/location branches and 79.6% file-operation
branches. It does not include the newer local commits.

Linux artifact `14234446311` was authenticated against its API SHA-256 and run/job
identity. Its 39-suite policy was loaded unchanged from `078691f2`; the complete
source tree matches the authenticated merge commit `e84c5206`. All session and
oracle receipts were checked under that historical policy and its per-layer
reports regenerated from raw probes. This does **not** satisfy the current
43-suite Linux policy or its new AArch64 measurement lane. No current admission
rule was changed to accept this older artifact.

Combining that verified artifact with baseline38 and the previously verified
matching-bytecode local/host measurements yields 1,201 sessions:

| Stable scope | Lines | Branches |
| --- | --- | --- |
| All 255 sources / 901 classes | 28,411/29,786 (95.4%) | 20,891/25,878 (80.7%) |
| Binary and location correctness, 152 sources | 18,310/19,197 (95.4%) | 15,089/18,726 (80.6%) |
| File transactions and validation, 61 sources | 6,379/6,677 (95.5%) | 3,430/4,250 (80.7%) |

This is a mixed-commit diagnostic union, not hosted acceptance or publication.
The branch targets still require at least 1,765 additional binary/location
outcomes and 395 file-operation outcomes on the unchanged denominator. Prioritize
variable-location proofs, stack value transfers and native-exporter error paths;
then host metadata/security failures and helper/transaction rejection paths.
Missing counters do not alone prove missing assertions or reachable behavior.
Inspect their existing tests and supported APIs before adding controls.

Evidence is retained in the bounded coverage workspace under
`javaexec-baseline-38/`, `report-backup-selected-mutations/`,
`report-backup-javaexec-verified/`, `report-backup-union-verified/`,
`verified-hosted-linux-43856734959/`, `hosted-43856734959-policy-snapshot/`,
`report-backup-hosted-partial-union-43856734959/` and
`report-backup-with-linux-union-43856734959/` and
`report-backup-all-mutations/`. `critical-branch-gaps-326326eb.json` indexes the
remaining critical decision lines with source and report hashes. The new hosted
cohort, protected merge and actual-main publication remain outstanding. Issue #209 stays incomplete.

## Backup readback and cleanup ownership controls

CONFIRMED: `AttachmentFileStoreSmoke` now passes 171 checks, retaining its four
abrupt-process-exit controls. New real filesystem operations change source size
after observation, corrupt or replace a copied stage, replace a staging directory,
replace a stage while applying metadata, and replace a published backup with an
independent byte/metadata-identical file. Rejected copied stages must not reach
the metadata adapter. Independent files with equal contents must not impersonate
the owned stage.

After publication, replacement of the staging directory (empty or occupied) must
produce a reconciliation-required failure, retain the complete backup and preserve
the foreign directory. Explicit adapter I/O failures before capturing directory or
file identity retain the unverified path and preserve the original exception with
cleanup diagnostics. Metadata changes during observation must also be refused.
All controls retain the source/concurrent bytes appropriate to that scenario and
check whether publication occurred. The fixture uses actual Linux files and atomic
renames with its existing test-only metadata contract; it does not substitute for
the separate production Linux/Windows metadata evidence.

The unchanged baseline and four selected mutations pass in 4.8 seconds. Ignoring
observation changes accepts an invalid snapshot; ignoring copied-stage verification
allows an unwanted metadata write; ignoring metadata-stage replacement publishes
an unowned file; ignoring published identity reports success for a replacement.
Each fault causes the corresponding Java assertion failure. The configuration now
contains 174 selected faults; the preceding full165 replay and subsequent selected
batches are separate evidence until current-head CI runs the full configuration.

Evidence: `.forge-work/scratch/coverage-expansion/backup-readback-focused-complete.log`
and `backup-readback-selected-mutations/result.json`. No production bytecode,
coverage threshold, inventory classification or host-support claim changed.

Full JavaExec baseline 37 at `bb0fc59d` passes all 210 tasks in 273.2 seconds,
plus 53,432 independent expression vectors and 181 coverage-tool tests. Raw
verification retains 901 production classes and 255 sources (603 test classes).
JavaExec measures 23,661/29,786 lines and 18,364/25,878 branches. The verified
499-session partial union measures 26,722/29,786 lines (89.7%) and 19,804/25,878
branches (76.5%). File transactions/validation improve to 91.4% lines / 77.6%
branches; binary/location remains 92.8% / 78.2%. The same-cohort comparison adds
eight covered lines and eleven branch outcomes in `AttachmentFileStore`, now
131/132 lines and 53/60 branches. The exact differences are retained in
`backup-readback-coverage-attribution.json`; verified reports use the same prefix.
These remain local partial results; accepted critical targets and hosted/main
publication remain outstanding.

## Retained frame inventory identity checks

CONFIRMED: `OriginalFrameSourcesSmoke` now calls the inventoried debug-frame reader
directly for ELF32/ELF64, both byte orders, and plain, GABI-compressed and
GNU-compressed frames. The complete expanded test passes 1,772 assertions.
It compares decoded bytes against the original supplied frame bytes, rejects
mismatched section offsets/sizes and stored/decoded identities, and rejects both
duplicate source records and two real section headers aliasing the same payload.
An authentic EH-only inventory must not supply a debug-frame section.

The content-change control keeps file size, modification time and file key fixed
while changing a stored byte, so metadata checks cannot mask the content-hash
requirement. Rejection leaves the supplied bytes unchanged. Cancellation at every
observed reader boundary also preserves the file; restoring the exact input
allows an identical successful read. These tests add no production behavior or
architecture-support claims.

The unchanged baseline and five selected mutation checks pass in 2.2 seconds.
Removing stored-hash, decoded-hash, decoded-size, section-ambiguity or duplicate-
inventory checks produces the intended behavioral assertion failure. The full
165-fault suite from the preceding checkpoint remains separate evidence; the
configuration now includes 170 faults and still needs a complete current-head
CI replay. Evidence is under `.forge-work/scratch/coverage-expansion/`:
`frame-reread-focused-final.log` and `frame-reread-selected-mutations/result.json`.

Full JavaExec baseline 36 at `4aad940e` passes all 210 tasks in 274.3 seconds,
with 53,432 independent expression vectors and 181 coverage-tool tests passing.
Strict raw verification retains all 901 production classes and 255 sources.
JavaExec measures 23,653/29,786 lines and 18,353/25,878 branches. The matching-bytecode
499-session partial union measures 26,714/29,786 lines (89.7%) and 19,793/25,878
branches (76.5%). Binary/location coverage is 92.8% lines / 78.2% branches; file
transactions remain 91.2% / 77.4%. Compared with the preceding same-cohort report,
this adds 23 covered lines and 26 covered branch outcomes, all in the retained
frame reader. The attribution and verified reports use the `frame-reread-` prefix
under the same local evidence directory. Hosted acceptance remains unverified;
the full current-head cohort, critical targets and main publication are pending.

## Mixed incoming register/stack proof controls

CONFIRMED: `MixedParameterPrefixSmoke` now runs the six decoded ARM scenarios in
both `ARM:LE:32:v8` and `ARM:BE:32:v8`, with 224 assertions. Actual compiler-assigned
and analyst-custom parameter storage must retain the expected object-memory piece
order, DWARF registers, stack-depth adjustment and unavailable tail. This is a
Java extraction test, not a new advertised big-endian ARM end-to-end support claim.

The former wrong-size Parameter proxy did not isolate size validation: its object
identity differed from the saved parameter, so ownership rejected it first. The
replacement uses the actual attached eight-byte formal with a valid twelve-byte
carrier. Additional real ProgramDB controls reject foreign programs/functions,
unsaved parameters, returns used as incoming formals, foreign-program storage,
forced indirection, missing value/stack-base mappings and unsupported function
body shapes. Rejections and immediate/mid-proof cancellation preserve bytes and
curated metadata, preserve the cancellation exception identity, and leave a
subsequent valid proof unchanged. Fixture transactions roll back.

The focused unchanged baseline and four selected mutations pass: dropping foreign
storage admission, dropping saved-parameter admission, forgetting indirection and
reversing stack-depth subtraction each cause the intended Java assertion failure.
Local selected replay took 12.8 seconds. The earlier attempt stopped on a nonunique
stack-depth mutation anchor; it is not a successful full run. The corrected anchor
selects only mixed-piece translation. The repository's full mutation configuration
now contains 165 faults. Its complete replay at `57f71654` passed in 384.4
seconds: all 165 faults detected and all 38 unchanged baselines passed.

Evidence: `.forge-work/scratch/coverage-expansion/mixed-prefix-focused-final.log`
and `mixed-prefix-selected-mutations-final/result.json`. The complete replay is
`mixed-prefix-all-mutation-checks/result.json`. No production code, production
inventory, coverage threshold or target mapping changed.

All 210 JavaExec tasks passed at `57f71654` in 273.1 seconds, as did 53,432
independent expression vectors and 181 coverage-tool tests. Baseline 35 records
901 production classes, 598 test classes and all 255 production sources. Raw
JavaExec verification gives 23,630/29,786 lines and 18,327/25,878 branches. The
changed production i386 logic still passes the minimum gate at 100% lines and
86.7% branches.

The verified 499-session **partial mixed-commit** union is 26,691/29,786 lines
(89.6%) and 19,767/25,878 branches (76.4%). Binary/location coverage is 92.7% lines /
78.1% branches; file transactions remain 91.2% / 77.4%. This is two more covered
lines and eight more covered branch outcomes than the preceding comparable
partial union. `GhidraVariableStorage` now measures 821/867 lines and 891/1,107
branches. `mixed-prefix-coverage-attribution.json` records the specific decisions.
The full hosted cohort, critical targets, protected integration and actual-main
publication remain outstanding. These local results cannot publish a badge.

## Measurement contract

[critical-sources.json](critical-sources.json) freezes the responsibility inventory:
152 binary/location sources, 61 file-transaction/validation sources and 42 remaining
production sources. All 255 sources and 901 compiled production classes stay in
the denominator, including GUI/framework code. No sources were moved between
groups or excluded to improve these results. Native C/libdwarf, Python and shell
are explicitly outside this Java metric.

The report unions raw JaCoCo probes only after matching production class identities
and probe counts, complete session receipts and recorded behavioral oracles. It
retains JavaExec, headless, native-Java and Windows reports separately. Percentages
are never added or averaged. Hosted acceptance additionally requires one exact
commit/run cohort, all required suites and the normal protected gate. Mixed-run
local analysis cannot publish a badge or stand in for that gate.

PR #208 was accepted on main at `c6265e1c657c9ffc7a4d9cb71017cca1e1bc5786`:
[CI 43761191009](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43761191009).
Its legacy JavaExec report is 23,305/29,782 lines (78.3%) and 17,330/25,872
branches (67.0%). That badge's scope remains unchanged.

## Historical local checkpoint before the i386 production fix

HISTORICAL: the pre-fix complete JavaExec run executed all 210 tasks at
`e40fabd6375e848ea41e2b08991346242b2139c0` in 273.5 seconds. The combined local report
contains 1,550 sessions with the full unchanged denominator:

| Scope | Line coverage | Branch coverage | Accepted target |
| --- | ---: | ---: | ---: |
| All production Java | 95.3% | 80.2% | 85% / 80% |
| Binary and location correctness | 95.3% | 80.1% | 95% / 90% |
| File transactions and validation | 95.3% | 79.6% | 95% / 90% |
| Remaining production | 95.1% | 81.7% | Included in overall |

The binary/location line count is 18,290/19,193, meeting its exact 95%
line gate. File transactions/validation also meets its line gate at
6,365/6,677. Both critical branch targets remain unmet. The exact overall
85% line and 80% branch targets were met locally for that production revision.

That production JAR SHA-256 was
`98ea0bbb8a292152d76cd2be9972ad5c5e270421ab65043fc1ced2afaa81caf9`. No production Java changed in this checkpoint.
Exact counters, per-line missed decisions, origins, execution hashes and separate
layer reports are retained under
`.forge-work/scratch/coverage-expansion/combined-i386-boundaries-hosted-baseline/`.
The local script `combine-verified-hosted-stable.py` reuses the normal collection
admission and class/probe verifier and retains each historical artifact's actual
run/merge commit. It does not claim a new hosted cohort.

## Measurement gaps versus behavioral gaps

| Area | Verified evidence | Remaining decisions or limitations |
| --- | --- | --- |
| Exporter, types and variable locations | Real failed/mixed/empty decompilation, C++/inheritance, lexical/object/formatter/call-site exports; validators and GDB assertions; isolated native-Java and analyzer measurements | Branch gaps remain in variable-storage proofs, stack value flow, native exporter decisions and vtable evidence. Add assertions for unsupported/conflicting evidence and lifetime boundaries; do not invent locations to increase coverage |
| Installation, attachment, rollback and recovery | Build-ID lifecycle/commands, crash recovery, receipts, source bundles, filesystem publication and saved-project protection; new transaction cases below | Native failures, output-parent/metadata races and several recovery observations remain outside the measured paths. Intentional halt children remain behavioral controls without JaCoCo shutdown data |
| Linux host operations | Historical CI's 43 Linux-host sessions were independently regenerated from raw probes, including both real privilege modes | This closes a measurement gap: 119 lines and 40 branch outcomes were absent from the prior local union. It is not a new behavior test. Privileged production attachment roles remain required in current CI |
| Windows filesystem implementations | Historical CI's 53 actual Windows JVM sessions independently regenerated; native metadata/security/attachment/build-ID oracles retained | Native API failures, sharing/descriptor/security branches and interactive host behavior still require Windows execution. Linux filesystem adapters do not prove these paths |
| Synthetic source and debugger loading | Native source relocation with byte comparisons, plain/zlib outputs, exec/PIE GDB checks, retained-source lookup; companion cancellation and alias rejection | Local LLDB is unavailable; hosted consumer assertions remain required. Some malformed-section and interrupted-publication decisions remain uncovered |
| Firmware and analyst context | Four hosted firmware sessions independently regenerated; real QEMU/GDB, invalid/cancelled export controls, deterministic retry, saved-program annotations/equates/context | The measured firmware profile does not establish every architecture or unsupported memory-map behavior. Residual extraction and cleanup failure paths remain |

Raw hosted verification used run
[43787120688](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43787120688),
merge commit `224f6cb76acfc12bccaff2bf5b1dbcb60479980c`. Artifact digests,
successful producing jobs, required suites, privilege oracles, exact bytecode and
regenerated counters/XML were checked. The only prose difference was the later
removal of the word “direct” from the halt-control description. No local process
was relabeled as GitHub Actions. Receipts live in
`verified-hosted-{linux_host,windows,firmware}-43787120688/` under the same workspace.

## New transaction behavior checks

`attachmentTransactionSmoke` passes 875 assertions for initial and refresh modes,
including the existing eight abrupt-process exits. Added scenarios verify:

- A prepared receipt must agree with the selected receipt path, host contract,
  durability contract and sidecar CRC before creating output.
- Interrupted recovery rejects a different operation, a substituted explicit role
  even when its bytes match, and changed required backups or previous artifacts.
  Rejection preserves the target and operation receipt and creates no recovery output.
- Refresh rejects an uncommitted or mismatched previous association, reused operation
  identity, changed target path, original backup, sidecar, source or prior CRC.
- A prior image independently restored to a new inode is accepted only with matching
  content and metadata. Foreign bytes, changed mode and dangling links are preserved
  and never reported as successful restoration.
- Concurrent replacement of the operation receipt is preserved; recovery does not
  overwrite it or publish an unauthorized recovery journal.

`AttachmentTransaction` measures 263/269 executable lines and
172/202 branch outcomes. These are filesystem-controller tests with an
explicit test host, not ELF/DWARF validation or native Windows evidence.

All 83 selected mutation checks pass with unchanged-source baselines. Four new
mutants remove the CRC check, permit reused operation identity, accept unrecorded
recovery paths or reject a correctly restored prior image. Detection requires a
behavioral assertion failure; compilation, loading and timeout failures do not count.
This is a selected fault inventory, not a repository-wide mutation score.

## MIPS allocation boundary checks

`mipsN32ParameterAllocationSmoke` passes 966 assertions using real Ghidra program,
compiler-specification and data-type objects. N32 and N64 run in both byte orders.
New cases admit the documented ELF flag variants and reject unsupported machine,
object kind, OS ABI, ABI revision, ISA/register-width/extension and record flags
without applying corrections or changing input bytes or saved signatures.
Initialization cancellation, unknown calling conventions and foreign program
ownership also preserve the selected program.

Typedef-wrapped direct double fields retain their positional floating register;
cross-slot doubles, short floats and partial structure slots use the appropriate
general slots and leave the following parameter at the expected position. The
allocation-only shape never replaces the analyst's saved type or signature.
`MipsWideParameterAllocation` measures 141/146 executable lines and
143/168 branch outcomes in the unchanged critical inventory.

Three selected mutants are detected: accepting unknown ABI-record flags, losing
a direct field's typedef, and dropping the alignment hole before a wide argument.
A removed component-offset guard did not change behavior because the real Ghidra
lookup already requires a component start; that experiment is explicitly not
counted as a detected fault. These allocation-model tests do not add new claims
of end-to-end MIPS target support. Existing compiler-correlated QEMU/GDB and
structural-validator lanes remain required. The ABI version check after an
AVAILABLE observation is still a defensive guard: the observer rejects nonzero
versions first; no fabricated observation was introduced to execute it.

## Variable-byte preservation and vtable evidence

`registerByteSliceFlowSmoke` passes 475,324 checks. The new 380 raw p-code
combinations compare shifts, sign/zero extension, masks, wrapping, carries and
both operand orders against an independent finite-width BigInteger evaluator.
Every admitted case preserves the exact tracked register byte across all 256
byte values and selected nuisance boundaries. Every rejected case has a concrete
destructive counterexample. These ARM-LE model controls complement the existing
decoded-instruction tests; they do not establish new target support.

`StackValueFlow` measures 534/542 executable lines and
617/789 branch outcomes. The new mask tests add seven
lines and 19 branch outcomes there. Four targeted faults are detected: invented
zero sign-extension bits, an incorrectly zeroed oversized arithmetic shift,
unsafe overlapping addition, and loss of the second operand's preserved byte.

`vtableBindingEvidenceSmoke` passes 690 checks using real x86-64 and AArch64
Ghidra programs and relocation records. One-field relocation changes (address,
type, status, values, bytes and symbol name) must change the context fingerprint
while preserving the original and loaded byte hashes. Explicit resaving admits
the new witness; ordinary reads reject stale evidence without refreshing it.
Relocations just outside the table do not invalidate its witness. Exact value
and byte bounds are accepted; oversized values, bytes and aggregate relocation
data are rejected without replacing saved evidence. Each control rolls back its
own transaction and verifies exact restoration before the immutable reopen test.

Malformed requests cover invalid identities, text, extents, point counts and
complete-object geometry. Persisted-record controls include version, count,
trailing bytes and the decoded-size limit independently of Base64 length.
`GhidraVtableBindings` measures 238/242 executable
lines and 209/234 branch outcomes. Five selected
mutants detect omitted relocation type/status/values and weakened value/byte
bounds. These are saved-program evidence tests, not new emitted-DWARF claims.

The prior hosted run at `aca32e4d`,
[43810870428](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43810870428),
failed when Maven Central returned HTTP 429 while resolving JaCoCo. Both native
builds passed; downstream integration jobs did not run. This infrastructure
failure is not passing validation and does not establish an exporter regression.

## Vtable inventory and file-mapping admission

The additional saved-program controls cover malformed option keys/types,
restricted export class models, and cancellation without changing saved evidence.
Explicit tables are omitted when the canonical class is absent, the ABI differs,
or the export only has an inferred class binding. A base relationship can establish
membership without local virtual methods; unrelated class graphs and function
symbols cannot establish a table association.

The exact inventory limits (4,096 keys, 16 MiB encoded records and 64 MiB declared
byte witnesses) retain the valid table among rejected records. Exceeding each
limit rejects the whole inventory with a diagnostic; it never returns an accepted
prefix or repairs the original record. These tests use real ProgramDB options,
including malformed persisted records, rather than mocked Program APIs.

Adjacent memory blocks backed by contiguous offsets in one FileBytes object are
accepted. A file-offset gap, a switch to another FileBytes identity, disagreement
between original and loaded offset-to-top bytes, a misaligned label or an overlay
address is rejected. Every test rolls back its own transaction and rechecks the
original encoded record and snapshot before immutable database reopen.

Five additional mutants are detected: a relaxed key count, undercharged encoded
records, undercharged byte witnesses, ignored file-offset discontinuity, and
merged FileBytes identities. These model tests preserve the existing independent
ELF/DWARF, debugger and supported-host acceptance requirements.

Residual gaps include defensive checks after inheritance admission, unobserved
relocation representations and demangler exceptions. The aggregate relocation
budget rejects records before the separate maximum-record-count guard can be
reached. These gaps remain in the denominator; no invalid Program API behavior
was fabricated to execute them.

CI [43814174541](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43814174541)
was started for pushed commit `f26eb1a1`. The next local test checkpoint is held
while that run completes, so frequent pushes do not repeatedly replace the
hosted integration measurement. Local measurements retain their own commit and
do not claim that the pending hosted run contains these additional tests.

That run's MIPS big-endian lane failed before export testing because its pinned
GDB source download returned `Network is unreachable`. The local downloader fix
retries transport failures up to three times, removes private staging after each
attempt, limits downloads to 128 MiB and publishes only an archive matching the
unchanged release checksum. Fourteen isolated transport/ownership tests and
actionlint pass. Hosted validation of this fix is still pending; the existing
run's other jobs are retained for their measurements. This Python change is
outside the Java coverage percentage.

## Remaining acceptance

Reach every accepted group target with meaningful tests, verify the current hosted
cohort, integrate through the protected PR/main gate and verify actual-main
publication of combined line/branch metrics and separately labeled reports.
Changed-code checks, independent readers/debuggers, original-input preservation,
deterministic output and real host/GUI/cancellation workflows remain mandatory.

Run builds/tests through `python3 support/storage-guard.py run -- COMMAND`, with
Ghidra 12.0.3, Java 21 and Gradle `--no-daemon`. Mutation runs delete their owned
compiled variants; retain concise reports and raw measurements within the existing
budgets. No new worktree or `/dev/shm` workspace is needed.

## Source observation portability correction

CI run 43814174541's Windows-host job 133128527297 failed the new
`SourceBundleFilesSmoke` identical-replacement assertion. The test assumed
`BasicFileAttributes.fileKey()` was available. OpenJDK 21's Windows implementation
returns null ([upstream implementation](https://github.com/openjdk/jdk21u/blob/master/src/java.base/windows/classes/sun/nio/fs/WindowsFileAttributes.java#L379)).
This is a test portability error and an explicit limit of the existing reader:
its size/hash/mtime binding cannot distinguish two files with identical values
when the provider supplies no identity key. It is not evidence that Windows
provides inode-change protection. Native attachment identity checks are separate.

The test still performs every identical replacement on every host and checks
that the replacement is a different file using `Files.isSameFile`. Providers
with file keys must expose distinct keys and reject the unstable observation;
providers without keys must report that limitation and preserve the identical
content binding. No production behavior or coverage denominator changed.

A new replacement case preserves size and mtime but alters the last byte, keeping
the index detection prefix intact. Index, manifest and source-part replacements
are swept across every observed cancellation checkpoint. Changed content must
be rejected during acquisition or by the retained bundle's verification on
**all** hosts. Every retained original is checked byte-for-byte. Linux focused
validation passes 65,352 assertions with 1,913 cancellation points; actual
Windows execution of this correction is **PRESENT, UNVERIFIED** until CI runs.

All 83 selected mutation controls pass after this correction, including the
removed inventory-key guard and removed part-mtime guard. The Linux checks still
catch both faults; no Windows mutation result is claimed.

## Static recovery admission boundaries

`staticRecoverySmoke` passes 360 assertions across real x86-64, AArch64, ARM32,
MIPS big-endian and MIPS little-endian Ghidra programs. Added cases reject stale
function IDs, symbol IDs, names, source provenance and addresses; null, undefined,
zero-length and dynamic-length types; and incompatible explicit extents. Valid
exact or unspecified extents retain the inferred-information diagnostic. Rejections
preserve saved symbols, bytes and undefined listing data.

Additional cases reject a label moved into another function, existing data that
starts before the inferred address, a type crossing a memory-block boundary,
unmapped storage, and address overflow. A saved symbol immediately after the
extent and a type ending exactly at the memory-block boundary remain valid.
Per-profile transactions restore the original fixture before the existing saved
binding and lexical-ownership tests run. These are admission tests using constructed
candidate evidence, not proof of extraction from a real decompiler `HighFunction`;
the separate headless tests remain necessary.

All 86 selected mutants are detected, including removal of the saved-symbol ID,
explicit-extent and containing-memory-block checks. Compilation and class loading
failures are not counted as detections.

Baseline19 adds two covered lines and 17 branch outcomes to the verified local
union. `GhidraStaticRecovery` now measures 63/87 lines and 66/116 branch outcomes;
most remaining gaps are in actual HighFunction evidence extraction. The full
production denominator and the accepted targets are unchanged.

## Bounded switch proof controls

`boundedSwitchProofSmoke` passes 98 cases / 927 assertions at original and rebased
addresses. All cases use real decoded x86-64 instructions and source-built ELF
bytes; there are no fabricated p-code/prototype overrides. New valid shapes
exercise byte/word/dword/qword index registers, addition/subtraction, AND/OR/XOR,
left/right shifts, repeated identical table reads, and the maximum accepted
unsigned guard. The expected target list and each original table address, width
and raw value are specified independently, including signed relative offsets.
The original ELF bytes remain unchanged and successful proofs repeat exactly.

Negative controls require the specific rejection reason for conflicting table
read widths, zero/excess guard limits, negative or undecoded targets, missing
ownership/instructions, another function entry, interior incoming flow, and
saved instruction length/flow/fallthrough overrides. Non-flow references and an
incoming edge from the expected predecessor remain valid. Exactly 32 dispatch
instructions are accepted; 33 are rejected. The test explicitly disassembles the
long NOP run because automatic Ghidra flow disassembly stops before its end.

Fixture development exposed two assumptions, not production defects: a direct
absolute memory operand lifts to COPY rather than LOAD, and Ghidra names the
strict unsigned guard `jnc`, outside the current audited profile. Register-indirect
loads now exercise the read consistency guard; `jnc` rejection is recorded as a
current profile limitation. No architecture-support expansion is claimed, and
failed fixture attempts are not included in passing coverage collections.

All 90 selected mutants are detected. The four new faults accept conflicting
read widths, exceed the dispatch-window budget, add instead of subtracting an
index, or shift the index in the wrong direction. Each is caught by a behavioral
assertion; unchanged-source baselines pass first.

Baseline20 adds six covered lines and 25 branch outcomes. `GhidraBoundedSwitch`
now measures 214/217 lines and 211/283 branches in the unchanged denominator.
The current combined report remains a local diagnostic union, not hosted acceptance.

The next identified measurement gap is `lexical-statics-export.py` and
`recovered-statics-export.py`: they contain real producer/headless/GDB assertions
but do not use `integration_coverage.Collection`. The already-measured
`lexical-shadow-export.py` is a separate harness. Instrument existing recovered
static modes and preservation/cancellation oracles before treating their missing
HighFunction probes as evidence of missing behavior tests.

## Static-scope integration measurement

The existing lexical-static and recovered-static harnesses now collect separate
headless and native-Java probes without changing their exporter or debugger
assertions. All three x86-64 roles (non-PIE, PIE and rebased PIE) passed locally:
15 complete collections, 96 analyzer sessions and three isolated native-Java
sessions. These exercise curated, inferred and memory-backed static variables,
stale/conflicting/coalesced evidence, decompilation failures, cancellation,
repeatable output and project/input preservation. The admission checks rederive
the expected object, value, lexical scope and relocated instruction address at
every debugger boundary, and require every mode and JVM session.

All 137 coverage-tool tests passed, including rejection of missing, reordered,
duplicated or semantically inconsistent static evidence. Hosted Linux acceptance
now requires these four additional suites for all three roles. Current CI run
43814174541 predates this instrumentation; its original 33-suite verifier is
retained by exact source hash only for historical local measurement verification,
not to satisfy the new 37-suite acceptance contract.

The first rebased attempt failed during import because the local Ghidra script
cache contained Java 25 bytecode while the test uses Java 21. Its incomplete
collections are excluded. A retry using a task-owned Java user cache passed;
the user's cache was preserved. The validation installation's original extension
was restored after every driver. Raw receipts remain under
`.forge-work/scratch/coverage-expansion/statics-measured-collections/`.
The verified raw-probe union adds 37 lines and 37 branch outcomes: overall
28,206/29,782 lines (94.7%) and 20,452/25,872 branches (79.1%). The overall branch
and critical-group targets remain unmet. The local preview remains ineligible
for hosted publication; all original session provenance is retained.

## Stack-control-flow integration measurement

The existing stack-control-flow harness now measures its import and two real
exports. Six local x86-64 cases passed: 32- and 64-bit locals, each in non-PIE,
PIE and rebased PIE. Every case retained its LLVM/readelf/strict-consumer checks,
repeatable sidecar/source checks, unchanged input and saved-project checks,
and compiler/exported GDB instruction-by-instruction value and availability
assertions. Each debugger trace contains 951 instructions across 42 invocations
of seven functions, covering both branch choices and three seed values.

Coverage admission additionally requires both debugger traces to agree on their
executed instruction addresses and bytes. It checks logical/physical values,
loop visits, stale register backups, unavailable and retired values, body holes,
return values, source navigation, process exit and all three analyzer sessions.
All 141 coverage-tool tests passed; synthetic receipt corruption tests are kept
separate from the actual runtime evidence. The cached validation installation was
restored to its original extension after the 18 measured analyzer sessions.

Hosted acceptance now requires the stack-flow suite for all six profiles (38
Linux suites total). Comparative old-package runs cannot contribute to this
single-package collection. This adds measurement to existing integration tests;
it does not change production behavior or broaden the advertised target set.
Raw data is retained under `stack-flow-measured-collections` in the bounded
coverage workspace. The verified union adds two covered branch outcomes in `StackValueFlow`: overall
28,206/29,782 lines and 20,454/25,872 branches, still 94.7% / 79.1%. This shows
most of this behavior was already measured by the Java tests. The next work
therefore targets genuinely missing boundary cases rather than more similar runs.

## ARM original mode-inventory boundaries

The ARM alias suite now passes 732 checks. New cases inspect real ELF section
and symbol bytes for invalid symbol-table/string-table framing, missing or invalid
extended section indices, malformed mapping records, unsupported code flags,
misaligned/out-of-section entries and contradictory mapping/function modes.
Positive controls retain absolute entries and valid visibility, coalesce equal
mapping duplicates, ignore unresolved/non-code symbols and non-executable
sections, and accept an end-of-section mapping marker. Independent expected maps,
deterministic results and unchanged input bytes/timestamps are asserted.

All 93 selected mutation controls passed, including three new faults: accepting
conflicting instruction modes, rejecting a valid section-end marker, and using
non-executable section mappings. Compilation and class-loading failures do not
count as detection. These are ELF inventory tests, not a new runtime architecture
support claim. Production code is unchanged. All 210 JavaExec tasks passed at this test-source snapshot. The verified
combined report retains 965 sessions, 901 production classes and all 255 sources.
Overall coverage is 94.7% lines / 79.2% branches.
The accepted critical-group targets and hosted acceptance remain incomplete.

## Curated type extraction boundaries

Real saved-program extraction now passes 266 additional checks across seven
selected Ghidra language/compiler profiles, alongside the existing 73 floating
layout checks. Tests preserve wide-character UTF encodings and profile sizes,
default member names, constant/volatile members without altering shared base
types, and one-byte storage for three-bit fields in both byte orders. Zero-width
bitfields affect alignment without becoming readable members. Function-owned
statics are omitted with diagnostics when their owner is not exported; negative
and overflowing global address translations cannot invent output variables.
Repeated extraction is deterministic and leaves the program modification number
unchanged.

The initial test incorrectly assumed four-byte wchar in the MIPS32 default
profiles. Inspection of the pinned compiler specs and DataOrganizationImpl
confirmed that those profiles inherit Ghidra's two-byte default; explicit test
expectations now preserve the selected saved data organization. This is not a
runtime ABI claim or a Windows-host test. The failed fixture attempt is excluded.

All 96 selected mutation controls passed, including three new faults: changing
UTF to unsigned integer encoding, changing member const to volatile, and emitting
a zero-width field as a value. All 210 JavaExec tasks and 141 coverage-tool tests passed. The combined
union adds 14 lines and 8 branch outcomes, retaining all 965 sessions and
the unchanged production denominator. The initial mutation baseline compile
failed on the existing deprecated DataType.VOID reference. Only that source
receives a deprecation-category warning exception; all other warnings remain
errors, and failed compilation never counts as a detected fault. No production
Java changed. Hosted acceptance and the full critical targets remain incomplete.

## Sectionless ARM mode evidence and resource boundaries

The ARM alias suite now passes 756 checks. A sectionless ELF32 little-endian
EABI5 fixture independently proves the ARM/Thumb entry map synthesized from
PT_LOAD allocations and dynamic symbols. Planning preserves a Thumb alias at
the allocation boundary and rejects contradictory ARM evidence. Cancellation
at the beginning, middle and end leaves the original bytes intact. Unsupported
machine, ELF class and byte order are rejected by the direct ARM policy.

Actual collection sizes test the 65,536/65,537 mode-cue boundary and the
16,777,216 alias/reserved-symbol comparison-product limit. At the admitted limit,
ambiguous aliases still receive their normal individual rejection; exceeding it
fails before those comparisons. Fixtures remain small and unchanged.

All 100 selected mutation controls passed. New faults drop the sectionless mode
mirror, reject the maximum permitted cue count, ignore the comparison budget,
and substitute a bitfield's base integer width for its actual storage width.
The latter is detected by the curated type checks, including the one-byte
three-bit field. These are parser/planner and saved-model tests, not a new
runtime architecture claim. All 210 JavaExec tasks and 141 coverage-tool tests
passed. The verified combined union adds six lines and eight branch outcomes
across the same 965 sessions. Production code and the denominator are unchanged.
Hosted acceptance remains pending.

## Call memory effects and nested frame boundaries

`callMemoryEffectsSmoke` now includes 42 independently assembled instruction
fixtures across x86-32, x86-64 and AArch64 (442 checks), plus 165 checks of the
existing composed call-graph scenarios. Saved Ghidra programs decode the real
bytes; assembly comments beside each fixture describe the independent input.
These are analysis tests, not new runtime architecture-support claims.

Assertions compare the complete possible-write/release set and return stack
delta. They cover copied stack pointers, commuted and constant arithmetic,
negative offsets, stack-pointer differences, absolute/unknown stores, partial
register clobbers, signed offset overflow and agreeing/conflicting joins.
Reversed instruction enumeration must produce the same proof. Duplicate rows,
missing entries and open successor graphs cannot establish a memory contract.
Cancellation at the beginning, middle and end stops immediately; bytes and
the saved-program modification number remain unchanged.

Nested callees write at SP+16. Their callers must translate those writes to
SP+8 on x86-64 and SP+0 on the selected AArch64 frame, including all frame
releases. A missing memory summary, missing register proof or evidence for a
different callee entry is rejected rather than treated as unaffected memory.

All 105 selected mutation controls passed. Five new faults accept absolute
stores as stack-relative, retain stack identity after subtracting two stack
pointers, accept narrow signed-offset overflow, fail to translate nested writes,
or retain released stack storage. Behavioral assertions detect each fault;
compilation and loading failures do not count. Production code is unchanged.
All 210 JavaExec tasks and 141 coverage-tool tests passed. The combined
union adds 2 lines and 13 branch outcomes, with all 965 sessions
and the production denominator retained. Hosted acceptance remains pending.

## Saved C++ configuration measurement

The existing saved-inheritance harness now measures its actual curation/export
JVM and its production-wrapper reopen JVM. All 34 existing x86-64 cases passed:
four exec/PIE and RTTI/no-RTTI profiles, two rebased PIE profiles with adjustment
thunks, and all four profiles for each of seven name/evidence variants. The
result is 34 complete collections and 68 headless sessions, with no production
Java change. The original installed extension was restored after validation.

Admission requires the complete 11-class, eight-base, 15-method, seven-vtable
configuration, its declaration, preview/apply/preview round-trip, both JVM
sessions, identical reopened sidecar/source, unchanged executable/project,
readelf/LLVM/libdwarf validation and the existing GDB observations. Those include
dynamic identities, physical base offsets, inherited values, vtable lookup and
compiler-agreed adjustment-thunk stepping/returns. Missing, stale and conflicting
evidence must retain the existing static-name behavior. Source hashes and both
compiler/reference and current observations remain in the receipts.

The normal hosted gate now requires 39 suites, including this complete cohort.
All 146 coverage-tool tests and actionlint passed; corruption tests reject lost
sessions, omitted profiles, modified inputs/projects/outputs, incomplete metadata,
changed values/layouts/thunks and lost debugger-call restrictions. The raw
class/probe union passed with all 901 production classes and 255 source files.
These existing integration tests add 33 covered lines and 42 branch outcomes to
the combined measurement. `GhidraCxxProfile` now measures 155/160 lines and
90/124 branch outcomes. The JavaExec baseline retains its actual `1f0de744`
identity; the new measurement records checkout `54f4285e` and harness snapshot
`2de1c651`. An initial local union attempt was correctly rejected for assigning
the newer commit to the older JavaExec receipts; the retry preserves all original
identities. This remains a mixed-run local report, not hosted acceptance.

After verification, 28 task-owned variant projects were retired with file hashes
recorded, reclaiming 37,044,224 physical bytes. Six selected positive projects,
all probes/oracles, debugger logs and ELF/source artifacts remain available.

## Saved C++ configuration rejection and inventory boundaries

`cxxProfileSmoke` now invokes `CxxProfileBoundarySmoke` against actual ProgramDB
instances. The x86-64 and AArch64 configuration cases reject missing symbols,
non-class symbols, missing types and saved non-structure types. A selected class
cannot reuse another retained class's canonical type. Rejection restores the
previous binding, including overwritten evidence bytes.

Stale retained declaration and vtable records cause a late rejection after the
selected class evidence has been written. Complete saved metadata is compared
before and after; inventory diagnoses invalid records without offering them as
valid selections or repairing them. Explicit removals commit only when requested;
a successful preview restores them. Target bytes and an independent analyst
label remain intact. These tests validate configuration, not new target support.

Inventory tests use real saved classes, structures, memory labels and functions.
They check 1,024 versus 1,025 candidates independently for each category, unique
identities, matching names, deterministic ordering and unchanged program state.
External non-memory labels and unrelated symbols are excluded. Null/oversized
filters, malformed/overflowing record keys and incompatible saved option types
are rejected without changing their contents. At 4,096 invalid saved records,
each record is diagnosed; the 4,097th exceeds the bound. Exactly 16 MiB of record
text is admitted to record validation; one further character exceeds the total
budget. Cancellation during inventory preserves metadata and modification number.

The focused suite passes 24,884 new assertions (including individual candidate
identity/filter checks), the existing 140 profile assertions and 41 parser checks.
Six mutation controls exercise committing previews, allowing retained canonical
type conflicts or stale declarations, and exceeding candidate/count/text limits.
All 111 selected mutation controls passed in 242.3 seconds, including all six
new faults. Compilation/loading failures do not count as detection. All 210
JavaExec tasks passed in 270.3 seconds; all 146 coverage-tool tests passed. The verified raw union adds 3 lines and 22 branch outcomes.
GhidraCxxProfile now covers 158/160 lines and 112/124 branch outcomes.
Hosted acceptance and the full critical targets remain pending.
Production code and the coverage denominator are unchanged.

## Saved vtable range and lookup conflicts

`CxxVtableConflictSmoke`, invoked by `cxxProfileSmoke`, adds 150 assertions on
real x86-64 and AArch64 ProgramDB instances with original FileBytes-backed memory.
An explicit saved class/base graph admits the baseline table. Its original
virtual address and file offset are checked independently against the fixture.

The controller rejects a second table overlapping from either side, an identical
extent under another label, a duplicate mangled name at a disjoint address, and
two different classes with the same debugger lookup name. A passive monitor
observes that both the selected class evidence and new table record were written
before the rejection. Exact record comparisons prove rollback, including restored
class evidence and the original table witness; all memory and independent tail
bytes remain unchanged.

Positive controls accept tables ending exactly at the baseline start or starting
exactly at its end, and disjoint tables. Ghidra's demangler accepts both
`_ZTV5Child` and `_ZTVN5ChildE` as `vtable for Child`: distinct spellings can share
a lookup name only when their saved class identity agrees. Successful previews
restore the original configuration; commits retain exact identities; filtered
inventory includes both saved tables without mutating the program. Repeat apply
is deterministic and explicit removal restores the baseline exactly.

Six new selected mutations omit either overlap test, change either comparison to
reject touching ranges, accept duplicate mangled names, or accept ambiguous
lookup ownership. All 117 selected mutation controls passed in 288.6 seconds.
All 210 JavaExec tasks passed in 271.5 seconds, and all 146
coverage-tool tests passed. The verified raw union adds one line and
six branch outcomes. GhidraCxxProfile now measures 159/160 lines and
118/124 branches. The full goal and hosted acceptance remain pending.
No production code, emitted format or architecture support claim changes in this batch.

## Call-value folding and expression boundaries

`callValueSmoke` now generates 53,432 expression vectors, including 45,452 new
boundary cases from `CallValueBoundarySmoke`. The independent Python DWARF VM
passed every vector in the focused run. Expected values use BigInteger arithmetic
and explicit machine-width masks; they do not evaluate the production expression
tree. Both 32/64-bit DWARF stacks and both byte orders are exercised.

The vectors compare folded and raw constant operations, including high unsigned
values and shift counts of zero, one, width-minus-one, width, width-plus-one and
the maximum unsigned stack value. Dynamic cases cover same operands, zero/one
on either side, literal/equal-arm selections, unaligned nested slices, slices
through bitwise operations, and slices crossing into signed/unsigned extensions.
Real expression trees at depth32 and node256 must serialize and evaluate; the
next depth/node is rejected. Twenty-nine new invalid cases also check that width
and tree limits are enforced before simplification can discard invalid input.

The mutation harness now runs the existing independent VM after successful
CallValue vector generation and records the evaluator and vector hashes. Five
new faults alter unsigned shifts, shift-count bounds, nested slice offsets,
constant sign extension or selection; a sixth rejects the exact node budget.
Only behavioral Java or independent-VM assertions count as detection. Missing
files, incomplete vector sets, compilation/class-loading errors and failed
fixture generation remain failures of the run. Eight outcome-classification
tests passed; these synthetic outcomes are not claimed as real mutation evidence.

All 123 selected mutants passed in 294.9 seconds. Five new numeric faults were
detected by the independent DWARF VM; the node-limit fault failed a Java behavioral
assertion. All 210 JavaExec tasks passed in 271.0 seconds, followed by all 53,432
independent VM checks and 154 coverage-tool tests. The verified raw union adds
five lines and 46 branch outcomes. CallValue covers 152/152 lines and 195/200
branches. Full critical targets and hosted main acceptance remain pending.
Production code and coverage scope are unchanged.

## Saved declaration boundaries

`ProgramDeclarationBoundarySmoke` runs through the existing `typeGraphSmoke`
task and adds 115 checks before native producer admission. It rejects missing
identities, namespace components, types, provenance and model components; tests
zero/negative extents; and preserves valid wide addresses without narrowing.
These are model-field checks, not new runtime architecture claims.

Caller-owned lists cannot alter saved declarations, and canonical ordering does
not reorder ABI parameters or mutate the caller's lists. Duplicate external
spellings retain their distinct identities. Saved local declarations retain
their first-use and assigned-storage hints without inventing a variable location.

Seven mutation controls check namespace ownership, blank identities, zero-sized
locals, first-use ordering, immutable globals and ABI parameter order. All 130
selected mutants passed with behavioral assertion failures and unchanged-source
baselines. The complete refreshed results are recorded below.

All 210 JavaExec tasks passed in 272.2 seconds; all 154 coverage-tool tests
passed. The raw union adds 6 lines and 57 branch outcomes. The declaration tests
account for 6 lines and 55 branches in ProgramTypeModel, now covering 226/226
lines and 236/236 branches. The existing real supervisor lifecycle test covered
two additional branch outcomes in this run; no new supervisor tests are included
in this checkpoint.

Overall coverage is 28,276/29,782 lines and 20,696/25,872 branches. Although the
branch display rounds to 80.0%, the exact gate remains two outcomes short and
correctly reports failure. Hosted acceptance and the stronger critical-group
targets remain pending.

## Validator status and launch boundaries

The existing `validatorSupervisorSmoke` now invokes two focused boundary suites.
`ValidatorStatusBoundarySmoke` passes 270 checks for malformed or incomplete
process-owner records: missing/duplicate fields, wrong token types, numeric
syntax and overflow, unknown schema/reason, counter consistency, ASCII and the
exact 4096-byte input limit. Valid failure reasons and incomplete cleanup remain
failures in the parsed record. Full-width observed counts and unsigned Windows
exit codes retain their exact numeric values; parsing those values on Linux does
not prove Windows process execution. Rejection preserves the input evidence.

`ValidatorLaunchBoundarySmoke` passed 40 checks with the real Linux native helper
and Python tool. Invalid bounds/arguments, early cancellation and directory,
empty, oversize or nonexecutable tools create no evidence. Valid minimum stream
and maximum stream/deadline bounds work; a 1 ms deadline either completes with
cleanup or reports a clean timeout. The longest permitted argument reaches the
actual tool unchanged on Linux; Windows aggregate command limits are explicitly
not inferred from that test. Saved command arguments are immutable snapshots.
The sparse oversize fixture is deleted immediately after rejection. Existing
real descendant cleanup, interruption, callback failure, timeout and output-limit
checks still pass. No production Java changed.

Six selected mutation controls test the record-size boundary, duplicate fields,
stderr counter consistency, exit-code and signal bounds, and wide-count
preservation. All 136 selected mutants passed in 303.6 seconds
with unchanged-source baselines. Refreshed results follow.

All 210 JavaExec tasks passed in 272.9 seconds; all 154 coverage-tool tests
passed. Before adding the newly completed hosted cohort, the raw union gained
6 lines and 21 branch outcomes. ValidatorSupervisor covers 154/167 lines and
119/146 branches. The exact overall branch target now passes locally; hosted
acceptance and the stronger critical-group branch targets remain pending.

## Completed x86 hosted cohort

The x86-64 producing job in [CI 43814174541](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43814174541)
passed. Its 517 sessions were downloaded as the bounded raw coverage artifact,
verified against the producing job, artifact digest, actual merge parents and
unchanged production JAR, and independently regenerated from JaCoCo probes.
The regenerated report matches the hosted counters and report text.

The actual merge is `6c00baafb91b6a26e672bdb9ada523875b7e19e3`; artifact
`14214744585` has SHA-256
`ca1efc54bc0b08389e4f789af1abcb54e6ff13b02594fa6ef2b1912279066a74`.
Verification receipts and raw collections are in
`verified-hosted-linux-43814174541/` under the bounded workspace.

The mixed-origin local union adds 90 lines and 29 branch outcomes: 85 lines and
23 branches in the real AttachmentHelper path, with smaller gains in attachment
invocation, binding, Linux-host and GUI paths. This closes a measurement gap; it
is not 90 lines of newly tested behavior. Both critical line targets now pass.

This historical cohort requires 33 suites; current hosted acceptance requires
39. It is admitted with its original provenance only for local analysis. It does
not satisfy the current single-run gate or authorize publication. The whole run
failed on Windows-host and big-endian MIPS; their local fixes require a fresh
hosted run. At that checkpoint, remaining exact branch outcomes for the critical 90% targets were
1,859 in binary/location code and 440 in file transactions/validation.

## Historical i386 allocation admission and compiler limits

The existing `i386ParameterAllocationSmoke` now invokes 367 additional checks
using actual Ghidra ProgramDBs and the pinned compiler specification. Supported
ET_EXEC/ET_DYN System V/Linux profiles remain eligible; relocatable inputs,
ABI revisions, unsupported ABI/flag combinations, a different supported ELF
machine and a real language mismatch receive no correction policy. ELF bytes
are unchanged. Foreign-program and nondefault-convention definitions remain
uncorrected; normal declaration/corrections entrypoints agree.

The compiler specification has a 500-byte input region. With Ghidra's saved
automatic result pointer, it fits 124 explicit four-byte integer arguments.
Those arguments receive exact stack offsets and a ten-byte ST0 return carrier.
At 125 and 4095 arguments, the allocation proof rejects storage outside that
region and preserves the saved definition. At 4096 explicit arguments, the
count guard returns no correction before that proof. These are model-layer
checks, not a claim that a whole export continues after a storage-proof error.
That workflow remains an explicit follow-up before advertising such signatures.

An oversized 600-byte by-value aggregate genuinely remains unassigned in the
real compiler model. Definition correction preserves its missing storage while
correcting the return; a call-site override requiring a carrier is rejected.
Real typedef chains of depth 64 and 65 remain eligible because Ghidra's public
`TypeDef.getBaseDataType()` resolves the whole chain. No fake recursive typedef
or modified compiler internals are used to reach defensive guards. Cancellation
at observed traversal boundaries preserves saved definitions and call signatures.

All focused checks pass alongside the existing 1246 assertions. Seven mutation
controls cover ABI revision, ELF role, both count guards, ST0 return, automatic
parameter omission and preservation of genuinely unassigned aggregate storage.
All 143 selected mutants passed in 320.6 seconds with unchanged-source baselines.
The complete refresh passed all 210 JavaExec tasks in 273.5 seconds and all 154
coverage-tool tests. The raw combined union adds 5 lines and 15 branch outcomes.
I386ParameterAllocation covers 94/101 lines and 99/134 branches. The exact
remaining critical branch gaps are now 1,844 and 440, respectively. Both critical
branch targets and current hosted acceptance remain pending.


## i386 input-region export failure and correction

CONFIRMED: a real headless export with 125 integer arguments and an i386 x87
extended floating return aborted the entire export with an audited-stack-boundary
exception. The saved Ghidra compiler model's 500-byte input region included a
spurious four-byte result pointer. Removing it makes room for the 125th integer,
but the old proof compared that valid new carrier with previously unassigned
storage. The original input, saved model and prior output pair survived the
failed export; unrelated functions did not get exported.

The correction accepts a newly available stack carrier only from the audited
compiler model and only when it contains the complete formal value with no
forced indirection. Existing assigned carriers retain their width, indirection
and offset checks. Inputs still unassigned in both models remain without a
location. Call overrides requiring a complete input allocation now decline
incomplete allocations without aborting the export. Count limits and compiler
identity checks remain in force.

The permanent integration harness covers 124, 125 and 126 arguments in both
ET_EXEC and PIE binaries. It uses compiler reference DWARF, the installed
production exporter, independent validators and GDB. Assertions check argument
values, unavailable storage, preservation of an ordinary function, normal
execution, unchanged input/model and byte-identical repeat exports. CI runs this
harness in the x86 target lane. Model tests additionally cover 4095/4096 limits,
a genuinely unassigned oversized aggregate, cancellation and 17 independent
storage-proof cases using public Ghidra objects.

All six permanent-harness cases passed in 73.2 seconds, including source lookup,
the explicit unavailable-location assertion, independent validators and GDB.
The cached installed module was restored and hash-checked after the experiment.
All 154 coverage-tool tests and workflow lint pass. At fix commit
`882a4be1573052a0afa2ccc99550e69598c6345d`, all 210 JavaExec tasks pass in 272.9
seconds, followed by all 53,432 independently evaluated DWARF expression vectors.
Raw JaCoCo verification confirms every session's production/test class identity
and probe count, with 901 production classes and all 255 source files retained.

The fresh **JavaExec-only** report measures 23,625/29,786 lines (79.3%) and
18,275/25,878 branches (70.6%). The executable-line and branch totals increase
with the production fix; no sources are excluded or reclassified. Changed
production code covers all 10 executable lines and 26/30 branches (86.7%). This
passes the 90% line / 85% branch minimum; the preferred 90% changed-branch target
is not met. The four unexecuted outcomes are on the callers' unavailable-input
and proof-rejection checks. The storage-proof helper itself exercises both
accepted and rejected carriers with real Ghidra storage objects.

This JavaExec-only result is not a cross-layer combined report. Its verified
raw report, hashes and changed-line counters are retained under
`.forge-work/scratch/coverage-expansion/i386-slot-fix-javaexec-verified/`.
Corrected-version hosted and combined coverage remain pending.

All 146 selected mutation controls pass in 327.2 seconds. The three new faults
reject the newly available carrier, accept a partial carrier, and fabricate an
unassigned call input. Each is caught by its intended behavioral assertion;
compilation/setup failure is not accepted as detection. These controls do not
constitute a repository-wide mutation score.

This is a production bytecode change. The historical combined percentages above
do not establish coverage of this fix. Fresh JavaExec, headless/native-Java and
Windows execution data must match the corrected classes before a new combined
report can be admitted. No sources are excluded or moved between critical groups.

## Saved-local ownership and proof rejection

The existing `mergedLocalLifetimeSmoke` invokes 696 additional checks using
eight actual ProgramDB profiles: x86-64/AArch64, four-/eight-byte values and
register-/stack-backed canonical locals. Independently encoded instructions
establish the initial value, transfer it to a saved register assignment, update
it, and destroy the current carrier. Assertions retain the expected intervals
and reject resurrection from the old register or stale stack slot.

Public Ghidra edits exercise lost curated provenance, same-width signedness
changes, moved definition PCs, and replacement of a defining instruction with
NOPs. Other cases check conflicting owners, disjoint register/stack owners,
unassigned unrelated locals and mappings borrowed from another function.
Each edit is rolled back; byte and local snapshots remain unchanged by the proof
itself, and the original positive intervals are restored. Cancellation is checked
at observed inspection, mapping, ownership and dataflow traversal points.

Separate proof-boundary cases deliberately supply a single mapping, omit the
canonical member, duplicate a member, remove a register, or omit the required
DWARF register mapping. These do not claim that Ghidra's saved-identity extractor
normally emits malformed lists. No private Ghidra state or fake Program objects
are used. These are model/proof tests, not a new debugger support claim.

An initial fixture rerun exposed a queued Ghidra analysis notification accessing
a database after close. Flushing pending notifications before releasing the
fixture produces a clean rerun. The existing 248 lifetime assertions also pass.
All 154 selected mutation controls pass in 348.0 seconds. The eight new controls
test lost provenance, changed formal types, missing machine definitions, absent
canonical ownership and falsely claiming disjoint stack storage. Each fails its
intended behavioral assertion. All 154 coverage-tool tests pass. A fresh complete
JavaExec run at `3a49ce87d3cd74d076febb98bcf7497688fe4872` passes all 210 tasks in
273.6 seconds and all 53,432 independently evaluated DWARF vectors. Raw class and
probe verification retains all 901 production classes and 255 sources.
`MergedLocalLifetime` increases from 135/212 to 163/212 covered branch outcomes
and from 162/163 to 163/163 executable lines. The JavaExec-only total is now
23,626/29,786 lines (79.3%) and 18,303/25,878 branches (70.7%). Production JAR
`3021d43ef8bcede78a4a87a7fe2c3f49bc15bb3b8cafb5121fb97fcd3a0cd8f6` is unchanged.
These are JavaExec measurements; current combined coverage still awaits matching
integration/Windows evidence.

## External-declaration integration measurement

The existing external-declaration workflow now measures both analyzer JVMs:
curation/export and read-only reopen/export. Its shell entry point delegates to
a Python driver that preserves compilation, raw DWARF checks, independent
validators, compiler/Forge GDB, deterministic output and protected-input checks.
The driver bounds command time and log size. It completes the coverage receipt
only after all behavioral checks pass. Both the measured and unmeasured paths
pass locally against the corrected production JAR above; the cached installed
extension is restored and its hashes verified after each run.

Admission requires the two sessions, exact harness hashes, equal saved-model
and output hashes, unchanged program database bytes, successful export reports,
and independent compiler/Forge GDB observations. Only disclosed Ghidra index
and journal backup changes are allowed. The three curated declarations must
retain their formal/variadic/no-return/artificial-carrier inventory without
invented runtime locations. Eight new metadata-rejection test methods bring the
coverage-tool suite to 162 passing tests. These synthetic receipts test admission;
they are not counted as exporter execution evidence. Workflow lint, shell syntax
and whitespace checks pass. CI and hosted admission now require this workflow,
bringing the Linux coverage suite inventory to 40.

The two real sessions pass independent class/session/probe verification. A local
union with the 210 JavaExec sessions at `3a49ce87` retains all 901 classes and 255
sources: 24,603/29,786 lines (82.6%) and 18,786/25,878 branches (72.6%). This adds
977 lines and 483 branch outcomes beyond that JavaExec baseline. In this partial
union, `MinimalDwarfSidecarExporter` reaches 756/1,196 lines and 336/728 branches.
Both outcomes of its declaration no-return, return-storage and variadic decisions
are observed in the new headless sample.

This is explicitly a partial local union, not the full combined acceptance
report or a published badge. It uses only corrected-JAR execution data; no
historical production version is mixed in. Evidence is retained under
`.forge-work/scratch/coverage-expansion/external-declaration-verified/`, with
separate measured and unmeasured logs. Critical-group targets, the complete
hosted cohort, normal integration and main publication remain outstanding.
Other existing ABI, function-type and variable-flow workflows still need the
same measurement audit before adding duplicate fixtures.

## Recovered scalar signatures and decompiler pass controls

The existing recovered-return and recovered-parameter workflows now collect
their import and two read-only export JVMs. Historical-package comparisons,
when explicitly requested, remain outside the collection. The full oracles run
before receipt completion: real decompiler failure isolation, single-attempt
behavior, cancellation, immutable evidence, analyst precedence, deterministic
outputs, saved-program preservation, raw DWARF, independent validators and
compiler/Forge debugger behavior. Inferred parameter names/types remain useful
without fabricating locations; the unresolved parameter list remains omitted.
The inferred unsigned return retains its observed eight-byte width while the
compiler reference records four bytes. Neither is relabeled to hide that
distinction.

Both workflows pass locally with and without measurement, and the cached
installed module is restored with identical hashes after each run. All six new
sessions pass raw class/session/probe verification against corrected JAR
`3021d43e`. Their admission checks require both profiles, all three phases,
exact source/input/JAR hashes, unchanged model/database evidence, both output
reports, compiler return values and normal debugger exits/source steps. Eight
new rejection test methods bring the coverage-tool suite to 170 passing tests.
Workflow lint and whitespace checks pass. These two suites bring the required
Linux coverage inventory to 42.

Adding the six sessions to the partial local union above gives 218 sessions:
24,640/29,786 lines (82.7%) and 18,817/25,878 branches (72.7%). The incremental
gain is 37 lines and 31 branch outcomes; the exporter now contributes 785/1,196
lines and 350/728 branches in this partial union. All 901 production classes
and 255 sources remain in its denominator. This still excludes the rest of the
current hosted integration/Windows cohort and is not full goal acceptance.
Reports and input hashes are under
`.forge-work/scratch/coverage-expansion/recovered-signature-verified/`.

A static audit lists 64 further direct-headless harness candidates in
`unmeasured-direct-harness-audit.json` under the same local workspace. This is
only a candidate list: imported adapters and parent wrappers must be inspected
before declaring any particular workflow unmeasured. Stack-value transitions
are a useful next candidate because their existing x86-64/AArch64 exec/PIE/rebase
oracles check whole storage transitions, reuse, aliasing and final value loss.

## Stack-value transitions on both target architectures

The existing stack-transition workflow now measures import, curation and both
read-only exports on x86-64 and AArch64. All six exec/PIE/rebased-PIE profiles
pass locally: 24 analyzer sessions, 12 exports and 432 compiler/Forge debugger
returns. The underlying oracle checks 12 function shapes at three positive and
negative input values, every instruction boundary, independent physical register
and stack values, exact serialized location lists, source navigation, slot reuse,
alias invalidation and final value loss. Inputs and saved program databases remain
unchanged apart from the disclosed Ghidra index/journal backups. Rebased PIE
retains the same input hash and link-time location semantics as its PIE reference.

An initial rebased run failed because the local Ghidra settings cache contained
a script compiled with Java 25; the selected runtime is Java 21. That incomplete
collection is retained separately and never admitted. A dedicated Java 21 settings
cache inside the accounted workspace resolves the mismatch. The remaining four
profiles pass with the same source and production bytes. Both architectures also
pass rebased export without instrumentation. Cached installed-module hashes are
restored after every wrapper run.

CI retains the AArch64 stack-transition collection as a separate required input;
its agent environment applies only to this workflow. The x86-64 suite inventory
is now 43, and AArch64 independently requires all three address modes. Hosted
admission rejects an x86-64 collection substituted for the AArch64 matrix input,
missing/duplicated roles, changed rebased semantics, mismatched serialized ranges,
lost runtime checks and incomplete session/input/model provenance. Eleven new
metadata test methods bring the coverage-tool suite to 181 passing tests. Their
synthetic receipts are explicitly not execution evidence. Workflow lint and diff
checks pass. The new hosted artifact and combined-input wiring remain pending CI.

Independent raw class/session/probe verification passes for all six real profiles.
The partial local union now has 242 sessions, with all 901 classes and 255 sources:
24,681/29,786 lines (82.9%) and 18,840/25,878 branches (72.8%). This adds 41 lines
and 23 branch outcomes to the preceding partial union; it is still not the complete
hosted measurement. No frozen inventory, threshold or production bytecode changed.
Evidence is under `.forge-work/scratch/coverage-expansion/stack-transition-verified/`,
with the failed Java-cache attempt retained in `stack-transition-failed-collections/`.

## Saved-parameter and carrier ownership

At `de8378a6`, `StackCarrierOwnershipSmoke` adds 92 assertions using actual
x86-64/AArch64 ProgramDB fixtures with four- and eight-byte saved parameters.
Detached or foreign parameters, foreign storage, split/partial/memory carriers,
stack-pointer values and inconsistent indirection cannot supply a scalar location.
Valid incoming locations remain exact, cancellation preserves the original
exception, and fixture instructions and analyst metadata remain unchanged. The
existing stack-value-flow task now passes 424 assertions.

All 157 selected mutation controls pass, including three new controls that remove
saved-parameter ownership, foreign-storage rejection and indirection agreement.
Each new control fails its intended behavioral assertion; compilation or loading
failures are not accepted as detections. This is not a repository-wide mutation
score. The full 210-task JavaExec baseline passes in 272.4 seconds, along with
53,432 independent DWARF-expression vectors and 181 coverage-tool tests.

Strict raw verification retains all 901 production classes and 255 source files.
JavaExec alone measures 23,627/29,786 lines and 18,311/25,878 branches. Its union
with the 32 current signature/stack-transition analyzer sessions measures
24,682/29,786 lines (82.9%) and 18,848/25,878 branches (72.8%). These ownership
tests add one line and eight branch outcomes to the preceding partial union.
The production JAR remains `3021d43ef8bcede78a4a87a7fe2c3f49bc15bb3b8cafb5121fb97fcd3a0cd8f6`.
Changed production Java remains 100% lines / 86.7% branches, meeting the minimum
changed-code gate. Full current-hosted acceptance and critical branch targets
remain outstanding; this partial local measurement cannot publish the badge.

Evidence is under `.forge-work/scratch/coverage-expansion/` in
`javaexec-baseline-33/`, `carrier-ownership-mutation-checks/`,
`carrier-ownership-javaexec-verified/` and `carrier-ownership-union-verified/`.

## Malformed build-ID recovery records

At `ab0e36c7`, the production Linux installation workflow passes 145 operation
checks and four GDB consumer checks in 69.4 seconds. Nineteen new malformed-record
cases exercise foreign schema/build identity/host/durability, malformed hashes
and UUIDs, unknown phases, invalid transitions, absent required fields, changed
directory inventories and mismatched generation identity. Each starts from an
actual validated installation and requires rejection without changing registered
or retained file bytes, inode identities, mode, ownership, mtime or link count.
Restoring the valid record permits ordinary recovery. Three further checks prove
empty-root recovery is unchanged and update/removal require a managed installation.
Existing structural validators, GDB, interrupted publication, cancellation and
crash recovery controls remain intact.

An isolated mutation removes installation-state host-contract agreement. The
workflow reaches the new foreign-host assertion and fails because recovery
incorrectly returns `UNCHANGED`. Compilation succeeds, the failure is the intended
behavioral assertion, and production source/JAR hashes remain unchanged. Mutated
classes are never instrumented or included in coverage. Its disposable installation
trees were removed after retaining the commands, failure output and detection receipt.

Raw verification accepts 129 completed native-Java sessions; 16 forced-halt
children remain unmeasured behavioral controls. Comparing the identical verified
session set with and without the 22 added operation checks attributes **13 new
branch outcomes** to `BuildIdInstallation`; it adds no executable lines. Evidence
is under `build-id-record-controls/`, `build-id-record-collections/`,
`build-id-existing-controls-verified/`, `build-id-records-union-verified/` and
`build-id-host-mutation-result.json` in the coverage workspace.

## Current completed host jobs, architecture cohort still pending

Completed jobs in [CI 43856734959](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43856734959)
provide 43 Linux-host, 53 Windows and four firmware sessions. Their artifact
digests, successful producing jobs, PR merge-parent provenance, required suites
and raw regenerated reports are independently verified against the current
`3021d43e…` production JAR. No old pre-i386-fix data is reused. The source merge
commit is `e84c5206f767df10a84d5e758fae658fac8785f4`; these are actual hosted
results, not local processes relabeled as CI.

Their union with the verified local sessions contains 471 sessions and all 255
sources/901 classes: **26,688/29,786 lines (89.6%) and 19,738/25,878 branches
(76.3%)**. The binary/location group measures 92.7% lines / 78.0% branches; the
file-transaction/validation group measures 91.2% / 77.1%. This is explicitly a
partial, mixed-commit diagnostic result with matching production bytes. Remaining
architecture integrations, fresh-head CI for the new tests and protected main
publication are still required. The overall branch and both critical-group gates
are unmet; this is not completion or a publishable badge result.

Reports and original cohort provenance are retained in
`current-hosted-partial-union-43856734959/` and
`verified-hosted-{linux_host,windows,firmware}-43856734959/` under the coverage
workspace. The current Windows host and Windows attachment/GDB jobs pass; the
five architecture jobs were still running at this checkpoint.

## Generation semantics beyond outer hashes

Commits `04adb58f` and `cf16ea77` extend the production Linux lifecycle to
173 passing operations and four GDB consumer checks (75.8 seconds). Twenty-eight
additional operations cover generation semantics, tree objects and build-ID
admission. Malformed manifests have their outer observation's hash, byte count
and CRC rebound while preserving their actual inode and supported metadata.
This forces recovery to check the manifest's meaning rather than merely reject
an obsolete hash. Cases include mismatched generation identity, original-image
identity, retained-file inventories, directory identities, source paths, content
keys and registration digests. Separately rebinding changed retained source
content still cannot make it agree with the reported export.

A bounded 132,000-entry JSON inventory tests the file-count limit without creating
a large filesystem tree. Noncanonical/overlength build IDs create no managed
paths. Symlinks and FIFOs in a generation are preserved and rejected; the FIFO
test completes without opening it or waiting for a writer. Each refusal preserves
registered/retained file contents, identities and supported metadata. Restoring
the original records and source permits normal unchanged recovery. No production
code, native binding or emitted ELF/DWARF changed.

A separate isolated mutation removes generation build-ID agreement. It compiles,
then the new semantic assertion catches incorrect `UNCHANGED` recovery of a
different-build manifest. The final expanded harness reproduces that detection.
Production source and JAR remain unchanged, and mutant classes contribute no
coverage. This is one further selected fault, separate from the 157-control suite
and the previous host-contract mutation.

Strict raw verification accepts 157 completed native-Java sessions and keeps
16 forced halts unmeasured. A same-cohort comparison with/without the 28 added
operations attributes 13 additional branch outcomes to `BuildIdInstallation`.
With the verified current host artifacts, that class measures 408/417 lines and
199/224 branches (88.8%). The full **partial** union now has 499 sessions:
26,688/29,786 lines (89.6%) and 19,751/25,878 branches (76.3%). File transactions
and validation measures 91.2% lines / 77.4% branches. The production denominator,
targets and all measurement limitations above remain unchanged.

Latest evidence is under `build-id-generation-bounds/`,
`build-id-generation-bounds-collections/`, `build-id-generation-bounds-attribution/`,
`build-id-generation-bounds-union-verified/`,
`generation-bounds-hosted-partial-union-43856734959/` and
`build-id-generation-bounds-mutation-result.json` in the coverage workspace.
The latest full installation tree is retained. Superseded installation/mutation
trees were removed while keeping reports, commands, relevant logs and raw
coverage collections; `build-id-generation-cleanup.json` records those exact
owned paths. Architecture CI and fresh-head acceptance remain outstanding.

## Register descriptions must match physical hierarchies

At `93b40b97`, the existing register-alias task passes 150 new agreement
assertions against pinned Ghidra register hierarchies. ARM and ARM BE8 cases
require logical parent widths, physical offsets and requested extents to agree.
MIPS BE/LE cases require the declared children, bit positions and widths to
describe the real pair. Accepted controls preserve exact register numbers,
logical offsets and memory-order pieces; rejection leaves those controls intact.
No production code or target map changed.

The initial 161-control mutation attempt failed: removing the paired-child width
check survived because MIPS's offset and complete-width checks still rejected
the malformed descriptions. That run is not a passing mutation result. An actual
PowerPC `crall` hierarchy supplies a rejection-only fixture with eight physical
children. Two declared pieces can match offsets and total width while wrongly
absorbing unrelated siblings. This isolates child-width validation without
inventing register objects or claiming PowerPC export support.

The unchanged baseline and all four new register-profile mutations then pass a
targeted replay in 11.0 seconds: parent width, physical slice offset, paired-child
offset and paired-child width omissions each fail their intended assertion.
The existing 157-control passing result remains separate evidence; the full
161-control configuration still needs fresh-head CI. Compilation or class-loading
failures are never credited as mutation detection.

The complete 210-task JavaExec baseline34 passes in 272.8 seconds, including
53,432 independently interpreted DWARF-expression vectors. All 181 coverage-tool
tests pass. Strict raw class/session/probe verification retains 901 production
classes and 255 sources. JavaExec measures 23,628/29,786 lines and
18,319/25,878 branches. Its partial union with the current matching integration
and host data contains 499 sessions: **26,689/29,786 lines (89.6%) and
19,759/25,878 branches (76.4%)**. This adds one line and eight branch outcomes to
the preceding partial measurement. Critical-group targets and full hosted
acceptance remain unmet; no thresholds, inventory or badge scope changed.

Evidence is under `javaexec-baseline-34/`, `register-profile-selected-mutations/`,
`register-profile-javaexec-verified/`, `register-profile-union-verified/` and
`register-profile-hosted-partial-union-43856734959/` in the coverage workspace.
The initial surviving-mutant evidence remains in `register-profile-mutation-checks/`
and `register-profile-mutations.log`. Both MIPS target CI jobs now pass; x86-64,
AArch64 and ARM32 were still running at this checkpoint.


### Allocation omission authority: definitions and external declarations

`AllocationOmissionAuthoritySmoke`, included in `i386ParameterAllocationSmoke`,
uses real i386 GCC ProgramDB signatures with either an integer result or the
compiler-generated hidden pointer for an extended floating result. The audited
allocation policy retains the explicit analyst name/type, omits only the hidden
pointer, and supplies the four-byte explicit input at stack offset four. Formal
extended return metadata remains 12-byte ABI size / 10-byte value width.
Fault policies request omission of the explicit parameter independently for
function definitions and external declarations. Extraction must reject each,
preserve saved names/types/storage/ordinals and the modification number, and
produce the original complete model on a clean retry. Original ELF bytes remain
unchanged. This tests model extraction, not a new debugger or target profile.

Guarded validation:

- `./gradlew --no-daemon i386ParameterAllocationSmoke`: PASS, 32 new authority
  assertions plus 17 stack-proof, 4,859 boundary and 1,246 existing allocation
  assertions. Initial test incorrectly expected floating payload size to equal
  ABI size; corrected to the independently specified i386 12/10-byte contract.
- `mutation-check.py` with the four `allocation-omits-explicit-*` and
  `allocation-retains-hidden-*` labels: PASS, unchanged-source baseline and
  four compiled faults detected by Java behavioral assertions, 10.874 seconds.
  Production source hash verified; no production code changes.
- Matching-bytecode diagnostic union: 1,400 unique sessions, 255 production
  sources / 901 classes. Verified raw execution hash, test-source hashes and
  exact manifest addition. Adds one line and four branches in GhidraTypeGraph.
  Overall 28,847/29,802 lines and 22,240/25,902 branches; binary/location
  18,610/19,213 lines and 16,071/18,750 branches (804 short of 90%); file
  operations unchanged at 6,502/6,677 lines and 3,775/4,250 branches (50 short).
  Historical cohorts remain: this is not current-head hosted acceptance.

Local evidence: `.forge-work/scratch/allocation-omission-authority-aligned.log`,
`allocation-omission-authority-mutants/result.json`, and
`coverage-recovery/allocation-omission-authority/`. All commands ran through the
storage guard. CI run 44105084385 finished with x86-64/AArch64/Windows passing;
ARM32 and both MIPS lanes failed final coverage collection. Its collector fix
and previous tests are pushed at a5a29b1d; fresh run 44150222826 is pending.


### Saved inheritance byte and physical-layout budgets

`InheritanceBudgetSmoke`, invoked by `inheritanceBindingEvidenceSmoke`, uses
actual saved class/type bindings in an x86-64 ProgramDB. A 128-base model with
bounded ASCII provenance fills exactly 1 MiB and round trips; adding one byte
must preserve the previous valid generation. The decoder separately rejects
1 MiB + 1 decoded bytes even though the Base64 text has the same length. Rejected
reads preserve the supplied record. Cancellation is calibrated at entry, within
traversal and at the last pre-publication check; each retains prior metadata and
the saved program modification number. A clean retry is deterministic.

Real physical layouts exercise exactly 65,536 traversal visits and exactly
4,096 distinct nodes, then one extra visit/node and an excessive component
inventory. Rejected saves preserve the old record and the analyst's layout edit;
restoring the physical layout makes the old evidence usable again. These are
metadata/model tests, not additional C++ ABI or runtime debugger claims.

Guarded `./gradlew --no-daemon inheritanceBindingEvidenceSmoke`: PASS in 5s,
36 new assertions and 188 existing assertions across x86-64/AArch64.
Eight registered compiled faults (both sides of byte, traversal and graph
bounds, decoded-byte bypass and component-budget bypass) were detected by Java
assertions, with baseline PASS, unchanged production source hash, 22.172s.

Verified diagnostic addition `coverage-recovery/inheritance-budgets/` contains
1,401 unique sessions with the same production JAR, all 255 sources / 901 classes,
and authenticated raw execution/test-source hashes and manifest addition.
Adds five branches in GhidraInheritanceBindings. Overall 28,847/29,802 lines,
22,245/25,902 branches; binary/location 18,610/19,213 lines,16,076/18,750 branches
(799 short of 90%); file operations unchanged at 6,502/6,677 lines,3,775/4,250
branches (50 short). Historical sessions remain: not current-head hosted acceptance.
Local logs: `.forge-work/scratch/inheritance-budgets-first.log` and
`inheritance-budget-mutants/result.json`. No production code changed.


### Synthetic-source dispositions and executable-row boundaries

`SyntheticSourceDispositionSmoke`, included in `syntheticSourceSmoke`, checks
that exactly one of decompiled text, a failure diagnostic or an intentional
omission describes each function. Contradictory function-line metadata and
executable mappings on failed/omitted source are rejected. Empty/whitespace
source yields a physical source row without invented executable addresses.
Actual rendered UTF-8 output checks comment escaping, missing header values,
CRLF/CR normalization, trailing whitespace, and stable address/name ordering.
An independent expected-row list checks comment/declaration exclusion, duplicate
address merging, token provenance and refusal of mappings beyond the text.
Nested mutable token inputs and returned byte arrays cannot alter the snapshot.

Guarded `./gradlew --no-daemon syntheticSourceSmoke`: PASS in 2s, 61 new assertions
and the existing source/line-plan checks. Eight compiled faults detected by Java
assertions, unchanged baseline PASS and production hash verified, 3.079s. The
faults cover missing disposition, failed-source mapping, three comment forms,
out-of-body rows, token aliasing and trailing tabs. No production code changes.

Verified diagnostic `coverage-recovery/source-dispositions/`: 1,402 sessions,
same production JAR, all 255 sources / 901 classes; raw/source hashes and exact
manifest addition verified. Adds 10 lines and 25 branches in SyntheticSourceFile.
Overall 28,857/29,802 lines and 22,270/25,902 branches; binary/location
18,620/19,213 lines and 16,101/18,750 branches (774 short of 90%). File operations
remain 6,502/6,677 lines and 3,775/4,250 branches (50 short). Historical cohorts
remain; this is diagnostic evidence, not current-head hosted acceptance.
Logs: `.forge-work/scratch/synthetic-source-dispositions-first.log` and
`source-disposition-mutants/result.json`. Hosted run 44150222826 remains live.


### Source relocation inventory and UTF-8 limits

Extended `SyntheticSourceRelocationBoundarySmoke` with hand-encoded DWARF32/v5
fixtures in both byte orders and four-/eight-byte target addresses. Exactly
128 abbreviation attributes, 65,536 abbreviation records and 65,537 source files
relocate successfully; the next entry is refused. Directory limits use UTF-8
bytes: both ASCII and multibyte strings at 65,535 bytes pass, while excess bytes
are refused independently of Java character count. Invalid later file basenames
are rejected, including empty, dot, dot-dot and both path separators.

Successful relocation compares every output byte against independently built
sections, preserves pooled strings, executable line programs and input arrays,
and remains idempotent for the same directory. Existing cancellation and malformed
metadata checks remain. Guarded `./gradlew --no-daemon sourceRelocationBoundarySmoke`
PASS: 1,244 cases, 3s. An initial command used a nonexistent task name and did not
run tests; the registered task above was then run successfully. Eight new compiled
boundary faults were detected by Java assertions, unchanged baseline PASS,
production source hash verified, 3.302s. No production implementation changed.

Diagnostic `coverage-recovery/source-relocation-limits/`: verified 1,403 unique
sessions, same production JAR, complete 255-source/901-class denominator, raw
execution/source hashes and manifest addition. Adds eight branches. Overall
28,857/29,802 lines and 22,278/25,902 branches; binary/location 18,620/19,213 lines,
16,109/18,750 branches (766 short of 90%). File group unchanged: 6,502/6,677 lines,
3,775/4,250 branches (50 short). Historical cohorts remain: not hosted acceptance.
Local evidence: `.forge-work/scratch/source-relocation-limits-assertions.log`,
`source-relocation-limit-mutants/result.json`. CI44150222826 remains live.


### ARM call ABI envelope and attribute inventory

Extended `Arm32CallPolicySmoke` with structurally readable ELF fixtures in both
byte orders. Admission varies executable/shared/relocatable/core type, machine,
OS ABI/revision, ELF class and BE8 flags independently. Invalid observations must
supply neither a declared nor a consumer ABI and must explain the restriction.
Section controls reject duplicate, mistyped or allocated ARM attributes while
accepting the correct section type without the conventional name. Foreign vendor
records are skipped within bounds; exactly 65,536 bytes pass and one extra byte
fails. Multiple AEABI file scopes and absent file scopes are rejected.

Optional attribute tests preserve UINT32_MAX values and the largest accepted
optional tag, handle string/compatibility attributes and Tag_nodefaults with an
explicit PCS, and refuse unknown mandatory or out-of-domain tags. Parsed maps
are immutable; all original ELF bytes remain unchanged. The Gradle task now
honors the guard-provided TMPDIR. This extends metadata classification tests,
not advertised architecture or debugger support.

Guarded `./gradlew --no-daemon arm32CallPolicySmoke`: PASS, 4,190 assertions, 4s.
An initial fixture incorrectly encoded tag 128 as a single byte; corrected to
ULEB128 0x80,0x01. Eight compiled mutation controls PASS in 4.977s with unchanged
baseline and verified source hash. The first mutation attempt lacked a Ghidra
fixture dependency and was rejected as a class-loading failure, never credited;
the linked retry detected all eight through behavioral Java assertions.

Diagnostic `coverage-recovery/arm-call-metadata/`: 1,404 unique sessions with the
same production JAR, all 255 sources / 901 classes, verified execution/source
hashes and exact manifest addition. Adds two lines and 23 branches. Overall
28,859/29,802 lines and 22,301/25,902 branches; binary/location 18,622/19,213 lines,
16,132/18,750 branches (743 short of 90%); file operations unchanged at
6,502/6,677 lines and 3,775/4,250 branches (50 short). Historical cohorts remain;
this is not current-head hosted acceptance. No production implementation changed.
Evidence: `.forge-work/scratch/arm-call-metadata-final.log` and
`arm-call-metadata-mutants-linked/result.json`.


### ARM callable signature budgets and transfer classification

`ArmCallSignatureBoundarySmoke`, included in `arm32CallPolicySmoke`, applies the
same bounded type graphs to function definitions, external declarations and
function-pointer types. It checks the exact 4,096-parameter and 64-wrapper limits
and next-entry refusals; mixed typedef/qualifier chains are real TypeGraph edges,
not Ghidra aliases that flatten to their base. Scalar encoding/width, enum and
pointer cases cover the admitted widths and unsupported widths explicitly.

Aggregate controls cover four/five members, empty layout, unsupported short/enum
members, tail padding and alignment, and mixed double/float/float members. The
last must retain base transfer even under selected VFP PCS; it is not homogeneous
floating evidence. Hidden-return controls reject duplicate pointers, small or
scalar results, nonpointer/wide/reference carriers, and unknown automatic roles.
All three callable forms must agree, preserve recovered return/parameter types
and independent restrictions, leave the input model unchanged, and be idempotent.
These are policy tests, not new target/debugger support claims.

Guarded `./gradlew --no-daemon arm32CallPolicySmoke`: PASS in 3s, 852 new helper
assertions across LE/BE8 plus 4,192 parent assertions. Nine compiled faults
(parameter/wrapper bounds, duplicate result pointers, reference carrier,
mixed floating widths, tail padding and unknown automatic roles) detected by
Java assertions; unchanged baseline PASS and source hash verified, 4.164s.
No production implementation changed.

Diagnostic `coverage-recovery/arm-call-signatures/`: verified 1,405 unique sessions,
same production JAR/all 255 sources/901 classes and exact execution/source hashes
plus manifest addition. Adds 20 branches. Overall 28,859/29,802 lines and
22,321/25,902 branches; binary/location 18,622/19,213 lines,16,152/18,750 branches
(723 short of 90%); file operations remain 6,502/6,677 lines,3,775/4,250 branches
(50 short). Historical cohorts remain: not current-head hosted acceptance.
Evidence: `.forge-work/scratch/arm-call-signatures-final.log` and
`arm-call-signature-mutants/result.json`. CI44150222826 remains active.

### MIPS N32/N64 signature boundaries (#209, local diagnostic)

Acceptance: callable definitions, external declarations and callbacks agree on
supported scalar transfers, bounded alias resolution and hidden-result storage;
classification preserves recovered parameters, input graphs and prior restrictions.
`MipsWideSignatureBoundarySmoke` runs from the existing `mipsWideCallPolicySmoke`
task for both ELF widths and byte orders. It covers 64/65 alternating aliases and
qualifiers, scalar/enum/pointer widths, reference kinds, conservative aggregate
field admission and malformed hidden-result carriers. No production code changed.
The task now uses the storage guard's temporary directory.

Guarded `./gradlew --no-daemon mipsWideCallPolicySmoke` passed in 4 seconds:
3,244 new helper assertions plus 13,964 existing checks. The initial test expectation
incorrectly treated ADDRESS/UTF encodings as integer transfers; that expectation
was corrected to the supported signed/unsigned/character/boolean envelope.
Eight targeted compiled mutants passed the mutation harness in 3.544 seconds,
with a passing baseline and Java assertion failures for all eight faults. Source
hash matched the unchanged production policy. Evidence:
`.forge-work/scratch/mips-wide-signatures-final.log` and
`.forge-work/scratch/mips-wide-signature-mutants/result.json`.

The verified local diagnostic adds 11 covered branch outcomes, no lines:
1,406 sessions, unchanged production JAR `58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`,
255 production sources and 901 classes. Overall 28,859/29,802 lines and
22,332/25,902 branches; binary/location 18,622/19,213 lines and 16,163/18,750
branches (712 outcomes short of 90%); file operations remain 6,502/6,677 lines
and 3,775/4,250 branches (50 short). Raw execution hash, test source hashes and
unique manifest extension verified. Historical cohorts remain in this diagnostic;
it is not current-head hosted acceptance. Evidence:
`.forge-work/scratch/coverage-recovery/mips-wide-signatures/`.

### MIPS O32 metadata admission (#209, local diagnostic)

Acceptance: aggregate-return definitions, declarations and callback types refuse
independently inconsistent ELF/ABI metadata while preserving recovered signatures,
existing restrictions and original bytes. Expanded `MipsAggregateCallPolicySmoke`
with 14 one-field disagreements, all eight PIC/CPIC/NOREORDER flag combinations,
ET_EXEC/ET_DYN, both accepted odd-register flag values, and an O32 record inside
ELF64. Both byte orders run the checks. The task honors the guard's TMPDIR.

Guarded `./gradlew --no-daemon mipsAggregateCallPolicySmoke` passed 12,444 checks
in 3 seconds. The first run correctly hit input-change protection because the
fixture was mutated after reading its ElfImage snapshot; the test now performs
metadata cases before taking that snapshot. Production behavior was unchanged.
Eight targeted compiled mutants were caught by Java assertions, baseline passed,
and production source hash verified (3.473 seconds). Evidence:
`.forge-work/scratch/mips-o32-metadata-refreshed.log` and
`.forge-work/scratch/mips-o32-metadata-mutants/result.json`.

The verified diagnostic adds 14 covered branch outcomes, no lines. It contains
1,407 unique sessions against unchanged production JAR58bd, 255 sources/901 classes.
Overall 28,859/29,802 lines and 22,346/25,902 branches; binary/location
18,622/19,213 lines and 16,177/18,750 branches (698 outcomes short of 90%). File
operations remain 6,502/6,677 lines and 3,775/4,250 branches (50 short). Raw
execution/test-source hashes and exact manifest extension verified. Historical
cohorts remain; this is not hosted acceptance for the current head. Evidence:
`.forge-work/scratch/coverage-recovery/mips-o32-metadata/`.

### Callee stack-relative arithmetic limits (#209)

Acceptance: decoded stack-relative writes at representable signed boundaries
retain their exact ranges; addition/subtraction and write-end overflow are refused
without a wrapped summary or an exception escaping. Added eight real decoded
x86-32/x86-64 cases to `CallMemoryEffectsBoundarySmoke`: minimum offsets,
maximum representable byte range, overflowing write end, positive/negative affine
overflow and subtraction of the most-negative offset. These symbolic proof
fixtures are not executable host-pointer tests. Existing checks cover immediate
cancellation, reversed instruction enumeration, missing/duplicate instructions,
and unchanged machine bytes and saved program state.

Guarded `./gradlew --no-daemon callMemoryEffectsSmoke` passed: 50 boundary cases,
525 boundary assertions and 165 parent assertions, 5 seconds. Four compiled
faults (unchecked add, subtract, write end, and rejecting valid negative offsets)
were detected by Java assertions; baseline and production source hash verified,
12.727 seconds. No production changes. Evidence:
`.forge-work/scratch/call-memory-affine-limits-final.log` and
`.forge-work/scratch/call-memory-affine-mutants/result.json`.

Verified diagnostic `coverage-recovery/call-memory-affine-limits/` contains
1,408 unique sessions against unchanged JAR58bd, 255 sources/901 classes. This
addition increases neither line nor branch counters; exception edges are not
JaCoCo branches. Overall remains 28,859/29,802 lines and 22,346/25,902 branches;
binary/location remains 698 branch outcomes short of 90%, file operations 50
short. This is useful boundary/fault detection, not a coverage-percentage gain.
Historical cohorts remain; current-head hosted acceptance is outstanding.

### Flexible arrays and incomplete structure emission (#209)

Acceptance: a zero-element flexible array preserves its element type and member
offset without an invented byte extent; a pointer to an incomplete structure
preserves the pointer width and named target without an invented layout.
Expanded the existing qualified-type producer fixture to 15 compiler globals.
The native production exporter runs twice and preserves original/source bytes;
paired compiler/exported GDB checks verify field layout, element width, pointer
value/width and incomplete target identity. The independent DIE oracle checks
zero count, omitted array/structure sizes and exact references/locations. It now
rejects 64 output corruptions, including five new controls. Admission requires
all 15 globals and all 64 controls; its eight unit tests pass.

The final guarded `qualified-type-producer.py` run passed GNU/LLVM and strict
validation plus both GDB workflows. The strict checker reported two frame
alignment diagnostics, both corroborated against the unchanged compiler original
by the existing strict policy. These were not unexplained or suppressed errors.
The first local run used a stale validator lacking the atomic-type correction
and failed; it was not admitted. Reused current CI validator artifact14358631735
from run44150222826 (5,452,742 compressed bytes); all bundle SHA256SUMS and
repository patch hashes verified. Shipped libdwarf and production Java unchanged.

`qualified-type-mutations.py` passed baseline plus eight compiled faults, including
invented flexible-array size/count and incomplete-structure size. Each mutant
produced readable DWARF and failed the independent output oracle; no compile
failure or native crash counted. Mutant execution excluded from coverage.
Final evidence: `.forge-work/scratch/qualified-incomplete-final/`,
`qualified-incomplete-final-coverage/`, `qualified-incomplete-final-mutants/`,
and `qualified-incomplete-admission.log`.

Verified native receipt, raw execution, production JAR/classes, harness/source and
protected-file hashes, validators/GDB logs and final mutation baseline binding.
Diagnostic `coverage-recovery/qualified-incomplete/` adds two exporter branch
outcomes, zero lines. 1,409 sessions, unchanged JAR58bd, 255 sources/901 classes:
28,859/29,802 lines and 22,348/25,902 branches overall; binary/location
16,179/18,750 branches (696 short of 90%), file operations 3,775/4,250 (50 short).
Historical cohorts remain; current-head hosted acceptance is outstanding.

### Firmware metadata boundaries (#209)

Acceptance: memory-map provenance is immutable; valid adjacent regions, the
last 32-bit address and largest signed file-offset endpoint remain accepted.
Malformed names, hashes, widths, extents and absent inputs must be rejected.
The existing firmwareMemoryMapSmoke now checks 1,800 pairs of regions against
an independent byte-occupancy model in both orders, all permission combinations,
Unicode identities and mutation of caller-owned lists.

Guarded task passed 3,674 assertions. Six compiled faults were detected by Java
assertions, with a passing baseline and verified source hashes (2.185 seconds).
No production changes. Evidence: .forge-work/scratch/firmware-map-boundaries-final.log
and firmware-map-mutants/result.json. Verified diagnostic
coverage-recovery/firmware-map-boundaries/ adds two lines and nine branch outcomes:
1,410 sessions, unchanged JAR58bd, 255 sources/901 classes; 28,861/29,802 lines
and 22,357/25,902 branches overall. Critical binary/location is 16,188/18,750
branches (687 short of 90%); file operations 3,775/4,250 (50 short). Historical
cohorts remain; current-head hosted acceptance is still outstanding.

### Raw value-transfer shapes and temporary lifetime (#209)

Acceptance: extraction, concatenation and byte-aligned shifts preserve only a
complete tracked byte window at its exact destination offset. Invalid widths,
runtime-dependent displacements, partial-bit shifts and truncated values must
not acquire a location; unique temporaries must not survive an instruction.
StackTransferShapeSmoke is invoked by existing stackValueFlowSmoke and checks
all fitting source windows for 1/2/4/8-byte values, extraction widths, shifts
at sign/byte/register boundaries, both concatenation operands and explicit
invalid shapes. Byte windows and BigInteger assertions provide independent
expected positions. Real Ghidra register descriptions and a decoded NOP supply
the instruction context; injected raw p-code does not claim new target support.
Original program bytes and modification counter remain unchanged.

Guarded stackValueFlowSmoke passed in 5 seconds: 4,440 new assertions and
5,540,773 total including existing exhaustive refinement checks. Six compiled
faults were detected by Java assertions (14.541 seconds), including rounded
bit shifts, wrong concatenation offsets and leaked unique temporaries. Baseline
and source hashes verified. The initial mutation invocation lacked the Ghidra
argument and failed its baseline; the corrected invocation is the only admitted
mutation result. No production code changes. Evidence:
.forge-work/scratch/stack-transfer-shapes-first.log and
stack-transfer-shape-mutants-final/result.json.

Verified diagnostic coverage-recovery/stack-transfer-shapes/ adds nine branches,
zero lines: 1,411 unique sessions against unchanged JAR58bd, all 255 sources and
901 classes. Overall 28,861/29,802 lines and 22,366/25,902 branches. Critical
binary/location 16,197/18,750 branches (678 short of 90%), file operations
3,775/4,250 (50 short). Historical cohorts remain; final hosted acceptance pending.

### Saved static-binding identity fields (#209)

Acceptance: each serialized namespace, address offset, type ID/path/size and
universal identity must match the current object; changed records are rejected
without repair or inferred fallback. The owner must resolve to a function.
StaticBindingRecordSmoke, called by existing staticBindingEvidenceSmoke, edits
each field independently through a reference v1 codec that first reproduces the
original bytes exactly. It verifies valid/rejected/absent result invariants,
invalid symbol keys, null owners/objects, malformed text and exact Unicode text
limits. A real saved structure exercises both present and missing universal IDs.
A 65,537-byte payload fits the Base64 length ceiling but must fail the decoded
size bound. Every rejected read preserves the payload and program modification
counter; restoring the original identity restores validity.

Guarded task passed in 4 seconds on x86-64, AArch64, ARM32 and both MIPS byte
orders: 61 new assertions per profile plus 505 parent assertions. Six compiled
faults were detected by behavioral Java assertions, with passing baseline and
source hashes verified (13.819 seconds). No production changes. Evidence:
.forge-work/scratch/static-binding-record-final.log and
static-binding-record-mutants/result.json.

Verified diagnostic coverage-recovery/static-binding-record/ adds one line and
18 branch outcomes: 1,412 sessions, unchanged JAR58bd, 255 sources/901 classes.
Overall 28,862/29,802 lines and 22,384/25,902 branches; critical binary/location
16,215/18,750 branches (660 short of 90%), file operations 3,775/4,250 (50 short).
Historical cohorts remain; current-head hosted acceptance is outstanding.

### Lexical record identity and range boundaries (#209)

Acceptance: persisted local type ID/path, size, first use, storage and block
identity must match the current function, and encoded ranges must remain ordered
and representable. LexicalRecordBoundarySmoke locates fields with an independent
v1 byte decoder, then changes each field separately through the public saved
property. Rejected reads omit the entire snapshot, emit one diagnostic and
preserve both payload and program modification counter. Restoring the original
record restores validity. Null/oversized block and local lists, malformed text,
missing variables and empty bodies are refused; exact 1,024-character Unicode
evidence, block IDs and display names round-trip without truncation.

Guarded lexicalScopeEvidenceSmoke passed in 4 seconds: 45 new assertions on each
of five profiles (x86-64, AArch64, ARM32 and both MIPS orders), plus 430 parent
assertions including rebasing and immutable database reopening. Six compiled
identity-check faults were caught by behavioral Java assertions, baseline and
source hashes verified (13.955 seconds). No production changes. Evidence:
.forge-work/scratch/lexical-record-boundaries-first.log and
lexical-record-mutants/result.json.

Verified diagnostic coverage-recovery/lexical-record-boundaries/ adds four lines
and 16 branches: 1,413 sessions, unchanged JAR58bd, all 255 production sources
and 901 classes. Overall 28,866/29,802 lines and 22,400/25,902 branches; critical
binary/location 16,231/18,750 branches (644 short of 90%), file operations
3,775/4,250 (50 short). Historical cohorts remain; this is not final hosted
acceptance.

### Dynamic-name decoding budgets (#209)

Acceptance: dynamic symbol inventory admits names at the exact 65,536-byte
limit, rejects longer names and version-qualified names beyond that limit, and
bounds aggregate decoded bytes even when names overlap in a small string table.
DynamicNameBoundarySmoke is invoked by existing dynamicSymbolMirrorSmoke for
both ELF classes and both byte orders. Its roughly 64 KiB table yields 256
accepted distinct suffixes but exceeds the 16 MiB aggregate decoding limit at
257 suffixes, verified by an independent arithmetic-series calculation. Hidden
and default version suffixes retain exact spelling and termination at the limit.
Long-name scan cancellation is checked at entry, midway and near completion;
original bytes remain unchanged and retry reproduces the original records.
These are bounded parser fixtures, not new runtime architecture claims.

Guarded task passed in 3 seconds: 26 new assertions per class/order combination,
plus 2,676 existing assertions. Four compiled faults (extra name byte, dropped
aggregate accounting, omitted version separator accounting and absent scan
cancellation) were detected by Java assertions; baseline and source hashes
verified (2.242 seconds). No production changes. Evidence:
.forge-work/scratch/dynamic-name-boundaries-first.log and
dynamic-name-boundary-mutants/result.json.

Verified diagnostic coverage-recovery/dynamic-name-boundaries/ adds one line
and four branches: 1,414 sessions, unchanged JAR58bd, 255 sources/901 classes.
Overall 28,867/29,802 lines and 22,404/25,902 branches; critical binary/location
16,235/18,750 branches (640 short of 90%); file operations 3,775/4,250 (50 short).
Historical cohorts remain; current-head hosted acceptance is still pending.

### Firmware target identity admission (#209)

Acceptance: a numerically valid raw-firmware descriptor does not establish an
implementation profile. FirmwareTargetBoundarySmoke, invoked by the existing
firmwareMemoryMapSmoke, changes each explicit identity field separately and
requires refusal by both profile admission and metadata extraction. It checks
null/blank/NUL identities, invalid ELF machine/flags widths, address/pointer
widths and null byte order. Valid lower/upper numeric limits round-trip exactly;
72 combinations admit only the complete registered Cortex-M3 descriptor.
Caller edits to returned metadata bytes cannot alter future metadata snapshots,
and rejected descriptors do not change the registered profile.

Guarded task passed in 2 seconds: 286 new assertions, 3,960 total. Six compiled
faults were detected by behavioral Java assertions; baseline/source hashes
verified (1.919 seconds). No production changes or additional architecture
support claims. Evidence: .forge-work/scratch/firmware-target-boundaries-first.log
and firmware-target-boundary-mutants/result.json.

Verified diagnostic coverage-recovery/firmware-target-boundaries/ adds two lines
and 13 branches: 1,415 sessions, unchanged JAR58bd, all 255 production sources
and 901 classes. Overall 28,869/29,802 lines and 22,417/25,902 branches; critical
binary/location 16,248/18,750 branches (627 short of 90%); file operations
3,775/4,250 (50 short). Historical cohorts remain; final hosted acceptance pending.

### Inherited-frame diagnostic corroboration (#209)

Acceptance: allowing an inherited-frame diagnostic requires matching ELF
identity, frame address/flags/extent and exact original bytes. The new
InheritedFrameBytesSmoke runs through existing originalFrameSourcesSmoke and
uses the real bounded CIE/FDE search-table fixture, both ELF classes/orders,
with named and sectionless originals. It checks the independent SHA-256,
original offset and discovery provenance, including relocation of the unchanged
frame bytes within the comparison ELF. Twelve independent metadata/payload
faults, absent discovery, duplicate sections and cancellation at every observed
poll must fail without changing either file. Retry must reproduce the evidence.

The first fixture incorrectly expected the named section's four-byte terminator
to be proven by the sectionless search table; it was corrected to expect 44
named bytes versus 40 proven sectionless bytes. The production exact-extent
policy was unchanged. Guarded originalFrameSourcesSmoke then passed in 3 seconds
(1,884 parent checks); standalone corroboration passes 488 assertions. Six
compiled faults were detected by Java assertions, baseline/source hashes
verified (2.117 seconds). No production edits. Evidence:
.forge-work/scratch/inherited-frame-bytes-final.log, inherited-frame-byte-mutants/
and coverage-recovery/inherited-frame-bytes/test.log.

Verified diagnostic inherited-frame-bytes adds three lines and 11 branches:
1,416 sessions, unchanged JAR58bd, all 255 sources/901 classes. Overall
28,872/29,802 lines and 22,428/25,902 branches; critical binary/location
16,259/18,750 branches (616 short of 90%), file operations 3,775/4,250 (50 short).
Historical cohorts remain; final hosted acceptance is outstanding.

### Current Windows cleanup evidence and stricter admission (#209)

Windows-host job134302506662 in run44150222826 completed successfully.
Authenticated coverage artifact14363985635 (414,992 compressed bytes) against
GitHub's SHA-256, run/head and producing merge3bdd9b76f85c0d4d49b169a049b23caaf6e824cd.
Bounded extraction, unchanged production JAR58bd and all901 classes verified.
The current admission path checks all raw sessions, receipts, native failure
oracles and XML hashes. Regenerating integration-report reproduces the hosted
layers exactly. The downstream windows-attachment-gdb job subsequently passed
as well; the architecture lanes are still running.

The existing admission checker did not require the 12 new privilege close
cases, although the native harness already checked them. It now requires their
complete ordered inventory, original privilege restoration, exactly one real
handle release, preserved primary/secondary error precedence and diagnostics.
Eight admission unit tests pass, including per-field corruption of every close
case. The authenticated current Windows artifact passes the stricter policy.
No production Java changes or Linux simulation of Windows privilege behavior.

Diagnostic coverage-recovery/windows-44150222826 replaces all114 historical
Windows sessions with57 completed current-run sessions. 1,359 total sessions,
unchanged255sources/901classes; other historical cohorts remain, so this is not
final hosted acceptance. The union gains4lines/14branches in
WindowsAttachmentPrivilege without losing any coverage. Overall28,876/29,802
lines and22,442/25,902branches; critical binary/location16,259/18,750branches
(616short90%), file operations3,789/4,250branches(36short90%).

Evidence: .forge-work/scratch/windows-close-admission.log,
coverage-recovery/current-44150222826/integration-java-coverage-windows/,
coverage-recovery/windows-44150222826/{job.json,producing-merge.json,result.json,
regenerated/summary.json,sessions.tsv,xml/combined.xml}, and guarded
coverage-recovery/admit-windows-44150222826.log.

### Firmware original-file selection boundaries (#209)

Acceptance: preserve explicit FileBytes associations at the 128-input boundary,
reject duplicate IDs and independently duplicate indices, retain immutable
selection snapshots, and leave selection files unchanged on refusal/cancellation.
FirmwareInputsSmoke now checks these through direct records and the JSON reader,
including maximum signed indices, shared path strings with distinct identities,
blank/NUL/null fields, and entry/middle/final cancellation followed by retry.
No production code or emitted ELF/DWARF changed.

Guarded `./gradlew --no-daemon firmwareInputsSmoke` passes 54 checks with Java25
and Ghidra12.0.3. Guarded `src/test/coverage/mutation-check.py` using compiled main
and test classes, the same Java/Ghidra installations, and repeated `--only`
selectors for firmware-input-accepts-129, firmware-input-rejects-128,
firmware-input-ignores-index-alias and firmware-input-retains-caller-list passes
its unchanged baseline and detects all four compiled faults by behavioral
assertions (2.585 seconds). An initial invocation omitted repeated `--only`
flags and exited at argument parsing; it supplies no test evidence.

Guarded measure-stack.py firmware-input-boundaries
 ghidradwarfforge.output.FirmwareInputsSmoke plus verify-local-addition.py
firmware-input-boundaries windows-44150222826 verifies the raw session, unchanged
production JAR and current test source hashes. The diagnostic union gains one
line and nine branches, all in FirmwareInputs, without losses. It retains all
255 production sources/901 classes in the denominator: 28,877/29,802 lines and
22,451/25,902 branches. File operations reach 3,798/4,250 branches, 27 short of
90%; binary/location remains 616 short. Historical cohorts remain in this
1,360-session diagnostic: it is not final hosted acceptance.

Evidence: .forge-work/scratch/firmware-input-boundaries-final.log,
firmware-input-mutants/{result.json,*.log}, and
coverage-recovery/firmware-input-boundaries/{result.json,sessions.tsv,counts.json,
gaps.json,xml/combined.xml}. CI44150222826 still has five live architecture lanes
and no failed completed jobs; this test change remains queued locally.

### Attachment path boundaries and pre-publication rechecks (#209)

Acceptance: read-only path preflight accepts the exact 128-path/64-character
role limits, rejects duplicate/invalid roles, retains immutable selections,
and refuses independent size, mtime, identity and parent-traversal changes
before output creation. AttachmentPathBoundarySmoke runs within the existing
attachmentProtocolSmoke task and also independently for mutation checks.

Real files isolate each change: size-only restores mtime; time-only retains
bytes; identity-only retains the old inode while copying equal bytes and mtime;
parent substitution redirects to a hardlink of the same leaf, so inode and all
leaf metadata stay equal. Rechecks must refuse each case, preserve input bytes
and leave the selected output absent. Restoring the parent allows retry.
The tests also cover missing/directory inputs and both input/new-output orders.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon attachmentProtocolSmoke`
passes 158 new assertions and 11,335 existing protocol assertions in 3 seconds.
Guarded `src/test/coverage/mutation-check.py` with compiled main/test classes,
Java25 and repeated `--only attachment-path-...` selectors for accepts-129,
rejects-128, ignores-size, ignores-time, ignores-identity and ignores-parent
passes its unchanged baseline and catches all six compiled faults by behavioral
assertions (2.302 seconds). Production code and ELF/DWARF output are unchanged.

Guarded measure-stack.py attachment-path-boundaries
 ghidradwarfforge.output.AttachmentPathBoundarySmoke followed by
verify-local-addition.py attachment-path-boundaries firmware-input-boundaries
verifies the added raw session/current test hashes and unchanged production
JAR. Diagnostic union: +5 lines/+9 branches, all AttachmentPaths, no losses;
1,361 sessions, all255 production sources/901 classes. Overall28,882/29,802
lines and22,460/25,902branches. File operations3,807/4,250branches (18short90%);
binary/location remains616short. Historical cohorts remain; this is not full
current-head hosted acceptance.

Evidence: .forge-work/scratch/attachment-path-boundaries-final.log,
attachment-path-mutants/{result.json,*.log}, and
coverage-recovery/attachment-path-boundaries/{result.json,sessions.tsv,counts.json,
gaps.json,xml/combined.xml}. Both earlier and final smoke runs pass; final run
and mutants use the stronger same-inode parent-substitution fixture.

### Independent report inventory/count consistency (#209)

Acceptance: completed detailed reports bind every diagnostic inventory to its
own reported count and derive SUCCESS/PARTIAL from all five inventories without
upgrading NOT_RUN validation. Exercise all32 presence combinations, independently
change each count and retained inventory, reverse status in the wire document
and direct Detailed constructor, and clear every caller-owned list after
construction. Earlier populated inventories must not conceal a later mismatch.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon exportReportDetailsSmoke`
passes1,840 checks in3seconds. Guarded mutation-check.py with compiled main/test
classes, the same Java/Ghidra installations and repeated --only selectors
report-inventory-ignores-{failed,skipped,omitted,unsupported,diagnostics,status}
passes the unchanged baseline and detects all six compiled faults by behavioral
assertions (5.688seconds). Production Java and emitted artifacts are unchanged.

Guarded measure-stack.py report-inventory-combinations
 ghidradwarfforge.output.ExportReportDetailsSmoke and subsequent
verify-local-addition.py report-inventory-combinations attachment-path-boundaries
verify unchanged production bytecode, current test hashes and the raw session.
The1,362-session diagnostic union adds4branches in ExportReportClaims without
losses: overall28,882/29,802lines22,464/25,902branches, file operations3,811/4,250
branches (14short90%). Binary/location remains616short90%. All255sources and
901classes remain measured. Historical cohorts mean this is not current hosted
acceptance. CI44150222826 remains live in five architecture jobs with all
completed jobs successful; current changes stay queued locally.

Evidence: .forge-work/scratch/report-inventory-combinations.log,
report-inventory-mutants/{result.json,*.log}, and
coverage-recovery/report-inventory-combinations/{result.json,sessions.tsv,
counts.json,gaps.json,xml/combined.xml}.

### Attachment invocation UTF-8 transport bounds (#209)

Acceptance: ATTACH and REFRESH requests accept exactly262,144 UTF-8 bytes,
refuse one extra byte independently of the16,384 UTF-16-unit per-path limit,
require every operation/recovery/tool path to be absolute, and honor cancellation
before inspecting a missing invocation file. The tests calculate padding from
the actual serialized envelope and use multibyte path text. Parsing is exercised
without creating referenced files, running helpers or granting authority; the
fixture directory snapshot stays unchanged. Missing/extra tool inventories and
null recovery selection are also rejected.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon attachmentInvocationSmoke`
passes131 checks in2seconds. Guarded mutation-check.py with compiled main/test
classes, the same Java/Ghidra installations and repeated --only selectors for
invocation-counts-characters-not-bytes, invocation-rejects-exact-byte-limit,
invocation-ignores-tool-inventory and invocation-ignores-operation-paths passes
its unchanged baseline and detects all four faults by behavioral assertions
(2.816seconds). No production Java or emitted artifact changes.

Guarded measure-stack.py invocation-transport-boundaries
 ghidradwarfforge.output.AttachmentInvocationSmoke and verify-local-addition.py
invocation-transport-boundaries report-inventory-combinations verify the added
raw session/current test hashes against unchanged production bytecode. Diagnostic
union gains1line/4branches in AttachmentInvocation, no losses;1,363sessions,
255sources/901classes retained. Overall28,883/29,802lines22,468/25,902branches;
file operations3,815/4,250branches(10short90%), binary/location616short90%.
Historical cohorts remain; full current hosted acceptance is still unproven.

Evidence: .forge-work/scratch/invocation-transport-boundaries.log,
invocation-transport-mutants/{result.json,*.log}, and
coverage-recovery/invocation-transport-boundaries/{result.json,sessions.tsv,
counts.json,gaps.json,xml/combined.xml}.

### Validator file observation boundaries (#209)

Acceptance: validator provenance refuses invalid identity/link/size records,
honors cancellation throughout a real streamed file read without modifying the
selected tool, refuses concurrent changes encountered between its observations,
and permits a stable retry. ValidatorObservationBoundarySmoke uses131,073 known
bytes and independently computed SHA-256. It exercises every observed cancellation
poll and appends one byte at every poll in separate fresh runs. Accepted snapshots
must pair the old or new complete digest with its matching size; changed input
bytes remain intact. No atomic filesystem snapshot is claimed: mutation before
the initial facts read or after the final facts read may legitimately succeed.

The helper is wired into existing attachmentHelperSmoke. Guarded Java25/
Ghidra12.0.3 `./gradlew --no-daemon attachmentHelperSmoke` passes83 new assertions
(seven injected changes refused) and6,664 existing helper checks in3seconds.
Guarded mutation-check.py with compiled main/test classes, the same Java/Ghidra
installations and repeated --only selectors for validator-observation-accepts-
empty-identity, validator-observation-accepts-zero-links,
validator-observation-accepts-negative-size and
validator-observation-ignores-concurrent-change passes its unchanged baseline
and detects all four compiled faults by behavioral assertions (2.640seconds).
These new runtime results are Linux evidence; their Windows execution is pending.
No production Java or emitted ELF/DWARF changed.

Guarded measure-stack.py validator-observation-boundaries
 ghidradwarfforge.output.ValidatorObservationBoundarySmoke and
verify-local-addition.py validator-observation-boundaries invocation-transport-boundaries
verify the raw session, current test sources and unchanged production bytecode.
Diagnostic union: +2lines/+4branches in ValidatorInput, no losses;1,364sessions,
255sources/901classes. Overall28,885/29,802lines22,472/25,902branches;
file operations3,819/4,250branches(6short90%), binary/location616short90%.
Historical cohorts remain and do not establish current hosted acceptance.

Evidence: .forge-work/scratch/validator-observation-boundaries.log,
validator-observation-mutants/{result.json,*.log}, and
coverage-recovery/validator-observation-boundaries/{result.json,sessions.tsv,
counts.json,gaps.json,xml/combined.xml}. CI44150222826 still has five live
architecture jobs and no failed completed jobs; this change stays queued locally.

### Debuglink bytes and formatter selection bounds (#209)

Acceptance: filename encoding accepts exactly65,536 bytes and refuses one byte
more; directory roots/control characters cannot be debuglink basenames, and
missing/invalid advertised encoding metadata fails closed. DebuglinkBasenameSmoke
checks ASCII, two-byte and four-byte UTF-8 characters with exact byte equality.
Host properties are restored in finally blocks. The invalid-property controls
exercise refusal policy, not a simulated supported host or a changed native
encoding. Large names are encoder-format fixtures; no filesystem support or
GDB discovery claim is made for such names.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon debuglinkBasenameSmoke` passes
78 checks in2seconds. Four guarded compiled mutants (debuglink-allows-extra-byte,
debuglink-rejects-exact-byte-bound, debuglink-counts-characters-not-bytes,
debuglink-ignores-native-encoding) plus unchanged baseline pass in1.386seconds;
each fault is detected by a behavioral assertion. Diagnostic
measure-stack.py debuglink-byte-boundaries ghidradwarfforge.output.DebuglinkBasenameSmoke
and verify-local-addition.py debuglink-byte-boundaries validator-observation-boundaries
verify +5lines/+5branches and1,365 sessions.

FormatterPlanSmoke additionally accepts exactly128 explicit canonical choices,
rejects129, blank keys and repeated keys with equal or different modes, preserves
canonical ordering and immutable copies, and leaves rejected selection files
unchanged. Guarded `./gradlew --no-daemon formatterPlanSmoke` passes in2seconds,
including existing60 witness-admission checks. Four guarded compiled mutants
(formatter-selection-accepts-129, formatter-selection-rejects-128,
formatter-selection-ignores-blank-key, formatter-selection-ignores-duplicate)
are detected by behavioral assertions; unchanged baseline passes (2.813seconds).
The initial mutation baseline lacked the packaged formatter runtime resource;
that setup failure is not detection evidence. The corrected harness includes
the checked-in runtime resources, as the Gradle test and production bundle do.

Guarded measure-stack.py formatter-selection-boundaries
 ghidradwarfforge.formatters.FormatterPlanSmoke and
verify-local-addition.py formatter-selection-boundaries debuglink-byte-boundaries
verify another +1line/+3branches. Final diagnostic1,366sessions, unchanged
production JAR and all255sources/901classes: overall28,891/29,802lines and
22,480/25,902branches. File operations6,521/6,677lines(97.66%) and
3,827/4,250branches(90.05%) meet numerical critical-group targets in this
historical/current diagnostic union. Binary/location remains616short90%.
Full current hosted admission, review, protected merge and main publication
remain outstanding; this milestone does not complete #209.

Evidence under .forge-work/scratch/: debuglink-byte-boundaries.log,
debuglink-byte-mutants/result.json, formatter-selection-boundaries.log,
formatter-selection-mutants-final/result.json and coverage-recovery/
{debuglink-byte-boundaries,formatter-selection-boundaries}/ containing raw
sessions, source hashes, verified manifests, counts, gaps and combined XML.
No production Java or emitted ELF/DWARF changed.

### Raw branch/return admission through the decoder (#209)

Acceptance: raw control transfers agree with instruction flow metadata, target
space/address, operand count/width, absent output and final-operation ordering.
RegisterControlBoundarySmoke supplies controlled raw p-code views over real
three-instruction x86-32, x86-64 and AArch64 program contexts and calls
RegisterDefinitionFlow.decodedInstructions. Positive branch/conditional/return
controls are admitted; malformed cases return no decoded proof and never crash
or modify saved program state/executable bytes. These boundary fixtures do not
establish new architecture support. Existing real local-flow tests remain.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon localDefinitionFlowSmoke`
passes147 new assertions,808 unreachable-definition assertions and508 existing
local-flow assertions in5seconds. Guarded mutation-check.py with compiled
main/test classes, the same Java/Ghidra installations and repeated --only
selectors register-control-ignores-{condition-width,return-width,branch-output,
return-output,branch-target} and register-control-allows-effects-after-branch
passes its unchanged baseline and detects all six faults by behavioral
assertions (14.576seconds). No production Java or emitted artifacts changed.

A measurement launch while the mutant run was active was refused by the storage
guard; no workload started and no evidence was admitted from that refusal.
After observing the mutant process complete, the guarded measurement ran.
measure-stack.py register-control-boundaries ghidradwarfforge.RegisterControlBoundarySmoke
and verify-local-addition.py register-control-boundaries formatter-selection-boundaries
verify the raw session/current test hashes, unchanged production JAR and all255
sources/901classes. Diagnostic1,367sessions: +15branches in RegisterDefinitionFlow,
no losses. Overall28,891/29,802lines22,495/25,902branches; binary/location
16,274/18,750branches (601short90%). File group stays97.66%line/90.05%branch.
Historical cohorts remain; full current hosted acceptance is not yet established.

Evidence: .forge-work/scratch/register-control-boundaries.log,
register-control-mutants/result.json,register-control-measure-final.log and
coverage-recovery/register-control-boundaries/{result.json,sessions.tsv,
counts.json,gaps.json,xml/combined.xml}. CI44150222826 still live; MIPSLE reached
archive step, no failed steps observed. Hold queued changes while CI continues.

### Current MIPS little-endian cohort admitted (#209)

CONFIRMED: target-preflight(mips32le) job134300299512 in run44150222826 completed
successfully, with every step successful or intentionally skipped. Authenticated
artifact14366336597 (560,160 bytes), its GitHub SHA-256 and run/head, and producing
merge3bdd9b76f85c0d4d49b169a049b23caaf6e824cd whose parent is PR heada5a29b1d.
Guarded download/extraction stayed below1MiB compressed/20MiB extracted and
rejected absolute/traversing/symlink archive paths. Current production remains
byte-identical JAR58bd,901classes, with no src/main delta from the producing head.

Current hosted-combined-report.load_job admits all11 sessions: seven headless
(context-boundaries and mips-truncated-space) plus four native-Java
(location-width-producer). Raw session receipts, oracle inventories and coverage
bindings pass current admission. Guarded integration-report regeneration exactly
reproduces hosted layers/counters/XML bindings. This confirms the context-boundary
collector wiring that failed in the earlier run now passes on hosted MIPSLE.

Diagnostic mips32le-44150222826 replaces eight historical hosted MIPSLE sessions
and three superseded local MIPSLE context-boundary sessions with these11 current
sessions. The1,367-session union loses and gains no lines or branches. Other
historical cohorts and queued tests remain; this is not current local-HEAD hosted
acceptance. Counts remain28,891/29,802lines22,495/25,902branches; binary/location
601short90%, file group97.66%line/90.05%branch. Four other architecture lanes are
still running; Windows host and downstream GDB jobs already passed.

Evidence under .forge-work/scratch/coverage-recovery/:
fetch-mips32le-44150222826.py/.log,admit-mips32le-44150222826.py/.log,
current-44150222826/integration-java-coverage-linux-mips32le{,.zip,.artifact.json},
and mips32le-44150222826/{job.json,producing-merge.json,origin.json,result.json,
regenerated/summary.json,sessions.tsv,counts.json,gaps.json,xml/combined.xml}.
No additional architecture artifact copies or large validation archives retained.

### Truncated-address affine storage contracts (#209)

Acceptance: declared32-bit physical addresses in64-bit MIPS register models use
correct low-address arithmetic in both byte orders, refuse unknown/malformed
operands and invalidate instruction-local temporaries at the next instruction.
TruncatedAffineBoundarySmoke exercises the actual TruncatedStackDepth.prove entry
point with controlled p-code over a real decoded N32 context. BigInteger modulo
2^32 calculations independently check additions/subtractions including wide
constants, sign boundaries and commuted addition. Tests cover COPY/extension
widths, low SUBPIECE extraction, absent/extra operands, unknown registers, partial
clobbers, unrelated writes and same-instruction versus cross-instruction unique
values. Rejected evidence yields UNKNOWN_STACK_DEPTH_CHANGE; it never invents a
depth or modifies the saved program. Raw fixtures are not new machine-code or
architecture support claims.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon truncatedStackDepthSmoke`
passes480 new assertions and14,479 existing checks in6seconds. Guarded
mutation-check.py with compiled main/test classes, the same Java/Ghidra
installations and repeated --only selectors for truncated-affine-retains-temporaries,
truncated-affine-accepts-shifted-subpiece,truncated-affine-accepts-equal-extension,
truncated-affine-accepts-copy-width-mismatch,truncated-affine-ignores-first-operand-width,
truncated-affine-uses-high-big-endian-bytes and
truncated-affine-treats-register-as-constant passes its unchanged baseline and
detects all seven compiled faults by behavioral assertions (15.179seconds).
No production Java or emitted ELF/DWARF changes.

Guarded measure-stack.py truncated-affine-boundaries
 ghidradwarfforge.TruncatedAffineBoundarySmoke and
verify-local-addition.py truncated-affine-boundaries mips32le-44150222826 verify
the raw session/current test sources and unchanged production JAR. Diagnostic
union gains3lines/28branches, all TruncatedStackDepth, no losses.1,368sessions,
255sources/901classes retained: overall28,894/29,802lines22,523/25,902branches.
Binary/location16,302/18,750branches is573short90%; file group remains above its
95%line/90%branch targets. Historical cohorts remain, so current queued-HEAD
hosted acceptance is still unproven.

Evidence: .forge-work/scratch/truncated-affine-boundaries.log,
truncated-affine-mutants/{result.json,*.log} and
coverage-recovery/truncated-affine-boundaries/{result.json,sessions.tsv,counts.json,
gaps.json,xml/combined.xml}. CI44150222826 has four live architecture jobs with
no failed steps observed; MIPSLE and Windows jobs already passed.

### Inherited frame coverage unions (#209)

Acceptance: appending generated FDEs preserves inherited bytes and refuses any
shared address, including enclosing tails, single-byte endpoint collisions and
unsorted/nested original ranges. Zero-sized inherited FDEs reserve no addresses.
FrameAppendCoverageSmoke independently walks serialized record extents to locate
original FDE fields, then varies two inherited ranges and compares every proposed
addition against a byte-occupancy oracle. Both ELF address widths and byte orders
are checked, including64-bit ranges near the supported signed-address ceiling.
No original CFI semantics are inferred from this coverage-only test.

The initial fixture crossed Long.MAX_VALUE and correctly hit the inherited
reader's existing `FDE extent overflows` refusal. The final fixture explicitly
tests that refusal and keeps admitted overlap cases within the reader's supported
domain; no production behavior or address-domain requirement was changed.

Guarded Java25/Ghidra12.0.3 `./gradlew --no-daemon callFrameEncoderSmoke` passes
58,554 new oracle assertions,7,992 existing encoding checks and362 existing
encoder checks in3seconds. Guarded mutation-check.py with compiled main/test
classes and Java25 detects all four compiled faults selected with repeated
--only flags: frame-append-forgets-enclosing-tail, frame-append-reserves-empty-range,
frame-append-allows-prior-last-byte and frame-append-allows-next-first-byte.
Unchanged baseline passes; all detections are behavioral assertions (1.689seconds).
An initial mutation anchor matched both union-building and collision checks;
the harness refused it. The final anchor selects only the intended collision
check. Neither failed setup is passing-test evidence.

Guarded measure-stack.py frame-append-coverage
 ghidradwarfforge.unwind.FrameAppendCoverageSmoke and
verify-local-addition.py frame-append-coverage truncated-affine-boundaries verify
the raw session/current test sources against unchanged production bytecode.
Diagnostic1,369sessions,255sources/901classes: +4branches in DwarfDebugFrame,
no losses. Overall28,894/29,802lines22,527/25,902branches; binary/location
16,306/18,750branches(569short90%). File-group targets remain met. Historical
cohorts mean full current queued-HEAD hosted acceptance is still outstanding.

Evidence: .forge-work/scratch/frame-append-coverage-final.log,
frame-append-mutants-final/{result.json,*.log}, and
coverage-recovery/frame-append-coverage/{result.json,sessions.tsv,counts.json,
gaps.json,xml/combined.xml}. Four architecture CI lanes remain live without
reported failed steps. No production Java or emitted-product changes.

### Raw callee memory-effect contracts (2026-11-17)

CONFIRMED: `CallMemoryRawSmoke` is invoked by `callMemoryEffectsSmoke`.
Acceptance: malformed store operands, wrong-width affine inputs, absolute or
unknown addresses, memory outputs, partial SP writes and expired instruction
temporaries must not establish an unaffected-stack contract. Positive controls
retain exact stack-relative write ranges. Real x86-32, x86-64 and AArch64 language
contexts supply the register model; decorated raw p-code exercises proof-boundary
contracts and is not additional machine-code support evidence. Program bytes and
modification number remain unchanged. Production Java is unchanged.

Guarded `./gradlew --no-daemon callMemoryEffectsSmoke` PASS in 5 seconds:
234 new raw checks, 525 existing decoded-boundary checks and 165 parent checks.
Log: `.forge-work/scratch/call-memory-raw.log`.
Five selected compiled faults (extra STORE operand, truncated space ID, ignored
offset width, retained instruction temporaries and ignored memory output) were
caught by behavioral assertions; unchanged baseline passed. Result:
`.forge-work/scratch/call-memory-raw-mutants/result.json` (17.382 seconds).

The verified diagnostic addition `coverage-recovery/call-memory-raw` contributes
22 branches to the same 58bd production JAR, retaining all 255 source files and
901 classes. Its 1,370-session mixed current/historical union has 28,894/29,802
lines and 22,549/25,902 branches; binary/location branches are 16,328/18,750,
547 below the 90% target. File targets remain met. These numbers do not establish
hosted acceptance of queued HEAD, merge readiness or main publication.

### Current hosted MIPS big-endian coverage admitted (2026-11-17)

CONFIRMED: job 134300299616 (`target-preflight (mips32be)`) completed
successfully in run 44150222826 at head a5a29b1d9512d81f1923da2d23ea2d4a2ff35ebd.
Authenticated artifact 14366797765 is 560,121 bytes, SHA-256
`16bbf1905a09aafd2d81a51817169bae8eccfc9a9a7380a6edde7f9a5cf56262`.
Guarded bounded download rejects unsafe paths/symlinks and caps extraction at
20 MiB. Current admission policy verifies the producing merge, unchanged
production JAR/classes, suite oracles, raw sessions and their receipts. Locally
regenerated per-layer counters match the hosted report exactly.

Eleven current sessions (four native producer, seven headless) replace eight
historical hosted and three local context-boundary sessions, without adding or
losing covered lines/branches. Result and provenance:
`.forge-work/scratch/coverage-recovery/mips32be-44150222826/result.json`.
The mixed diagnostic remains 1,370 sessions, 28,894/29,802 lines,
22,549/25,902 branches. Other historical cohorts remain, so this does not prove
complete current-HEAD coverage or final acceptance of #209.

### Saved identity controls for repeated register copies (2026-11-17)

CONFIRMED: `RegisterCopyChainSmoke` now checks coherent metadata views against
seven independently inconsistent bindings: function/program, storage/program,
parameter/function, ordinal, saved-row identity, first-use offset and forced
indirection. For real x86-64/AArch64 decoded chains and both 32-/64-bit values,
consistent views retain the complete expected chain. Inconsistent views preserve
only the original prefix and first independently proven backup; later ranges
remain unavailable and cannot be filled by the separate value-flow proof.
Saved metadata stays unchanged and valid retry produces the original result.
These are proof-boundary checks, not new processor support claims.

Guarded `./gradlew --no-daemon registerCopyChainSmoke` PASS, 496 checks, 4 seconds.
Log: `.forge-work/scratch/copy-chain-identity-final.log`. The first setup attempt
incorrectly passed a program-owned compiler spec to a new ProgramDB; Ghidra
refused it. The fixture now obtains the compiler spec from the language. No
production workaround or coverage from that failed run was admitted.
Seven independently removed composition guards all produced behavioral assertion
failures, with the unchanged baseline passing (17.357 seconds):
`.forge-work/scratch/copy-chain-identity-mutants/result.json`.

The verified diagnostic addition `coverage-recovery/copy-chain-identity` adds
five GhidraVariableStorage and two StackValueFlow branches. Its 1,371-session
mixed current/historical union retains the same production JAR, 255 source files
and 901 classes: 28,894/29,802 lines and 22,556/25,902 branches. Critical
binary/location branches are 16,335/18,750, 540 below 90%. File-operation targets
remain met. Full current hosted validation, merge and publication remain unmet.

### Stack-spill instruction geometry and return contracts (2026-11-17)

CONFIRMED: `StackSpillSmoke` now rejects zero/inconsistent lengths, mismatched
instruction/end/fallthrough address spaces (even at equal numeric offsets), and
RETURN output/arity/null/width/order violations. Real x86-64/AArch64 spill fixtures
supply the context for 32-/64-bit values. A valid retry must still prove the spill.
Raw metadata controls do not establish new machine-code or architecture support.

Guarded `./gradlew --no-daemon stackSpillSmoke` PASS, 2,270 checks (68 added),
4 seconds; log `.forge-work/scratch/spill-metadata.log`. Six selected compiled
faults all produced behavioral assertion failures and the baseline passed:
`.forge-work/scratch/spill-metadata-mutants/result.json` (14.603 seconds).
Production Java is unchanged. Diagnostic `coverage-recovery/spill-metadata`
verifies one additional line and eleven branches against the same 58bd JAR and
full denominator. The 1,372-session mixed cohort has 28,895/29,802 lines and
22,567/25,902 branches; critical binary/location branches are 16,346/18,750,
529 below 90%. Other current/historical cohorts remain; this is not full hosted
acceptance, merge readiness or main publication.

### MIPS delayed-return closure and instruction contracts (2026-11-17)

CONFIRMED: `DelayedReturnPrefixSmoke` checks delayed-return owner length,
parsed length, overrides, fallthrough and terminal-call inconsistencies; slot
adjacency, extent and fallthrough; eight control/opaque p-code kinds in a slot;
extra instructions and undecoded trailing bytes. Valid retry retains the exact
incoming-value boundary. The existing matrix covers MIPS BE/LE 32-bit, 64-bit
and N32 contexts, with the original write before or inside the delay slot.
Decorated metadata controls are defensive proof tests, not new runtime support.

Guarded `./gradlew --no-daemon delayedReturnPrefixSmoke` PASS, 468 checks,
4 seconds; final log `.forge-work/scratch/delay-contracts-isolated.log`.
Tests were refined before mutation measurement to isolate owner length from
parsed length and slot adjacency from extent. Six selected compiled faults
all produced behavioral assertion failures; unchanged baseline passed:
`.forge-work/scratch/delay-contracts-mutants/result.json` (14.087 seconds).

Verified diagnostic `coverage-recovery/delay-contracts` adds one line and twelve
branches on the unchanged production JAR. Its 1,373-session mixed cohort keeps
all 255 sources and 901 classes: 28,896/29,802 lines and 22,579/25,902 branches.
Critical binary/location branches are 16,358/18,750, 517 below 90%; file-operation
targets remain met. Hosted validation of queued HEAD, merge and main publication
are still required. Current run 44150222826 has three architecture jobs live and
no failed jobs at the last poll; both MIPS jobs and Windows have passed.

### Saved merged-local storage changes and unknown owners (2026-11-17)

CONFIRMED: `MergedLocalOwnershipSmoke`, invoked by `mergedLocalLifetimeSmoke`,
now changes actual saved variable storage to unassigned, invalid and a different
register. Existing extracted mapping groups must then be rejected without
repairing the analyst's state. Transaction rollback restores the original proof.
A stack canonical mapping cannot claim a register assignment. An unrelated saved
variable with an assigned but invalid storage extent also blocks the proof,
because its extent cannot establish nonoverlap with the tracked value. That final
bad row is retained only until its owned ProgramDB is released, avoiding Ghidra's
known deleted-variable cache behavior. No production changes were made.

Guarded `./gradlew --no-daemon mergedLocalLifetimeSmoke` PASS, 880 ownership
checks plus 248 parent checks, 4 seconds. Log:
`.forge-work/scratch/merged-storage-ownership.log`. Three compiled faults
(ignoring invalid stack/register owners and accepting a register on the stack
canonical mapping) were caught by behavioral assertions; baseline passed in the
8.986-second run: `.forge-work/scratch/merged-storage-ownership-mutants/result.json`.

Verified diagnostic `coverage-recovery/merged-storage-ownership` adds seven
branches to MergedLocalLifetime. The same 58bd JAR/full denominator has 1,374
mixed current/historical sessions, 28,896/29,802 lines and 22,586/25,902 branches.
Critical binary/location branches are 16,365/18,750, 510 below 90%; file-operation
targets remain met. This is not hosted acceptance of queued HEAD. Current CI
44150222826 has three architecture jobs live with no failed jobs at the last poll.

### Explicit AArch64 switch-guard omissions (2026-11-17)

CONFIRMED: the tested AArch64 `CMP W0,#limit; B.HI` and `B.HS` dispatch guards
are conservatively refused with `guard does not establish a bounded fallthrough`.
The first two probes incorrectly assumed these shapes would be admitted; both
failed before target enumeration. No failed-run data was admitted and production
was not changed to expand the supported symbolic guard forms.

`Aarch64SwitchOmissionSmoke`, called by `boundedSwitchProofSmoke`, now makes this
limitation explicit. Ten original-image fixtures exercise both guard forms with
multiple bounds at ordinary and rebased addresses. They verify the decoded
conditional edge, exact refusal, unchanged original ELF and unchanged ProgramDB.
GNU AArch64 as/ld/objdump independently checked the embedded dispatch encodings;
owned source/disassembly evidence is in `.forge-work/scratch/switch-arm-encoding`.
This is a safe-omission regression, not an AArch64 switch-support claim. Any future
extension must additionally assert target enumeration and downstream behavior.

Guarded `./gradlew --no-daemon boundedSwitchProofSmoke` PASS in 9 seconds:
70 new omission checks plus the existing 116-case/1,041-check x86-64 suite.
Log: `.forge-work/scratch/aarch64-switch-omission.log`.
Diagnostic `coverage-recovery/aarch64-switch-omission` verifies 1,375 sessions
with **no additional covered lines or branches**. The critical deficit remains
510 branches; no denominator changes or target reductions were made. This test
adds an architecture-specific behavioral boundary, not a coverage percentage gain.
Full current hosted acceptance, protected merge and main publication remain unmet.

### Operand contracts for tracked-value transfers (2026-11-17)

CONFIRMED: `StackTransferShapeSmoke` now tests missing, extra, null and
wrong-width operands for COPY, extensions, SUBPIECE, PIECE, shifts and ADD/OR
joins. Each runs with direct-register and instruction-temporary destinations.
After the original carrier is overwritten, malformed transfers must leave the
tracked byte unavailable. Valid controls before/after preserve the low byte in
the exact expected register slice. These are raw-pcode contract tests on a real
language/register model; they do not claim additional machine-code support.

Guarded `./gradlew --no-daemon stackValueFlowSmoke` PASS in 5 seconds. The final
transfer suite has 4,948 checks; existing carrier-ownership and pointwise interval
refinement tests also pass (full task 5,541,281 checks, not distinct test cases).
Log: `.forge-work/scratch/stack-transfer-operands-final.log`.
Five compiled faults admitting extra operands in copy/extension, subpiece,
piece, shift and join operations all produced behavioral assertion failures;
unchanged baseline passed in the 12.627-second mutation run:
`.forge-work/scratch/stack-transfer-operands-mutants/result.json`.

Diagnostic `coverage-recovery/stack-transfer-operands` verifies 33 additional
StackValueFlow branches on the unchanged production JAR/full denominator. Its
1,376-session mixed cohort has 28,896/29,802 lines and 22,619/25,902 branches.
Critical binary/location branches are 16,398/18,750, 477 below 90%; file-operation
targets remain met. This is not current hosted acceptance of queued HEAD.
CI run 44150222826 still has three architecture jobs live and no failed jobs
at the last poll. Full validation, protected merge and publication remain unmet.

### Complete byte windows and address identity for stack loads (2026-11-17)

CONFIRMED: `StackTransferShapeSmoke` now stores a tracked value, attempts a load,
then erases both the saved slot and original register. Only the loaded register
can establish availability. A BigInteger interval oracle checks complete
containment across 1/2/4/8-byte values/loads, negative/adjacent offsets and extreme
signed displacements. Missing/extra/null LOAD operands, nonconstant/wrong/
truncated space IDs, incorrect pointer widths, unknown/absolute addresses and
ordinary values masquerading as stack addresses cannot preserve the value.
Both sign-extended and zero-extended encodings of a valid space ID are accepted.
These raw transfer checks do not expand architecture support.

Guarded `./gradlew --no-daemon stackValueFlowSmoke` PASS in 5 seconds; transfer
suite 5,370 checks, full parent 5,541,703 checks (not distinct test cases).
Log: `.forge-work/scratch/stack-load-contracts-final.log`.
Five compiled faults (extra LOAD operand, truncated/ignored space ID, wrapping
relative subtraction and treating a value as a stack address) all produced
behavioral assertion failures; baseline passed in 12.741 seconds:
`.forge-work/scratch/stack-load-contracts-mutants/result.json`.

Diagnostic `coverage-recovery/stack-load-contracts` verifies nine additional
StackValueFlow branches against the unchanged 58bd production JAR, retaining
255 sources/901 classes. Its 1,377-session mixed cohort has 28,896/29,802 lines
and 22,628/25,902 branches; critical binary/location branches are 16,407/18,750,
468 below 90%. File-operation targets remain met. No production code or coverage
denominator changed. Final current hosted validation, protected merge and main
publication remain unfulfilled; CI44150222826 still has three architecture jobs
live and no failed jobs at the last poll.

## Unwind instruction metadata consistency

The existing `ghidraUnwindInstructionsSmoke` now checks contradictory API
observations around real x86-64 and AArch64 decoded instructions. A transparent
API view must reproduce the original graph and evidence. Independently changed
parsed lengths, byte counts, decoded bytes, short memory reads, unreadable memory,
and null or nonadjacent fallthroughs must reject capture with the relevant
reason. Every case preserves code bytes, the saved function body, and the program
modification counter; a normal retry reproduces the original capture.

The guarded parent task passes in 6 seconds: 135 admission assertions, 882
call-site effect assertions, and 1,849 existing unwind assertions. Five compiled
faults that ignore length, byte-count, short-read, stale-byte, or adjacency checks
are caught by behavioral assertions; the unchanged baseline passes (13.639
seconds for the mutation run). An initial test compilation failed because the
iterator adapter lacked `iterator()`; that run contributes no coverage evidence.
Production code is unchanged, and these API consistency tests make no new ISA
or emitted-CFI support claim.

Verified diagnostic union `unwind-metadata-contracts` contains 1,378 sessions with
the same 255 production sources / 901 classes and production JAR SHA-256
`58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`.
The task adds three covered lines and six branch outcomes. Overall counts are
28,899/29,802 lines and 22,634/25,902 branches. The binary/location critical group
is 16,413/18,750 branches, still 462 short of its 90% target. File-operation
critical targets remain met in this diagnostic union only. This mixed local and
historical cohort does not satisfy final hosted acceptance.

Evidence: `.forge-work/scratch/unwind-metadata-contracts-final.log`,
`unwind-metadata-contracts-mutants/result.json`, and
`coverage-recovery/unwind-metadata-contracts/`.

## Current-run Linux host and firmware evidence

The successful `extension-build` and `cortex-m-profile` jobs from run
`44150222826` now replace their older diagnostic coverage sessions. Their exact
job IDs are `134276166465` and `134300299426`; both are completed successfully,
with every recorded step successful or intentionally skipped. The producing
merge `3bdd9b76f85c0d4d49b169a049b23caaf6e824cd` contains PR head
`a5a29b1d9512d81f1923da2d23ea2d4a2ff35ebd`. Production sources are unchanged
between that head and the queued local work, and all sessions match the existing
production JAR SHA-256 and class inventory.

Authenticated artifacts are Linux host `14360978132` (277,435 bytes, SHA-256
`87b5ded986a889d1999cddf05938e30bd2f1c104a768f023b379eb5173a571c3`) and
firmware `14360614334` (280,253 bytes, SHA-256
`192adf5e16962e449413b18d8df2853cc0cea5bc5f72c4effa63fc7deaf16b11`). Downloads
and extraction ran under the storage guard, with archive and extraction caps.
Current admission checks validate receipts, oracle evidence and raw session
bindings; independently regenerated reports reproduce the hosted layer counts.

The 45 current Linux host sessions replace 90 older sessions, and four current
firmware sessions replace eight older sessions. The resulting diagnostic union
has 1,329 unique sessions and unchanged coverage: 28,899/29,802 lines,
22,634/25,902 branches, with the binary/location critical group still 462 branch
outcomes short of 90%. No coverage gain is claimed for this evidence refresh.
Other historical sessions remain, and this run does not validate queued local
commits; full hosted acceptance remains outstanding.

Evidence is under `.forge-work/scratch/coverage-recovery/`: authenticated archives
and manifests in `current-44150222826/`, job and origin records, regenerated
reports and unions in `linux-host-44150222826/` and `firmware-44150222826/`.

## Closed register flow and delay-slot ownership

`outsideBodyFlowSmoke` now includes 35 controlled metadata cases around real ARM
and little-/big-endian MIPS instruction decoding. They reject missing entry or
slot observations, negative/nested delay depths, unmarked/orphan/shared slots,
a function entry or branch into a delay slot, slot control transfers, and
terminal instructions with fallthrough or without a final RETURN operation.
Transparent views and null empty target lists remain accepted. Tests preserve
input graph entries by identity, code bytes, saved function bodies and program
modification counters; the original graph remains valid after each refusal.
These API consistency controls make no new architecture-support claim.

The guarded parent task passes in 6 seconds (328 closed-flow assertions,
17,419 entry-contract assertions and 85 body-flow assertions). Seven compiled
faults are detected by behavioral assertions, with a passing unchanged baseline
in 21.924 seconds. The initial negative-depth mutant survived because MIPS's
independent orphan-slot check still rejected the graph; an ordinary ARM return
now isolates the depth check and detects that fault. An initial proxy equality
assertion was corrected to compare graph-entry identity. An asynchronous Ghidra
listener error observed during fixture teardown prompted flushing queued events
before releasing the three affected fixture types; the final parent and measured
runs contain no such error. Failed/intermediate runs are not coverage evidence.

Diagnostic `closed-delay-ownership` has 1,330 sessions and adds four lines and
15 branch outcomes, all in `GhidraVariableStorage`. With the unchanged production
JAR/classes and full denominator, overall counts are 28,903/29,802 lines and
22,649/25,902 branches. Binary/location critical coverage is 16,428/18,750
branches, 447 outcomes short of 90%. This remains a mixed diagnostic cohort,
not final hosted acceptance; production code is unchanged.

Evidence: `.forge-work/scratch/closed-delay-ownership-complete.log`,
`closed-delay-ownership-mutants-complete/result.json`, and
`coverage-recovery/closed-delay-ownership/`.

## Current-run ARM32 evidence

Run `44150222826` completed `target-preflight (arm32)` successfully, including
its debugger, validator and compressed-DWARF checks. Job `134300299620` has no
failed steps. Coverage artifact `14369983001` is 514,499 bytes, authenticated by
SHA-256 `334b1374c27a72b16483bbfa7c29a2b6af463e6a84f579ded1d3c1fc1c639457`,
run/head identity and producing-merge parentage. Its seven raw coverage sessions
(three headless context-boundary and four native location-width sessions) pass
current admission checks, and independent report regeneration reproduces the
hosted layer counts with the unchanged production JAR and full denominator.

These replace three local ARM32 context-boundary sessions. The diagnostic union
`arm32-44150222826` now has 1,334 unique sessions with unchanged line/branch
counts and a remaining critical branch deficit of 447. No coverage increase is
claimed. Other historical cohorts remain, and the successful run does not
validate queued local commits. Full issue #209 acceptance remains outstanding.

Evidence: `.forge-work/scratch/coverage-recovery/current-44150222826/` contains
the authenticated ARM32 archive and artifact metadata; `arm32-44150222826/`
contains job/origin records, regenerated reports and the diagnostic union.

## Raw call-transfer contracts

The existing `callSiteEvidenceSmoke` now runs 146 additional cases around real
x86-64 and AArch64 direct/indirect calls, direct/conditional/computed tail
candidates, and rebased direct calls. Original ELF byte matching remains active.
Controlled raw p-code changes test missing/duplicate transfers, forbidden outputs,
missing/extra operands, opaque effects, effects after calls, internal branch
control, contradictory call/branch kinds and mismatched targets. Invalid evidence
must become an explicit UNAVAILABLE transfer without a target, return PC or
callee; unchanged retry and transparent views preserve the original transfer.
The raw-operation cap accepts exactly 4,096 operations and refuses 4,097.
Program modification counts and decoded bytes remain unchanged, and the parent
suite confirms the input ELF is unchanged. This is evidence capture testing,
not a new call-site emission or tail-call proof claim.

The guarded parent task passes in 6 seconds with its existing 527 checks plus
146 new transfer cases. Seven compiled faults are caught through behavioral
assertions, with a passing unchanged baseline (18.984 seconds). The first test
attempt selected BRANCH as a contradictory call opcode, which the earlier
intra-instruction-control guard rejected; using RETURN isolates the intended
call-kind check. That failed attempt contributes no coverage evidence.

Verified diagnostic `call-transfer-contracts` contains 1,335 sessions with the
unchanged production JAR, 255 sources and 901 classes. It adds one line and
15 branch outcomes: 28,904/29,802 lines and 22,664/25,902 branches overall.
Binary/location critical coverage is 16,443/18,750 branches, 432 outcomes short
of 90%. File-operation critical targets remain met in the diagnostic union only;
the mixed cohort and queued local commits still need final hosted acceptance.

Evidence: `.forge-work/scratch/call-transfer-contracts-final.log`,
`call-transfer-contracts-mutants/result.json`, and
`coverage-recovery/call-transfer-contracts/`.

## Call-transfer metadata and memory observations

The existing call-site evidence task now adds 174 metadata cases to the 146
raw-transfer cases above. Real x86-64/AArch64 calls and tail candidates, including
rebased calls, reject inconsistent lengths, contradictory flow/fallthrough,
delay ownership, register/foreign memory address spaces, stale/short parsed
bytes, short memory reads, unreadable instructions and nonadjacent return PCs.
Transparent views remain accepted. Refusals must be UNAVAILABLE with a nonblank
diagnostic and no target, return PC or callee. Tests preserve live and parsed
code bytes and the program modification number; normal retries reproduce the
original transfer. The parent still checks unchanged original ELF bytes.

The guarded parent task passes in 6 seconds (527 existing assertions, 146 raw
transfer cases and 174 metadata cases). Five compiled faults are detected by
behavioral assertions with a passing baseline in 14.661 seconds: accepting delay
owners/slots, ignoring parsed-byte counts or short reads, and accepting a
nonadjacent return PC. The initial strict-diagnostic mutation run appeared to
detect six faults, but requiring safe omission without a particular guard's
message exposed a surviving address-space mutation. It still safely omitted
these fixtures via other checks. That mutation is not counted as detected; the
final semantic run contains only the five demonstrated faults. Production code
is unchanged.

Verified diagnostic `call-transfer-metadata` adds 11 branch outcomes and no lines
to the full, unchanged production denominator. Its 1,336 sessions cover
28,904/29,802 lines and 22,675/25,902 branches overall. The binary/location group
covers 16,454/18,750 branches, still 421 outcomes short of 90%. This mixed cohort
does not establish final hosted acceptance or validate queued local commits.

Evidence: `.forge-work/scratch/call-transfer-metadata-final.log`,
`call-transfer-metadata-mutants-semantic/result.json`, and
`coverage-recovery/call-transfer-metadata/`.

## Unwind arithmetic and caller identity

`unwindFlowSmoke` now invokes an independent BigInteger boundary oracle with
1,808 cases over all supported symbolic widths (one through eight bytes).
Signed minimum/maximum, zero and adjacent signed values cover affine stack
addition/subtraction, modular constants, commuted addition, noncommutative
subtraction, incoming-register/return-address identities, missing operands and
mismatched widths. A caller identity survives only a zero displacement. Results
outside the target's signed stack-offset range are unavailable. The existing
conservative omission for subtraction requiring negation of signed 64-bit MIN
is retained explicitly; this does not claim all modular expressions are proved.
Every case checks unchanged unrelated registers, memory ownership and input state.

The guarded parent task passes in 2 seconds (1,808 arithmetic cases plus its
existing 105 assertions and cancellation checks). Six compiled faults are caught
by behavioral assertions, with a passing baseline in 2.807 seconds: ignoring
either operand width, commuting subtraction, retaining shifted caller identity,
wrapping a 64-bit stack offset, or exceeding a narrower signed target offset.
Production code is unchanged.

Verified diagnostic `unwind-arithmetic` contains 1,337 sessions and adds six
branch outcomes, with no line increase. Overall coverage is 28,904/29,802 lines
and 22,681/25,902 branches. Binary/location critical coverage is 16,460/18,750
branches, still 415 short of 90%. Production JAR SHA-256 and the full 255-source,
901-class denominator remain unchanged. This mixed diagnostic cohort does not
satisfy final hosted acceptance.

Evidence: `.forge-work/scratch/unwind-arithmetic.log`,
`unwind-arithmetic-mutants/result.json`, and `coverage-recovery/unwind-arithmetic/`.

## Unwind memory aliases and exact reloads

`unwindFlowSmoke` now also runs 4,760 memory cases. An independent byte-by-byte
BigInteger oracle compares stores of one through eight bytes with three saved
caller facts across negative, zero and near-signed-limit stack coordinates.
Every overlapping write invalidates the complete prior fact; only a known value
with the exact stored width establishes a replacement. Exact reloads recover
that value, while partial-width or displaced reads cannot invent it. Additional
cases cover overflowing store/load extents, unknown pointers and constants or
caller identities that are not proved stack addresses. Every case checks the
input state, unrelated registers and memory preservation across loads.

The guarded parent passes in 3 seconds: 4,760 memory cases, 1,808 arithmetic
cases and the existing 105 checks. Five compiled faults are caught through
behavioral assertions with a passing baseline in 2.481 seconds: missing either
endpoint of an overlap, retaining slots across an unproved store, accepting a
mismatched stored width, and reloading an adjacent address. A valid effect graph
that unexpectedly throws is an assertion failure, distinct from a compilation
or class-loading failure. Production code is unchanged.

Diagnostic `unwind-memory` has 1,338 sessions and adds four branch outcomes,
with no additional lines. Its full-denominator counts are 28,904/29,802 lines
and 22,685/25,902 branches; binary/location critical coverage is 16,464/18,750
branches, 411 short of 90%. The production JAR and 255-source/901-class inventory
are unchanged. This mixed diagnostic cohort is not final hosted acceptance.

Evidence: `.forge-work/scratch/unwind-memory.log`,
`unwind-memory-mutants/result.json`, and `coverage-recovery/unwind-memory/`.

## Unwind call-summary ownership

`unwindFlowSmoke` now includes 2,446 call-summary cases using independent
BigInteger arithmetic and byte-level ownership checks across widths one through
eight. They cover exact/unknown write bounds, signed-bound overflow, positive
and negative stack adjustments, target-width overflow, unknown/non-affine stack
anchors, exact register preservation and partial aliases that do not authorize
whole-register preservation. Caller values and saved slots must match the
summary, and newly released stack memory cannot remain owned. Summaries with
out-of-width adjustments are rejected. The input state remains unchanged.

The guarded parent passes in 3 seconds with 2,446 call-summary, 4,760 memory,
1,808 arithmetic cases and 105 existing checks. Seven compiled faults are caught
by assertions with a passing baseline in 3.181 seconds: ignoring write bounds,
dropping exact-boundary slots, wrapping a bound, preserving partial aliases,
forgetting adjustments, retaining released memory and truncating out-of-width
summaries. Production code is unchanged. This primarily strengthens assertions
on paths already executed elsewhere; it adds only one new branch outcome.

Diagnostic `unwind-call-memory` contains 1,339 sessions covering 28,904/29,802
lines and 22,686/25,902 branches overall. Binary/location critical coverage is
16,465/18,750 branches, 410 short of 90%. The unchanged production JAR and full
255-source/901-class denominator remain in use. This mixed diagnostic cohort
is not final hosted acceptance.

Evidence: `.forge-work/scratch/unwind-call-memory.log`,
`unwind-call-memory-mutants/result.json`, and `coverage-recovery/unwind-call-memory/`.

## Current-run JavaExec and AArch64 evidence refresh

Authenticated run `44150222826` at PR head `a5a29b1d` and producing merge
`3bdd9b76` supplied 212 JavaExec sessions and 26 AArch64 sessions. Both producing
jobs completed successfully. Raw artifact identities, archive SHA-256 values,
collection receipts, test/production fingerprints and report-tool hashes were
checked before admission. The production JAR remains
`58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`.

The regenerated JavaExec-only report matches the hosted 24,205/29,802 covered
lines. The regenerated AArch64 per-layer counters match its uploaded report.
These sessions replace the corresponding earlier-run sessions; they do not add
duplicate evidence. The diagnostic union remains 1,339 unique sessions and
255 sources / 901 production classes, with 28,904/29,802 lines and
22,686/25,902 branches. Binary/location branches remain 16,465/18,750 (410 short
of 90%); file-operation branches remain 3,827/4,250. This refresh changes no
coverage counters. Historical/local evidence remains in the union, so it is
not final current-head hosted acceptance.

Raw artifacts: `combined-javaexec-input` 14362235659, SHA-256
`602fcf497d6c06bcb458d14a0fc5a7aaadabe2d559caa7a681b3aeeb4a2eda56`;
`integration-java-coverage-linux-aarch64` 14373471215, SHA-256
`482a2f9a8bc425f64e8691c55b5e99f67c8985de26dc5d5ee345081b7e6ac93e`.
Verification receipts and regenerated XML:
`.forge-work/scratch/coverage-recovery/javaexec-44150222826/` and
`aarch64-44150222826/`. The separately downloaded rendered JavaExec report is
artifact 14360634181; it was not mistaken for raw execution data at admission.

## Composite parameter metadata consistency

The existing composite-value smoke task now tests a transparent API view and
nine contradictory metadata cases on real decoded x86-64, AArch64, ARM
little-endian and ARM big-endian programs: mismatched owner, negative ordinal,
detached parameter, late first use, zero/negative/short length, missing formal
type and short formal type. Invalid claims produce no location. Every case
checks a clean retry and unchanged saved parameter, storage, type and program
modification counter. The transparent view retains the independently asserted
piece order, widths and discontiguous intervals from the real fixture.

The guarded `compositeValueFlowSmoke` passes in six seconds: 1,208 boundary
checks (120 added) plus 1,032 existing parent checks. Five compiled mutations
that remove owner, ordinal, attachment, first-use or formal-size checks are
detected by behavioral assertions; the unchanged baseline passes (19.358s
for the mutation run). No production source changes or new architecture
support claims result.

Evidence: `.forge-work/scratch/composite-metadata-final-build.log`,
`composite-metadata-mutants/result.json`, and
`coverage-recovery/composite-metadata-final/`. The local measurement initially
refused a stale test JAR after the JavaExec cohort refresh; that failed merge
is not admitted. The final helper uses the current authenticated bundle, and
source hashes, session uniqueness and the full denominator were reverified.
The 1,340-session diagnostic union adds five branches and no lines:
28,904/29,802 lines, 22,691/25,902 branches; critical binary/location
16,470/18,750 branches, 405 short of 90%. File operations remain 3,827/4,250.
Mixed historical/local evidence still prevents final hosted acceptance.

## Scalar, mixed and indirect parameter metadata

The existing scalar-flow, mixed-prefix and indirect-parameter tasks now run
92 additional cases over real decoded programs: x86-64/AArch64 scalar values
at four/eight bytes, ARM register/stack joins in both byte orders, and AArch64
ABI pointers arriving in registers or on the stack. Transparent API views must
retain each fixture's independently checked locations and transitions. Altered
ownership, ordinals, attachment, first use, widths and formal types must not
seed a proof. Indirect controls additionally reject non-pointer effective
types, unknown or incompatible pointees, short pointers, empty objects and
a self-consistent four-byte carrier/pointer that disagrees with the 64-bit ABI.
Every case checks a clean retry and unchanged saved program/parameter state.

Guarded tasks `stackValueFlowSmoke mixedParameterPrefixSmoke
indirectParameterStorageSmoke` pass in ten seconds. Eight compiled guard faults
are caught by Java assertions, with all three unchanged baselines passing
(27.995 seconds total). The tests do not change production code or emitted
artifacts. They run in already registered JavaExec tasks.

Evidence: `.forge-work/scratch/parameter-proof-metadata-build.log`,
`parameter-proof-metadata-mutants/result.json`, and sequentially verified
`coverage-recovery/{scalar,mixed,indirect}-parameter-metadata/` reports. Three
new measured sessions add 12 branches (one scalar, five mixed, six indirect),
with no new lines or denominator changes. The 1,343-session diagnostic union
reports 28,904/29,802 lines and 22,703/25,902 branches. Binary/location branches
are 16,482/18,750, 393 short of 90%; file-operation branches remain 3,827/4,250.
These local additions still need validation in a complete hosted cohort.

## Completed hosted cohort 44150222826 and refreshed x86-64 evidence

Run `44150222826` completed at head `a5a29b1d` / producing merge `3bdd9b76`.
All native, architecture, Windows, firmware, GUI, packaging and performance
jobs passed. The combined target gate failed with `COVERAGE_TARGETS_UNMET`;
required-validation consequently failed and publication was skipped.

The complete hosted report was independently regenerated from all 1,270
authenticated raw sessions. Production class/probe identities, exact session
sets, and every per-source line/branch counter match the uploaded combined,
JavaExec, native-Java, headless and Windows XML reports. Hosted totals are
28,853/29,802 lines (96.8%) and 22,250/25,902 branches (85.9%). Critical
binary/location coverage is 18,611/19,213 lines and 16,063/18,750 branches;
file operations are 6,507/6,677 lines and 3,793/4,250 branches. Changed production
Java meets 30/30 lines and 50/54 branches. Thus this cohort proves the overall
and changed-code targets, but not either critical branch target.

The fresh x86-64 artifact replaces 893 historical sessions with 897 current
sessions. The current qualifier admission policy initially rejected its older
receipt: the queued flexible/incomplete-type tests did not exist at the producing
revision. For diagnostic admission only, that receipt was verified with the
exact producing-merge qualifier policy (SHA-256
`08e142b598b1e6e1102ed0cd23662ff44e187b1cf089ecc00fe234820bc89d94`).
The current policy remains strict and unchanged; a new hosted cohort must
exercise the extended fixture. Local extended-type evidence remains separate.

This refresh adds five lines and 13 branches to the diagnostic union. Its
1,347 sessions now cover 28,909/29,802 lines and 22,716/25,902 branches. Critical
binary/location: 18,652/19,213 lines and 16,491/18,750 branches (384 short of 90%).
File operations: 6,522/6,677 lines and 3,831/4,250 branches. Local-only additions
still prevent treating this union as current-head hosted acceptance.

Evidence under `.forge-work/scratch/coverage-recovery/`:
`complete-44150222826/` independently reproduces the full hosted report;
`linux-44150222826-producing-policy/` records the diagnostic refresh.
Raw Linux artifact 14373258357 has SHA-256
`cf6fc29f0f06bef9b7132b026c3af40b4e34d64a31a3ab828d3c9aa00a7b1b6f`;
combined report artifact 14374180886 has SHA-256
`6b1a012b700394b6c4c19958adaa334f15fc3fd40e0d48ee84e6719bd593b3bd`.
Before the next push, 139 admission tests and actionlint pass; production Java
is unchanged from the completed run. The next run must validate the queued
tests and stronger admission requirements. PR #210 remains draft.

## Curated stack-local admission and competing owners

The existing stack-local lifetime task adds 312 checks over four real decoded
x86-64/AArch64 fixtures (four/eight-byte locals). An already proven location
and unrelated omission reasons must not be replaced. Transparent saved-API
views preserve exact intervals; contradictory ownership, first-use, validity,
assignment, type extent and carrier metadata must produce no lifetime.
Each metadata refusal checks saved identity, unchanged program state and a
clean retry. Real disjoint and unassigned saved variables must not claim the
local's bytes; an invalid saved owner must prevent a lifetime proof.

`stackLocalLifetimeSmoke` passes in four seconds (312 new checks plus 376
existing checks). Eight compiled admission/ownership faults are detected by
behavioral assertions; the unchanged baseline passes (19.141 seconds total).
An initial fixture setup used a program-specific compiler model to construct
a second database; corrected to obtain the language's compiler specification.
No production changes were necessary.

Evidence: `.forge-work/scratch/stack-local-admission-final-build.log`,
`stack-local-admission-mutants/result.json`, and
`coverage-recovery/stack-local-admission/`. The verified diagnostic union adds
16 branches and no lines: 1,348 sessions, 28,909/29,802 lines and
22,732/25,902 branches. Critical binary/location branches are 16,507/18,750,
368 short of 90%. File operations remain 3,831/4,250. Full-denominator scope
and production JAR are unchanged; current-head hosted acceptance is pending.

## Call-memory target profiles and stack direction

The raw call-memory fixture adds 105 checks in i386, x86-64 and AArch64
language contexts. Transparent target views retain their empty-write summary;
missing/partial stack pointers, missing/overlay/non-RAM spaces, word addressing,
zero/oversized pointers and pointer/register-width disagreement must be refused
without crashing. Each rejected profile is followed by an unchanged-program
retry. Both stack directions exercise zero, small positive/negative and signed
32/64-bit endpoint adjustments, checking exact release ranges and final SP
coordinates. These are raw proof contracts, not new processor/ABI support claims.

`callMemoryEffectsSmoke` passes in five seconds: 339 raw checks, 525 existing
boundary checks and 165 parent checks. Five compiled faults are detected by
behavioral assertions: accepting overlay/register/word-addressed memory,
ignoring pointer-width disagreement, and assuming a downward stack. The
unchanged baseline passes (17.299 seconds total). A candidate mutation removing
only the partial-register guard remains safely rejected by the independent
width guard, so it is not counted as a detected fault. No production changes.

Evidence: `.forge-work/scratch/call-memory-profile-build.log`,
`call-memory-profile-behavior-mutants/result.json`, and
`coverage-recovery/call-memory-target-profiles/`. The verified diagnostic union
adds 12 branches and no lines: 1,349 sessions, 28,909/29,802 lines and
22,744/25,902 branches. Critical binary/location branches are 16,519/18,750,
356 short of 90%; file operations remain 3,831/4,250. All 255 production
sources / 901 classes remain measured. Current-head hosted acceptance remains
pending; these additions follow the revision running in CI 44185360886.

## Merged-local saved metadata consistency

The existing merged-local lifetime task now tests 188 additional metadata cases
(564 assertions) over eight real x86-64/AArch64 fixtures: register-backed and
stack-backed identities, each at four/eight bytes. Canonical and later members
are tested separately. Transparent views retain the independently asserted
initialization, handoff, update and retirement intervals. Foreign ownership,
invalid/unassigned variables, width/type conflicts, detached members, and
foreign/indirect/short/missing stack-path carriers must not create a merged
lifetime. Every refusal checks clean retry and unchanged saved state.

`mergedLocalLifetimeSmoke` passes in five seconds: 1,444 ownership checks and
248 existing parent checks. Eight compiled guard faults are caught by behavioral
assertions; the unchanged baseline passes (19.659 seconds total). Production
code is unchanged.

Evidence: `.forge-work/scratch/merged-local-metadata-build.log`,
`merged-local-metadata-mutants/result.json`, and
`coverage-recovery/merged-local-metadata/`. The verified diagnostic union adds
16 branches and no lines: 1,350 sessions, 28,909/29,802 lines and
22,760/25,902 branches. Critical binary/location branches are 16,535/18,750,
340 short of 90%; file operations remain 3,831/4,250. Full-denominator scope
is unchanged. Hosted validation of these local additions remains pending.

## Stack-value target admission and observable initialization

The existing raw memory fixture adds 117 checks for stack-value tracking in
i386, x86-64 and AArch64 language contexts. Target metadata refusals also apply
to local-state creation and incoming pieces. A memory space with the correct
ID but without the matching registered identity must be refused. Nonpositive
local widths, SP-as-value, overwide/zero-width register spans and memory,
constant or unique-space carriers cannot invent incoming facts.

Positive controls verify observable semantics: a local has no location before
its defining store, the completed store establishes the exact SP-relative
coordinate, and incoming register/stack values retain their exact register
number, width and offset. Transparent API views preserve these observations;
the original program's bytes and modification counter remain unchanged.

`callMemoryEffectsSmoke` passes in five seconds (456 raw checks, 525 boundary
checks and 165 parent checks). Eight compiled faults are caught by behavioral
assertions, including an invented location for a non-value carrier and accepting
a foreign memory-space identity. The unchanged baseline passes (26.622 seconds
total). These raw contracts do not establish additional target support.

Evidence: `.forge-work/scratch/stack-value-target-build.log`,
`stack-value-target-mutants/result.json`, and
`coverage-recovery/stack-value-targets/`. The verified 1,351-session diagnostic
union adds one line and 15 branches: 28,910/29,802 lines and 22,775/25,902
branches overall. Critical binary/location branches are 16,550/18,750,
325 short of 90%; file operations remain 3,831/4,250. All 255 production
sources / 901 classes remain in scope with unchanged production bytecode.
These local additions still require hosted validation.

## Later register-local metadata agreement

The existing `laterRegisterLocalSmoke` now checks 80 metadata cases (240 new
assertions) over the real decoded x86-64/AArch64 four/eight-byte local fixtures.
Transparent views preserve the independently specified available interval;
contradictory owner/program, validity, assignment, storage, type extent and
register metadata must not invent a location. Each case preserves saved state
and permits a clean retry. The narrow AArch64 w9 control remains valid for a
four-byte local. These are admission tests, not additional architecture claims.

Guarded `laterRegisterLocalSmoke` passes in four seconds: 401 ownership checks
and 112 parent checks. Five compiled faults are caught by behavioral assertions
(validity, assignment, type extent, foreign storage and indirect storage), with
the baseline passing; mutation run takes 13.201 seconds. A candidate removing
only the register-address guard survived because later lifetime checks still
refuse the mismatched register; it is not counted as detected or retained as a
required mutation. No production code changed.

Evidence: `.forge-work/scratch/later-local-metadata.log`,
`later-register-metadata-behavior-mutants/result.json`, and
`coverage-recovery/later-local-metadata/`. Raw execution SHA-256:
`cc6758b836b2d8492116bac2b025bd8c198d6fa6f8e445c4d736e685fd9beeb1`.
Source hashes, unique session addition and all 255 production sources verify.
The 1,352-session diagnostic union adds 13 branches, reaching 22,788/25,902
overall and 16,563/18,750 binary/location branches (312 short of 90%). Line
counts and file-operation coverage are unchanged. This mixed diagnostic union
is not current-head hosted acceptance; PR #210 and issue #209 remain incomplete.

## Register-definition metadata agreement through control flow

The metadata oracle above is now shared in `RegisterLocalMetadataSmoke` and
also called by `localDefinitionFlowSmoke` on its four real decoded diamond
fixtures. Both parents pass: 240 metadata assertions each, 161 separate later
ownership checks/112 later-parent checks, and 508 definition-flow parent checks
plus its existing unreachable-definition and control-boundary children. The
shared extraction avoids duplicating the admission oracle. The definition
suite retains its independent join, loop, bypass, available-range and input
preservation assertions.

Guarded `laterRegisterLocalSmoke localDefinitionFlowSmoke` passes in six seconds.
Five separately compiled faults in `RegisterDefinitionFlow` are detected by
behavioral assertions (validity, assignment, type extent, foreign storage and
indirect storage); the unchanged baseline passes, total 15.301 seconds. Production
code and bytecode remain unchanged.

Evidence: `.forge-work/scratch/register-definition-metadata.log`,
`register-definition-metadata-mutants/result.json`, and
`coverage-recovery/register-definition-metadata/`. Raw SHA-256:
`653822af4953532a36cd71cef3697674122adb46fc48e983c09b73ae64cb913e`.
Source hashes and the unique session addition verify. The 1,353-session diagnostic
union adds 13 further branches, reaching 22,801/25,902 overall and 16,576/18,750
binary/location branches (299 short of 90%); all 255 production sources remain
included. Line and file-operation counters are unchanged. Current-head hosted
acceptance, protected merge and main publication are still required.

## Exact parameter-entry location boundaries

`EntryLocationBoundarySmoke`, invoked by the existing call-argument task, adds
108 assertions over real x86-64/AArch64 evidence. Six half-open range shapes
exercise entry inclusion/exclusion, exact one-address extent and retained
prefix/suffix omissions. Adjacent proven locations, omission reasons/confidence,
input state and idempotence are preserved. Stale entry owner/ordinal, missing
instruction evidence and local-variable declarations cannot acquire a parameter
location. The public model constructor rejects missing declarations and width
inconsistency before refinement; the tests respect that invariant instead of
forcing an impossible model through the refinement path. The first fixture run
failed at that constructor, and the corrected test explicitly asserts it.

Guarded `callArgumentFlowSmoke` passes in five seconds (108 new, 612 parent
checks, 25 cases). Six compiled behavioral faults are caught: lost prefix,
lost suffix, expanded lifetime, included exclusive end, proof before the range
start, and stale owner acceptance. Baseline plus the independent DWARF value
oracle pass; mutation run takes 16.747 seconds. The separately measured run's
240 numerical vectors also pass `check-call-values.py --min-count 240`.

Evidence: `.forge-work/scratch/entry-location-boundaries-final.log`,
`entry-location-boundary-mutants/result.json`, `entry-location-boundaries-oracle.log`,
and `coverage-recovery/entry-location-boundaries/`. Raw SHA-256:
`af116881b3b83944d8164bcd252456f459288aa5a3ee4a1fee1a150b90167a1c`.
Source/session/full-denominator verification passes. The 1,354-session diagnostic
union adds five branches: 22,806/25,902 overall and 16,581/18,750 binary/location
(294 short of 90%); other counters are unchanged. Production code is unchanged.
This remains diagnostic evidence; hosted current-head gates, merge and main
publication are still pending for #209.

## Saved local merge metadata agreement

`SavedMappingMetadataSmoke` runs through `localMappingsSmoke` with actual saved
three-member Ghidra merge groups on x86-64, AArch64 and MIPS in both byte orders.
108 cases/324 assertions check each member's owner, program, validity, assignment,
register identity, width and first-use consistency. Transparent views preserve
all canonical symbol IDs, ordered definitions and physical registers; negative
views cannot include the inconsistent member or skip a gap. Saved state and
subsequent clean extraction remain unchanged. These are listing-identity tests,
not new emitted-artifact or runtime architecture claims.

The first fixture incorrectly demanded an empty result when Ghidra filtered an
invalid trailing member before encoding. The corrected oracle permits its
complete valid prefix, matching the independently tested missing-ordinal rule;
it never permits the rejected member or a later member across the gap. A wrong
register control uses another register of the same width, isolating identity
from width validation.

Guarded `localMappingsSmoke` passes in four seconds: 324 new assertions, 92
parent checks and 592 existing encoding checks. Four compiled faults are caught
by behavioral assertions (variable owner/program, register identity and assigned
storage); baseline passes, total 10.022 seconds. Production code is unchanged.
Evidence: `.forge-work/scratch/saved-mapping-metadata-same-width.log`,
`saved-mapping-metadata-mutants/result.json`, and
`coverage-recovery/saved-mapping-metadata/`. Raw SHA-256:
`d2dcd37b947401971da57f9737fd5f83f7c4ebbb6ce16c3043f3ec9888655035`.
Source hashes, unique raw session and all 255 sources verify. The 1,355-session
diagnostic union adds eight branches: 22,814/25,902 overall and 16,589/18,750
binary/location branches (286 short of 90%). Line and file-operation counters
are unchanged. Hosted current-head acceptance remains outstanding for #209.

## Decoded call-argument arithmetic and independent numeric checks

The existing call-argument suite now covers 49 decoded fixtures, adding twelve
arithmetic/bit-operation shapes per x86-64/AArch64 target. GNU target assemblers
and disassemblers independently confirm the fixture encodings; instruction text
is recorded beside each byte string. Accepted cases cover subtraction, multiply,
AND/OR/XOR, shifts, complement, signed/unsigned byte extension and zero comparisons
where the existing profile admits them. The selected profile rejects x86 `setz`
and AArch64 `mul`/`mvn`; those three controls assert explicit refusal and no value
proof. The first run identified the existing `setz` restriction, which was kept;
no production profile was widened to make these tests pass.

Guarded `callArgumentFlowSmoke` passes in six seconds (858 checks, 49 fixtures).
The independent DWARF VM validates 576 numerical vectors, checking both low-word
and bound whole-register values for zero, positive, negative, signed boundaries
and high-word-only inputs. Original ELF bytes are preserved and repeat analyses
agree. Eight compiled arithmetic faults are detected through behavioral/value
assertions: wrong subtraction, multiplication, AND/OR/XOR, left/right shifts and
lost sign extension. Baseline passes; mutation run takes 34.412 seconds. CI and
mutation checks now require at least 576 vectors. Workflow lint and all eight
mutation-outcome classifier tests pass.

Evidence: `.forge-work/scratch/call-arithmetic-assembly/`,
`call-argument-arithmetic-profiled.log`, `call-argument-arithmetic-mutants/result.json`,
`call-argument-arithmetic-measured-oracle.log`, and
`coverage-recovery/call-argument-arithmetic/`. Measured raw SHA-256:
`836031b1089e9e3b8a10f39bde41faa31cb3c77be120a19093d700e616331275`.
Raw/source/session/full-denominator verification passes. The 1,356-session
diagnostic union adds two lines and six branches: 28,912/29,802 lines,
22,820/25,902 branches overall; binary/location 18,655/19,213 lines,
16,595/18,750 branches (280 short of 90%). Production code/bytecode is unchanged.
This is not a fresh hosted acceptance cohort; #209 still requires its hosted
gates, protected merge and main publication.

## Call-value byte containment and snapshot budgets

`ArgumentValueStorageSmoke` adds 1,704 assertions to the existing call-argument
suite. For every one-through-eight-byte owner in both register/temporary banks,
it checks every nearby one-through-eight-byte query against exact containment
and independently calculated little-endian literal bytes. Cross-bank and
out-of-owner reads remain unavailable. An undersized expression cannot fabricate
whole-register bits; a depth-budget refusal retains the source expression.
Snapshots copy input maps, expose immutable state, accept exactly 1,024 entries
and reject the first excess entry without changing the previous snapshot.

Guarded `callArgumentFlowSmoke` passes in six seconds (1,704 new assertions plus
858 parent checks/49 fixtures). Six compiled faults are detected: cross-bank
reads, rejected exact containment, bit/byte offset confusion, wrong exact/excess
state budget and retained mutable input maps. The initial mutation run rejected
an exception-only result at the valid budget boundary; the test now explicitly
asserts successful construction there. Final mutation baseline and all six
behavioral detections pass in 12.066 seconds. The independent 576-vector DWARF
oracle also passes for the measured run. No production code changed.

Evidence: `.forge-work/scratch/argument-value-storage-final.log`,
`argument-value-storage-behavior-mutants/result.json`,
`argument-value-storage-oracle.log`, and `coverage-recovery/argument-value-storage/`.
Raw SHA-256: `d54b02a23e789fa6cca6bf1e091e2dc0ec4b768a514711fc1c9243f231b96761`.
Source/raw/session/full-denominator verification passes. Most exercised branches
were already measured elsewhere: the 1,357-session diagnostic union adds one
line and one branch, reaching 28,913/29,802 lines and 22,821/25,902 branches overall;
binary/location 18,656/19,213 lines and 16,596/18,750 branches (279 short of 90%).
File counters remain unchanged. Current-head hosted acceptance is still pending.

## Stack-spill target profile agreement

The real decoded x86-64/AArch64 four/eight-byte spill fixtures now check eleven
profile views each. The transparent view retains the exact SP-relative storage
and lifetime; missing/partial SP, missing/overlay/non-RAM/word-addressed memory,
wrong pointer width and unregistered memory identity must not acquire a spill.
Each case leaves the program unchanged and permits a clean original-profile
retry. The shared `TargetProfileViews` helper replaces the equivalent private
call-memory helper, retaining its existing checks and controls. These tests do
not extend the supported target profiles.

Guarded `stackSpillSmoke callMemoryEffectsSmoke` passes in seven seconds:
2,406 spill checks (136 additional assertions across 44 profile cases), plus
456 raw, 525 boundary and 165 parent call-memory checks. Four compiled faults
are detected by behavioral assertions: accepting overlay memory, register-space
memory, word addressing and an unregistered memory identity. Baseline passes;
mutation run takes 10.949 seconds. No production code changed.

Evidence: `.forge-work/scratch/stack-spill-target-profiles.log`,
`stack-spill-target-mutants/result.json`, and
`coverage-recovery/stack-spill-target-profiles/`. Raw SHA-256:
`8221feb30fb7be75791a4d8be7a6902845fe1a80c3821ca945061ceaf480f65c`.
Source/raw/session/all-255-source verification passes. The 1,358-session diagnostic
union adds seven branches: 22,828/25,902 overall and 16,603/18,750 binary/location
(272 short of 90%). Other counters remain unchanged. Hosted current-head gates,
protected merge and main publication are still required for #209.

## Inheritance physical member snapshots

`InheritancePhysicalLayoutSmoke`, called by the existing inheritance evidence
task, adds 68 assertions over real x86-64/AArch64 program databases. A 16-byte
class contains a three-bit field in one byte of storage, a four-byte typedef and
an eight-byte pointer. Changing bit offset or width while retaining outer extent,
changing the typedef base while retaining its universal ID/size, and changing
pointer targets invalidate saved relationships. Restoring each physical layout
restores the prior valid evidence. Display names/comments leave the serialized
snapshot unchanged. Valid and rejected reads preserve the saved record and
program modification counter; no stale evidence is silently repaired.

Guarded `inheritanceBindingEvidenceSmoke` passes in five seconds: 68 new physical
checks, 188 existing parent checks and 36 budget checks. Four compiled faults
are detected by behavioral assertions: omitting bit offset, bit width, typedef
base traversal or pointer-target identity from the fingerprint. Baseline passes;
mutation run takes 13.208 seconds. No production code changed.

Evidence: `.forge-work/scratch/inheritance-physical-layout-final.log`,
`inheritance-physical-layout-mutants/result.json`, and
`coverage-recovery/inheritance-physical-layout/`. Raw SHA-256:
`b552e04d7f6ac5f5789745ceff54e8883b7718b7030476b193c5058a314be59d`.
Source/raw/session/all-255-source verification passes. The 1,359-session diagnostic
union adds one line and four branches: 28,914/29,802 lines and 22,832/25,902 branches
overall; binary/location 18,657/19,213 lines and 16,607/18,750 branches (268 short
of 90%). File-operation counters remain unchanged. Hosted current-head gates,
protected merge and actual main publication remain outstanding for #209.

### Function model admission and capture boundaries (2026-11-17)

CONFIRMED locally: `FunctionEntrySmoke` now rejects absent/blank lexical names,
invalid namespace components, absent/empty/overlapping/unsorted bodies, negative
addresses, invalid extents, and overflowing exclusive ends. Positive controls
exercise zero, the 32-bit address boundary, the highest supported signed end,
interior entries, adjacent ranges, split bodies, and duplicate qualified identities
at different addresses. Independent interval predicates verify membership without
invented gap coverage. Captured body and namespace lists survive caller mutation;
delimiter collisions are rejected in either order.

Acceptance addressed: issue #209 malformed-input/address-boundary assertions and
representative fault controls, preserving all production classes and behavior.
Guarded `./gradlew --no-daemon functionEntrySmoke` passed in 2 seconds. Existing
32/64-bit, both-byte-order range/line checks also passed. Four compiled mutations
were detected by behavioral assertions: body aliasing, namespace aliasing,
accepted overlap, and inclusive exclusive-end membership (3.544 seconds).
Commands used Java 25 and Ghidra 12.0.3; native producer mode was not invoked by
this local model check. No emitted-artifact implementation changed.

Evidence: `.forge-work/scratch/function-model-boundaries.log`,
`.forge-work/scratch/function-model-mutants/result.json`, and
`.forge-work/scratch/coverage-recovery/function-model-boundaries/`.
The independently verified diagnostic union adds one unique session (1360 total),
four lines and eight branches, all in `MinimalDwarfSidecarExporter`. Overall:
28,918/29,802 lines and 22,840/25,902 branches. Binary/location critical group:
18,661/19,213 lines and 16,615/18,750 branches, 260 branches short of 90%.
File critical counters remain 6,522/6,677 lines and 3,831/4,250 branches.
The unchanged production JAR SHA-256 is
`58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`;
all 255 sources remain measured. This mixed local diagnostic does not replace
fresh hosted acceptance, protected integration, or actual-main publication.

### Native class-method declaration metadata (2026-11-17)

CONFIRMED locally: the isolated `ClassScopeSmoke` adds two addressless class
methods. One is variadic/no-return with an unnamed scalar parameter and an
artificial return-storage variable; the other explicitly disables debugger calls.
Both have an unknown convention. The independent DIE checker verifies root and
class declarations, specification ownership, exact parameter/variable tags and
types, missing locations/addresses, omitted unknown calling convention, and
`DW_CC_nocall` for the restricted declaration. It now detects 15 malformed-DIE
controls per ordinary variant and 13 for the failed-source variant.

The guarded `class-scope-native.py` harness passed normal, failed-source,
collision, ambiguous, and unbound-collision variants using the pinned 2.3.2
producer/consumer and unchanged current production JAR. All five passed GNU
readelf, LLVM verification, strict pinned-libdwarf checks, and DIE assertions.
The four non-failed variants passed 26 fresh GDB queries; class views preserve
`static int metadata(int, ...)` and `static int disabled(int)`. Repeated ordinary
export remained byte-identical and the original executable hash was unchanged.

An initial direct GDB lookup of the addressless external method failed: GDB did
not index it as a standalone function. The final test checks the containing
class, without inventing executable addresses or relaxing metadata assertions.
That incomplete collection is excluded from the coverage addition.

Guarded driver: `.forge-work/scratch/run-class-metadata.py`; final log:
`.forge-work/scratch/class-method-metadata-final.log`; successful harness output:
`build/test-results/class-scope-native/tmp6pdqh5ju`; validated collection:
`.forge-work/scratch/class-method-metadata/collections/class-scopes-_ps85kny`.
Its raw execution SHA-256 is
`172d018fead8668fc51967f9224ece69902bbdda389f93e818a7bd948477859c`.
The matching native-Java session adds six covered exporter branches, no lines,
to the diagnostic union (1361 sessions). Overall is 28,918/29,802 lines and
22,846/25,902 branches; binary/location is 16,621/18,750 branches, 254 short of
90%. File-operation counters remain unchanged. Execution identities, artifact
and oracle hashes, full 255-source denominator and harness sources are retained
in `coverage-recovery/class-method-metadata/result.json`. No production code or
native ABI changed. Fresh hosted acceptance and actual-main publication remain
required for issue #209 completion.

### Unwind policy and alias model limits (2026-11-17)

CONFIRMED locally: `UnwindFrameRowsSmoke` rejects missing/aliased frame roles,
invalid DWARF register numbers, temporary rather than physical-register cells,
wrong widths, overlaps, and excess register count. Positive 32/64-bit cases
accept exactly 512 adjacent registers and check all projected identities and
509 explicit unavailabilities. Caller mutation cannot change the captured policy;
register number 4095 and a shared return/counter role remain valid. Missing either
side of a call produces no recovery rules, and caller-stack/CFA overflow is
explicitly omitted. The initial overflow fixture used `-1 - Long.MAX_VALUE`,
which equals representable `Long.MIN_VALUE`; corrected to `-2 - Long.MAX_VALUE`.
No implementation defect or production edit was needed.

`FunctionAliasSymbolsSmoke` adds invalid hash/extent/name/owner/body inputs,
case-normalized hash identity, exactly 65,536 UTF-8 bytes (one-, two-, and
four-byte code points), exactly 65,536 body ranges and one-over-limit refusal,
immutable capture, half-open address boundaries through the highest supported
signed address, and entry-containing suffix extents. Existing both-width/order
ELF symbol merge, byte-preservation, collision and cancellation checks still run.

Guarded `./gradlew --no-daemon unwindFrameRowsSmoke functionAliasSymbolsSmoke`
passed in 3 seconds (107 unwind checks and 463 alias checks). Eight compiled
faults were detected by behavioral assertions in 3.313 seconds: exact-count
rejection, temporary-cell acceptance, mismatched-width acceptance, stack/counter
aliasing, omitted UTF-8 budget, exact-range-count rejection, noncanonical hash,
and mutable alias body. Evidence logs are
`.forge-work/scratch/policy-alias-boundaries-final.log` and
`.forge-work/scratch/policy-alias-mutants/result.json`.

The independently verified `unwind-policy-boundaries` and `alias-model-boundaries`
diagnostic additions contribute two sessions, two lines and 24 branch outcomes.
Final union: 1363 sessions, 28,920/29,802 lines, 22,870/25,902 branches.
Binary/location critical: 18,663/19,213 lines, 16,645/18,750 branches, 230 short
of 90%. File-operation critical counters remain 6,522/6,677 and 3,831/4,250.
The production JAR and full 255-source denominator are unchanged. These local
measurements do not replace current hosted acceptance or main publication.
