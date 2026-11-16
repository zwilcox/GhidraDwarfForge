# Combined Java coverage and behavioral gaps

Issue #209 remains **incomplete**. The accepted targets are 85% lines / 80%
branches overall, 95% / 90% for **each** critical group, and 90% lines / 85%
branches minimum for substantially changed Java logic (90% branches preferred).
A passing coverage percentage does not replace independent debugger, validator,
input-preservation, determinism, cancellation and recovery assertions.

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
now contains 165 faults; its complete current-head run remains outstanding.

Evidence: `.forge-work/scratch/coverage-expansion/mixed-prefix-focused-final.log`
and `mixed-prefix-selected-mutations-final/result.json`. No production code,
production inventory, coverage threshold or target mapping changed.

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
