# Combined Java coverage and behavioral gaps

Issue #209 remains **incomplete**. The accepted targets are 85% lines / 80%
branches overall, 95% / 90% for **each** critical group, and 90% lines / 85%
branches minimum for substantially changed Java logic (90% branches preferred).
A passing coverage percentage does not replace independent debugger, validator,
input-preservation, determinism, cancellation and recovery assertions.

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

## Verified local checkpoint

The latest complete JavaExec run executed all 210 tasks at
`f249bab053622bc6e28697e3444bb1cc2445ecf3` in 270.3 seconds. The combined local report
contains 1,033 sessions with the full unchanged denominator:

| Scope | Line coverage | Branch coverage | Accepted target |
| --- | ---: | ---: | ---: |
| All production Java | 94.9% | 79.6% | 85% / 80% |
| Binary and location correctness | 95.2% | 79.5% | 95% / 90% |
| File transactions and validation | 93.9% | 78.5% | 95% / 90% |
| Remaining production | 95.1% | 81.6% | Included in overall |

The binary/location line count is 18,273/19,193, meeting its exact 95%
line gate. Both critical branch targets and the file-transaction line target
remain unmet, as does the overall 80% branch target.

Production JAR SHA-256 remains
`98ea0bbb8a292152d76cd2be9972ad5c5e270421ab65043fc1ced2afaa81caf9`. No production Java changed in this checkpoint.
Exact counters, per-line missed decisions, origins, execution hashes and separate
layer reports are retained under
`.forge-work/scratch/coverage-expansion/combined-cxx-profile-hosted-baseline/`.
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
lookup ownership. Focused tests and all 117 selected mutations pass; the complete combined
coverage refresh is pending. No production code, emitted format or architecture
support claim changes in this batch.
