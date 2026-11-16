# Combined Java coverage and behavioral gaps

Issue #209 remains **incomplete**. The accepted targets are 85% lines / 80%
branches overall, 95% / 90% for **each** critical group, and 90% lines / 85%
branches minimum for substantially changed Java logic (90% branches preferred).
A passing coverage percentage does not replace independent debugger, validator,
input-preservation, determinism, cancellation and recovery assertions.

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
