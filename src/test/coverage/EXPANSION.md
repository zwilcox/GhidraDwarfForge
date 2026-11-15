# Integration coverage and behavioral gaps

This work follows completed issue #203. The user requested both measurement
of existing integration tests and new behavioral tests for genuinely uncovered
paths. It includes all six areas below; completing one row does not complete
the work.

## Baseline and acceptance

The baseline is main `664f8076a7ffdd7fe261e9d439d6a4254dcb1071`, validated by
CI run 43654611110. Its published report is commit
`114926ef740cd8032027bebcdb095eb0692d6d92`: 23,118/29,782 Java lines and
17,246/25,872 branches, all 901 production classes / 255 source files, from
208 Linux JavaExec tasks. The separate installed-headless sample is not part
of that metric. Native C is not measured by JaCoCo.

Required outcomes:

1. Measure existing isolated native-Java, headless, and Windows integration
   execution, with each layer identifiable and the complete production
   population retained. Do not add percentages or silently change the badge's
   scope. Check bytecode identity, session completeness, and stale/foreign data.
2. Review the six areas below using existing behavioral assertions and measured
   missed branches. Add meaningful negative tests for actual gaps, with
   independent expected results and representative defect-detection controls.
3. Compare before/after on the same production population. Distinguish new
   instrumentation from new behavioral coverage. Record any production fix and
   denominator change explicitly. No overall percentage is promised in advance.
4. Preserve native-process isolation, original inputs, deterministic outputs,
   structural/debugger validation, and the normal protected architecture/host
   gates. Verify actual-main publication after integration.
5. Keep collection opt-in and test-only, record reproduction/runtime/storage,
   and retain bounded evidence through the existing storage guard.

## Initial audit (before implementation)

| Area | Existing evidence located | Remaining work |
| --- | --- | --- |
| Central exporter | Isolated producer tasks, five architecture lanes, tiny headless coverage pilot | Extend measurement beyond the tiny sample; inspect missed failure/type/location paths |
| Installation, validation, project protection | Build-ID lifecycle/cancellation/rollback probes; attachment validator controls; saved-project preservation integration | Instrument real probes; direct project-path/alias/cancellation assertions; inspect residual gaps |
| Source sidecar and debugger companion | Source relocation independent byte checks plus GDB/LLDB; companion and bundle probes | Instrument existing subprocesses and inspect uncovered branches |
| Firmware image/session | Isolated firmware producer; raw firmware failure/cancellation and saved-program checks | Collect isolated and headless coverage, inspect residual gaps |
| Source context, annotations, equates | Saved-program readback, cancellation, deterministic source and constant checks | Collect existing headless checks and inspect residual gaps |
| Windows filesystem implementations | Native Windows installation/attachment and metadata probes | Collect actual Windows JVM execution; keep its report distinct; inspect residual gaps |

The first direct suite targets `GhidraProjectOutputProtection` (baseline 0/31
lines): missing project association, legal siblings, project descendants,
marker/lock/data aliases through real hard and symbolic links, missing parents,
non-recursion through directory links, and cancellation at every visited
checkpoint. Target at least 95% lines / 90% branches, with independent file/link
snapshots proving no mutation. Ghidra's Program/DomainFile accessors may be
stubbed for these filesystem cases; saved-project integration remains required.
This first suite does not substitute for the other five areas or the integration
measurement work.

## Local checkpoints (hosted acceptance still pending)

The production JAR remains the baseline JAR with SHA-256
`98ea0bbb8a292152d76cd2be9972ad5c5e270421ab65043fc1ced2afaa81caf9`.
No production code has changed. These are separate measurements, not additions
to the published JavaExec percentage.

- **CONFIRMED:** new project protection suite passes 33 filesystem/cancellation
  checks and measures 31/31 lines and 18/18 branches. Four injected protection
  faults are detected with unchanged baselines.
- **CONFIRMED:** new firmware image lifecycle suite passes 134 assertions:
  independent decoding of mapped bytes, cancellation at each construction
  checkpoint, temporary-carrier cleanup, input provenance changes, direct/link
  output aliases, invalid input selection, and deterministic retry. It measures
  152/162 image-construction lines and 65/80 branches without loading libdwarfp.
- **CONFIRMED:** all 17 selected mutations are detected with unchanged-source
  baselines passing (13.0 seconds). The four new firmware faults drop cancellation,
  leak failed carriers, ignore input provenance, or copy from the wrong offset.
- **CONFIRMED:** the collector's 17 receipt/admission tests pass. A real JVM
  round trip retains an unloaded class, OR-merges branch probes, and rejects
  wrong bytecode IDs, foreign classes, combined sessions, and no production hits.
- **CONFIRMED:** existing source-context headless tests pass independent saved
  project preservation/readback and deterministic-output assertions. They
  measure 174/181 source-context lines and 111/142 branches.
- **CONFIRMED:** the packaged raw-firmware harness passes 20 failure/cancellation
  controls, deterministic retry, structural validation and actual QEMU/GDB
  behavior. Its two measured analyzer JVMs cover 691/1,196 central-exporter
  lines, 152/162 firmware-image lines, and 104/117 firmware-session lines.
  This extends measurement of existing tests, not their behavioral scope.
- **CONFIRMED:** the packaged debugger-companion harness passes non-PIE, PIE,
  and shared-object runtime checks. New assertions cancel at every observed
  checkpoint (314, 322, 285 respectively), reject eight unsafe final pathname
  cases per fixture, prove input preservation/no companion publication, and
  verify a deterministic successful retry after failures.
- **CONFIRMED:** actual Linux build-ID installation passes both executable and
  PIE lifecycle suites with real host metadata, crash/recovery and debugger
  discovery. Source relocation and derived-artifact validation pass against
  plain and zlib-compressed exports. Their combined native-Java report has
  137 sessions: installation 408/417 lines, attachment validator 186/204,
  source sidecar 196/200, and debugger companion 122/153.
- **CONFIRMED:** the combined 22-session headless sample covers exporter
  825/1,196 lines, annotation inventory 109/109, equate extraction 116/122,
  and equate source rendering 49/49. It includes real all-failed, mixed-failed
  and empty decompilation exports, deterministic reruns, source limits,
  cancellation, independent validators and GDB behavior.
- **CONFIRMED:** the 209-task full JavaExec run passed in 249.9 seconds; the
  additional firmware lifecycle task then passed, producing a 210-task report
  with 23,305/29,782 lines (78.3%) and 17,330/25,872 branches (67.0%). All 901
  production class files are byte-identical to the baseline release JAR.
  The comparable gain is 187 lines and 84 branches. These are local results;
  the published badge still requires hosted main acceptance.
- **PRESENT, UNVERIFIED:** CI collection/reporting for Linux native Java,
  headless firmware/analyst tests, Windows attachment and build-ID installation.
  Native Windows execution and the complete protected matrix remain required.
  The Windows sample also runs the existing privilege/host/transaction/lock
  probes against the installed JAR. Its four direct JVMs are measured; nested
  lock contenders and eight intentional halt children are not. Their native
  behavior and recovery assertions still run. This avoids treating installer
  success as sufficient coverage of privilege restoration or sharing failures.

The raw-firmware attempt with the old local installation failed because its
native pair metadata was missing. It is retained separately and is not admitted
to a report. The passing retry used the complete release package from baseline
CI run 43654611110, verified its manifest and JAR hash, and restored the previous
test installation afterward. Intentional `Runtime.halt(73)` controls remain
behavioral tests with explicitly unmeasured execution, since they bypass the
agent shutdown hook. No missing dump from an ordinary process is accepted.

The first combined report rejected execution from a test-only inherited host
helper in the derived-validation suite. Explicitly excluding that helper and
its test superclass, then rerunning all four complete suites, resolved the
failure. Production-named nested helpers remain measured; broad `*Probe*` or
`*Smoke*` exclusions are forbidden. The failed collection is not admitted.

## Behavioral review and residual limits

| Area | Assertions now measured or added | Remaining limitations |
| --- | --- | --- |
| Central exporter | Existing real failed/mixed/empty decompilation, cancellation, source-limit, deterministic-repeat and validator/debugger oracles now measured | The sample does not cover every C++ inheritance/vtable, inline/call-site, variable-location or native-error branch. Their existing architecture suites remain required; no claim of complete exporter coverage |
| Installation and protection | Existing stale/foreign registrations, interrupted transactions, metadata/rollback, binding/validator mismatches; new direct saved-project aliases and every-checkpoint cancellation with file snapshots | Intentional process halts have no coverage dump; real crash/recovery assertions still run. Filesystem power-loss guarantees are not inferred |
| Source sidecar and GDB companion | Existing relocated line-directory decoding, byte comparisons, wrong sidecar rejection and real GDB discovery; new companion cancellation/unsafe-path/input-preservation/retry tests | Local source-relocation runs used GDB; optional LLDB/perf consumers remain hosted checks. Not all malformed section branches are hit |
| Firmware image and session | Existing 20 packaged failure/cancellation controls and QEMU/GDB; new direct carrier lifecycle tests cover failures obscured by outer preflight | Local sample uses the Cortex-M3 profile. Multi-input selection/session changes require their existing dedicated suites; filesystem deletion failure and unsupported wider-target encoding remain unmeasured here |
| Analyst source context | Existing saved-program readback/preservation, deterministic comments/equates, conflicting/dynamic/enum evidence, cancellation and rendered source limits | Residual invalid evidence/exception branches remain. High line coverage is not a claim that every recovered annotation is valid |
| Windows filesystem | Existing real NTFS installation, interruption/recovery, security/metadata, attachment rollback and refreshed artifacts are instrumented | **PRESENT, UNVERIFIED:** needs native Windows CI, receipt inspection and missed-branch review; Linux mocks cannot satisfy this row |

Remaining acceptance: native Windows validation and review, the complete
protected PR matrix, and actual-main report/artifact publication verification.
Local receipts and logs live under the bounded workspace
`.forge-work/scratch/coverage-expansion/`; `review-selection-2.json` records
exact successful collections and explicitly excluded failed/superseded attempts.
No failed attempt is converted into passing evidence by editing its receipt.
