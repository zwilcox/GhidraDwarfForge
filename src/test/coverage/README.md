# High-risk exporter test coverage

This is the test-local acceptance record for issue #203. It distinguishes
missing behavioral tests from missing instrumentation. It does not replace
structural validators or debugger tests.

## Baseline

The successful main run [43566698124](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43566698124)
tested commit `f8ee3b7a83bbf857faa8aae43c61669537f3e4bb`. Its
[published report](https://github.com/zwilcox/GhidraDwarfForge/blob/6c972b4841dc0116396a1dee68386b926367aebe/README.md)
measures 22,865 covered of 29,780 production Java lines (76.8%), across
901 classes in 255 source files and 205 completed JavaExec tasks.
These are task counts, not individual test-case or assertion counts.

The XML counters, completed task inventory, production JAR class population,
and regenerated published files were independently checked. All production
classes remain in the denominator, including classes not loaded by these tests.

## Test taxonomy and measurement boundaries

| Layer | Examples | Current Java coverage measurement |
| --- | --- | --- |
| Native-free unit/behavior tests | `Dwarf32InfoRepairSmoke`, `ElfImageReaderSmoke`, `CompanionArtifactPublisherSmoke` | Selected JavaExec tasks instrumented in the Linux extension-build job |
| Ghidra API/component tests | ProgramDB fixtures for type, storage, class, and saved-profile evidence | Selected JavaExec tasks instrumented; these are broader than pure unit tests |
| Isolated native producer tests | `nativeProducerSmoke`, `packagedNativeProducerSmoke`, `callSiteProducerSmoke` | Separate target jobs are not included in the published measurement; native C is never measured by JaCoCo |
| Installed headless exporter | Saved-program export, source relocation, raw firmware and failure fixtures | One tiny Linux x86-64 sample now has a separate provisional report; the other subprocess suites remain unmeasured. Neither is included in the badge |
| Consumer/system tests | GNU/LLVM/libdwarf validators, GDB/LLDB, QEMU, Windows and GUI workflows | Behavioral evidence, not Java line coverage |

A zero in the XML is not evidence that a feature has no tests. For example,
`SyntheticSourceRelocation` and `SyntheticSourceSidecar` have independently
validated producer/ELF/GDB tests in `src/test/integration/source-relocation.py`.
Those Java subprocesses are outside the instrumented extension-build population.

## Ranked gap inventory and selected batch

| Priority | Path and baseline | Risk and existing evidence | Planned improvement |
| --- | --- | --- | --- |
| 1 | `Dwarf32InfoRepair`: 112/169 lines, 53/103 branches | Changes serialized offsets and DIE references. Existing direct regression checks one little-endian repair and the 32-bit pass-through. | Independent byte fixtures for both byte orders, reference adjustment and form boundaries; malformed/truncated/overflow refusals; input immutability. Target at least 90% lines and 80% branches. |
| 1 | `CompanionArtifactPublisher`: 138/164 lines, 65/92 branches | Partial publication or incorrect rollback can lose user outputs. Existing tests cover install-index failures, cancellation, aliases and concurrent writes. | Add distinct preflight, invalid-stage, observation-change and cleanup-failure cases with exact old/new bytes and retained recovery checks. Target at least 90% lines and 80% branches. |
| 1 | `SyntheticSourceRelocation`: 0/182 lines, 0/196 branches | A malformed line/CU table can corrupt source paths or unrelated bytes. Integration tests already check real producer output, cancellation and debugger lookup. | Add standalone independently encoded fixtures and adversarial table/form boundaries, preserving the integration oracle. Target at least 85% lines and 75% branches in the measured unit population. |
| 2 | `MinimalDwarfSidecarExporter`: 97/1196 lines, 49/728 branches | Major measurement gap in the native/headless path; existing architecture, failure and lifecycle suites are essential. | Evaluate a bounded isolated-native/headless instrumentation pilot, including class identity and incomplete-session handling. Do not represent Java coverage as native C coverage. |
| 2 | Source-sidecar, build-ID and validation binding classes | Several are zero in the measured JVM but have installed subprocess and transaction tests. | Preserve those tests; record instrumentation feasibility and residual gaps before expanding collection. |
| 2 | Type and variable evidence | `GhidraTypeGraph` 605/665 lines; `GhidraVariableStorage` 817/867. Wrong inferred locations are more serious than omitted ones. | Retain compiler/debugger oracles and failure controls; review uncovered branches by semantics, not only percentage. Further expansion follows the selected batch. |
| 3 | ELF parsing and image identity | `ElfImage` 261/266 lines, 178/198 branches; existing independent 32/64-bit, endian, malformed, sectionless, PIE and rebase fixtures. | Avoid duplicating strong existing coverage. Preserve the full architecture and validator gate. |
| 3 | Windows platform implementations and GUI paths | Not measured by Linux JavaExec instrumentation; covered by separate host/UI jobs. | Keep exclusions explicit and preserve required host jobs. Do not simulate a Windows coverage claim with Linux tests. |

The targets above were selected before implementation. Local results are
recorded below; these targets are not a blanket repository threshold. New tests must reject representative
faults using targeted mutation/fault injection, not merely execute more code.
If a test exposes a production defect, fix it and report any denominator change
separately; do not exclude or remove untested classes to improve the number.

## Completion evidence to record

- Selected-batch cases, relevant cancellation/failure paths, and detected mutants.
- Before/after line and branch counters for the same production population;
  distinguish new test coverage from newly instrumented execution.
- Native/headless collection experiment and remaining measurement blind spots.
- Focused commands, runtime, peak/retained storage, full protected CI and actual
  main publication. Tests use the shared storage guard and bounded fixtures.

## Focused local results

**CONFIRMED locally; full CI and main publication pending.** The independent
repair fixture exposed a section offset of `0x100000007` being silently
truncated to `7`. Repair now refuses a nonzero upper half before deleting bytes.
Valid byte-order and reference fixtures still produce exactly the expected bytes.

| Source | Baseline lines | Local lines | Baseline branches | Local branches |
| --- | --- | --- | --- | --- |
| Dwarf32InfoRepair | 112/169 | 171/171 | 53/103 | 99/105 |
| CompanionArtifactPublisher | 138/164 | 150/164 | 65/92 | 81/92 |
| SyntheticSourceRelocation | 0/182 | 181/182 | 0/196 | 165/196 |

The repair fix adds two executable lines and two branches. The other production
sources and the class population are unchanged. These are selected-source
results from focused runs, not a new repository-wide coverage percentage.
The complete CI population must be measured before updating that claim.

The repair suite executes 1,020 checks across both byte orders. The publication
suite exercises 111 scenarios, including every observed cancellation checkpoint,
invalid stages, concurrent changes, restored symlink outputs, and cleanup errors
both before and after installation. The relocation suite exercises 1,188
scenarios across 32/64-bit address widths and both byte orders, using hand-encoded
CU/abbreviation/string/line tables and exact unchanged-byte oracles.

`mutation-check.py` compiles nine explicit faults into disposable directories,
runs unchanged-source baselines first, and requires a behavioral assertion to
detect every fault. Compiler errors, class-loading failures, timeouts and
surviving mutants fail the harness. It tests bad offset narrowing, reference
adjustment, byte order, directory references, duplicate files, cancellation,
rollback and cleanup diagnostics. This is not a repository-wide mutation score.
All nine were detected locally in 4.45 seconds, with at most 32,642 bytes of
temporary source/classes at once; each temporary directory is removed.

Focused Gradle commands (through `support/storage-guard.py run` locally):

```sh
./gradlew --no-daemon -PtestCoverage=true \
    dwarfInfoRepairSmoke dwarfInfoRepairBoundarySmoke \
    companionArtifactPublisherSmoke companionPublicationFailureSmoke \
    sourceRelocationBoundarySmoke testCoverageReport
python3 -B src/test/coverage/mutation-check.py \
    --classes build/classes/java/main --tests build/classes/java/test \
    --java-home "$JAVA_HOME" --output build/test-results/high-risk-mutations
```

Use a fresh coverage build directory or a clean owned build when comparing full
runs. Do not combine execution data from different production class versions.

## Native and installed headless collection

**CONFIRMED locally; hosted CI pending.** The existing `minimalDwarfSidecarSmoke`
can be instrumented through `-PtestCoverage=true` in its isolated native JVM.
For a source-built x86-64 non-PIE fixture, it measured 607/1,196 lines and
221/728 branches in `MinimalDwarfSidecarExporter.java`. LLVM accepted the
artifact and GDB read the expected register parameter value of 19. This is Java
execution around the native API, not native C coverage. No JNA signature changed.

`headless-coverage.py` adds one bounded sample to the x86-64 target job. It
compiles the existing `minimal.c`, removes compiler debug information, and
invokes the installed production exporter twice. It checks unchanged input,
identical sidecar/source hashes, GNU/LLVM/strict libdwarf validation, and GDB
breakpoint, source, signature and stepping behavior. Headless exit status alone
does not prove script success; the exporter completion message is required too.

The JaCoCo agent is passed only to Ghidra's headless JVM through `launch.sh`.
It is not injected into LaunchSupport, Gradle, native code or debugger processes.
Each run has a fresh execution file and unique expected session identifier.
The installed JAR supplies **all** report classes, including unloaded classes;
a newly compiled local JAR is not substituted as its denominator. The receipt
binds the completed runs to JAR and execution hashes. The verifier rejects
unknown/mismatched class IDs, unexpected sessions, empty production execution
and a missing exporter. Five real execution-data fault controls and seven
receipt tests prove these checks reject invalid evidence.

The local headless sample measured 8,014/29,782 production Java lines across
the unchanged 901-class population. It took 9.0 seconds for both exports and
artifact/debugger checks, plus about six seconds for agent preparation, class
verification and report generation. Retained logs, execution data, XML and
HTML totaled about 12 MiB. These numbers describe a tiny sample, not overall
headless coverage, and do not replace the complete architecture/host matrix.

The artifact `headless-java-coverage-sample` contains this separate report and
its evidence. The existing `test-code-coverage` artifact and public badge still
measure only the selected extension-build JavaExec tasks. Their improvement
therefore reflects new tests, not addition of headless execution to the metric.
No totals from different reports should be added together.

Reproduce on Linux x86-64 with the current release installed into Ghidra 12.0.3
and the matching pinned native libraries/validator (use the storage guard locally):

```sh
./gradlew --no-daemon -PtestCoverage=true prepareHeadlessCoverage
python3 -B src/test/coverage/headless-coverage.py \
    --ghidra "$GHIDRA_INSTALL_DIR" \
    --consumer "$LIBDWARF" --producer "$LIBDWARFP" \
    --agent "$PWD/build/test-coverage-tools/jacocoagent.jar" \
    --output "$PWD/build/headless-coverage" --dwarfdump "$DWARFDUMP"
./gradlew --no-daemon -PtestCoverage=true headlessCoverageReport
python3 -B -m unittest discover -s src/test/coverage -p 'test_*.py' -v
```

Use a fresh output directory. The coverage-only launcher rejects whitespace,
comma or equals characters in agent/output/temp paths because of the upstream
VM argument splitting and agent option grammar; ordinary export has no new
path restriction. It never edits the Ghidra installation. Temporary projects
are removed on success/failure; failed runs retain an incomplete receipt and
diagnostics and cannot produce an accepted report. Each command owns a process
group, which is stopped before returning on failure, timeout or SIGTERM. Three
process controls prove descendants cannot keep writing after the caller returns;
the timeout and nonzero-exit controls reproduced the previous orphaning defect.
The seven receipt tests plus these three process tests take about four seconds.

Remaining gaps: native C/libdwarf execution, Windows Java execution, other target
architectures, GUI execution, and the broad independent integration suites.
They retain their existing required behavior tests. Native producer lifecycle,
ABI, failure and cancellation tests remain isolated from interactive Ghidra.

The existing Windows host job also runs the native-free repair and relocation
boundary tests. The new filesystem fault suite is Linux-only; existing Windows
publication and attachment behavior tests remain required.

An actual-main versus local full-suite comparison exposed a timing-dependent
coverage difference in `ArtifactPairPublisher.publishNew`: the original fresh
publication test used wall-clock timestamps, so the timestamp adjustment branch
could be taken or skipped depending on filesystem clock resolution. The existing
timestamp oracle now exercises fresh publication too, with explicit older,
equal and newer staged times. No production publication behavior changed.

## Full local JavaExec comparison

All 205 baseline tasks plus the three new tasks passed. The first complete run
(including fresh compilation and report generation) took 247.6 seconds; after
the timestamp test improvement, that task and the report were rerun successfully.
The final local measurement is **23,118/29,782 lines (77.6%)**, up from
22,865/29,780 (76.8%), and **17,246/25,872 branches (66.7%)**, up from
17,018/25,870 (65.8%). All 901 class names and 255 source names match the baseline.
Only the repair source's denominator changes (+2 lines / +2 branches).

Full-suite selected results are repair 171/171 lines and 99/105 branches,
publication 151/164 and 82/92, relocation 181/182 and 165/196. The publication
figure is slightly higher than the focused subset because existing tests also
exercise it. Every preselected goal is met. These are local results; protected
hosted CI and actual-main publication must still pass before #203 is complete.
