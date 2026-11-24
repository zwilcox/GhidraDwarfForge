# Architecture integration groups

`integration-groups.json` assigns the architecture suite to independent jobs.
Acceptance requires successful hosted execution, complete group admission and
reproduced coverage. A generated matrix or passing local admission fixture alone
does not establish an optimized hosted run. The first successful grouped PR
measurement is recorded below; subsequent revisions and main publication still
require their own validation.

The baseline is main `9326d3acfcc07d880accdefea6d118aa0c4bb2dc`, successful
run [44376883886](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44376883886).
The inventory retains all 207 workflow steps, their exact command/action hashes,
and explicit architecture applicability. Counts below count assigned workflow
steps, including their associated evidence retention actions, **not individual
behavioral test cases**. Nested cases remain in their original scripts.

| Target | Assigned steps | Groups |
| --- | ---: | --- |
| x86-64 | 149 | primary, unwind, types, registers, stack, source, i386-mmio, performance |
| AArch64 | 98 | primary, unwind, types, registers, stack, source |
| ARM32 | 51 | primary, modes, calls, aggregate |
| MIPS32BE | 55 | primary, abi32, abi64 |
| MIPS32LE | 55 | primary, abi32, abi64 |

The smaller targets use fewer groups because their test distribution differs.
ARM's mixed ARM/Thumb cases and aggregate-call cases each take tens of minutes;
they run separately from scalar-call and primary-image cases. Both MIPS targets
separate O32 from N32/N64 cases while retaining every wide producer and runtime
profile. x86's 1,000/10,000-function performance experiment keeps its warmups and
alternating AB/BA pairs sequential in one job.

`integration-plan.py` checks the preserved baseline before generating a matrix.
It rejects omitted/changed commands, lost architecture assignments and split
dependency components. Primary fixture creation, saved projects, source and ELF
outputs, validator indexes and report handoffs stay together. Inheritance,
call-site, formatter and unwind consumers remain with their producers. Nested
lexical/static/object/register-copy controls are never split out of their parent
command, including their cancellation and deterministic rerun checks. Saved
program determinism, existing compiler DWARF replacement and compression also
consume primary fixtures and stay in that group.

Direct `build/fixtures` consumers also stay with the primary fixture producer,
including paths prefixed by `$PWD` or containing `$TARGET`. This includes the
line-sequence controls, instruction-context pipeline, indirect-pointer producer,
ARM scalar bit-piece producer and function-entry producer. The workflow checker
rejects splitting these paths even if an explicit dependency entry is missing.
Called scripts still require dependency review; this path check does not attempt
to infer shell dataflow or transitive dependencies.

Every group uses its own checkout, Ghidra installation, mutable
projects and outputs. Harness classes and the production JAR are built explicitly
in group setup: the old sequential steps implicitly supplied both for later
commands. The CFI encoder/composition harness requires the JAR even when its
standalone Gradle smoke test needs only classes. Run those
original native smoke cases once per architecture, preserving their iteration
counts and BE8, firmware, i386 and wide MIPS profiles. Tool reuse must retain
hashes, dependency closure and runtime checks; sharing source/build trees or
mutable Ghidra projects is not part of this design.

The admission function checks API-shaped observations for the exact expected
group set, commit, run and attempt. Every selected step must complete
successfully in inventory order. Missing, failed, cancelled, skipped, duplicate
or stale groups cannot satisfy it. Step names include their stable inventory
IDs so repeated action names cannot disguise an omitted test. PR merge commits
remain distinct from the head commit reported by the jobs API. The protected
gate requires the group matrix, API admission and whole-target coverage jobs.
Local admission tests use synthetic observations; real hosted validation remains
required. Admission requires one complete attempt: rerun all jobs after an
incomplete attempt rather than silently mixing successful jobs from old attempts.

Collections record the commit, run, attempt, target and group when created.
Each group seals only collection receipts, oracle records and raw probes; no
projects, production JARs or toolchains are duplicated into coverage artifacts.
An empty measured group is recorded explicitly and still requires a successful
execution job. Aggregation requires every group and rejects stale identities,
missing groups, changed files and duplicate sessions. It retains group evidence
alongside each whole-target report, where the existing complete suite/profile
and behavioral oracle checks still apply. The combined report, separate
JavaExec/native-Java/headless/Windows views, denominator and thresholds remain.

Local real-JVM controls exercise different branches in separate groups. Each
individual report covers one branch; the merged report covers both and retains
the unloaded fixture class. This proves the grouping/report round trip for a
tiny Java fixture, not production architecture behavior. The existing malformed
probe/class/session controls also still run. All platform and debugger behavior
must pass in the actual grouped pipeline before integration.

## Timing baseline

`serial-timing-baseline.json` records three successful attempts with source API
metadata hashes. `workflow-timing.py` rejects failed, mixed or truncated attempts
and distinguishes workflow elapsed time from summed job wall time. Only the
expected PR-only publication skip is accepted; skipped validation is rejected.

| Run | Attempt | Workflow minutes | Summed job wall minutes |
| --- | ---: | ---: | ---: |
| 44258407287 | 1 | 285.3 | 788.1 |
| 44323595785 | 2 | 259.7 | 727.3 |
| 44376883886 | 1 | 244.3 | 768.5 |

Job wall time is not GitHub billed time. Workflow time spans the first job start
to the final job completion within that attempt; PR212's failed first attempt
is not included in its successful-attempt baseline. Setup costs are recorded
separately for each target; downloads nested inside test commands remain in
test time. Run 44376883886 spent 31m55s installing the MIPSBE toolchain, including
31m3s fetching 132 MB, while MIPSLE fetched 133 MB in 3s. This establishes download
variability, not its underlying network cause. Compare complete successful
grouped runs, including duplicated setup and queue time, before claiming a
speedup. The extension build and mutation checks remain prerequisites and may
limit the improvement after architecture splitting.

## First successful grouped PR measurement

**CONFIRMED for this recorded run:** PR run
[44461447108](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44461447108),
attempt 1, passed all 24 architecture groups, host/GUI checks, group admission,
coverage reports and `required-validation`. It executed merge `ff87fafb` for head
`6cc8df52`. This is historical evidence for that revision, not a substitute for
the checks required on a later revision or on main. Exact identities, artifact
hashes and timing input hashes are in `grouped-timing-first-pr.json`.

The closest baseline is successful main run `44376883886`, with identical
production bytecode. Independent reconstruction reproduced all five coverage
views from 1,270 sessions across nine origins. Every source's line and counter
data matches the baseline in each view; all 255 production sources and 901
classes remain in the denominator. Overall coverage remains 97.3% lines / 89.2% branches,
and both critical groups retain their 95% line / 90% branch thresholds. JaCoCo
XML branch counts do not identify individual branch alternatives; unchanged
counts supplement the complete test/profile admission rather than replacing it.

| Complete workflow metric | Serial baseline | Grouped PR |
| --- | ---: | ---: |
| First job start to final job completion | 244.3 min | 141.5 min |
| Summed job wall time | 768.5 min | 952.3 min |

This run reduces the complete workflow's elapsed time by 102.9 minutes (42.1%),
while increasing summed runner occupancy by 183.8 minutes (23.9%). Runner
occupancy is not GitHub billed time. The grouped attempt took 142.9 minutes from
attempt start, including 85 seconds before the first job started. The largest
observed job queue was 23.0 minutes. Neither queue time nor parallel job time
should be added again to the elapsed workflow measurement.

| Target | Serial elapsed | Grouped tests span | Grouped through report | Serial / grouped setup, summed |
| --- | ---: | ---: | ---: | ---: |
| x86-64 | 184.7 min | 42.0 min | 81.0 min | 20.9 / 30.9 min |
| AArch64 | 143.7 min | 47.9 min | 80.9 min | 20.6 / 67.9 min |
| ARM32 | 133.5 min | 65.6 min | 80.8 min | 28.6 / 45.2 min |
| MIPS32BE | 96.3 min | 77.5 min | 77.8 min | 38.5 / 81.2 min |
| MIPS32LE | 74.4 min | 46.6 min | 81.0 min | 7.8 / 33.6 min |

Each target report waits for the complete group matrix. That wait is included
in the through-report column: MIPS32LE's own tests finish sooner, but its report
finishes 6.6 minutes later than the serial target baseline. Repeated setup also
increases runner occupancy. These are measured costs of this first split;
the result does not claim every target report is faster or that setup is optimal.
Setup includes named toolchain, debugger, Java, Ghidra and artifact preparation;
downloads nested within test commands remain counted as test time.

Against the other two successful serial baselines, workflow elapsed time is
45.5% and 50.4% lower. Those revisions differ, and hosted-runner variability
limits inference from one grouped run. Actual-main confirmation and publication
are tracked in [PR #213](https://github.com/zwilcox/GhidraDwarfForge/pull/213)
and [issue #211](https://github.com/zwilcox/GhidraDwarfForge/issues/211).

## Manual comparisons

The following commands use artifacts from a previous run. Supply the indicated case or isolated Ghidra installation.

| Comparison | Entry point | Input and result |
| --- | --- | --- |
| Variable shadowing across extension versions | `python3 src/test/integration/lexical-shadow-previous.py CASE PREVIOUS_GHIDRA` | Reopen the completed lexical-shadow project with a pre-lexical package and compare GDB's inner-scope lookup with the current observations. |
| Debugger performance with alternative section layouts | `python3 src/test/performance/consumer-candidates.py CASE --workload sqlite` | Use a completed SQLite workload or choose `--workload uboot` for a U-Boot case. Measure compression and index variants on private copies. |
| Re-export a curated project after attaching a debug link | `bash src/test/scenarios/debuglink/reexport.sh GHIDRA STRIPPED_ELF` | Attach to a private copy of a source-built x86-64 executable, retry export using the saved original and compare both generated files. |
