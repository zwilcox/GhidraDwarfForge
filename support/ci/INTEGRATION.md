# Architecture integration groups

**PRESENT, UNVERIFIED on hosted CI:** `integration-groups.json` assigns the
architecture suite to independent jobs. The workflow, group admission and
coverage aggregation are implemented and validated locally. A generated matrix
or passing admission fixture is not evidence of an optimized hosted run.

The baseline is main `9326d3acfcc07d880accdefea6d118aa0c4bb2dc`, successful
run [44376883886](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/44376883886).
The inventory retains all 207 workflow steps, their exact command/action hashes,
and explicit architecture applicability. Counts below count assigned workflow
steps, including their associated evidence retention actions, **not individual
behavioral test cases**. Nested cases remain in their original scripts.

| Target | Assigned steps | Proposed groups |
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

Every group uses its own checkout, Ghidra installation, mutable
projects and outputs. Harness classes compile explicitly in group setup: the
old producer smoke steps implicitly compiled them for later commands. Run those
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
