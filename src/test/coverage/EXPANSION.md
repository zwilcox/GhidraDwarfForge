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
`3e65d14b047937047cfe1f5b75c613656951c2f4` in 260.5 seconds. The combined local report
contains 848 sessions with the full unchanged denominator:

| Scope | Line coverage | Branch coverage | Accepted target |
| --- | ---: | ---: | ---: |
| All production Java | 94.4% | 78.4% | 85% / 80% |
| Binary and location correctness | 94.5% | 77.9% | 95% / 90% |
| File transactions and validation | 93.9% | 78.5% | 95% / 90% |
| Remaining production | 95.1% | 81.5% | Included in overall |

Production JAR SHA-256 remains
`98ea0bbb8a292152d76cd2be9972ad5c5e270421ab65043fc1ced2afaa81caf9`. No production Java changed in this checkpoint.
Exact counters, per-line missed decisions, origins, execution hashes and separate
layer reports are retained under
`.forge-work/scratch/coverage-expansion/combined-mips-allocation-hosted-baseline/`.
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

All 69 selected mutation checks pass with unchanged-source baselines. Four new
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
