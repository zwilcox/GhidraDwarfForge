# Synthetic unwind acceptance audit (#112)

**CONFIRMED implementation and final-documentation integration.**
This audit covers the six original issue requirements and the additional matrix
promised in `SYNTHETIC-CFI-EVIDENCE.md`. PR #183 integrated this final audit as
`9c3029f97a418eb3c63742213d68392608ff15a2` after required run `42291314960`
passed; issue #112 is closed. Its LLDB follow-up also passed, as recorded in
[the debugger consumer contract](DEBUGGER-CONSUMERS.md). The implementation is
opt-in and limited to the ordinary integer x86-64 SysV LP64 and AArch64 AAPCS64
LP64 profiles in [ADR-0002](ADR-0002-DEBUG-FRAME.md).

The audited production implementation is unchanged between `23fbfef`, the
Windows producer head `1872477`, and the split-body checkpoint `da74f01`.
The audit adds only six negative decoder cases to the profile test. Historical
component receipts identify their own versions; they are not whole-tree passes
for the current branch. The final current-head gate, artifact review and
protected implementation integration have passed as recorded below. Historical checkpoints retain their
original scope and do not substitute for that gate.

## Requirement-to-evidence map

| Original requirement | Implementation and executable evidence | Assessment |
| --- | --- | --- |
| New evidence model and ADR before synthesis; preserve trusted CFI and original executable | [Evidence model](SYNTHETIC-CFI-EVIDENCE.md), revised ADR, `OriginalFrameSources`, `OriginalUnwindCoverage`, `OriginalFrameRanges`, `InheritedFrameBytes` and `MatchedElfSidecarWriter`. `unwind-export.py` exercises plain/gABI/GNU original `.debug_frame`, original runtime `.eh_frame`/header, disjoint new records, compression, rebasing and original hashes. `production-unwind-saved.py` repeats these through saved projects and the installed normal wrapper. [Original coexistence](NATIVE-FRAME-COEXISTENCE.md), [runtime coexistence](RUNTIME-FRAME-COEXISTENCE.md), [typed sections](TYPED-UNWIND-SECTIONS.md). | **CONFIRMED locally** for the documented source/layout bounds; confirmed by the final combined hosted gate below. |
| Instruction-varying CFA, saved registers and CFG joins through isolated ABI descriptions; reject incomplete/conflicting evidence | `targets/UnwindAbiProfile`, `GhidraUnwindInstructions`, `UnwindFlow`, `GhidraUnwindCalls`, `UnwindCalls`, `UnwindFrameRows`, `GhidraUnwindRecovery` and `DwarfDebugFrame`. The profile, native instruction, flow, call, projection and encoder smoke suites exercise actual Sleigh effects, caller identities, exact saves/restores, fixed-point joins, invalidation, refusal and cancellation. `unwind-frame-recovery.py` and `unwind-export.py` exercise the recovered rules through real ELF/GDB. | **CONFIRMED locally** within the explicit profile and memory policies; tests of an isolated encoder are not evidence of recovery by themselves. |
| Nested calls, recursion, omitted frame pointers, split/shrink-wrapped saves and invalid/partial instructions for each profile | `compiler-unwind-export.py` uses independent unchanged C compiler references; `--frame-pointer keep` and `frame-pointer-gdb.py` additionally observe real recursive RBP/X29 values. `unwind-frame-recovery.py --fixture-family shrinkwrap` covers alternate save paths. `discontiguous-unwind.py` curates two real body ranges and checks every ordinary caller at gap crossings; `discontiguous-unwind-controls.py` removes part of a decoded branch and requires root refusal and runtime fallback. Both targets have local evidence. | **CONFIRMED locally**; [frame-pointer](FRAME-POINTER-UNWIND.md) and [split-body](DISCONTIGUOUS-UNWIND.md) checkpoints also pass the final combined hosted gate below. |
| Independent compiler references plus GDB backtraces, caller values, finish and instruction-boundary stepping on no-CFI native/QEMU targets | `synthetic-cfi-reference.py`, `compiler-cfi-boundaries-gdb.py`, `synthetic-cfi-reference-gdb.py`, `cfi-encoder-gdb.py` and the production wrapper/companion harnesses. Separate no-CFI inputs retain the reference's allocated bytes; comparisons include caller PCs/SP offsets/register witnesses, nested/recursive returns and actual DWARF unwinder selection. Plain/compressed, exec/PIE/shared and database-rebased exports are covered across the linked checkpoints. | **CONFIRMED locally**, including Linux GDB consumption of native Windows-produced artifacts described below. Actual native Windows GDB execution of Linux ELF is not claimed. |
| Distinguish ordinary and interrupt/signal/exception frames; no latter claim without runtime validation | Positive instruction/profile selection, process-entry refusal and explicit unsupported-profile diagnostics. The audit's `unwindAbiProfileSmoke` decodes and rejects x86-64 SYSCALL/INT/IRETQ and AArch64 SVC/HVC/ERET through both the instruction guard and complete guarded capture. Existing controls reject hidden/visible PAC, SIMD and wrong mode. | **CONFIRMED refusal controls**; asynchronous-frame recovery is deliberately unsupported. ABI metadata and a normal-looking instruction sequence do not prove arbitrary code obeys an ordinary ABI. No function-name heuristic or claim to unwind across a signal trampoline is made. |
| GNU/LLVM/pinned strict validators, determinism, genuine failures/cancellation, unchanged originals and published support/omission policy | All generated matrix artifacts use `readelf`, `llvm-dwarfdump` and `check-dwarfdump.py` with the pinned consumer. `ProductionUnwindControls.java` injects cancellation and failure during recovery, frame serialization, evidence and loader generation; it requires byte-identical preceding four-file generations, unchanged program state and no staging leaks. Normal wrapper/saved-project tests repeat exports and hash input/project/outputs. `UnwindEvidenceJson` records `NOT_RUN`, original bytes/rules/omissions and explicit external conditions. [Production contract](PRODUCTION-UNWIND.md), ADR and profile docs publish the limits. | **CONFIRMED locally** and for the scoped native Windows producer/consumer checkpoint below. Final combined hosted validation and scoped ADR acceptance are recorded below. |

## Additional promised cases and limits

- Existing unwind metadata remains authoritative. Unknown or overlapping
  coverage is a refusal, not permission to overwrite it. Runtime metadata is
  retained; this feature does not rewrite the executable's `.eh_frame` or enable
  runtime exception handling.
- Compiler frame-pointer use and omission, prologue/body/epilogue boundaries,
  nested/recursive calls, split/shrink-wrapped saves, discontiguous bodies,
  exec/PIE/shared images and database rebasing all have the local evidence linked
  above. The fixture combinations are explicit; no complete Cartesian product
  of all compilers, ABIs and control-flow shapes is claimed.
- `cfi-encoder.py` corrupts an FDE's CIE pointer and requires independent decoder,
  LLVM frame-reader and pinned strict rejection. This is a **structural corrupt-CFI
  control**, not a malformed-CFI GDB runtime claim. Missing-CFI and disabled-DWARF
  runtime controls separately establish which unwinder is used. AArch64 fallback
  may recover a correct chain, so backtrace equality alone is insufficient.
- Strict analysis does not prove that arbitrary global addresses cannot alias
  stack storage. The unchanged compiler global-write fixture therefore needs
  explicitly conditioned recovery; strict mode must refuse it. Fixed relocated
  pointer values are another explicit condition. Reports retain both as
  `EXTERNAL_CONDITION_NOT_PROVED`; no passing fixture establishes them for other
  executables or runtime environments.
- Normal Bash/PowerShell wrappers, the dedicated Script Manager chooser, saved
  analyst projects and the GDB companion share the production implementation.
  Automatic build-ID discovery is #109 and LLDB behavior is #110; neither is
  established by this audit. Attachment preparation currently rejects synthesis
  options rather than changing its existing transaction contract.

## Native Windows checkpoint and independent consumption

Run [42235627038](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42235627038),
producer head `187247735ec4b132e6a4f37ae399ce62dee98a7c`, completed its native
Windows job `127959283321`. Both new unwind steps passed. Downloaded artifact
`13515745229` (`windows-host-validation`) has SHA-256
`6c41ddafcd72e1c23272f7e5b365cc0039d13cc446e4587913e33dbe58ab4b57`.

The PowerShell result records five exports, one invalid-range preservation
control and packaged native libraries. The GUI result records seven choices,
four exports and three cancellations. Native GNU/LLVM results, actual chooser
screenshots and cancellation records are retained. The reported installed JAR
hash is `3346f363e47a97807a356cc38e6bd8d3f8c89ac3e67a57b5cb3c832cf61d7e6e`,
matching the locally tested production package. The producer scripts and
production sources have no changes between this head and `da74f01`.

Fresh local Linux runs of `powershell-unwind-gdb.py --producer-host Windows`
and `windows-unwind-gdb.py` verify transport hashes and preserve incoming and
copied artifacts. All eight sidecars pass GNU/LLVM/pinned strict validation.
Fourteen GDB sessions pass: six PowerShell and eight GUI sessions, including
independent reference traces, 90 executed ordinary boundaries per boundary
trace, caller values, selected DWARF unwinders and recursive returns. These use
direct symbol loading after transport; cross-host relocation of the companion's
recorded absolute paths is not claimed. This historical local consumer evidence
does not replace current-head evidence; the final gate and new Windows artifact
review are recorded below.

## Audit provenance and remaining gates

The [audit receipt](evidence/unwind-acceptance-audit.json) binds the new test,
native Windows artifacts, consumer logs, source snapshots and archive inventory.
All 21 selected historical evidence archives were rehashed against their recorded
size/SHA-256 and every regular member was read. That establishes retention and
integrity, not new semantic acceptance of every historical source version.
The expanded ABI profile suite passes **775 checks**, including all six newly
decoded special transitions; these negative tests do not alter emitted artifacts.

## Final implementation acceptance (2026-11-06)

Head `06348e1ab923e37ab86ed5f08f86003e40af6d48` passes every production job in
[run 42242341105](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42242341105),
including `required-validation`. PR #176 merged through normal protection as
`6b582b4007311f334b954d361458b0775c35904e`. Both commits have tree
`a7ea61c973305c5477205b0ede773c7cf3a81505`. No bypass or history rewrite was used.

Independent review downloaded the exact-head package, native and target
artifacts, checked their recorded hashes and revalidated retained strict reports
against their raw checker output. Counts below are reports, not unique binaries:

| Hosted target | Positive strict reports | Intentional rejection controls | Reviewed unwind result records |
| --- | ---: | ---: | ---: |
| x86-64 | 883 | 89 | 41 |
| AArch64 | 678 | 9 | 39 |
| ARM32 | 595 | 1 | 0 |
| MIPS32 big-endian | 339 | 1 | 0 |
| MIPS32 little-endian | 339 | 1 | 0 |

The three latter rows are regression coverage, not new synthesis profiles.
Checker self-tests and expected invalid-input reports are kept separate from
positive reports. Inherited-CFI diagnostics are corroborated by the existing
strict-check policy and raw logs, not treated as blanket warning exemptions.
Hosted runtime results are reviewed as hosted evidence; this is not a claim
that every hosted runtime was rerun locally.

The current package's 464 manifest entries, 738 classes and 210 production
sources match the accepted head. Native exports/dependencies and packaged native
hashes match the corresponding platform builds. Current native Windows artifact
`13517844236` also passes review: eight generated sidecars pass independent GNU,
LLVM and pinned strict checks, with fourteen fresh local compiler-reference GDB
sessions. The hosted Windows producer and transported consumer both pass.

The [final acceptance receipt](evidence/unwind-final-acceptance.json) records
job IDs, archive hashes, package/native identity, raw review counts and component
ancestry. Earlier review status strings inside that receipt preserve their
observation time; the top-level final gate supersedes their pending-job notes.
All PR #167–#174 head commits are ancestors of the merged implementation, so their
component histories are preserved. The ADR accepts the bounded opt-in feature;
it does not authorize a release.

Remaining administrative acceptance: integrate this final documentation update
through normal protection, then close #112. Continue the existing goal with
#110 LLDB validation and #109 build-ID installation. Neither task is completed
or replaced by this unwind evidence.
