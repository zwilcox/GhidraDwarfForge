# Stable register locations require contained control flow

## Complete-body control after value-flow composition

**CONFIRMED locally; fresh hosted acceptance pending (PR100):** the old fixture
expected no location even when every control-flow instruction was present.
That expectation predates the shared value-flow engine. The complete body now
proves its incoming register copy and retains the exact parameter until the
return-value arithmetic overwrites the final carrier. The excluded-clobber body
still has no parameter location. The stable-register-only API independently
continues to reject both cases; the production exporter composes the stronger
proof only for the complete CFG.

Both target jobs in run `41230414679` failed the stale omission-reason assertion,
before GDB. No production change is required. The fixture now labels its completed
copy, captures actual instruction bytes and verifies the raw DWARF 5 intervals:
incoming register to copy completion, backup to arithmetic completion, then
unavailable. The excluded case retains its name/type with no `DW_AT_location`.
GDB steps every executed instruction for both signed inputs, checks physical
carriers and bytes, and rejects scope/location leakage into the excluded block.

Six x86-64/AArch64 exec/PIE/rebased-PIE cases pass 24 real exports and 270 GDB
instruction observations on actual Java 21. There are 78 available complete-body
values; the final overwrite tails and every excluded-body value stay unavailable.
GNU, LLVM and pinned strict checks pass, as do original/module/source preservation,
read-only saved-program checks and deterministic output pairs. PIE and rebased-PIE
raw intervals match. Four existing stack-spill/direct-leaf-call exec regressions
also pass. Tested hosted production JAR SHA-256:
`444d2479c2792c23e057f19768749dccd35bf022058161e1f9a8094c40dee7e2`.
Receipt `build/pr100-outside-flow-fix/acceptance.json` SHA-256:
`2d5981475cbdb6859fab80e754ace616c7a4de3f63b0cca06b276a5fca8e0425`.

The enhanced oracle exposed another test assumption: GCC describes one inline
assembly statement, not each internal instruction. At 24 interior observations
its DWARF still displays the clobbered incoming register. Those observations
are recorded, not treated as correct parameter values. Compiler GDB must agree
at the entry, completed-copy and completed-statement boundaries; interior
correctness is independently checked against the known invocation value and
physical preserved carrier. Forge must display the exact value at every proven
instruction. The failed initial local attempts remain in the evidence directory.

The older accepted gate and counts below describe the original guard, before
this additional complete-CFG value proof. They are not acceptance for PR100.
P1.11a/P3.3 and the exact-head hosted gate remain open.

**CONFIRMED integration (2026-10-25):** PR64 head
`23d9c57d5e8fc339650428d7252d9b5381adb49e` passes all twelve jobs in
`40263198239`, independent exact-package/twenty-one actual Java 21 suites,
raw five-target review, 43 native Windows model tasks and both GUI hosts.
The six hosted control-flow roles pass 24 exports and 72 GDB observations.
Normal merge `db66cd5f1832238fa32392d568d0369d48efb9a0` preserves the tested
tree. Hosted receipt SHA-256:
`4d6ab95d2a4fa6ced53f5bae017ff50343c4beeffdbd0f558efa34b517cd7106`.
The distinct main-push gate remains pending. Earlier local-only status for
this correction is historical; broader lifetime recovery remains partial.

**CONFIRMED defect and correction:** a fully decoded
curated function body can omit a real branch destination. The excluded block
can change an incoming register and return to the body. Inspecting only the
body's instructions then incorrectly declares that register stable.

The retained x86-64 and AArch64 reproduction uses compiler-generated backup
storage for `value=19` and `value=-19`. Inline assembly clears its incoming
register in a block excluded from the Ghidra function. At the next statement,
the compiler reference still prints the original value and the function returns
`value + 7`; the preceding Forge package prints zero. GNU/LLVM/libdwarf checks
accept those structurally valid but semantically incorrect locations.

## Correction and limits

After complete listing coverage and the existing call, write and opaque-effect
checks, `stableRegister` requires contained control flow:

- Default instruction targets and additional reference targets must be decoded
  instruction starts inside the body. Removing a database reference cannot
  erase the instruction prototype's target.
- Ordinary fallthrough must stay inside the decoded body. Computed jumps,
  flow/fallthrough overrides and uncertain terminal transfers are rejected.
- A delayed transfer must own all its contiguous decoded delay slots. Slots
  cannot be independently entered, orphaned, multiply owned or themselves
  contain another transfer. Their lexical fallthrough is not a separate path
  after their owner's return or jump. This preserves ordinary MIPS returns.
- Alternate entries into body interiors or instruction offcuts are rejected.
  References to the function entry retain the ordinary incoming-value contract,
  including Ghidra's pointer-data `INDIRECTION` references.

A direct jump over an unused gap remains valid. Falling through an excluded gap
is unproven even when its bytes happen to be NOPs. The coverage smoke test now
separates this control-flow failure from missing decoding inside the body.

An unproven flow produces `UNKNOWN_LIFETIME`; parameter/local names and types
remain, with no fabricated location. The change applies to scalar and composite
stable registers and preserves the preceding diagnostic precedence. It does not
recover values from excluded blocks, solve arbitrary computed control flow,
add register mappings or change native bindings. Broader lifetime recovery
remains incomplete.

## Evidence

`OutsideBodyFlowSmoke` passes 85 checks with real decoded x86-64, AArch64 and
both MIPS32 byte orders: excluded clobbers, excluded fallthrough, valid jumps
over gaps, unknown jumps, delay-slot ownership, alternate entries, offcuts,
overrides, deleted references and unchanged bytes. Ordinary entry calls,
jumps and pointer references remain accepted. `RegisterBodyCoverageSmoke`
passes 446 checks over five language models. Twenty-one isolated suites pass
on actual Java 21 with the candidate package first on the class path and
verified class-loading origins.

The integration harness runs six x86-64/AArch64 non-PIE, PIE and rebased-PIE
roles. Each preserves a complete-body control and an excluded-body case,
reopens each saved program read-only, and exports it twice. The 24 corrected
exports are deterministic; six additional exports through the preceding
package reproduce the incorrect value. Compiler, control, corrected and
preceding-package GDB runs supply 96 entry/after-statement observations and
normal exits. The preceding package comparison is local; hosted CI requires
72 observations across compiler/control/corrected variants.

Independent raw review verifies ELF class/machine/type/flags/build ID, absence
of program headers, exact function ranges excluding the removed block, the
retained signed four-byte parameter type and absence of `DW_AT_location`.
GNU and LLVM checks pass; strict libdwarf diagnostics have zero unexplained
errors, with only separately corroborated inherited frame diagnostics. Input
hashes and saved-program hashes are checked; only Ghidra's two documented
backup-index files may change during read-only reopen. GDB resolves the name,
lists synthetic source, reports the parameter type and returns the expected
result under native x86-64 or QEMU AArch64 execution.

Candidate JAR SHA-256:
`7721cfd99fb86e791aebfd9bbde6f2a11ab19e749af62bdf8447093fe7f8bca7`.
Raw six-role acceptance receipt SHA-256:
`592703456780b5c13b66024d491381498c5b48d1abdc9028589e97c229ee7ef9`.
Evidence lives in `build/outside-flow-review/` and
`build/test-results/outside-body-flow/` in the `outside-body-flow` worktree.
Local headless runs used Java 25 with Java 21-compatible bytecode; actual
Java 21 model tests are separate evidence; exact hosted acceptance is recorded
above. Both Linux and Windows CI invoke the new model smoke test; both
mandatory runtime target lanes invoke the six-role exporter/GDB harness.

## Retained failed attempts

The baseline model test fails on the expected incorrect `RegisterStorage`,
matching the earlier real compiler/GDB reproduction. The first expanded model
run exposed a synthetic instruction double lacking `getDefaultFlows`; the
double now explicitly reports no branch targets.

The first candidate passed the six new cases but failed the existing ordinary
x86-64 parameter regression: Ghidra attached an `INDIRECTION` reference from
pointer data to the function entry, which the initial guard treated as an
alternate entry. Inspection of Ghidra 12.0.3's `RefType` and `Instruction`
contracts established the distinction. The corrected entry contract has
explicit positive controls, a fresh package, twenty-one Java 21 reruns and
fresh six-role exports. The rejected package, logs and diagnostics remain
separate evidence. No failed compatibility run is counted as a pass.

The final local compatibility run passes ten ordinary-parameter exports on all
five baseline targets, thirty scalar floating-register exports, twelve MIPS
FP32 pair exports, six ARM terminal-composite exports and eight i386 exports.
Together with the new matrix this is 90 corrected exports, plus six preceding-
package reproductions. All five fixture reproducibility checks, seven
architecture-guard controls, actionlint and the extension build pass. Local
acceptance receipt SHA-256:
`c6b71677e5e7c2c24b6ed600888d5555725a9e392c23fed902b5d6461ea9b733`.
Full hosted validation and independent package/host review remain pending.
