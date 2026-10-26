# Stable register locations require contained control flow

**CONFIRMED locally; hosted acceptance pending (2026-10-25):** a fully decoded
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
Java 21 model tests are separate evidence, and the hosted runtime remains
pending. Both Linux and Windows CI invoke the new model smoke test; both
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
