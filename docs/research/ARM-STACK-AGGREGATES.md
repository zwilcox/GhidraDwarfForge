# ARM exhausted-register and partial-aggregate investigation

**CONFIRMED local progress; full P2.3b/#70 acceptance remains incomplete.**
This work retains the complete P2.3–P2.3c requirements in
[the completion plan](../TARGET-ABI-COMPLETION-PLAN.md). The extension baseline
remains Ghidra 12.0.3, Java 21 and libdwarf 2.3.2.

## Reference and retained failures

`src/test/fixtures/arm-stack-aggregates.c` contains fourteen natural C functions:
base/VFP variants of a two-word structure, an eight-byte-aligned structure,
a five-byte packed structure, three bytes, an integer array, mixed float/integer
storage and an exhausted floating-register bank. Each receives source-known
values, captures them in volatile globals, and returns a checked result. The
comparisons deliberately retain the compiler's conditional instructions.
Do not simplify the source to remove these instructions to make a test pass.

The exploratory builds use ARMv7 ARM state, VFPv3-D16, hard-float, GCC `-O1`,
DWARF 5 without GNU location views, frame pointers, no inlining/IPA argument
rewriting, static non-PIE linkage and the existing freestanding startup.
Big-endian builds additionally select `-mbig-endian -Wl,--be8`.
Both references execute all fourteen functions correctly under QEMU. Raw entry
register/stack bytes and captured aggregate fields agree with source values.

**CONFIRMED compiler-reference defects:** the strict GDB observer records 90
little-endian and 84 big-endian field/argument mismatches. Several split
aggregates are described in a stack slot before their register part is stored.
The base-PCS double argument also remains assigned to an overwritten integer
register. These failing observations remain retained; no compiler exception or
unavailable-value allowance has been introduced into the new observer.

The first Forge experiment rejects entire incoming proofs because of predicated
instructions. It records 1,014 little-endian and 1,038 big-endian unavailable
field/argument observations, with no incorrect numeric values. These are
field-level counts, not counts of instruction stops.

## Shared conditional execution

`IntraInstructionFlow` admits only checked ordinary fallthrough instructions
whose p-code branches move forward within the instruction or to its exact
fallthrough. Ghidra 12.0.3 actually represents the tested conditional move with
a `CBRANCH` to `inst_next`, not a constant operation-relative target. The initial
model rejection of this representation is retained in the local v1/v2 logs.
The installed p-code reference and raw decoded operations establish both forms.

`StackValueFlow` evaluates the forward graph with intersection at joins and
preserves instruction-local temporaries until the instruction boundary.
Conditional copies/stores are never promoted to unconditional facts. Conditional
clobbers, released slots and unknown stores retire affected facts. Incoming
scalar/indirect/composite proofs opt in; local-definition ownership and inspected
callee effects retain their separate existing decoder requirements.

The real LE/BE8 instruction model checks conditional copies, backups, stores,
unrelated writes, self-copies, overwrites, frame release, unknown aliases,
flow/fallthrough overrides and cancellation. Synthetic forward branches exercise
common versus conflicting copies and temporary propagation. Malformed and hidden
control transfers are rejected. The suite passes 598 checks.

## Partial aggregate allocation

**CONFIRMED wrong-value control:** enabling conditional flow alone exposes twenty
wrong big-endian packed-structure field observations. The computed Ghidra storage
is `r3:4,Stack[0x3]:1`; raw compiler/runtime evidence puts that final byte at
`Stack[0x0]:1`. GNU, LLVM and the pinned strict validator accept the incorrect
artifact, demonstrating why debugger behavior is mandatory.

[AAPCS32, pinned 2025Q4 edition, section 6.5 and rules B.4/C.4/C.5](https://github.com/ARM-software/abi-aa/blob/2025Q4/aapcs32/aapcs32.rst)
rounds aggregate allocation to words and transfers its memory representation
through consecutive core registers and, when necessary, the stack. Padding must
follow the object bytes. Ghidra's audited general join right-justifies a partial
stack word. `ArmCompositeParameterAllocation` corrects only computed aggregate
storage in the checked BE8 profile; explicit analyst storage remains authoritative.

The policy verifies the complete recorded signature against its original
prototype. Its encoded prototype SHA-256 baselines are:

- `__stdcall`: `ba8574da1c90f0de5f2c200657abf9ee36ba32836797c3f4e26b979bb001210b`
- `__stdcall_softfp`: `3aff662ed70b8bd451ae1d1ce9eae845d041f4cda1f94b03e7e8b43b32bf4e7d`

Object bytes are assigned to the already allocated core/stack words. Short core
pieces account for BE8's little-endian physical register storage; changing all
prototype justification would incorrectly alter those slices. The model covers
sizes 1–5, 7–9, 13, 17, 19 and 20 with zero through five leading integers, both
conventions and both byte orders. All 1,152 checks pass, including custom-storage
preservation. Existing HFA allocation still passes 792 checks.

## Current validation and outstanding work

The local final candidate is `build/arm-stack-aggregates/ghidra-call-predicate-v3`.
Its extension JAR SHA-256 is
`751ce4b3279a46b8364c79456244045bcfa7933317ed1b584e2b106c0b3cd9b2`.
The assembled Linux/Windows archive SHA-256 is
`ade10f2232f68293b0884759e720261e7d783ca96fe45da3826bb479c7a554da`.
Assembly is not Windows-hosted runtime acceptance.

Thirteen Java suites pass 6,520 checks, followed by `buildExtension`. The suites
cover the new predicates/allocation and existing stack, composite, indirect,
upper-alias, terminal, control-flow, local-definition and call-memory behavior.
Exact commands, logs, package/source hashes and repeated-export commands reside
under the local `build/arm-stack-aggregates` evidence directory. Earlier candidate
and compiler failures are retained alongside the corrected results.

The corrected strict aggregate observer checks 250 LE and 256 BE8 instruction
stops with **zero incorrect numeric values**, correct raw entries, captured
fields, checked returns and exit zero. It still fails its full-availability
assertion: 225 LE and 241 BE8 field/argument observations are unavailable. All
these omissions remain explicit failures of the exploratory full-availability
expectation, not passing end-to-end aggregate acceptance.

Both generated sidecars and both compiler references pass GNU inspections,
`llvm-dwarfdump --verify` and pinned strict `check-dwarfdump.py` checks. Repeated
exports are byte-identical for both `.dbg` and `.dbg.c`; original binaries and
saved program files remain unchanged. Existing default HFA runtime regressions
pass against the exact candidate, with commands/results retained separately.
The local combined receipt `predicate-review-v3.json` has SHA-256
`fe170d719324bf1963bf296b500045cc473bcdae3c9254c7898e673585348f5d`.

**PLANNED next work:** support defensible unnamed partial-register slices in the
shared value-flow analysis, classify the remaining split-aggregate and wide-float
lifetime gaps, calibrate the compiler's incorrect prologue descriptions against
exact raw carriers, and turn the exploratory driver into a reproducible pipeline
harness. Broader calling/return classifications, failure/cancellation compositions,
exact hosted gates, independent review and protected integration still apply.
Do not claim this completes #70 or any of #68–#71.

The exploratory observer returns through the raw incoming link-register address
and checks the declared integer result. Automatic GDB `finish` on the stripped
base-PCS floating fixture previously unwound incorrectly and is retained as a
failed experiment; this observer does not claim to validate that unwinder.
