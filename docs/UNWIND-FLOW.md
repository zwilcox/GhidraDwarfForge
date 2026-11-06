# Caller identity flow and native instruction capture (#112)

**CONFIRMED locally:** the isolated state analysis and native listing adapter
pass their component controls. **PLANNED:** ABI/profile selection, proved call
summaries, conversion into evidence-backed frame rows and production synthesis.
Neither component is called by the exporter. This does not complete #112.

## Analysis contract

`UnwindFlow` tracks exact incoming-register and return-address identities,
affine addresses relative to entry stack, and constants through supplied effects.
Physical register and temporary byte coordinates are separate from DWARF register
numbers. A partial physical write invalidates the overlapping whole-value fact;
partial values are not reconstructed. Stack loads require an exact saved slot and
width. Unknown stores invalidate memory facts. Caller identities and the saved
return address remain distinct, even when physically carried in one register.

The worklist computes a fixed point before returning any result. At a join, a
fact survives only when every reachable incoming path agrees. Unvisited nodes
are different from reachable nodes with unknown facts. Loop backedges can remove
an initially plausible fact, and unreachable predecessors do not invent a
conflict. Unchanged input states are immutable and instruction temporaries never
cross machine-instruction boundaries.

Stack-slot expiration occurs after the complete machine instruction. This is
necessary for Ghidra's AArch64 post-increment load: native p-code updates the
stack pointer before loading through a temporary old address. Expiring memory
at the intermediate operation lost valid restores. The failing native trace is
retained; both native and effect-level regressions now prove the load and the
subsequent expiration. Explicit stores still invalidate overlaps immediately.

A call effect requires an explicit, separate proof identifier, preserved physical
cells, stack adjustment and optional memory-write bound. A missing bound means
arbitrary memory effects; it cannot silently preserve saved slots. The model
**does not verify** that a supplied call summary is true. That verification is a
remaining prerequisite before production use. Unknown effects clear evidence;
no ABI name is accepted as a substitute for a call proof.

The component accepts byte widths up to eight, with bounded nodes, operations,
facts and transfers. Arithmetic/physical-range overflow and invalid graph edges
are rejected or lose the affected fact. Cancellation interrupts capture/analysis
without returning a partial result. These bounds are component limits, not an
architecture support declaration.

## Native capture contract

`GhidraUnwindInstructions` retains `Address` keys through extraction. It records
complete instruction bytes, assembly, processor context, native p-code and
omission reasons. Every byte of the selected body must belong to a complete
instruction; body gaps require explicit decoded edges. Length/flow overrides,
unreadable or incomplete bodies and unresolved edges are rejected. No target
register names or machine-specific opcode tables enter generic code.

The adapter lowers copies, addition/subtraction and exact-width memory operations.
Known pure arithmetic kills its explicit output when identity cannot be proved.
Unknown user operations, unsupported memory spaces or widths and unmodeled
internal p-code branches make the whole instruction opaque. Empty p-code for an
ordinary decoded fallthrough instruction is an observed no-effect case; both
reference targets exercise it. Calls require an explicit resolver result. A
call-flow/raw-call disagreement is not interpreted as an ordinary call.

A native x86 call-next/pop sequence is decoded as a push and an intra-function
branch, and correctly retains caller state after consuming the pushed PC. The
initial negative fixture incorrectly expected an ordinary callee call; its native
trace exposed that test assumption. Separate ordinary direct and indirect calls
now prove the missing-call-summary omission. This is separate from the real
post-increment analysis defect fixed above.

## Local validation and remaining acceptance

```bash
./gradlew unwindFlowSmoke ghidraUnwindInstructionsSmoke callFrameEncoderSmoke buildExtension
src/test/integration/architecture-neutrality.sh
actionlint
```

The effect suite has 75 checks covering exact saves/restores, conflicting and
agreeing joins in both traversal orders, loops, unreachable paths, partial
register/memory writes, unknown stores/calls, stack switches/releases, width and
overflow controls, every observed cancellation poll and retry.

Seventeen actual Sleigh-decoded cases across x86-64 and AArch64 pass 582 checks.
They include agreeing/conflicting split saves, conditional save/restore paths,
discontiguous bodies, ordinary save/restore sequences, no-effect instructions,
call-next/pop, unknown direct/indirect calls and an opaque syscall. Each also
checks capture cancellation/retry and rejects flow overrides, truncated bodies
and undecoded bytes. Raw bytes/p-code/context/final states are retained.

These are component tests on actual Ghidra ProgramDB instructions, **not**
compiler/GDB validation of generated unwind information. The existing encoder's
158 checks still pass, but no test here proves a production unwind profile.
Hosted component execution is wired and **PRESENT, UNVERIFIED**.
See [the receipt](evidence/unwind-flow.json) for exact sources, logs and failures.

Next: select audited ABI profiles; establish entry and return invariants; prove
callee register restoration and memory-write effects (including recursive call
graphs); derive complete CFA/return/register rows with explicit omitted ranges;
respect original-CFI precedence; run the real exporter with compiler/GDB oracles
on the full required non-PIE/PIE/shared/rebased and failure/cancellation matrix.
The [evidence model](SYNTHETIC-CFI-EVIDENCE.md) and
[ABI audit](UNWIND-ABI-AUDIT.md) remain the full acceptance contract.
