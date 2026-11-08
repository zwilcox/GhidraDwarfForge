# Explicit stack-separation conditions (#112)

The analysis-only checkpoint below is historical. The follow-up
[conditioned compiler export](CONDITIONED-COMPILER-UNWIND.md) adds explicit
projection and normalized provenance with local compiler/GDB validation.
Default unqualified projection still refuses conditional evidence.

**CONFIRMED locally; conditional analysis only.** The unchanged compiler fixture
writes `cfi_sink`, and the strict verifier cannot prove that this absolute address
is separate from saved stack values. The new internal condition model allows that
dependency to be represented explicitly without weakening strict verification.
No CLI/GUI policy has been selected, and no conditional frame artifact is emitted
by this checkpoint. The pending shipping-policy preference remains unresolved.

## Condition and call contract

`UnwindStackSeparation` records a target address width, ordered non-overlapping
absolute address ranges and a bounded explanation of the external condition.
Its meaning is that these ranges never overlap live stack storage belonging to
the analyzed call group **or its callers**. Addresses must use the same coordinate
system as the instruction effects. A database rebase therefore requires rebasing
the supplied ranges. This abstraction does not infer truth from an ELF section,
symbol name or ABI label. Its test-only basis explicitly says it is an assumption.

The default is `NONE`. Existing analysis and call-verification overloads use it.
Under an explicit condition, only a complete known constant-address store inside
one supplied region can retain saved stack evidence. Unknown pointers, writes
that straddle a boundary, wrong-width addresses and wrapping ranges still fail
the call proof or invalidate memory facts. Stack stores keep the original exact
overlap and lifetime rules. Unsupported instructions remain unsupported.

Conditional call contracts permit writes below entry stack **and** within the
separated ranges. The condition stays attached to the verified group, each flow
result and every exported call summary. A strict flow rejects a conditional call
summary; a different condition also rejects it. Unconditional summaries remain
usable under a stronger condition. The closed-group verifier still replaces all
incoming summaries with its own hypotheses and verifies final converged effects,
so recursive summaries cannot authorize themselves or exploit a first-visit state.

The current `GhidraUnwindFrames.plan` explicitly rejects conditional evidence.
This prevents the new verification overload from silently feeding the existing
unqualified projection/export path. Condition-aware projection, normalized
provenance and explicit export acknowledgement remain required follow-up work.
The existing captured JSON report still describes strict recovery only.

## Validation

The new component suite passes 82 checks, including all 50 observed cancellation
polls, direct/self/mutual calls, divergent joins, malformed ranges, unsigned and
32-bit boundaries, incompatible summaries and immutable metadata. Existing flow,
call, native call, projection and report suites pass, including 10,497 native
checks. Java 21 extension build, architecture isolation and workflow lint pass.

The real native byte-import probe uses the unchanged `synthetic-cfi.c` on x86-64
and AArch64 at original and rebased Ghidra addresses. For each of four cases:

1. Strict analysis still rejects the eight-byte global store and emits no plan.
2. An explicit condition covering the exact symbol-derived eight-byte range
   allows all four ordinary functions' call proofs to complete. The condition
   remains attached to every flow and summary. Unqualified projection rejects it.
3. A condition missing the first byte rejects the same store. No conditional or
   unqualified plan is left under its final name.

GNU symbols supply the test range independently of Ghidra's proof. The native
probe verifies original instruction bytes and existing coverage before checking
the calls. This establishes conditional analysis, **not** that the environment
satisfies the condition or that generated CFI matches compiler/GDB behavior.
The compiler source, global increment and startup instructions remain unchanged.

Two real native exporter regressions, one per target, retain strict policy and
pass 18 exports, 8 staged failure controls, 8 sidecars and 18 GDB sessions. GNU,
LLVM, pinned strict checks, instruction/CFI report agreement, deterministic
repeats, rebases and unchanged inputs pass. The raw validation reports are retained.
See [the evidence receipt](evidence/unwind-stack-separation.json).

Reproduce the conditioned native checks with the standard pinned toolchain:

```bash
./gradlew unwindStackSeparationSmoke
python3 src/test/integration/compiler-memory-effects.py build/condition-x86 \
    --target x86_64 --conditional-proof
python3 src/test/integration/compiler-memory-effects.py build/condition-arm \
    --target aarch64 --conditional-proof
```

Optional `--gradle-init` and `--gradle-cache` support an isolated local build.
The native probe's supplied ranges are test inputs, not a new supported user
interface. The unchanged strict probe remains available without the flag.
Hosted validation of these additions is **PRESENT, UNVERIFIED**. PR176's separate
integration gate and PR175's earlier priority remain unchanged; #112 stays open.
