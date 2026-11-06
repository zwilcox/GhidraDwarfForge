# Closed callee verification (#112)

**CONFIRMED locally:** closed groups of ordinary integer functions now have
native direct-call capture and simultaneous register/stack/write verification.
**PLANNED:** wider memory-effect proofs, frame projection, original-byte
agreement, original-CFI precedence and full exporter/GDB acceptance. This does
not enable production synthesis or complete #112.

## Obligations instead of an assumed calling convention

`GhidraUnwindCalls` discovers a bounded direct-call closure from a root function.
Each member must pass the same [audited profile](UNWIND-PROFILES.md). An actual
native CALL, its decoded target and a known function entry must agree; indirect,
external, missing, thunk and incompatible callees receive no implicit contract.
Capture retains complete bytes, processor context, p-code and omission reasons.
Terminal instructions must contain an ordinary native return operation.
A consistent program view is the caller's responsibility. Original ELF byte
agreement is still a separate prerequisite before using this in production.

`UnwindCalls` verifies the supplied effect graphs as one closed group. It replaces
**every** supplied call effect with its own candidate contract, so an arbitrary
preserved-register set, memory bound or stack adjustment cannot enter as proof.
The candidate promises only the selected incoming callee-saved identities,
restored stack/return target, and writes strictly below callee-entry stack.
The latter is an explicit predicate of this verifier, not a universal assumption
about all target stacks or ordinary ABI-conforming code.

After fixed-point analysis, final per-effect replay checks every reachable store
and nested call. A store needs a known affine entry-stack address whose complete
extent ends at or below entry stack. A nested call must enter at or below that
boundary. Unknown, absolute/image-relative and overlapping positive-offset
writes are rejected; opaque reachable effects are rejected. Every reachable
return must recover the original return-address identity, expected post-return
stack offset, and every selected preserved register. Incompatible paths at a
join cannot borrow an optimistic first-visit fact. Unreachable returns do not
establish proof, and a group needs reachable ordinary return sites.

A verified result is published only after **all** member obligations pass. Self
and mutual recursion use simultaneous contracts: induction on finite call depth
establishes register/return preservation, and the transitive entry-stack bound
establishes the write predicate. This does not prove termination or authorize
an arbitrary supplied ABI contract. The native adapter supplies the audited
entry model; the pure component accepts an explicit model for testing/reuse.
No strongly connected component is approved merely because it calls itself.
A failing member rejects the entire group. Cancellation returns no partial proof.

The closure is bounded to 1024 functions and 65,536 distinct instruction nodes.
Overlapping function graphs, missing targets, extra call bindings, unmatched
terminals and excessive groups are rejected. Results and evidence maps are
immutable. Recovered states remain keyed by Ghidra `Address` values.

## Current memory scope is not full #112 acceptance

The existing compiler reference `src/test/fixtures/synthetic-cfi.c` increments
`cfi_sink`, a global variable. This verifier does **not** yet prove that global
writes are disjoint from caller stack storage. The fixture remains unchanged;
removing that operation to make the first verifier pass would not satisfy the
requested end state. Unknown-pointer and absolute-address stores have explicit
negative tests. A wider memory provenance/alias proof is required for that
reference, together with the planned full exporter/runtime matrix.

Indirect/external calls and nonordinary frames likewise need additional evidence
or explicit omitted coverage. The current isolated stack-writing subset is a
prerequisite, not the definition of completion. Compiler prologues, discontiguous
ranges, split/shrink-wrapped cases, PIE/shared/rebased artifacts and actual GDB
unwinder selection remain in the [full acceptance contract](SYNTHETIC-CFI-EVIDENCE.md).

## Validation

```bash
./gradlew unwindCallsSmoke ghidraUnwindCallsSmoke unwindFlowSmoke \
    unwindAbiProfileSmoke ghidraUnwindInstructionsSmoke callFrameEncoderSmoke buildExtension
src/test/integration/architecture-neutrality.sh
actionlint
```

The pure suite passes 182 checks, including all 152 cancellation polls and retry.
It covers direct/self/mutual recursion, reversed function traversal, saved caller
values across calls, forged supplied summaries, invalid preserved-register
restoration, partial writes, unknown/absolute/overlapping stores, bad stack and
return target, a bad member in a recursive group, unmatched bindings/terminals,
excessive groups and nested-call bounds. The nested-call negative specifically
checks that boundary diagnostic, rather than failing first on a bad store.

Twenty real ProgramDB/Sleigh fixtures pass 662 checks across x86-64 and AArch64.
Both targets accept leaf/direct/self/mutual groups and reject clobbered registers,
unknown writes, incorrect return adjustment, missing and indirect callees and
custom callee storage. Negative tests require their expected diagnostic category.
Every observed direct-group cancellation poll is tested (240 and 316), followed
by a deterministic retry. Input instruction bytes are unchanged. Native byte,
assembly, p-code and converged-state observations are retained in the receipt.

The existing flow/profile/native-capture/encoder suites pass 102/235/653/158
checks. Extension build, architecture guard and workflow lint pass. CI runs both
new suites; current hosted execution is **PRESENT, UNVERIFIED**. These are native
instruction/component tests, not structural validation or GDB acceptance of new
emitted CFI. No emitted ELF/DWARF behavior changes at this checkpoint. See
[the receipt](evidence/unwind-calls.json) for exact source and evidence hashes.
