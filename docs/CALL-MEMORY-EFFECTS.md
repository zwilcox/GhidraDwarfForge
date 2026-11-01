# Inspected call memory effects

**CONFIRMED locally; broader composition and hosted acceptance remain open.**
The exporter can now preserve an evidenced caller stack slot through a call
whose complete inspected body proves nonoverlapping memory effects and an
exact return stack-pointer adjustment. P1.11a/#67 and P3.3/#73 are not complete.

## Proof and limits

`CallMemoryEffects` follows exact affine addresses relative to callee-entry SP
through the already validated physical CFG. Constants and stack addresses are
distinct terms, including constants carried in p-code temporaries. At joins,
facts must agree; possible stores and released frame ranges accumulate. Every
reachable return must establish the same SP adjustment. Pointer width, RAM
space, SP register and stack direction come from the selected Ghidra language
and compiler specification. No return-address size or adjustment is hardcoded.

Nested nonrecursive summaries resolve from the leaves upward. Register facts
still need the separate selected-ABI and physical-nonwrite proof. An unknown
store, unknown SP, incompatible return adjustments, unavailable nested summary
or recursive dependency prevents a memory summary. These failures retain any
independently valid register proof; they do not invent a memory contract.

`StackValueFlow` interprets the caller's raw CALL effects first, then translates
the callee's ranges through that actual entry SP. Overlapping slots are retired;
a possible change to the canonical stack local retires its old register copies
as well. Unrepresentable arithmetic or unknown effects retain the previous
conservative invalidation. The return SP fact is restored only from the new
proof. Ordinary local frame-change and saved-assignment ownership rules remain.
CALL instructions themselves remain invalid saved local definitions.

This does not prove arbitrary indirect calls, pointer aliases, recursive stack
effects, frame-pointer save/restore patterns that cannot be followed, or memory
preservation on untested processor profiles. Unknown observations stay gaps.
The nonrecursive register summary construction currently retains transitive
instruction lists for each inspected function; no large-call-graph performance
claim is made by these correctness fixtures.

## Independent acceptance

Two source-built baseline comparisons against the preceding register-call JAR
`d2695509eec0abd11dfdd5c5069e421965a815eddea8cdc23e79bfcb273321c4` reproduce
stack-location loss after calls. Compiler reference and stripped input bytes
match the candidate cases exactly. Each primary target gains 18 available
instruction observations in its non-PIE case; earlier available observations
and all actual returns are preserved.

Twelve candidate configurations cover register and stack storage on x86-64 and
AArch64 in exec, PIE and rebased-PIE roles. Twenty-four immutable exports pass
determinism, original/module/harness/project preservation, raw location checks,
GNU/LLVM/pinned strict validation and actual compiler/Forge GDB comparison.
Stack offsets come from the compiler's DWARF and actual process memory before
Ghidra curation, not from a guessed target frame layout.

The register cases include conditional calls, repeated calls in a loop,
discontiguous bodies and physical temporary clobbers inside a callee that
restores its ABI register. There are 3,204 caller and 948 callee observations,
783 available Forge values and 216 checked returns. The stack cases exercise
callee-owned stack writes, nested calls and a real write through a pointer to
the local. Their 1,152 caller and 684 callee observations include 234 available
Forge values and 108 returns. The aliasing case correctly loses its location;
the compiler and actual memory establish that the logical local changed.

Twelve existing runtime regressions also pass on both targets: independent
composite pieces, direct leaf calls, local CFGs, merged register assignments,
stack CFGs and mutable stack assignments. Nine suites pass on actual Java 21
against the exact production JAR with class origins checked. Model checks
include 145 memory-summary assertions, 446 local-call assertions and 536
inspected-call assertions. They cover partial overlap, adjacent nonoverlap,
unknown aliases, stale slot reloads, unequal returns, changing-SP loops,
recursive rejection, nested effects and cancellation.

Evidence: `build/call-memory-review/{matrix,regressions,checkpoint}.json`,
`java21/receipt.json`, the two `baseline-*.log` cases and `review.py` in the
`local-call-lifetimes` worktree. Checkpoint SHA-256:
`4c7a4599ab04b86de1d1e31ec3d9fbe8ede3241f19b843716f548efb729c9219`.
Tested production JAR:
`5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`.
All 85 production sources match the packaged source archive; all 318 production
classes have Java 21 bytecode. No native ABI changed. The model and runtime
lanes are wired into CI; hosted acceptance of this component is still pending.

Reproduction, with actual Java 21 and the pinned `DWARFDUMP`:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew callMemoryEffectsSmoke localCallLifetimeSmoke inspectedCallsSmoke compositeValueFlowSmoke buildExtension
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra x86_64 --storage stack --role exec
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra aarch64 --storage stack --role pie-rebased
```

Run all three address roles with both storage options on both targets.
`--expect-memory-gap` is only for the preceding package and is never used in
candidate CI. The fixture explicitly disables compiler stack protection to
isolate the inspected calls from the unrelated external canary-failure path;
that external call remains unsupported, rather than silently assumed harmless.

## Retained failures and remaining work

The first summary implementation lost an AArch64 SP adjustment because a p-code
constant traveled through a temporary; distinct constant terms correct that
loss. The former blanket stack-retirement test used a callee with no memory
write. It is now paired with a preservation case and an actual unknown-pointer
store negative control. Neither original failure is counted as a passing test.

Initial headless setup attempts exposed incorrect `updateFunction` argument
ordering and a missing local-variable cast, then the fixture's extra canary
failure call. The AArch64 oracle also initially assumed restoration directly
preceded `ret`; it now checks the actual earlier release boundary. Logs and
failed artifacts remain alongside the passing reruns.

**CONFIRMED subsequent boundary coverage:** `CALL-MEMORY-BOUNDARIES.md` records
six executed partial-overlap, adjacent-write, released-slot and unknown-SP
target/address configurations, four harness regressions and two old-package
comparisons. These controls use compiler-derived outgoing copy locations.

**CONFIRMED subsequent composition:** the expanded boundary fixture executes
incompatible return-SP paths and immediate caller restoration on both targets.
`MUTABLE-CALL-MEMORY.md` adds twelve mutable-identity runtime roles with stale-slot
controls and preceding-package comparisons.

**PLANNED:** independently migrating pieces. The existing regressions do not replace
those targeted cases. Compose
the new intervals with lexical ownership and genuine failure/cancellation
paths, review the exact final target/host package and integrate normally.
PR102's separate scope gate and the full original requirement audit remain
required before either umbrella can close.
