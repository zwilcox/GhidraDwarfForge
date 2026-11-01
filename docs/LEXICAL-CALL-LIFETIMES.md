# Lexical identities through inspected calls

**CONFIRMED locally; final combined acceptance pending.** The existing saved
lexical fixture now executes calls inside both outer and inner scopes. The
exporter preserves proven stack locations and explicit scope ownership together.
This checkpoint changes tests and harnesses, not production/native code.

## Contract

`--calls` inserts a separately compiled leaf that writes its own stack after
each local initializes. The caller's two `shadow` variables remain distinct:
outer 11 and inner 23. The curator records the helper's complete body, default
ABI, void/no-argument signature and bytes, and requires exactly two direct
calls with return successors matching compiler markers.

GDB steps every helper instruction and unwinds to the caller to read `shadow`.
Compiler and Forge must agree on exact instruction bytes, addresses, four-byte
type and the appropriate value while stopped in the callee. On return the
caller resumes with the same value. The explicit discontiguous inner scope
still exposes the outer variable in its visibility gap, without extending the
inner identity over that gap. Before initialization, stale bytes remain
unavailable. The harness never changes target instructions or variable bytes.

`--controls` reuses the actual stale/coalesced ownership, native decompiler
failure and production-copy cancellation paths on this call-containing program.
The native failure is `Flow exceeded maximum allowable instructions`; the
failed function retains symbol-only behavior without orphan lexical children
or source attributes, and subsequent functions still export. Cancellation after
16 MiB of a separately imported 128 MiB input retains the previous complete
output pair and leaves no temporary residue. Protected hashes now include the
fixture and relevant harness/preparation/failure/cancellation scripts.

## Validation

Six x86-64/AArch64 exec/PIE/rebased-PIE call configurations pass 42 exports and
six cancelled attempts. They include 192 Forge caller observations, 120
compiler/Forge callee observations and 48 rejected-binding observations.
Two no-call discontiguous exec cases also pass as harness regressions.
GNU/LLVM/pinned strict validation, raw lexical/range/location checks, source
lookup, GDB values, immutable saved programs, original preservation,
deterministic output pairs and actual Java 21 runtime checks pass.
Both primary CI lanes run all call configurations with all controls.

The independently reviewed archive's 85 production Java sources match the
current tree and its 318 classfiles target Java 21. The installed JAR matches
the archive and the prior nine-suite actual-Java-21 receipt:
`5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`.
Evidence: `build/lexical-call-review/{matrix,checkpoint}.json` and `review.py`.
Checkpoint SHA-256:
`73dce963805a7e3940cddcff3c7b4ac3b3de3c6c2a97f31fcb8170745192dc8a`.
The x86/AArch64 source inventories and workflow lint pass. Local receipts are
not substitutes for the exact final combined hosted package and runtime gate.

Reproduce with actual Java 21 and the pinned `DWARFDUMP`, for each address role:

```bash
python3 src/test/integration/lexical-shadow-export.py /path/to/private-packaged-ghidra x86_64 --role exec --discontiguous --controls --calls
python3 src/test/integration/lexical-shadow-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased --discontiguous --controls --calls
```

The remaining work is final combined target/host/package acceptance, normal
protected integration and requirement-by-requirement reconciliation. The full
P1.11a/#67 and P3.3/#73 objective remains open.
