# Aggregate pieces across call memory effects

**CONFIRMED locally; final combined acceptance pending.** Two independently
tracked pieces now have explicit runtime coverage while both reside in memory
across a call. This checkpoint adds fixtures and checks; production/native code
is unchanged. The existing late-call cases alone did not prove this composition.

## Contract and negative controls

`pieces_memory_registers` and `pieces_memory_mixed` save both observed scalar
arguments, call a helper that writes its own stack, and reload the pieces.
The curator groups those arguments into `AnalystPair` as explicit analyst
knowledge; it does not claim the original C signature was an aggregate.
Raw DWARF must contain exactly two correctly ordered eight-byte pieces. At the
return marker both pieces must still be described by stack locations.

`pieces_memory_unknown` saves the second piece in an ABI-preserved register but
leaves the first only in memory. Its callee performs an unknown-pointer store.
The actual pointer targets a separate sink, so the old bytes remain readable;
that runtime coincidence is insufficient to prove nonaliasing. The whole value
must be unavailable after return even though the second register still agrees.

Two initial x86 runs exposed limits that are retained as dedicated controls:

- With red-zone slots, temporary call allocation followed by SP restoration
  releases the slots. `--red-zone` requires the aggregate gap at `restored`,
  including a mixed case whose second incoming stack piece still survives.
- A callee saving/restoring RBP still physically writes it. The current
  selected-ABI/nonwrite proof does not establish save/restore preservation.
  `--frame-pointer-leaf` retains this callee, requires stack/stack at the first
  load, then a gap when the later store uses an unproven frame pointer.

The positive x86 case uses `-mno-red-zone` and a helper compiled without a frame
pointer. Both negative variants run in all three address roles. They are not
new support claims for released slots or arbitrary saved/restored pointers.
Initial failures remain in `build/piece-call-memory-review/x86-first.log` and
`x86-allocated.log`, with their artifacts; they are not counted as passing runs.

## Validation

Twelve configurations pass: x86-64/AArch64 exec, PIE and rebased PIE, plus the
six x86 boundary controls. Compiler/Forge runs supply 14,250 caller and 426
callee observations, 4,659 available Forge aggregates and 336 checked returns.
There are 24 two-memory-piece return observations, 12 unknown-write controls
with a surviving half, and three released-slot controls with a surviving half.
Both exec cases also execute the preceding register-call package on identical
inputs/programs: x86 gains 22 and AArch64 26 whole-value observations, without
losing previously available observations.

GNU/LLVM/pinned strict validators, exact raw intervals/pieces, saved instruction
bytes, actual GDB field values, source/list/next/step, normal exit, deterministic
repeats and unchanged originals/modules/harnesses/saved programs pass. CI runs
all twelve variants. The local source inventories and workflow lint also pass.

Production JAR: `5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`.
Evidence: `build/piece-call-memory-review/{matrix,checkpoint}.json`, `review.py`.
Checkpoint SHA-256:
`8e6c4febb307a37ff0a1e2a6a32342f8c3709bdf647d2f7acc1f1bf2d2a891dc`.
These local build receipts are evidence from this checkout; the checked-in
harness is the reproducible CI acceptance path.

With actual Java 21 and the pinned `DWARFDUMP`, repeat for each address role:

```bash
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra x86_64 --role pie --red-zone
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra x86_64 --role pie --frame-pointer-leaf
```

Lexical/failure composition is recorded separately in `LEXICAL-CALL-LIFETIMES.md`.
Final target/host/package acceptance, protected integration and the full original
requirement audit remain open. Neither P1.11a/#67 nor P3.3/#73 is complete.
