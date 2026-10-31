# Proven stack and register values across control flow

**CONFIRMED locally; hosted acceptance pending:** the shared stack/register
transfer proof now follows closed, fully decoded branches, loops and
noncontiguous function bodies. This extends P1.11a; it does not complete that
umbrella or P3.3. Ghidra 12.0.3, Java 21-compatible bytecode and pinned native
libraries are unchanged.

## Acceptance and evidence policy

For an attached incoming scalar, retain only copies of its original bits.
For an explicit USER_DEFINED stack local with a recorded initializing STORE,
retain only the current definition. Every reachable predecessor must agree on
a physical carrier or stack slot at a join. Keep unavailable paths and holes,
including skipped definitions, partial writes, losing backedges and conflicting
stack-pointer offsets. Re-executing a definition retires old register backups;
reaching another saved overlapping owner retires the preceding local.

`StackValueFlow` now computes instruction input/output states to a fixed point.
Unvisited predecessors begin at top; visited states intersect exact register
facts and entry-relative stack slots. Distinct affine stack offsets become
unknown. Instruction-local unique temporaries never cross an edge. The entry
contract participates even when a backedge reaches the entry. Existing physical
CFG validation still rejects missing instructions, alternate entries, outside
edges, calls, delay slots and opaque effects. Cancellation is checked throughout.
Output intervals describe states before instructions and never fill body holes.

The shared proof also retains immutable incoming copies made before their first
handoff and exact-width self-copies. Earlier two-copy tests deliberately omitted
these cases. Their arithmetic, partial-write, killed-copy and post-loss negative
controls remain. A valid incoming prefix is no longer discarded just because a
later stack reload fails. The type extractor uses this proof when the older
prefix path has no valid result; existing established intervals are preserved.

This requires actual saved identity and instruction evidence. It does not infer
source lexical scope, a new assignment from stale bytes, or ownership from a
high-variable name. Broader inspected calls, mutable stack mapping identities,
mixed-piece migration and the full scope plan remain required.

## Local validation

The private production JAR SHA-256 is
`1f10a59fc1fe1323c77b5048b1c62bb5085c231c55c0d3814e233d5ef4619139`.
The package runs on an isolated full JDK 21.0.13 installation. Actual Java 21
class-origin checks and 21 standalone suites pass. The new decoded-machine
suite passes 832 checks; stack-local, stack-value, merged-local and register-local
flow suites also pass, including cancellation and unknown-SP loops.

`stack-control-flow.c` provides seven shapes at signed 32/64-bit widths:
diamond, killing branch, skipped initialization, stable loop, killing loop,
repeated definition and an explicit unreachable body hole. Three input values
and both branch choices execute each shape. The compiler oracle measures the
stack slot. Preparation saves its exact STORE and symbol identity; read-only
exports preserve that evidence. GDB visits every executed instruction, checks
advertised values against physical storage, rejects stale backups and checks
`list`, prototypes, `next`, `step` and normal exit.

Twelve x86-64/AArch64 exec/PIE/rebased-PIE cases pass 24 candidate and twelve
previous-package exports, with byte-identical output pairs. Raw location lists,
matched ELF identity/build IDs, no program headers, protected input/module
hashes, saved-program preservation, GNU/LLVM and pinned strict validation pass.
Inherited compiler frame diagnostics are matched to original bytes and messages.
There are 36,828 compiler/candidate/previous GDB observations, 6,102 available
candidate values, 180 stale definition-backup checks and 216 unavailable join
checks. The previous package omits these locals. PIE and rebased PIE normalize
to identical location intervals.

Fourteen additional early-copy/self-copy/ordered-regression cases pass 28
candidate exports and 1,848 compiler/candidate GDB observations. Both target
lanes include all new shapes; Linux and Windows model lists include the new
suite. Hosted execution of this component is still pending.

Controlled decompiler failure retains one symbol-only failed function and the
successful function-owned static; its artifact passes LLVM, the pinned strict
checker and GDB. Cancellation after 16 MiB preserves the original and prior
output pair. Architecture neutrality and its seven negative controls, workflow
lint and fixture inventory/reproducibility pass.

Evidence under `build/stack-control-flow-review`:

- `runtime-acceptance.json`: SHA-256 `772afcad64a174fe756bc3ca5da6ff8419d6a4d4c68a8caef6dd15912313b777`.
- `copy-acceptance.json`: SHA-256 `e3055c367cad9be30dd81e0036bfd4dfe595469a3a208afe29b7927fa7cdbddd`.
- `java21-2/acceptance.json`: SHA-256 `0091577d65dc7cd923c773b59872f19cec4ce806df794f8fcff318b5a1e4d4be`.

## Retained failures and corrections

LLVM 18.1.3 hangs on the original optimized compiler driver because its call-site
verifier advances with `Die.getParent()` instead of `Curr.getParent()` when a
call site is nested inside a lexical block. The sampled child backtrace and
upstream source are retained. See the [LLVM 18.1.3 implementation](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/llvm/lib/DebugInfo/DWARF/DWARFVerifier.cpp).
Only the fixture driver now uses `optimize("O0")`; all functions under test
remain optimized with `-O2`. Every compiler reference and exported sidecar still
passes LLVM verification, now bounded to 60 seconds. No validator was disabled.

The first comparison assumed the previous package retained incoming parameters
at branch entries. It does not. Both packages' physical incoming registers are
checked; the candidate and compiler must expose entry parameters, while previous
unavailable parameters remain unavailable. The previous-local omission control
is unchanged. An early-copy fixture originally placed the post-clobber marker
inside a single inline-assembly block, where GCC's debug location had not yet
transitioned. Splitting the block makes the compiler oracle agree at the actual
instruction boundary. The failed logs are retained.

An initial failure-isolation command omitted its native arguments; the corrected
export succeeded, but the default system checker lacks the repository's pinned
consumer fixes. That failure is retained. The same artifact then passes the
pinned checker and remaining GDB checks under `failure-completion/`; it was not
re-exported to erase the failed evidence.

## Reproduction

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew stackControlFlowSmoke secondRegisterCopySmoke
python3 src/test/integration/stack-control-flow-export.py /path/to/private-packaged-ghidra x86_64 --width 64 --role exec
python3 src/test/integration/stack-control-flow-export.py /path/to/private-packaged-ghidra aarch64 --width 32 --role pie-rebased
python3 src/test/integration/second-register-copy-export.py /path/to/private-packaged-ghidra aarch64 --copy-shape early --role pie
```

Set `DWARFDUMP` to the pinned checker described in `support/validation/README.md`.
Run both widths and all three roles on both targets. Optional
`--previous-ghidra` selects the preceding stack-local package for comparison.
