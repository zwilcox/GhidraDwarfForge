# Register lifetimes across inspected call graphs

**CONFIRMED locally; hosted acceptance pending.** Incoming scalar values can
survive repeated register transfers across fully inspected direct calls. This
extends the earlier straight-line leaf proof to closed branches, loops, nested
and recursive call graphs, and discontiguous function bodies. P1.11a and P3.3
remain incomplete; see `LIFETIMES-AND-SCOPES-PLAN.md`.

## Proof and boundaries

`DirectLeafCalls` retains its historical name, but its summary now covers the
whole reachable direct-call graph. A worklist decodes each function once and
handles cycles without a recursion-depth cutoff. A retained register requires
both an exact full-base-register unaffected declaration from every selected
calling convention and no physical/listing write anywhere in the graph.
Unknown callees, thunks, call fixups, indirect calls, incomplete bodies, opaque
operations, unexpected entry edges and unestablished calling conventions reject
the proof. Raw p-code and listing call destinations must agree; local return
fallthroughs remain separate from callee edges.

The complete-state scalar proof tracks all exact copies, including short-lived
argument setup copies. At each call, it retires every memory fact and every
register fact whose preservation is unproved. It does not infer callee memory
non-aliasing or restored stack-pointer offsets. A register written and restored
by a callee also remains unavailable after the call; physical restoration has
not yet been proved. Explicit stack-local call survival, mutable stack mapping
identity and independently migrating mixed pieces remain separate work.

The shared instruction decoder retains its default no-call mode for existing
local-definition proofs. Only explicitly selected paths admit inspected calls.
No target register numbers or ABI names were added to generic production code.
No native/JNA signatures changed.

## Behavioral acceptance

The new `inspected-call-callees.c` fixture is compiled with the existing
`second-register-copy.c` driver. Its six selected graphs exercise branching,
loops, nesting, recursion, a genuine discontiguous body, and a callee that
writes/restores the saved register on one branch. Four register handoffs retain
signed 32/64-bit input values. Both outcomes of the clobber control stay
unavailable after the call, even though raw runtime registers retain the value.

Thirty-six x86-64/AArch64 exec/PIE/rebased-PIE cases pass 72 candidate and 36
preceding-package exports on actual Java 21. They include:

- 17,496 compiler/candidate/previous marker observations.
- 9,774 distinct candidate caller instruction observations (15,318 samples
  include repeated marker boundaries), with 7,533 available values checked
  against their exact physical register and original instruction bytes.
- 144 preserved-but-unproven negative controls.
- Exact raw location coverage, every executed caller instruction, actual
  branch/loop/recursive execution counts and normal returns.
- Byte-identical repeated outputs, protected module/input/source hashes,
  unchanged saved program evidence, matched ELF metadata, no program headers,
  GNU/LLVM verification and the pinned strict checker. Inherited frame
  diagnostics are corroborated against the original bytes and messages.
- Identical normalized PIE/rebased-PIE location intervals.

The earlier package omits the new call-graph locations. Both compiler-reference
and production GDB checks retain source navigation, types, `next` and `step`.
Twelve additional direct-leaf, stack-control-flow and two/four/early/self-copy
regressions pass 24 exports and 5,400 compiler/candidate observations.

Twenty-two packaged suites pass on actual Java 21. The new decoder suite has
512 checks, including caller control flow, nested clobbers, opaque/indirect
rejection and retirement of stack facts at a call. Its final memory-retirement
addition was run separately; the other 21 suite sources and package are
unchanged. Controlled decompilation failure, cancellation after 16 MiB,
architecture neutrality with seven negative controls, workflow lint and fixture
inventory/reproducibility also pass. Both runtime CI lanes contain all six
call shapes and all three address roles; Linux/Windows model lists include the
new suite. Hosted execution is still required.

Local evidence under `build/inspected-call-review`:

- `runtime-acceptance.json`: SHA-256 `4019b611d9d0c4d92a601cbe0c8944e3509ca87f60704b44050b67ced90899e1`.
- `regression-acceptance.json`: SHA-256 `1762767efd395f3e5108b74e9b1a8bbc72cc99314036ad15c2822dcb3d086560`.
- `java21-acceptance.json`: SHA-256 `f0c55ed9e804605031c06b83269abea11bcbb48e452b0d809cfed7c4fea85437`.
- Tested production JAR: SHA-256 `241adc7d2345b55bde03c7587fb6b9629c323bb85853dbeca4c0258604660331`.

## Reproduction

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew inspectedCallsSmoke
python3 src/test/integration/second-register-copy-export.py /path/to/private-packaged-ghidra x86_64 --handoffs 4 --call-graph nested --role exec
python3 src/test/integration/second-register-copy-export.py /path/to/private-packaged-ghidra aarch64 --handoffs 4 --call-graph recursive --role pie-rebased
```

Run every graph (`branching`, `loop`, `nested`, `recursive`, `split`, `clobber`)
in all three roles on both targets. Select actual JDK 21 in the private
installation's `support/launch.properties`. Use the pinned `DWARFDUMP` described
in `support/validation/README.md`. `--previous-ghidra` optionally compares the
preceding stack-control-flow package.

## Retained failures

Initial model failures exposed a prefix rejection at a call before the original
register's first physical write. The corrected proof uses inspected preservation
and also retires ABI-clobbered original facts. A real compiler argument setup
then exposed a short-lived first-copy heuristic; the complete-state proof now
tracks the later surviving copy too. Both cases have decoder regressions.

The first preparation attempt omitted the callee-curation script, and a private
launcher initially selected Java 25. Neither attempt counts toward acceptance.
The split fixture initially looked like a thunk to Ghidra; placing its existing
global write before the split creates the intended non-thunk body.

LLVM 18's compiler-reference verifier hit the previously documented parent-walk
loop with a recursive call inside a lexical block. Moving that call to function
scope preserves optimization and recursive behavior; all final compiler
references verify within the existing timeout. No validator is bypassed.
The first independent regression audit expected the wrong validator log name
for the stack harness; it was corrected to inspect the actual `fixed-llvm.log`
and its strict-check receipt. Failed logs remain outside passing receipts.

## Hosted semantic-harness correction

PR100 run `41229139226` exposed stale AArch64 semantic-harness assertions. The
new scalar proof retains `recovered_add`'s original arguments through stack
spills, but the old checks required a register-only diagnostic and optimized-out
values. The corrected checks require the stack-spill diagnostic and exact
`left=19`/`right=23`. Four extended-sections exec/repeat/PIE and shared-object
exports pass with the exact hosted JAR on actual Java 21, structural validators,
QEMU GDB, original preservation and deterministic exec repeats. Receipt:
`a3483015113053cf4390dcd2bb9b5475c638fc109cbcd38c4dda20e8eae75c9f`
(`build/pr100-harness-fix/acceptance.json`). Production code is unchanged.
The failed run is retained; a replacement full gate is still required.
