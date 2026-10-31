# Curated local definitions through control flow

**CONFIRMED locally; hosted acceptance pending:** an additional location proof handles an
explicit analyst-defined register local whose recorded nonzero first-use
instruction defines its entire physical storage. This is part of P1.11a, not
original lexical-scope reconstruction. The existing straight-line proof retains
priority. Call effects, memory migration and mixed pieces remain separate work
in `LIFETIMES-AND-SCOPES-PLAN.md`.

The new proof requires an attached variable and function, matching formal and
physical widths, an exact mapped register, and no overlapping variable binding.
Every declared body byte must belong to a complete decoded instruction. It
checks prototype targets as well as flow references, rejects alternate entries,
and retains the established outside-body control-flow guard. Calls, computed
jumps, delayed execution, flow/length overrides, opaque effects and internal
conditional p-code are rejected. It permits direct branches only when the last
raw p-code operation and the instruction's real target agree.

Availability is computed over all reachable instruction predecessors. Entry
has no initialized local; completion of the recorded full-width definition
establishes it. Other physical register writes kill it. A join is available
only when every reachable predecessor preserves the definition. This includes
loop backedges: a location valid on the first iteration but not subsequent
iterations is unavailable at the shared PC. Starting the must-analysis at top
and monotonically removing facts preserves loop-invariant definitions without
assuming them at function entry. Cancellation is checked throughout.

Each emitted interval describes instruction-entry state. The defining
instruction is not itself evidence that its post-execution value already
exists. A clobbering instruction still has its pre-execution value, and its
successor loses availability. Discontiguous body holes never acquire a range.
Unreachable declared instructions do not acquire an initialized local.

## Current evidence and remaining work

**CONFIRMED locally:** 380 checks use real x86-64/AArch64 decoding, 32/64-bit
register locals, diamonds with/without kills, loops, initialization bypasses,
discontiguous bodies, offcut definitions, alternate entries, flow overrides
and cancellation. Existing definition/read-start, coverage and outside-body
suites also pass. These Gradle runs use the installed Java 25 toolchain. Fourteen suites also
pass against the exact packaged production JAR on actual Java 21, with class
origins verified.

**CONFIRMED locally:** all six x86-64/AArch64 exec/PIE/rebased-PIE cases pass
12 candidate exports and six preceding-package comparisons. The fixture checks
signed 32/64-bit locals in preserving/killing diamonds, preserving/killing
loops, initialization bypasses and discontiguous bodies. Each of 72 calls per
case is observed at every executed instruction in compiler, Forge and previous
package modes: 18,576 GDB observations across the six cases. The preceding
package has no location for these locals. The candidate agrees with raw
registers and compiler values where the curated definition is proven, and
retains honest unavailable joins even on a runtime path that kept the value.
Every loop visit and both choices are checked. Source lookup, types, next/step,
return values and successful program exits pass. PIE and rebased-PIE inputs are
byte-identical and retain identical normalized location/body intervals.

GNU readelf, LLVM verification and the pinned strict checker pass, with inherited
frame diagnostics corroborated against original bytes. Original inputs,
compiler references, package and harness hashes are unchanged; saved projects
only rotate the documented backup index/journal files. Repeat sidecar/source
pairs are byte-identical. Local runtime receipt:
`8e1d9fe32ebf2a392812935d002d47b45a2558c5f9b7ce65f77e30cc0c5a7059`.
Tested JAR: `65dc550a37297dbe4993c8ffd3aaa2c398590f43b6be8947a046e2b9e1a8e0d3`.
Evidence resides under `build/local-definition-flow-review`, with the six
exact cases named in `runtime-acceptance.json`.

**PRESENT, UNVERIFIED:** the workflow requires all three roles on both targets
and the new decoder suite on Linux/Windows. Final committed packaging and the
full hosted gate remain pending. This component does not complete P1.11a or
establish additional architecture support. Cancellation is exercised by the
model. Packaged controlled-decompiler-failure and cancellation after 16 MiB
also pass, preserving the original and prior output pair; their hosted checks
remain required. The first failure-isolation command used a nonexistent
unversioned native filename. Its error is retained; the corrected command uses
the exact versioned packaged libraries and passes.

Reproduction (repeat each role for both targets):

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew localDefinitionFlowSmoke
python3 src/test/integration/local-definition-flow-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/local-definition-flow-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Use the pinned `DWARFDUMP` from `support/validation/README.md`. Optional
`--previous-ghidra` selects the preceding package for explicit omission controls.

## Fixture setup and retained failed attempts

The compiler's symbols establish exact function bounds and instruction labels.
Ghidra initially treats some interior assembler labels as separate functions,
and marks the branch across a gap as a `CALL_RETURN` override. The fixture
preparation reunites only tails wholly inside the compiler-recorded body and
restores that known internal branch after verifying its raw p-code and target.
Production still rejects overrides. Curation occurs in a separate no-analysis
invocation after import; otherwise post-script analysis changes the saved body.
Reopen-only observations verify the entire curated body, local and instructions.
These setup failures are retained and excluded from acceptance.

The initial caller expanded three lexical loop blocks; installed LLVM 18
verification exceeded 60 seconds on both untouched compiler references.
Replacing the caller with six explicit calls to one helper preserves every
runtime case and produces compiler references that immediately validate and
run. No verifier check was suppressed. The rejected references and timeout logs
are retained in the five diagnostic case directories listed in
`retained-failures.json`. An initial independent comparison also compared raw
Ghidra disassembly text between rebased programs; that text correctly contains
rebased addresses. The final audit compares normalized labels/intervals and all
instruction bytes, sizes and flow metadata instead.

The first loop model had no unique PC between initialization and a loop that
kills the local on its backedge. The must-analysis correctly offered no
location. The fixture now includes an observable pre-loop instruction and
requires that prefix to be available while the shared loop PC remains
unavailable. A separate test compilation error was corrected by retaining the
returned variable's `LocalVariable` interface for the first-use setter. Both
failed attempts remain in `build/local-definition-flow-review`.
