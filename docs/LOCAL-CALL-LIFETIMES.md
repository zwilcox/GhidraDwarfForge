# Saved local identities across calls

**CONFIRMED local register checkpoint; full call composition incomplete.**
P1.11a/#67 and P3.3/#73 remain open. This component connects saved later-local
definitions to the existing fully decoded direct-call graph proof. It does not
finish callee memory effects, stack restoration, or the final integration gate.

**Current extension:** `CALL-MEMORY-EFFECTS.md` supersedes the memory-omission
limit and missing branch/loop/split controls described in this initial
checkpoint. Its remaining acceptance list is still open.

## Behavior and evidence

The previous scope package (`64c91bc6756cac18b9e471949563839fa53be30c39c2afccbbd3006c5c8ac36d`)
omits a saved local in R12/x19 even when its existing call summary proves that
register unchanged. Real Java 21 models reproduce zero local intervals versus
three intervals for an otherwise identical no-call control. Two source-built
non-PIE compiler/Forge comparisons independently reproduce the unavailable
local through one and two calls. Their immutable exports and validators pass.

The local decoder now requires both saved caller ownership and a complete
inspected call graph. A call's local successor is its return fallthrough; its
callee entry is never inserted into the caller worklist. A surviving register
requires both the selected callee ABI's unaffected declaration and absence of
physical writes throughout the inspected graph. Partial writes also retire it.
Unknown callees and incomplete instruction bodies remain rejected. Register
definitions, joins, explicit merged assignments and overwrite boundaries retain
their existing identity rules.

The same inspected-call evidence reaches stack-owned and merged-stack local
analyses, enabling their defensible pre-call intervals. They still retire the
logical local at an unmodeled memory effect, including old register copies:
preserving bits does not prove that a callee left the logical stack object
unchanged. No caller-slot survival or restored affine stack pointer is claimed.

`LocalCallLifetimeSmoke` passes 242 checks on actual x86-64/AArch64 language
models: preserved/clobbered/partial/volatile registers and rejected call-instruction definitions, missing callees, included
body holes, cancellation, merged register assignments, stack loads, stack-only
storage, merged stack assignments and stale-slot reload controls. Eight suites
also pass on actual Java 21 against the packaged production JAR, with class
origins checked. Gradle's separate build/smoke runs use Java 25 with Java 21
bytecode; those are not the actual Java 21 receipt.

Six source-built runtime cases cover both primary architectures in non-PIE,
PIE and rebased-PIE roles. Twelve immutable candidate exports are deterministic;
raw DWARF location lists contain precisely the R12/x19 interval after definition
and before restoration. Compiler/Forge GDB runs provide 882 caller instruction
observations and 270 callee observations, including 207 available Forge values
and 72 checked function returns. They prove the initialization gap, one/two
calls, signed values, restored-register gap, source lookup and type lookup.
GNU, LLVM and pinned strict validation pass; original, module, harness and
saved-program preservation checks pass. AArch64 executes under QEMU.

Eight existing runtime regressions also pass: local control flow, merged local
assignments, stack control flow and mutable stack mappings on both targets.
The new fixture is included in the reviewed source inventory, both host model
lists and the x86-64/AArch64 three-role CI loop. The x86-64 reproducibility
inventory, workflow lint and script syntax checks pass locally. Hosted checks
for this new component are **PRESENT, UNVERIFIED**.

## Reproduction and retained failures

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew localCallLifetimeSmoke localDefinitionFlowSmoke mergedLocalLifetimeSmoke stackLocalLifetimeSmoke stackValueFlowSmoke buildExtension
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Run all three roles on both targets with actual Java 21 and the pinned
`DWARFDUMP`. `--expect-baseline-gap` is an explicit old-package reproduction,
not candidate acceptance. Candidate CI never passes that option.

Evidence is retained in the `local-call-lifetimes` worktree under
`build/local-call-review`: `matrix.json`, `regressions.json`,
`java21/receipt.json`, and `checkpoint.json`. Checkpoint SHA-256:
`e061db4c14ca61ab7095c3bc6585817b86d12f666322d8420d3632e80a0a9e2c`.
Tested production JAR SHA-256:
`d2695509eec0abd11dfdd5c5069e421965a815eddea8cdc23e79bfcb273321c4`.
All 84 production sources match the packaged source archive, and all 314
production class files have Java 21 bytecode versions. No native ABI changed.

Retained failures are not counted as passes:

- The new model test fails against the preceding implementation at the first
  pre-call availability assertion.
- LLVM 18.1.3 verification of the initial compiler reference stalls with an
  array-loop test driver, including with debuginfod disabled. The fixture's
  unrelated driver was simplified to ordinary `round_values` calls; its target
  functions and call scenarios remain. Fresh compiler/Forge runs then pass
  all validators. The LLVM root cause is **UNCERTAIN**; the initial artifacts,
  timeouts and successful direct GDB observations remain in the evidence tree.
- Review reproduced a call-definition bug in the initial candidate: raw CALL
  p-code writes to SP/LR precede callee execution and cannot establish a
  return-time local value. All local paths now reject call-instruction
  definitions; the corrected package passes fresh model and runtime suites.
- The first mapped-local expectation incorrectly assumed that a preserved
  register proved a stack-owned logical object unchanged. Existing memory
  invalidation correctly retires it. The corrected control explicitly requires
  that gap until a separate callee memory proof exists.
- The first Java 21 origin checker treated VM-generated lambda origins as JAR
  URLs. It now checks ordinary production classes against the JAR; the corrected
  eight-suite run passes. The initial checker failure is retained.

## Remaining acceptance

**PLANNED:** extend the call-specific runtime controls to branches, loops,
discontiguous bodies, native clobbers and saved merged identities. Establish
callee memory effects and return-time stack state before retaining caller slots
or stack-owned identities. Unknown aliases, passed pointers, partial overlap,
released slots and incomplete piece identities must stay unavailable. Apply
these proofs independently to pieces and intersect them with lexical ownership.
Complete genuine failure/cancellation composition, exact target/host/package
checks and protected integration before closing either umbrella.
