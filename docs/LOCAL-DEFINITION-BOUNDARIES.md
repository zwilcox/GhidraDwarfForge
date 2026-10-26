# Local register initialization boundaries

**CONFIRMED integration (2026-10-25):** PR62 head
`b5771e30711ff1825c6416b75f2a19eae778877b` passes all twelve jobs in
`40252798774`, independent exact-package/nineteen actual Java 21 suites,
raw five-target review, 40 native Windows tasks and both GUI hosts. Six
hosted definition-start roles/twelve exports provide 504 compiler/Forge GDB
observations; read-start (396) and stack-spill (900) regressions also pass.
Normal merge `fd0a5bac8ad3b97483253f9f6723d229edb777b9` preserves the tested
tree. Hosted receipt SHA-256:
`066960b5571e8e10cae4983dd8d97913b80c7c6d49ff9517efc7ab18ce4c8ad9`.
The separate main-push run `40256250143` remains pending. Earlier pending
notes for this PR are historical; general lifetimes and lexical scopes remain
incomplete. No release publication is included.

**CONFIRMED within the accepted profile.** An analyst's
recorded first-use instruction can initialize a register local. The prior
read-start proof omitted that case. The extension now begins availability at
the next instruction boundary, after the entire definition has executed.
It never presents the stale register value at the initializing instruction.

## Acceptance and limits

All ownership, provenance, exact register/type width, overlap, complete decoding
and straight-line leaf restrictions in [later register locals](LATER-REGISTER-LOCALS.md)
still apply. A writing first-use must contain a full-width p-code definition
of the recorded local storage. An offcut, NOP or partial definition is rejected.
A read-only first-use still requires a prior completed full-width definition.
The first later physical overwrite ends availability after that instruction;
explicit unavailable intervals cover the earlier prefix and later tail.

This is an explicitly curated function-owned binding. It adds no original
lexical scope, automatic local inference, migration, reacquisition, branch or
call-crossing proof. The compiler's nested local is deliberately distinguished
from Forge's curated local: at the kill instruction the compiler's lexical
lookup is absent, while the physical register still holds the curated value.
The independent raw register comparison establishes that boundary. No native
producer or architecture-specific mapping changes are introduced.

## Reproducible checks

`definedRegisterLocalSmoke` passes 28 real-decoder checks; the existing
`laterRegisterLocalSmoke` retains 108 checks with its writing-first-use case
updated to require availability only after completion. Nineteen packaged suites
pass on actual Java 21 with checked class origins. Local headless integration
uses Java 25, a separate observation.

The shared harness selects `defined-register-local.c` with `--first-use definition`.
Before initialization, this fixture puts the sentinel **-12345** in the physical
register. GDB must report the curated local unavailable at both the preceding
NOP and the initializing instruction, then exactly `input + 7` at the following
read and kill instructions, and unavailable again after the kill. Signed
32/64-bit values, positive/negative/wide inputs, `list`, `ptype`, `next`, `step`,
returns and normal exit are checked against compiler debug information and raw
register values. The preceding read-start package omits this location throughout.

Six x86-64/AArch64 exec/PIE/rebased-PIE definition roles pass twelve candidate
exports and six preceding-package comparisons: **756 GDB observations**.
Six read-start regression roles pass another twelve exports and **396 GDB
observations**. All use the same tested production JAR and frozen shared harness.
Repeated sidecar/source pairs are byte-identical, target/package/harness files
are unchanged, and saved programs change only Ghidra's documented backup files.
PIE/rebased inputs and normalized boundaries match; runtime biases are nonzero.

GNU and LLVM validators pass for compiler and Forge artifacts. Strict libdwarf
checking has no uncorroborated errors: inherited frame diagnostics exactly match
the original multisets, and copied `.eh_frame` bytes match. Independent review
rechecks raw location bytes, ELF symbol boundaries, recorded first-use offsets,
completed instruction boundaries, omissions, debugger values and source hashes.

```text
build/local-definition-review/acceptance.json
SHA-256 edd71cd11b7f82f4b528abc793ba61ea022739370a941c7f1a63411c739456d3
tested JAR 5b510ad6c1a7bdd7a1c52008f247eacc2b6ec3f5dc23eb6e5515682ab1681c50
actual Java 21: build/local-definition-review/packaged.etqipgp1/result.json
accepted case inventory: build/local-definition-review/final-exports.log
```

With a packaged installation and configured strict checker:

```bash
./gradlew definedRegisterLocalSmoke laterRegisterLocalSmoke
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" x86_64 --role exec --first-use definition
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie --first-use definition
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie-rebased --first-use definition
```

CI requires both first-use profiles for all three roles in both target lanes,
and both decoder suites on Linux and native Windows. The new fixture is included
in the explicit audited inventory; all five local reproducibility profiles pass.
Architecture guard controls and workflow lint pass. The new hosted checks are
**PRESENT, UNVERIFIED** until their exact-head full gate and artifact review pass.

## Retained failures

The pre-change model fails at the new positive definition case, as expected;
`baseline-model-failure.log` preserves that regression evidence. Initial case
`x86_64.exec.esq3c57o` failed an incorrectly renamed diagnostic expectation in
the copied harness; production intentionally retains the shared later-local
diagnostic. This was corrected without changing emitted behavior.

After consolidating the duplicated harness, case `aarch64.exec.0s7m1xa2`
correctly failed source-preservation validation: the agent renamed a Java helper
local during the running matrix. Only that helper changed. This mixed-source
run is rejected, with the before/after hashes and explanation retained in
`retained-harness-edit.json`. All twelve accepted cases were subsequently rerun
with frozen final harness bytes; the independent audit verifies those hashes.
Earlier successful cases are retained but do not replace this final evidence.
