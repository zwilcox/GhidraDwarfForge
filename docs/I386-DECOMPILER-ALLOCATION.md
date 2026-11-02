# i386 decompiler allocation and analyst call overrides

**CONFIRMED locally; hosted acceptance pending:** the selected i386 extended
floating-return allocation now also reaches the native decompiler. The emitted
C body and token-derived lines use the corrected storage. This follows
[I386-EXTENDED-RETURN.md](I386-EXTENDED-RETURN.md) and
[FLOATING-TYPE-LAYOUT.md](FLOATING-TYPE-LAYOUT.md); it does not complete #71 or
any of the full P2.3–P2.3c requirements.

## Contract

The selected baseline remains Ghidra 12.0.3, Java 21 and libdwarf 2.3.2. The
existing i386 ELF/language/compiler/prototype fingerprint gates the correction.
Explicit function storage remains authoritative. Other target source passes
use the existing DecompInterface path. Native producer declarations are unchanged.

GhidraAllocationDecompiler captures the original callback's typed Encoder
operations and replaces the effective return carrier and parameter mappings.
It preserves the original function attributes, caller-specific extrapop,
nonparameter locals, jump-table data and analyst overrides. A transient Function
view supplies corrected signature encoding only: HighFunction deliberately skips
DB overrides for non-FunctionDB implementations, so replacing the complete
function encoding would silently discard analyst knowledge.

Analyst call-site FunctionSignature overrides also use the faulty dynamic
allocation. A real helper fixture reproduced native decompilation failure:
`Symbol $$undef00000001 extends beyond the end of the address space`.
Removing the override in a discarded read-only session made the same caller
succeed, isolating this second path. The correction preserves each override's
formal types, names, locks, convention, varargs and call address, while supplying
validated computed storage to its otherwise empty address fields. Explicit
address fields are never replaced. Unsupported conventions remain unchanged.

No saved Function, datatype or compiler specification is edited. The native
result supplies both C text and token addresses; no textual signature/body
rewrite is used. The capture preserves wire types (including signed/unsigned
integers, indexed strings, address-space forms and opcodes). It rejects invalid
shapes, changes to unrelated local symbols, more than 100,000 encoding events,
nesting beyond 128 or text exceeding 4,194,304 Java string units. Capture and
replay check cancellation. Existing per-function failure isolation handles a
rejected encoding without inventing source evidence.

## Validation

Local evidence is in the `i386-source-view` worktree under
`build/i386-source-view`. Candidate `ghidra-call-wired-v4` was assembled through
`support/assemble-release.sh`; its JAR SHA-256 is
`d8ebbd98ebce2fad1d129dcc597c6752eecf87bfff0d2f3d6bac70d3b656970a`.
`production-sources-wired-v4.json` matches all current production sources.
`validation-v4.json` records the five accepted case directories and result hashes.

The libc-backed fixture now contains a genuine extended-floating helper call
and a saved analyst call-site override. Four i386 roles (exec, sectionless,
PIE and rebased PIE) and the x86-64 global-layout regression pass ten repeated
packaged exports. Compiler and Forge GDB checks agree on scalar arguments,
typed returns, sizeof, array stride, structure fields and floating objects.
For each i386 role, source-level `step` enters the helper with value 3.75,
`list` shows the corrected signature, and both helper and caller return 3.875.
The x86-64 case retains its existing ordinary float/double and global-layout
scope; it is not an x86-64 extended-return claim.

GNU ELF/DWARF views, LLVM verification and the pinned strict checker pass.
Known inherited x86-64 GNU FDE alignment messages are corroborated against
original frame bytes by the existing strict policy; they are not raw
zero-diagnostic output. Inputs, packaged files, saved signature/override
observations and persistent program files remain unchanged. The exact existing
journal/index backup housekeeping is recorded separately. Repeated sidecar and
source bytes are identical.

Each i386 role additionally passes a real native instruction-limit failure in
the helper, successful neighboring corrected caller source, cancellation inside
the allocation callback, and a fresh successful pass after cancellation. No
partial source object returns on cancellation. These source-pass tests do not
replace the existing whole-export atomic-publication tests.

Six suites pass in `models-v2.log`: allocation decompiler (28 checks), i386
allocation/override selection (1,246), floating layout (73), formal return (348),
dynamic parameter storage (232), and synthetic source. They cover typed replay,
budgets, cancellation, real DB overrides, unchanged locals, caller-specific
extrapop, unknown metadata preservation and explicit override-storage refusal.
Both host jobs run the new model suite; the existing x86-64 target job runs the
expanded runtime harness. Workflow actionlint and diff checks pass.

Reproduce with the packaged Ghidra installation and existing tool requirements:

```bash
./gradlew allocationDecompilerSmoke i386ParameterAllocationSmoke floatingTypeLayoutSmoke formalFunctionReturnSmoke dynamicParameterStorageSmoke syntheticSourceSmoke
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role exec
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role sectionless
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role pie
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role pie-rebased
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --target x86_64
```

## Retained failures and integration

`wired-v2` is explicitly invalid: compilation failed and an older ZIP was
packaged by faulty sequential orchestration. It is not evidence for this source.
`wired-v3` built correctly but fails the helper override, motivating the separate
call-site correction; that failure and the discarded no-override probe remain.

PR145 run 41405692129 failed all five target lanes at fixture inventory, before
export tests, and skipped Windows-host. The inventory omitted the reviewed
`i386-extended-return.c` introduced in PR144. This change registers that exact
source; it does not loosen the inventory check. The full x86-64 fixture
reproducibility check now passes locally. The failed hosted run remains failed.

Exact-head hosted acceptance, protected integration, broader i386 vector,
aggregate and additional convention requirements, and the remaining original
AArch64/MIPS/ARM rows remain open. No release or issue is completed here.
