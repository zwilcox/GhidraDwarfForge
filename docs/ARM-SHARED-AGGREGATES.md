# ARM shared-library aggregate storage

**CONFIRMED local component; hosted acceptance remains required.** The existing
fourteen-function aggregate fixture now runs as a real little-endian ARMv7
hard-float shared library, loaded by a separate libc-backed executable. Both
ordinary and `+0x2000000` Ghidra-rebased programs pass with the same production
package used by the exec/PIE tests. Production/export-native sources are
unchanged; Ghidra 12.0.3, Java 21 and libdwarf 2.3.2 remain selected.

## Actual shared loading and independent address checks

The source-built library uses `-fPIC -shared -nostdlib -nostartfiles -Bsymbolic`.
The driver uses the matching ARM hard-float libc/sysroot and an `$ORIGIN` search
path to load the stripped library. The library has real `R_ARM_RELATIVE` GOT
relocations and no executable entry point. This test does not execute the DSO
directly as a freestanding PIE, and it does not claim symbol interposition.

GDB starts with the driver, stops at its `main`, locates the exact library in
`info sharedlibrary`, and derives the bias from its live versus link-time text
addresses. Automatic shared-library debug-symbol loading is disabled. The
compiler reference or Forge sidecar is then explicitly loaded at that bias.
Every named function address must agree with independent compiler labels.

`arm_stack_shared_contract.py` records the complete audited instruction prefixes.
Each final four-word literal pool must point at the actual GOT base and the
three source-known globals used by that function. Static checking binds each
slot to a symbol-free `R_ARM_RELATIVE` relocation and its original addend.
Runtime checking reads every selected GOT slot from the inferior and requires
the relocated source-known address. The mapping-symbol boundary independently
separates instruction bytes from the final literal pool.

## Variable and reference contract

GDB typed values and a separate evaluator of the actual emitted location-list
bytes must both match source-known arguments at every checked PC. Unknown global
stores retire mixed register/stack backup proofs at these explicit boundaries:

| Object | First unavailable PC relative to entry |
| --- | --- |
| Pair and packed object | 48 |
| Three-byte object | 40 |
| Integer array | 52 |

Scalar, aligned, mixed and exhausted floating cases retain their independently
checked locations throughout their tested prefixes. This is the explicit
audited-prefix contract; the retained full-availability research mode is not
silently redefined as passing.

The compiler reference still needs bounded, raw-corroborated prologue windows.
Its shared `base_floats` keeps `b` in `r2/r3` after the GOT-offset load overwrites
`r3` at offset 52. From offsets 56 through 96, the oracle reads the surviving
`d7` copy and checks it against the C value. Every preserving instruction is
audited; all literal/GOT targets are independently checked at runtime. Each
case retains 85 compiler discrepancies across 57 exact windows, including the
eleven new floating discrepancies. Forge receives no compiler exception.

## Failure, cancellation and negative evidence

A separately compiled function is linked before the aggregates and actually
called by the driver. Its real native decompiler rejection proves processing
continues into later functions. Selecting the final library function originally
failed this assertion; that failed run is retained, and the isolation check was
not weakened. Packed, three-byte and floating functions are also rejected
individually. Failed functions retain symbol/range information without owned
parameters, types, source attributes or orphan locations. Neighbors must match
the baseline observations exactly.

Production-copy cancellation after 16 MiB preserves an existing validated
output pair. Saved program data and original library/driver bytes remain
unchanged. As in the predecessor, only the explicitly recorded Ghidra index
backup files may rotate in the cancellation project.

Each layout also rejects eight copied-test corruptions: wrong load bias, wrong
GOT base, wrong global address, a live inferior GOT write, a wrong physical
carrier, early and late gap boundaries, and a wrong compiler-reference carrier.
The latter reads `d6` instead of `d7` and must fail before excusing a typed
compiler error. Every rejection checks the exact reason and private QEMU socket
cleanup; baseline inputs remain intact.

## Local validation and reproduction

Both shared layouts pass 660 compiler and 660 Forge instruction stops, 472
required unavailable fields, sixteen deterministic failure exports, 2,488
neighboring/152 symbol-only observations, and two cancellations. Three fresh
LE exec/LE PIE/BE8 PIE regressions pass another 760 stops per variant, 24 failure
exports and three cancellations. The twelve existing PIE mutation controls
also pass with the updated helpers.

GNU, LLVM and the pinned seven-correction standalone validator pass. Four new
shared and ten existing unit tests, two thirteen-artifact fixture inventories,
Python/shell checks, actionlint and whitespace checks pass. All 103 production
source hashes still match the tested JAR
`c3eb4886ebb1d82e1d34131e27d323e80132b6e8c44a50ac4909e83e28650ade`.

Receipt in the `arm-stack-shared` worktree:
`build/arm-stack-shared/shared-v4.review.json`, SHA-256
`5d8a133e35eb6fb25d78eca08e946c76326cd0b76641f93154e35f7cdc22b026`.

```bash
python3 src/test/integration/arm-stack-shared-contract-test.py
python3 src/test/integration/arm-stack-aggregates.py "$GHIDRA_INSTALL_DIR" \
    --order little --role shared-rebased --availability-contract audited-prefix \
    --with-controls --qemu /path/to/qemu-arm \
    --gdb /path/to/gdb-multiarch --gdb-data /usr/share/gdb
python3 src/test/integration/arm-stack-shared-controls.py /path/to/passing/case
```

`FORGE_ARM32_SYSROOT` selects the matching loader/libc; `ARM32_CC`,
`ARM32_OBJCOPY` and `DWARFDUMP` select the toolchain/validator. CI includes both
shared layouts and their failure/cancellation/mutation controls. A BE8 dynamic
loader/sysroot reference has not been established; the separately validated
BE8 exec/PIE evidence does not imply BE8 shared-library support.

**PLANNED:** exact-head hosted acceptance, artifact review and normal protected
integration. The mixed-body mode documentation still lists runtime conflict/
context-change controls as model-only; inspect and resolve that gap in the full
ARM requirement audit. All original AArch64, MIPS, ARM and i386 requirements
remain in scope. This component does not close the umbrella goal or authorize
a release.
