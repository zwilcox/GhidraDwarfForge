# AArch64 computed parameter allocation

**CONFIRMED local defect and candidate correction; acceptance in progress.**
Ghidra 12.0.3's baseline default prototype permits a composite argument to span
an integer register and the incoming stack. With seven integer arguments and
a 16-byte structure, it assigns `x7` plus `Stack[0]:8` to the structure and
`Stack[8]:8` to the following scalar. GCC 13.3 puts the whole structure at
`Stack[0]:16` and the scalar at `Stack[16]:8`. The original Forge sidecar
therefore displays three incorrect fields, although its DWARF validates.

The original failing fixture is retained at
`build/test-results/aarch64-abi/exec.56pzt74z`. Compiler GDB passes all 357
instruction stops after the harness uses GDB's decimal formatter for 128-bit
integers; Forge has no correct observations for either structure member or
its following scalar. GDB 15's Python `int(Value)` cannot convert integers wider
than eight bytes; its typed decimal formatter and register bytes can.

## Correction and limits

[AAPCS64 2025Q4, rules C.12–C.15](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aapcs64/aapcs64.rst#parameter-passing)
require the entire composite to fit in the remaining general registers or to
move to the stack. The next stack address then advances past the complete
argument. This also affects later alignment and indirect-pointer slots.

The target policy creates an isolated copy of the selected Ghidra prototype.
It disables register-to-stack splitting in the final general-register join
rule and adds a fallback that places the whole argument on the stack and
consumes the remaining general registers. The existing Ghidra allocation
engine handles the remaining types, alignment, FP registers and automatic
parameters. No hand-built second argument allocator is introduced.

The correction requires all of the following:

- The validated little-endian ELF64 AArch64 metadata, `v8A/default` language
  and compiler selection, and resolved default function convention.
- Dynamic storage, with a known 9–16-byte structure/union actually split
  between registers and stack. Unknown and undefined argument classifications
  do not acquire a guessed ABI class.
- An exact match to the audited Ghidra 12.0.3 default prototype serialization,
  SHA-256 `6ad78c7504e89518ca8205c4b78b99177bd49726c966d46074888b31e50afa25`.
- The original prototype must reproduce every saved effective argument's
  storage and flags. Return and automatic-parameter inventories must agree.
  Every changed carrier must remain the same size and kind and become one
  valid stack slot. Unexpected differences fail the export before publication.

Explicit custom storage is authoritative and is not changed. Named arguments
of variadic functions use the same validated allocation; this does not claim
`va_arg` reconstruction. An unrecognized language/compiler/ELF profile or a
changed default prototype is outside this correction's contract.

The saved program and compiler specification are never modified. Extraction
passes corrected stack carriers into the existing location and indirect-value
analysis, with the original parameter ownership checks intact. Diagnostics
record each old and new location. Types, names, return types and analyst
annotations remain those of the saved program.

**Material limitation:** the generated C remains Ghidra's decompiler output.
The correction fixes DWARF locations; it does not rewrite a decompiler expression
that was produced using Ghidra's incorrect original allocation. The diagnostic
explicitly identifies this distinction. The C is synthetic, and no original
compiler-source semantics are claimed for those expressions.

## Expanded fixture and validation

The ABI fixture now has fifteen functions. In addition to the original nine
integer/FP exhaustion, direct/indirect aggregate, hidden-buffer and HFA cases,
it covers narrow signed/unsigned stack values, 128-bit register/stack alignment,
a composite that cannot fit in one remaining register, subsequent aligned and
indirect-pointer arguments with an independent FP argument, and fixed named
arguments in a variadic function.

The shared-library variants use a separate PIE driver and the stripped target
library. GDB keeps automatic library-symbol loading disabled, waits for the
loader, derives load bias from the library's actual mapping and link-time text
address, and explicitly adds the compiler or Forge symbol file. Original and
curated function names must resolve to the same actual runtime addresses;
curated names must be absent before adding the Forge sidecar. Shared and
rebased-shared runs use the same exporter and value assertions as executables.

Every role requires repeated read-only exports, GNU/LLVM/pinned strict checks,
exact typed values at multiple PCs, raw ABI entry/return bytes and independently
decoded location expressions. The allocation checks bind actual stack offsets,
widths and encodings; the indirect checks follow the shifted pointer carrier.
Failure controls use an actual native instruction limit on one decompilation;
other values and returns must still pass. Cancellation occurs in production ELF
copying and must preserve the previous output pair. Input, module and saved
program database hashes are retained and rechecked.

The model smoke test exercises actual compiler specifications across register
exhaustion boundaries, ELF flags/OS ABI and language/compiler negatives. It also
covers subsequent 128-bit alignment, shifted indirect pointers, independent FP
allocation, hidden-return parameter ordinals, named variadic arguments,
undefined types, explicit custom storage, cancellation and repeatability.
The existing cross-architecture dynamic-parameter and composite-order suites,
indirect-parameter and stack-value suites remain required regressions.

## Reference observations

The existing exact GCC HFA/indirect-entry calibration remains. The new chained
argument fixture exposes another prematurely named pointer: GCC describes `x7`
at entry before `ldr x7,[sp,#48]` executes. Only that function's entry PC and
exact instruction bytes qualify. Raw ABI memory and all source-known argument
values must agree at that stop; the incorrect compiler display or access error
is retained. Subsequent compiler observations and every Forge observation remain
strict. Changed bytes/offsets and unrelated function names are rejected by
mutation tests. `FORGE_AARCH64_ABI_STRICT_REFERENCE=1` retains the failing
uncalibrated reference reproduction.

Adding compiler structural validation exposed GCC's `DW_OP_GNU_uninit` in an
optimized driver-local aggregate, which LLVM 18 could not decode. Declaring the
driver's result aggregates volatile keeps their observable stores and removes
that reference-only expression. The callee fixtures, source-known arguments and
strict validators remain in place; the original failure is retained under
`build/test-results/aarch64-abi/exec.icvllbr4`.

## Reproduction and outstanding acceptance

```bash
./gradlew aarch64ParameterAllocationSmoke dynamicParameterStorageSmoke \
    dynamicCompositeOrderSmoke indirectParameterStorageSmoke stackValueFlowSmoke
for role in exec pie pie-rebased shared shared-rebased; do
    python3 src/test/integration/aarch64-abi.py "$GHIDRA_INSTALL_DIR" \
        --role "$role" --with-controls
done
```

**CONFIRMED final local candidate matrix:** all five roles pass with package
SHA-256 `5b05d5553274c30eba1686b75e2e9334b601c7657730db58a64550deecd233b3`
and installed JAR SHA-256
`57a720a4212e2ed215c39683a48a663f7c1bd0da44c813e168545191df862779`.
The final cases are `exec.ovmg0k8i`, `pie.l92rqnta`,
`pie-rebased.giytye4m`, `shared.bjtm1il6` and
`shared-rebased.ojj4kmuw` beneath `build/test-results/aarch64-abi/`.
There are 4,076 baseline compiler/Forge instruction observations and 1,753
additional Forge observations after genuine decompiler failure, ten deterministic
failure exports and five production-copy cancellations. Compiler and Forge
artifacts pass GNU, LLVM 18.1.3 and pinned strict validation. Raw review confirms
whole-stack structures, later alignment, narrow signedness and the indirect
pointer at entry-stack offset 48 followed by its loaded register. The input,
module and script hashes were independently rechecked after the matrix; 186
files are protected per executable role and 187 per shared role. Receipt:
`build/abi-completion/matrix-v3-review.json`.

Actual Java 21 model checks pass: allocation 670, indirect parameter 34 and
stack value flow 332. The unchanged dynamic-parameter and composite-order
regressions previously passed 154 and 1,484 checks respectively.

**CONFIRMED packaged regressions:** rebased vector storage with real failure/
cancellation controls (`pie-rebased.hdhwl0no`), x86-64 stack transitions
(`x86_64.pie-rebased.larhtz19`), positive AArch64 selection
(`v8A.default.0.0.0x0.pie-rebased.d9hqlm4v`), AppleSilicon selection
(`AppleSilicon.default.0.0.0x0.pie-rebased.s60q4nco`) and unsupported ELF flags
(`v8A.default.0.0.0x1.pie-rebased.p0xhc6oi`) all pass with the same installed
package. These preserve custom storage, generic lifetime behavior and the
existing guarded-call selection contract. The big-endian MIPS FP32 double-call
regression also passes (`mips32be.fp32.double.pie-rebased.fmt9i9du`), preserving
the existing independent architecture policy. The fixture inventory/reproducibility
guard, four exact-reference-window tests, architecture isolation, actionlint,
Python compilation, shell syntax and whitespace checks also pass.

**PRESENT, UNVERIFIED as a finished component:** final CI and protected
integration still require reconciliation.
Earlier candidate results are historical and do not replace this matrix.
The source inventory includes the new shared fixture header. Both host smoke
lists and the AArch64 runtime lane include the new checks. P2.3/#68 and all
other original target requirements in #69–#71 remain open.
