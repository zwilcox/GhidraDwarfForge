# AArch64 SIMD lane storage

**CONFIRMED locally; hosted acceptance pending:** the candidate adds a separate
128-bit SIMD storage fixture to the AArch64 integration lane. Non-PIE, PIE and
rebased-PIE runs pass all six functions, including failure/cancellation controls.
It changes no production exporter, native binding or target mapping. P2.3/#68
and the related target issues remain open until their full requirement maps
are satisfied.

## Representation and acceptance

The source-built C fixture uses four signed 32-bit integer lanes and four
32-bit floating-point lanes. Saved analyst signatures express the same layouts
as four-element Ghidra arrays with explicit 16-byte storage. The tests retain
the analyst type and storage across read-only project reopening and export.
They do not identify an ordinary array as a native compiler vector type.
The emitted types are typedefs and ordinary DWARF arrays; they do not acquire
`DW_AT_GNU_vector` merely from a register name or a type name.

Six functions require independent, instruction-by-instruction GDB observations:

| Function | Required storage and behavior |
| --- | --- |
| `vector_plain` | Four distinct signed lanes in the incoming vector register; unavailable after destruction. |
| `vector_copy` | A full-width copy to a second vector register survives clearing the original register. |
| `vector_stack` | A 16-byte spill survives actual clearing of all 32 vector registers; a reload provides the value after the spill slot is released. |
| `vector_alias` | An unproven intervening store retires the spill identity; its unavailable location must not reappear on reload. |
| `vector_float` | Four distinct floating-point lanes, including negative values, and an honest clobber gap. |
| `vector_stack_arg` | The ninth vector argument arrives in 16 bytes at the caller's stack pointer. |

Raw DWARF expressions are decoded independently of GDB's value display. Actual
register or memory bytes must agree with all four source-known lane values at
every exported location. The register-clearing functions must reach a stop
where all 32 vector registers are zero. Every function must return the expected
lanes and the original process must exit successfully.

The custom array signatures retain `DW_CC_nocall`: a reconstructed lane layout
does not establish the debugger's native vector calling convention. All six
attempted Forge calls must be rejected with registers and 256 stack bytes
unchanged. Return storage is checked using raw `q0` bytes and the exported type;
this is not a claim of automatic native-vector `finish` display or injected-call
support. Those operations require a defensible native vector type model.

The same packaged exporter runs on stripped non-PIE, PIE and rebased PIE inputs.
Each role requires deterministic exports, source lookup, GNU/LLVM/strict
libdwarf checks, unchanged original and program database bytes, two real native
decompilation-failure exports with surviving neighboring values, and production
ELF-copy cancellation that preserves the previous output pair.

## Compiler-reference investigation

The initial GCC 13.3 fixture correctly spilled the value but described it in
`v0` until the end of a 32-instruction inline-assembly block. After the first
instruction cleared `v0`, GDB displayed zero lanes instead of the original
parameter. Selecting the physical owning frame fixed an earlier inline-scope
lookup problem but did not fix this incorrect compiler location. An explicit
memory operand also failed to fix the location. A Clang 16 alternative reported
the copied parameter unavailable and did not satisfy the strict reference test.

The maintained fixture declares an empty, all-vector-register clobber before
the real clobber block. This establishes a compiler debug-location boundary
before the first actual register clear. On the inspected GCC 13.3 non-PIE
fixture, the entire `.text` section before and after this declaration has the
same SHA-256:
`c70199b19c8a0734701c964ebc612788161ffda43aca40a2755d793da75182ff`.
Thus the instruction-level storage challenge is unchanged. There are no
exceptions to expected compiler or Forge runtime values in the maintained
harness. Failed alternatives and instruction comparisons are retained under
the ignored `build/vector-research` directory.

The pinned libdwarf 2.3.2 checker has no allowed form class for
`DW_AT_GNU_vector` in `src/bin/attr_form/attr_formclass_ext.list`. GCC emits that
attribute as `DW_FORM_flag_present` on its two vector array types; GNU and LLVM
accept the reference. The reference-only helper retains the original failed
strict report, binds exactly two diagnostics to the independently decoded
integer/float array DIE offsets, and validates the remaining report with the
unchanged shared checker. Five mutations must reject unrelated diagnostics,
changed forms/categories, incomplete output and incorrect offsets. Its receipt
says `EXPLAINED_COMPILER_EXTENSION`, not that the raw strict check passed.
Forge's ordinary array types pass the strict checker without this accounting.

## Reproduction

The final local run of the reviewed harness records:

| Role | Result directory | Compiler / Forge / failure instruction stops |
| --- | --- | --- |
| Non-PIE | `build/test-results/aarch64-vector/exec.bud_ihkm` | 119 / 119 / 119 |
| PIE | `build/test-results/aarch64-vector/pie.krhrto6n` | 119 / 119 / 119 |
| Rebased PIE | `build/test-results/aarch64-vector/pie-rebased.1_jee4mj` | 119 / 119 / 119 |

All nine runtime processes exit successfully: 1,071 instruction observations,
33 unchanged-state call rejections, six real failure exports and three real
cancellations. GNU, LLVM and strict Forge checks pass for each baseline and
failure artifact. All three compiler references retain the explained extension
diagnostics and pass five diagnostic mutation controls each. Input, module and
saved program hashes were rechecked after the complete runs.

`build/vector-research/matrix-receipt.json` binds these results to the installed
production JAR SHA-256
`12b76f077e7570f0ee6b7b17396a93589e1c4cb9333df5b05141f033739cd6a6`.
The fresh Java 21 extension build produces that same JAR. `actionlint`, Python
compilation, shell syntax and whitespace checks also pass. Hosted validation
and protected integration remain pending; no umbrella issue is closed here.

Use the selected Ghidra 12.0.3 installation with the assembled package, Java 21,
the pinned strict checker in `DWARFDUMP`, AArch64 GCC/binutils, QEMU user mode,
LLVM and GDB multiarch:

```bash
for role in exec pie pie-rebased; do
    python3 src/test/integration/aarch64-vector.py "$GHIDRA_INSTALL_DIR" \
        --role "$role" --with-controls
done
```

The runtime CPU is explicitly `cortex-a53`. Each unique result directory retains
compiler and Forge observations, return bytes, raw location intervals, all
validator logs, input/module hashes, before/after project hashes and failure/
cancellation receipts. CI retains these through the existing target artifacts.
