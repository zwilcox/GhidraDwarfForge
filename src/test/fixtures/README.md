# Integration fixtures

`semantic.c` is a redistributable source-built fixture shared across target
architectures. It intentionally contains functions, globals, parameters,
locals, arrays, an enum, union, typedef, function pointer, and recursive
structure.

The integration preparation script applies explicit analyst register storage
to `recovered_add` parameters using each target ABI's input registers. The
exporter may emit those locations only when its instruction/p-code scan proves
the register is not written and the function contains no calls. The current
x86-64 and MIPS functions retain their input registers; AArch64 overwrites
`x0`/`x1`, providing the negative case where locations must remain absent.
ARM32 overwrites `r0` but retains `r1` in the executable/PIE roles; its shared
object overwrites both, and the role-specific tests require honest omission.
The compiler fixture also receives a fourth, otherwise-unused argument whose
ABI input register contains 31. The preparation script models that entry-live
storage as the analyst-defined local `analyst_register`; the same whole-function
overwrite/call scan must prove it stable before the exporter emits a location.

`recovered_composite` receives a known 64-bit value split across the third and
fourth ABI input registers. The preparation script models those ordered
varnodes as `analyst_composite`; little-endian fixtures put the low word first
and the big-endian MIPS fixture puts the high word first, matching Ghidra's
`VariableStorage` contract and DWARF's memory-address piece order. GDB
reconstructs `0x1122334455667788` on x86-64, AArch64, and both MIPS profiles.
ARM32 overwrites an input piece, so its composite is deliberately locationless.

The preparation script also applies a user-defined `analyst_stack` name to the
compiler fixture's `sum` stack slot. Its Ghidra incoming-stack-pointer offset is
translated with Ghidra's instruction-level stack-pointer-depth analysis. The
resulting DWARF 5 location-list expressions are checked for the target stack
register and read as 42 by GDB on every target lane without relying on unwind
information.
The function also includes two assembly marker addresses around a balanced
16-byte stack-pointer adjustment. GDB reads `analyst_stack` as 42 both before
and during the adjustment, proving two distinct location-list expressions.

The preparation script adds a favorite Ghidra `packed_flags` structure with
3-bit and 5-bit unsigned fields. This exercises real Ghidra bit-field
extraction and target-endian `DW_AT_data_bit_offset` emission; every target
lane validates the DIE and GDB `ptype` result.

Build the current non-PIE reference and stripped inputs with:

```bash
make -C src/test/fixtures all
```

The default matrix is x86-64, AArch64, ARM32, MIPS32 big-endian, and MIPS32
little-endian, each as non-PIE `ET_EXEC` and PIE. The ARM32 profile is ARMv7
hard-float, little-endian ARM state. Reference files retain compiler DWARF 5
for test-oracle and diagnostic use. `.stripped` files are the inputs intended
for Ghidra.

Each target also has `semantic.exec.no-build-id.{reference,stripped}` built
with `--build-id=none`. Its Forge sidecar must remain free of a build-ID claim
and load through the documented explicit `symbol-file` workflow.

Each target also has `semantic.exec.no-sections.stripped`, an executable whose
ELF section-header table has been removed (`e_shoff`, `e_shnum`, and
`e_shstrndx` are zero). This models firmware and BusyBox-style inputs that are
loadable from program headers alone. The Forge sidecar writer must create a
fresh section table and section-name string table for this case; an absent
input section table is not an error.

The Makefile requires the corresponding GNU cross-compilers and binutils.
Runtime integration for non-host targets additionally requires QEMU user-mode
and a matching multi-architecture or cross GDB. Cross-compilation or headless
Ghidra import by itself is not a complete architecture-support test.

After installing the current extension, exercise import and target metadata
detection for every fixture with:

```bash
src/test/integration/headless-preflight.sh "$GHIDRA_INSTALL_DIR"
```

This preflight is intentionally weaker than the future integration suite: it
does not enable native export or run validators/GDB.

With `qemu-user-static` and `gdb-multiarch` installed, validate the non-host
fixture/runtime/debugger infrastructure against the compiler-DWARF reference
files:

```bash
src/test/integration/qemu-gdb-oracle.sh
```

That harness runs AArch64, ARM32, and both MIPS byte orders, checks a function
breakpoint and arguments, performs source stepping, prints a local, and waits
for normal process exit. It is an oracle/infrastructure test, not a Forge
sidecar test; the future exporter acceptance harness will load `.dbg` instead
of the reference binary's compiler DWARF.
