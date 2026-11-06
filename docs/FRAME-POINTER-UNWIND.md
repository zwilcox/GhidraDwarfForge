# Compiler frame-pointer recovery (#112)

**CONFIRMED locally; hosted acceptance pending.** The unchanged freestanding C
fixture now has an explicit `--frame-pointer keep` compiler-reference mode.
The existing omitted-frame-pointer mode remains the default. Both independent
builds must be byte-identical, and disassembly must show the recursive function
establishing RBP from RSP or X29 from SP; passing a compiler flag alone is not
accepted as evidence. The stripped input retains the reference's allocated bytes
and program headers and contains no original unwind metadata.

Both x86-64 SysV and AArch64 AAPCS64 non-PIE cases pass the real recovered-frame
export path and normal wrapper. As with the omitted-frame-pointer compiler
fixture, the unchanged global increment requires an explicitly acknowledged
stack-separation condition. Strict mode continues to refuse that call group;
frame-pointer use does not establish memory separation.

The matrix passes 28 exports, ten failure/invalid-option controls, sixteen
GNU/LLVM/pinned strict sidecars and 42 GDB sessions. It includes original/rebased
extraction, compressed/plain output, deterministic generations and normal
four-artifact publication. The production exporter and installed package are
unchanged from the preceding production-entry checkpoint.

The additional caller-value oracle compares every executed ordinary boundary
with independent compiler CFI, including actual DWARF unwinder selection. It
reads RBP or X29 for every observed frame and normalizes nonzero stack addresses
against the initial stack pointer. Zero remains an explicit zero. It requires
multiple distinct recursive frame-pointer values so equality of unused or
unavailable registers cannot satisfy the test. Both normal conditioned and
compressed exports agree at all 99 x86-64 and 85 AArch64 stops. Existing saved
R12/X19 witnesses, caller PCs, stack offsets, backtraces, recursive branches and
normal exit remain checked. The original return/finish oracle also passes.

No-CFI and disabled-DWARF controls remain independent: x86-64 does not recover
all required witnesses, while AArch64 recovers the reference chain through its
fallback unwinder. The latter is why an apparently correct backtrace alone is
not acceptance evidence for generated CFI.

Reproduce using the same pinned Ghidra/native/checker installation as the normal
compiler harness:

```bash
python3 src/test/integration/compiler-unwind-export.py build/compiler-frame-pointer \
    --frame-pointer keep --ghidra "$GHIDRA_INSTALL_DIR" --dwarfdump "$DWARFDUMP" \
    --libdwarf "$LIBDWARF" --libdwarfp "$LIBDWARFP"
python3 src/test/integration/production-unwind-export.py build/compiler-frame-pointer \
    build/production-frame-pointer --ghidra "$GHIDRA_INSTALL_DIR" --dwarfdump "$DWARFDUMP" \
    --libdwarf "$LIBDWARF" --libdwarfp "$LIBDWARFP"
python3 src/test/integration/frame-pointer-gdb.py build/compiler-frame-pointer \
    build/production-frame-pointer build/frame-pointer-values
```

CI runs these cases in both target lanes. The optional caller-value branch was
added after the compiler/normal-export matrices completed and was then exercised
on their retained, hash-bound artifacts. The prior helper version and its hash
are retained with those matrices; the ordinary branch is unchanged. See
[the checkpoint receipt](evidence/frame-pointer-unwind.json).

This establishes the named compiler layout, not dynamic stack allocation,
arbitrary frame-pointer manipulation or every compiler strategy. Actual
noncontiguous-body export/runtime coverage, native Windows acceptance, the full
current-head hosted gate and final #112/ADR acceptance remain required. LLDB
and build-ID installation remain separate later goal items.
