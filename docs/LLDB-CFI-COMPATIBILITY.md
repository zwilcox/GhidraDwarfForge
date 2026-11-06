# LLDB call-frame compatibility checkpoint (#110)

**CONFIRMED locally; hosted integration PRESENT, UNVERIFIED.** This is the first
consumer compatibility checkpoint for #110, not acceptance of its full source,
type, variable-location, image-layout or discovery matrix. #112's separate
combined validation and protected integration remain pending.

## Reproduced problem and encoding decision

LLDB 18.1.3 loads the production x86-64 sidecar and resolves its functions, but
stops unwinding at the first function in the no-CFI compiler fixture. The
independent compiler reference and the no-CFI fallback both recover eight frames
at that stop. The original Forge encoding passes GDB and structural validators.

The pinned [LLDB CIE parser](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Symbol/DWARFCallFrameInfo.cpp)
stops at an unsupported initial instruction. It does not handle
`DW_CFA_val_offset_sf`, so the stack-pointer value rule prevents it from reading
the following return-address rule. Recorded `image show-unwind` output and
unwinder logs corroborate the missing rules. On AArch64, the return register
precedes this instruction and the observed backtrace still succeeds; this does
not establish that the parser consumed the entire original CIE.

Encode a CFA-relative register value with `DW_CFA_val_expression`. Under
[DWARF 5 sections 6.4.2 and 6.4.2.3](https://dwarfstd.org/doc/DWARF5.pdf), the
expression starts with the CFA already on its stack. Nonnegative offsets use
`DW_OP_plus_uconst`; negative offsets use `DW_OP_consts` and `DW_OP_plus`.
This preserves signed 64-bit offsets without negating the minimum signed value.
No target register numbers or ABI rules move into the generic encoder.

`DW_OP_call_frame_cfa` is prohibited in these expressions. An early experimental
variant using it is retained as a rejected experiment, not as another valid
encoding or an LLDB defect. Existing original unwind sections remain unchanged.
The recovery policy, conditions, rules and evidence format do not change.

## Local evidence

- Five focused Java suites pass: encoder (362 checks), original ranges (4,275),
  original sources (1,256), projection (77 plus 19 cancellation points), and
  evidence JSON (1,521). The extension builds for Ghidra 12.0.3/Java 21.
- The independent encoder harness passes ten cases with plain and compressed
  artifacts. It covers both widths and byte orders, initial CIE rules, row
  changes, zero/positive/negative/full signed-range value offsets, large address
  gaps and corrupt-CIE rejection. GNU, LLVM and pinned strict checks pass;
  x86-64/AArch64 non-PIE and PIE runtime cases pass in GDB.
- Normal headless exports pass on both targets for non-PIE, PIE and shared
  images: 30 exports, six invalid-option preservation controls, 24 validated
  sidecars and 30 GDB sessions. Deterministic repeat and input hashes pass.
- `cfi-unwind-lldb.py` consumes the normal non-PIE exports in LLDB 18.1.3.
  Six sessions compare independent compiler references with plain/compressed
  Forge sidecars. All 90 x86-64 and 77 AArch64 ordinary instruction boundaries
  match function names, relative PCs, caller stack offsets and R12/X19 values.
  Both traces reach eight frames, cover all recursive depths and exit normally.
  Unwinder logs record use of DWARF CFI. Inputs remain byte-identical.

The AArch64 transport is QEMU user 8.2.2; the exact package/version is in the
receipt. This is not an LLDB test of the other supported GDB architectures.
The first isolated-install attempt resolved the base Ghidra installation through
a linked Utility module and encountered an old Java 25 script cache. The test
installation was corrected by copying Utility, preserving the base installation.
The failure and corrected run are both retained.

## Reproduction and remaining work

After the existing `compiler-unwind-export.py` and
`production-unwind-export.py` non-PIE runs, use:

```bash
python3 src/test/integration/cfi-unwind-lldb.py \
    <compiler-cases> <production-exports> <new-output> --lldb lldb-18
```

The combined local case directory contains both targets. CI uses `--target`
with each lane's existing case directories. The workflow pins LLDB and its
Python package to Ubuntu's `1:18.1.3-1ubuntu1` build. Linux x86-64 runtime and
QEMU AArch64 runtime use the same production exports and retain transcripts.

This new CI step is **PRESENT, UNVERIFIED** until its actual hosted run passes.
The full #110 requirement still includes source listing/stepping, types, globals,
bitfields, split/changing locations and unavailable intervals, PIE/shared load
bias, database rebases, stripped/sectionless inputs, separate discovery tests,
and the final consumer support contract. None is implied by this CFI checkpoint.

The checkpoint receipt is [lldb-cfi-compatibility.json](evidence/lldb-cfi-compatibility.json).
