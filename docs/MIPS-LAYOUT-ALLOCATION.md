# N32/N64 aggregate layout audit

**CONFIRMED defects; candidate acceptance in progress.** This extends the
allocation audit required by P2.3a/#69. It does not complete that issue or the
combined P2.3–P2.3c goal.

The owned `mips_layout_arguments.c` fixture distinguishes arrays, unions and
nested structures from direct double fields, small and padded structures, and
native 128-bit integers after odd register and stack slots. It runs under
N32/N64 QEMU in both byte orders. Every compiler-reference field has a correct
typed observation at the body marker. Compiler entry displays are retained as
observations; they are not accepted as positive values before aggregate homes
have been written. The Forge checks require every field at both markers.

## Reproduced allocation defects

The pinned Ghidra N64 input classifier recursively flattens nested floating
fields. GCC 12.4's `mips_function_arg` selects floating registers only for
direct, naturally aligned double fields of the argument structure. In the
fixture, the array occupies two general registers; the union-containing and
nested-structure arguments occupy one general register and one floating
register. The earlier copied N32 input rules inherited the same defect.

Ghidra also aligns its 16-byte integer to eight bytes. The compiler uses a
16-byte argument boundary, skipping an odd register slot or aligning the stack
offset accordingly. The old export displayed the wrong integer and following
argument. For example, the following `tail=53` displayed as `47` on big-endian
targets and `43` on little-endian targets.

The isolated candidate is now `MipsWideParameterAllocation`. It checks the
original ELF metadata, exact language/compiler pair and serialized prototype
fingerprint before computing replacements. It keeps the original return model,
automatic parameters, explicit analyst storage, saved program and DWARF types.
An allocation-only shape preserves direct double fields and treats other
structure chunks as integer bytes. A private 16-byte integer shape supplies
its ABI alignment; aligned joins skip occupied/unaligned slots. No program data
organization or decompiler compiler specification is modified.

Primary implementation evidence:

- [GCC 12.4 MIPS argument classifier and boundary rules](https://github.com/gcc-mirror/gcc/blob/releases/gcc-12.4.0/gcc/config/mips/mips.cc).
- Ghidra 12.0.3 `MultiSlotDualAssign`, `PrimitiveExtractor`, `MultiSlotAssign`
  and the selected MIPS compiler specifications, inspected from the installed
  source archive.

## Unnamed register slices and consumer boundary

The three-byte big-endian structure has a valid register-space varnode but no
named Ghidra register alias. The old extractor omitted it. The shared candidate
resolves such a slice only through a mapped register whose actual physical
extent contains it, derives its bit offset from that register's byte order,
and applies the existing whole-register lifetime proof. Incomplete decoding,
calls and writes retain their existing conservative rejection. This does not
yet extend changing-location or copy recovery for unnamed slices.

**CONFIRMED GDB 15.1 consumer defect:** the four-byte big-endian structure
already had a correct `DW_OP_regx 4; DW_OP_bit_piece 32,32` location. Raw argument
register bytes contain `40f8000000000000`, representing the expected `7.75f`
in the high half. GDB 15.1 displays zero. Its `read_write_pieced_value` applies
the offset directly when offset plus size equals the register width, selecting
the wrong half on a big-endian target. GDB 16.3 retains that implementation.
The unmodified GDB 17.1 release reads the same location correctly. The emitted
DWARF is not distorted to accommodate the old consumer.

- [DWARF register-piece semantics](https://dwarfstd.org/issues/161206.2.html).
- [GDB 15.1 expression implementation](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-15.1-release/gdb/dwarf2/expr.c).
- [GDB 17.1 expression implementation](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-17.1-release/gdb/dwarf2/expr.c).

A private GDB 17.1 source build supplies the positive consumer reference; no
system package was changed. Official archive SHA-256:
`14996f5f74c9f68f5a543fdc45bca7800207f91f92aeea6c2e791822c7c6d876`.
`support/validation/build-mips-gdb.py` verifies that archive and builds an
unmodified, Python-enabled MIPS debugger in a new private directory. It retains
commands, tool versions, build logs and source/executable hashes, and never
installs over the system debugger. The versioned builder passes locally; the
candidate MIPS CI lanes provision it for this layout test while preserving the
system-debugger coverage of existing fixtures. Hosted provisioning is still
**PRESENT, UNVERIFIED** until its required run passes.

## Current evidence and remaining acceptance

**CONFIRMED locally:** candidate v2 passes 256 exact entry/body values across
four cases in GDB 17.1, plus GNU, LLVM and the pinned strict validator. The
allocation model passes 282 checks; shared dynamic-storage tests pass 232
checks across seven target profiles. The complete workflow model/build command
passes 114 tasks. Four preceding wide-argument runtime regressions pass against
candidate v1. These are distinct package receipts, not an exact-head acceptance
claim for subsequent edits.

Candidate v1 ZIP:
`43206b894636b82f04d524b59781eccb357ba1951517803dff8db5f29a124863`.
Candidate v2 ZIP:
`db9cf1ea04d1540402b6e5eefd22da211d2a4017765f023f97e134e4eaae7333`.
Evidence root: `build/mips-layout-audit/` in the `work/mips-layout-audit` worktree.

The versioned harness is `src/test/integration/mips-layout-arguments.py`. It
accepts an installed packaged extension, ABI, byte order, optional extracted
toolchain, debugger executable and debugger data directory. It requires
compiler body values, Forge entry/body values, structural validation,
deterministic repeats and unchanged input/program bytes. The initial non-PIE checkpoint below is superseded by the expanded
layout and pipeline evidence recorded afterward.

**CONFIRMED follow-up package:** v3 preserves explicit composite alignment in
its temporary allocation shape. The versioned harness passes all four ABI/byte
order cases: 256 Forge entry/body and 128 compiler-body observations, structural
validators, deterministic repeated outputs and unchanged input/program bytes.
The targeted allocation/dynamic-storage/body-coverage suites pass 282/232/529
checks. ZIP SHA-256:
`7bd183201856850d2509d099d4ae878b55c9720b679a4ef0a52a256f24276627`;
JAR: `5cea9565f5aa2eaf70c2e7c7b49807323fe8978eb133fcc1c3f42e8bad238f3d`.
Receipts are `versioned-v3-fixed.json` and its per-case directories. The first
N64 harness run rejected identical `.dynsym`/`.symtab` labels; the corrected
harness accepts a duplicate only when its address agrees. The failed log stays
available. The source-fixture reproducibility and architecture-boundary checks
also pass. The final driver replay records and protects the selected debugger
binary and its version. Four v3 rebased-PIE wide-argument regressions also pass
(`wide-v3-regressions.json`), including two real failure exports and one
cancellation in the N64 big-endian case. These regressions cover the preceding
wide fixture; the new layout fixture still needs its own expanded layouts and
failure/lifetime tests.

**CONFIRMED expanded local matrix:** the same v3 production package passes
all 20 N32/N64, big/little-endian, non-PIE/PIE/rebased-PIE/shared/rebased-shared
combinations. An independent replay of the retained JSON checks the source-known
literal values: 1,280 Forge entry/body values and 640 compiler-body values.
GNU/LLVM/pinned strict validation, artifact/input hashes and deterministic
repeats pass. Receipts: `layout-matrix-v2.json` and
`layout-matrix-v2-review.json`. The versioned builder's debugger hash is
`2baa5b2276d963e2ca2f2d32907c6cde96b6212fd6ef7ab540a6bd022c781702`.

The first shared-library run failed because GDB 17's `info sharedlibrary`
reports the entire mapped image range, whereas the previous test assumed text
bounds. The corrected oracle reads the original loaded image's relocated
`.text` from `maintenance info target-sections` before loading either symbol
file, checks it against the mapped image bounds and subtracts the original
ELF text address. Compiler and Forge replays and all expanded cases pass;
the original failure and subsequent section/address evidence remain retained.
No production address calculation changed for this harness correction.

The versioned failure/cancellation harness composes real decompiler rejection
with this fixture, requiring the failed function to lose variable locations
while neighboring functions retain exact values. It also cancels production
copying of an independently imported padded input, checking that the previous
artifact pair and both program databases remain unchanged. The main driver
requires these controls before marking its result successful. All 20 control cases pass: 40 deterministic failure exports, 20 cancellations,
1,160 exact neighboring values and 120 symbol-only variable absences. The raw
review checks the failure artifact hashes, strict-reader reports and observation
rows. Receipts: `layout-controls-matrix.json` and `layout-controls-review.json`.
A fresh integrated shared-rebased driver replay also passes.

**PLANNED acceptance:** multiple-instruction and clobber tests, broader negative
model cases and exact-head hosted validation remain. Audit explicit composite alignment, wider
floating/return types and general delayed control-flow/storage transitions.
The call policy remains restrictive for the newly inspected aggregate types;
debugger-injected calls are not established by these argument observations.
All original rows in `TARGET-ABI-COMPLETION-PLAN.md` remain binding.
