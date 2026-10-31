# ARM and Thumb analyst-alias evidence

**CONFIRMED compiler-fixture research (2026-10-31); production alias support
remains PLANNED.** P1.7/#66 remains open. The isolated ARM mode-symbol planner
does not currently authorize analyst aliases.

## Toolchain and observed layouts

The earlier ARM compiler is retained under the `arm-unwind-fixture` worktree's
private `build/arm-toolchain` directory. It is absent from the normal PATH; the
preceding i386 regression therefore used recorded hosted ARM inputs. A fresh
private toolchain is now extracted from those recorded Debian packages plus
GCC 13.3 C++ and development packages. Package identities and hashes are retained;
no system installation or alteration of the older toolchain is required.

Four source-built instances of `retained-function-aliases.cpp` use ARMv7-A,
VFPv3-D16 hard float, DWARF 5 and unwind tables: ARM/Thumb each as exec and PIE.
All four execute successfully under QEMU. ELF symbol, instruction and unwind
inventories are retained independently of Ghidra.

- ARM function symbol values are even; Thumb function values are odd. Code and
  DWARF addresses must remain distinct from the tagged ELF values, consistent
  with the pinned [Arm ELF ABI, symbol values](https://github.com/ARM-software/abi-aa/blob/17f2cc8ee6645c1709088f4e0cb4438ce75a14ff/aaelf32/aaelf32.rst).
- The exec fixture's function bodies end at `bx lr`. PIE symbols additionally
  cover literal-pool words; Thumb PIE includes alignment padding before them.
  Symbol size is therefore not evidence of an entirely executable body.
- The existing homogeneous mode extractor checks saved decoding context,
  current per-byte TMode, instruction tiling and original bytes. Its primary
  mode planner only adds cues for selected section-backed ET_EXEC cases;
  aliases need an explicit policy for retained symbols, PIE and sectionless ELF.

Receipt: `faba119441caf12d7a1d5ad3e3eac63459911fddc4191717cede1a2c7a59cfc7`.
Evidence is under `build/arm-alias-review/`. The initial compiler invocation
failed before fixture creation because private binutils needed a command-scoped
host-library path; the corrected four-case probe passes. This is compiler/QEMU
evidence, not proof of Forge alias correctness.

## Required next proof

Keep ARM encoding decisions outside generic alias planning. Bind instruction
mode evidence to the actual entry-containing code range and its original bytes;
do not infer Thumb state from pointer width, a name or a guessed address bit.
Retain generic ownership, collision, full-body and discontiguous-range checks.
Do not solve the range issue by expanding function bodies across literal pools.

First prove compiler and unchanged-exporter observations with exact code-end
boundaries, static disassembly and native/QEMU debugger behavior. Then test a
separate tagged-symbol packaging experiment before changing production policy.
The implementation must reconcile existing static/dynamic mode information,
preserve original inventory, and diagnose unknown/conflicting mode evidence.

Acceptance needs retained/stripped and sectionless ARM/Thumb cases, exec/PIE/
rebased images, mixed-mode neighbors and indirect calls. GDB must preserve
original and analyst lookup, typed prototypes, mode-correct static disassembly,
breakpoints, source stepping, values and returns. Include malformed, changed-code,
ambiguous-mode and discontiguous/entry-interior controls. Shared-object behavior
must be proven before claiming that scope. General ARM modes and calling ABIs
are not established by these four compiler fixtures.
