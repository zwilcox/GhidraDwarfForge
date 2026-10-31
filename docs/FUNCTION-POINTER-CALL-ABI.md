# Function-pointer calling conventions

**CONFIRMED locally; hosted acceptance pending.** Function-pointer types now
retain Ghidra's calling-convention identity and receive the same compiler-profile
and MIPS signature restrictions as direct function declarations/definitions.
This closes a debugger-call bypass; it does not add support for a new ABI.
P1.7/#66 remains open.

## Defect and behavior

A typed global pointer to an x86-64 Microsoft-ABI function bypassed the direct
function's `DW_CC_nocall`. With deterministic unused-register sentinels, GDB
returned 4389 instead of 1234 and incremented the function's counter. The direct
call was already refused. LLVM accepted the defective sidecar: valid DWARF
structure alone cannot prove correct argument transfer.

`TypeGraph.SubroutineType` now carries the exact Ghidra convention name and a
separate debugger-call restriction. Extraction resolves the type's convention
against the selected program's compiler specification. A different or unresolved
convention is conservatively uncallable. The existing compiler/ELF profile,
MIPS floating, and MIPS aggregate-return policies also examine subroutine types.
Return types, explicit formal parameters, variadic status, names, and type
references are retained. No register mapping or native/JNA signature changes.

The emitted subroutine type carries `DW_AT_calling_convention` with
`DW_CC_normal` or `DW_CC_nocall` according to that evidence. GDB refuses the
unsupported pointer call before execution. It still resolves and displays the
pointer and prototype. Ordinary program execution remains unaffected; compatible
pointer calls continue to return the expected values.

These restrictions describe a type, not the dynamic provenance of every pointer
value. They cannot prove that an arbitrary runtime address or explicit debugger
cast actually matches the declared prototype. The exporter does not invent such
proof or claim to secure arbitrary debugger expressions.

## Validator compatibility decision

DWARF 5 Appendix A does not list `DW_AT_calling_convention` for
`DW_TAG_subroutine_type`. LLVM nevertheless deliberately emits this combination
for explicit function-pointer conventions, and GDB consumes it. Forge treats it
as an established LLVM/GDB extension, not as a new core-standard guarantee.
See the [LLVM 20.1.8 producer](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/lib/CodeGen/AsmPrinter/DwarfUnit.cpp)
and [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf), Section 5.10 and Appendix A.

The pinned libdwarf 2.3.2 checker initially rejected the fixed sidecar. An
untouched Clang 16 compiler-produced fixture independently reproduces the same
rejection. A fourth pinned validation-only patch recognizes precisely this pair
in the checker's existing extension table. The standard table and strict output
parser remain unchanged. Regenerating the table with upstream's generator
produces byte-identical output. The patch does not enter the shipped native
producer/consumer source patch set. See
[the validator correction record](../support/validation/README.md).

The corresponding evidence profile explicitly changes from three to four
corrections and includes the fourth patch's SHA-256. Old evidence is not silently
relabeled. The 32 metadata controls cover ELF32/64 and both byte orders: normal,
no-call, and LLVM Win64 conventions pass; invalid tag/attribute pairs, a reserved
convention, a wrong form, and a broken reference are rejected. LLVM alone misses
the wrong-form control, so both independent validators remain required.

## Local acceptance evidence

The installed package passes 51 saved-program cases:

- Six x86-64 cases: GCC and Windows compiler specifications, each with non-PIE,
  PIE, and rebased PIE. These all run on a Linux host; selecting the Windows
  compiler specification is an ABI mismatch control, not Windows-host testing.
  Previous-package controls reproduce the pointer bypass.
- Twenty-four MIPS floating cases: both byte orders, FP32/FPXX, float/double,
  and the three ELF/rebase roles. FPXX floating pointer calls are refused;
  FP32 floating and integer pointer calls work under QEMU/GDB.
- Twenty-one aggregate cases: x86-64, AArch64, ARM32, and both MIPS byte orders,
  the three roles, and both MIPS FP32/FPXX profiles. Supported aggregate and
  scalar pointer calls work; unsupported MIPS wide-argument aggregate calls
  are refused, as for their direct definitions.

Independent raw review verifies actual variable-to-pointer-to-subroutine DIE
references and calling-convention attributes, 240 correct calls and 90 refused
calls in the fixed-package GDB sessions, structural validation, unchanged
original inputs, and byte-identical repeat output pairs. Rejected x86 calls
preserve all exposed registers, the stack mapping, and counters. MIPS pointer
controls compare exposed registers/256 stack bytes for floating calls and the
existing argument/control register set/128 stack bytes for aggregate calls.
Saved program content is preserved; documented Ghidra backup-journal changes
are recorded separately.

The focused checks also pass 374 saved/reopened pointer extraction assertions,
473 compiler-profile assertions, 4,608 MIPS floating policy assertions, and
7,128 aggregate policy assertions. All 39 installed-package suites pass on an
actual Java 21 runtime. Isolated packaged native-producer tests pass on Java 21
for five target profiles. The validator configuration, strict parser, and all
97 retained-evidence controls pass. Workflow lint passes.

Raw-review receipt:
`6a441bb81bc6607d36e3d9d6b580d1438867f9ef0709444502750bbee18ca44e`.
Evidence is under `build/pointer-convention-runtime/` and
`build/pointer-convention-research/`. These are local observations, not hosted
or release acceptance. Final committed package verification, hosted checks and
normal integration remain pending.

## Reproduction

Build/install the extension and the pinned standalone validator as documented
in `AGENTS.md`. Set `DWARFDUMP` to that bundle's `bin/dwarfdump`, then run:

```bash
python3 src/test/integration/dwarfdump-subroutine-conventions.py "$DWARFDUMP"
python3 src/test/integration/function-pointer-conventions-export.py "$GHIDRA_INSTALL_DIR" --role pie-rebased
python3 src/test/integration/function-pointer-conventions-export.py "$GHIDRA_INSTALL_DIR" --compiler windows --role pie
python3 src/test/integration/mips-floating-call-export.py "$GHIDRA_INSTALL_DIR" mips32be --profile fpxx --scalar double --role exec
python3 src/test/integration/aggregate-return-calls.py "$GHIDRA_INSTALL_DIR" mips32le --profile fp32 --role pie
```

The pipeline runs the full maintained role matrices and retains failed-test
artifacts. The x86 harness optionally accepts `--previous-ghidra` for an installed
PR92-era package; its oracle distinguishes already-guarded direct calls from the
old pointer bypass.
