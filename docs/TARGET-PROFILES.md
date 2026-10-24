# Tested ELF and ABI profiles

**CONFIRMED:** the five Linux target lanes exercise the production exporter,
independent ELF/DWARF validators, and native or QEMU/GDB behavior. This document
describes the profiles and storage cases actually tested. An ELF machine number
or a successful import does not establish support for every ABI of that CPU.
Windows x86-64 is a Ghidra host; it does not imply Windows target-ABI support.

This assessment covers the exporter at `1f2a46b`. Subsequent feature branches
need their own behavior evidence before extending these claims. See
[VALIDATION.md](VALIDATION.md) for the recorded commands and hosted runs.

## Current fixture profiles

| Lane | Tested profile | Distinguishing evidence |
|---|---|---|
| `x86_64` | Linux System V, ELF64, little endian, LP64 | `EM_X86_64`; Ghidra `x86:LE:64:default` with GCC compiler specification |
| `aarch64` | Linux A64, ELF64, little endian, LP64/AAPCS64 | `EM_AARCH64`; Ghidra `AARCH64:LE:64:v8A` |
| `arm32` | Linux ARMv7-A, ELF32, little endian, EABI5 hard float, ARM state | `-marm -mfpu=vfpv3-d16`; ELF flags `0x05000400`; ARM attributes identify VFP register arguments |
| `mips32be` | Linux MIPS32r2, ELF32, big endian, O32, toolchain-default FPXX hard float | ELF flags `0x70001007`; ABI attributes identify 32-bit GPRs and FPXX-compatible FPU use |
| `mips32le` | Same MIPS32r2/O32 profile, little endian | Same ISA/ABI flags and attributes, opposite ELF byte order |

The ordinary fixtures use `-O0 -g3 -gdwarf-5 -fno-omit-frame-pointer` for the
compiler oracle. Ghidra/runtime inputs have compiler DWARF removed. Each lane
covers non-PIE, PIE, shared objects, partially stripped inputs, absent build IDs,
and absent section tables. Special rebase/layout fixtures test address handling
without introducing another ABI. Input flags and attributes are inspected with
`readelf -h -A`; Ghidra language and compiler-specification identifiers are a
separate part of the evidence.

ARM startup objects may advertise Thumb-2 even though the recovered fixture
functions are compiled in ARM state. Ghidra's generic ARM v8 language name does
not establish ARMv8 instruction coverage. Similarly, readelf's generic MIPS
machine label does not replace the MIPS32r2 ISA flags/attributes.

## What the variable tests prove

**CONFIRMED:** the common tests cover curated integer signatures, types and
globals, plus a stack local addressed correctly before and after stack-depth
changes. Stable GPR
parameters and an entry-live register local have positive value checks where
their storage survives. Overwritten registers are deliberately unavailable.
ARM32's current composite/register-local cases prove omission after overwrite;
they are not positive proofs of those values.

The composite fixture uses analyst-curated pieces in two integer registers.
It does not establish compiler aggregate-passing rules, mixed GPR/FP storage,
homogeneous floating-point aggregates, or hidden return-value pointers. A
variadic signature test does not exercise `va_arg`. Functions containing calls
do not currently establish a live register location across those calls.

**CONFIRMED limitation at this assessment:** scalar floating-point locations
can be omitted because extraction looks up the largest Ghidra base register.
Pinned Ghidra 12.0.3 reports XMM0's base as ZMM0, AArch64 s0/d0/q0's base as z0,
ARM s0/d0's base as q0, and MIPS f12's base as f12_13. Those bases are absent
from Forge's maps. Having an FP alias in a map is insufficient behavior
evidence. A fix needs audited covering-register selection, correct piece
offsets, alias-aware overwrite checks, and exact GDB values before and after
stores; a guessed number for the larger base is not a solution.

## Accepted metadata is broader than validated ABI behavior

**CONFIRMED implementation boundary:** `DwarfTarget.fromElf` selects by
`e_machine`, ELF class, and byte order. It rejects x86-32, x86 x32, AArch64
ILP32, MIPS64, and big-endian x86-64/AArch64/ARM. It does not classify ARM or
MIPS ABI attributes. For example, an untested ELF32 MIPS ABI can reach the
same target map as O32. Preserving its `e_flags` does not prove its locations.

Ghidra's loader uses additional processor opinions and ABI properties. Forge's
preflight compares width and byte order, but does not yet prove agreement of
every ELF ABI with the selected Ghidra language/compiler specification.
Nondefault calling-convention strings also lack independent behavior coverage.
These are **PLANNED** classification and diagnostic checks, not claims that all
accepted files are correctly modeled or that every such file is broken.

## Bounded next validation slices

Each positive slice requires compiler-DWARF behavior as an independent oracle,
stripped real-export inputs, exact typed GDB values at multiple instruction
addresses, explicit unavailable gaps, structural validation, original hashes,
and deterministic repeats. Add PIE/rebase coverage once non-PIE works. Add a
shared-object case when binding, load bias or data access changes the behavior.

| Priority | Planned slice | Acceptance boundary |
|---|---|---|
| 1 | ABI and Ghidra-profile classification | Positive metadata assertions for the five profiles; explicit diagnostics for unvalidated ABI/compiler combinations and mismatched same-width languages |
| 2 | Scalar float/double | Exact values through mapped aliases and RAM stores; unavailable after clobber; keep unproven MIPS paired representations unavailable |
| 3 | Stack-passed parameters and real aggregates | Exhaust argument registers; include a 64-bit argument on 32-bit targets; then test bounded aggregate classes independently of the artificial composite |
| 4 | ARMv7 Thumb-2 and one ARM/Thumb call | Named/address breakpoints, function-pointer mode bit, source stepping, values and PIE/rebase on stripped inputs |
| 5 | MIPS O32 FP32 and FP64A | Explicit compiler options and ABI attributes, compatible runtime FPU, scalar/pair value checks in both byte orders |
| 6 | x86-32 System V | New audited descriptor/map and real stack arguments, paired values, source stepping, PIE/shared loading |
| 7 | MIPS N32, then N64 | Separate pointer/GPR-width models, additional argument registers, matching sysroots and actual runtime values |

The local audit found existing x86-64, AArch64 and MIPS O32 compilers/sysroots.
ARM32 is available in hosted CI but its local compiler/sysroot was absent.
x86-32 development startup files and matching N32/N64 startup/sysroot support
were also absent. QEMU availability alone does not supply a compiler ABI or a
matching runtime. These observations describe the audit environment, not
permanent prerequisites for every developer.

**PLANNED separately:** ARM big endian/BE8, AArch64 big endian or ILP32, MIPS
EABI/MIPS16/microMIPS/R6, x86 x32/wide vectors, SVE/SME, and non-Linux ABIs.
Their absence does not invalidate the bounded five-profile milestone. No new
profile is claimed by this documentation change.

## Evidence locations

The profile audit used the fixture Makefile and source, actual `readelf -h -A`
output, the pinned Ghidra language/register API and opinion files, the target
and register-map implementation, and existing GDB oracles. Detailed local
evidence remains in `build/target-profile-audit/`, including the native-free
`RegisterAliases.java` probe, register output and toolchain queries. These
ignored files are research evidence, not a new required test suite.

The executable regression contracts are under `src/test/fixtures/` and
`src/test/integration/`, including `RenameFixtureFunction.java`,
`qemu-gdb-symbols.sh` and `shared-object-gdb.sh`. Architecture-boundary guards
keep mappings isolated; they do not prove every register in each map.
