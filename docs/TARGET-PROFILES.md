# Tested ELF and ABI profiles

**CONFIRMED:** the five Linux target lanes exercise the production exporter,
independent ELF/DWARF validators, and native or QEMU/GDB behavior. This document
describes the profiles and storage cases actually tested. An ELF machine number
or a successful import does not establish support for every ABI of that CPU.
Windows x86-64 is a Ghidra host; it does not imply Windows target-ABI support.

The baseline audit below covers the exporter at `1f2a46b`; its scalar-alias
finding is historical. Subsequent bounded scalar-alias corrections and the
definite ELF/Ghidra processor/width/endian agreement guard pass combined run
`40068401197`, normally merged as `befce2c`. See
[current acceptance](VALIDATION.md#combined-hosted-acceptance-and-main-integration-2026-10-24)
for exact value/omission tests and conditional scope. This does not complete
ABI classification or expand the five profile definitions below.

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

**CONFIRMED in hosted run `40138005382`:** a separate mixed ARM/Thumb
ET_EXEC regression now checks restored static instruction-mode information for
a fully stripped input. Only contiguous, fully decoded homogeneous functions
with matching original bytes receive generated local ELF mode symbols. Existing
symbol tables, uncertain bodies, any named defined dynamic symbol and sectionless mode
cues remain outside this correction. The compiler-relative GDB test checks the
following ARM function as well as the Thumb body, calls, values and source
stepping. This does not broaden the ARM-state profile above to arbitrary Thumb
ABIs, PIE/shared objects or mixed-mode function bodies. See
[the mode-symbol investigation](research/ARM-THUMB-MODE.md).
The supplemental cue planner explicitly rejects ET_DYN; the existing ARM-state
PIE/shared export support remains subject to its original behavior tests.

## What the variable tests prove

**CONFIRMED:** the common tests cover curated integer signatures, types and
globals, plus a stack local addressed correctly before and after stack-depth
changes. Stable GPR
parameters and an entry-live register local have positive value checks where
their storage survives. Overwritten registers are deliberately unavailable.
ARM32's current composite/register-local cases prove omission after overwrite;
they are not positive proofs of those values.

**CONFIRMED locally; full hosted acceptance pending:** an additional computed
parameter-storage control covers real saved/reopened programs in all five
languages. A hard-float ARM executable with analyst-selected base/VFP dynamic
conventions proves four exact float entry values and two honest modified-register
omissions. It demonstrates that a file's VFP argument attribute does not select
every function's parameter convention. The correction preserves existing
lifetime checks and does not establish debugger-injected-call or return-value
ABI behavior. See [computed parameter storage](DYNAMIC-PARAMETER-STORAGE.md).

**CONFIRMED correctness finding:** later ordinary eight-byte by-value structure
fixtures reveal reversed fields for ARM32 and MIPS32 little endian despite the
scalar-only gate passing. Computed Ghidra joins use significance order, which
must be translated separately from each register's bit offset. A real conversion
to custom storage also requires the same normalization. The original injected
custom/local controls did not establish Ghidra join semantics. PR #45
corrects the shared extraction boundary: computed/custom/reopened cases and
primary regressions pass on all five targets in exact run `40145554731`, with
independent reviews and normal merge `96fa0a8`. Main-push acceptance is separate. See
[the correction](DYNAMIC-COMPOSITE-ORDER.md).

The composite fixture uses analyst-curated pieces in two integer registers.
It does not establish compiler aggregate-passing rules, mixed GPR/FP storage,
homogeneous floating-point aggregates, or hidden return-value pointers. A
variadic signature test does not exercise `va_arg`. Functions containing calls
do not currently establish a live register location across those calls.

**HISTORICAL limitation at the baseline assessment:** scalar floating-point locations
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
The bounded local ARM base/VFP parameter control does not establish behavior
for arbitrary nondefault calling-convention strings.
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

## Truncated-space investigation

**CONFIRMED in PR #46 run `40148228012`:** an owned
freestanding O32/N32 comparison in both byte orders observes four-byte pointers
with eight-byte N32 argument registers and STORE address operands. The preceding
exporter omits the N32 locations conservatively because RAM is explicitly
truncated. The selected fix addresses that memory-space proof. All four local packaged
compiler/Forge controls now pass exact values, honest omissions, validators and
repeatability. All twelve hosted PR jobs, independent target/host/package
reviews and 28 native Windows suites pass. Normal merge `800081f` preserves the
tested tree; distinct main-push run `40150436365` also passes all twelve jobs
and independent fresh target/host artifact review. It does not
change ABI selection or the five supported profile definitions above. Its scope
excludes libc startup, N32 floating/aggregate rules, PIE/shared objects and N64.
See [the contract and evidence](TRUNCATED-MEMORY-STORES.md).

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
