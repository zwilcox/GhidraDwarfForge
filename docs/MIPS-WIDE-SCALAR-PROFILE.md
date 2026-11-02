# MIPS N32/N64 scalar profile

**CONFIRMED locally; hosted acceptance pending:** the candidate extends the
matched ELF/DWARF format to MIPS ELF64 in both byte orders. It retains N32 as
ELF32 with four-byte pointers and 64-bit GPR/FPR storage. This component is part
of P2.3a/#69, not completion of that issue or the four-issue goal.

## Format and native boundary

`DwarfTarget` selects a description by ELF machine and address width. MIPS32
and MIPS64 descriptions share the pinned producer's `mips` ISA, with separate
pointer flags and target names. DWARF offsets remain 32-bit. No JNA declarations,
native source, production patch or shipped native binaries change.

The inspected libdwarf 2.3.2 source maps this ISA to R_MIPS_32/R_MIPS_64 and
handles pointer width independently of DWARF offset width. Before enabling the
Ghidra path, isolated producer tests passed 16 lifetimes in each byte order,
including deterministic sections and eight-byte target relocations. An ELF64
big-endian matched sidecar retained a function address of `0x120000af8` and
passed GNU, LLVM and the corrected strict consumer. The validation-only GNU
frame-terminator correction is documented in `research/MIPS-ABI-COMPLETION.md`.

Physical register numbers come from the existing isolated MIPS mapping. N64
does not acquire the O32 FP32 paired-register interpretation. Actual Ghidra
ProgramDB tests cover both 64-bit languages, dynamic four-byte integer
parameters in `a0_lo`/`a1_lo`, shared type/storage extraction and immutable
reopening. Those tests do not infer full ABI support from register names.

## Runtime contract

`src/test/integration/mips-wide-abi.py` builds the owned floating fixture with
GCC `-mabi=n32` or `-mabi=64`, MIPS64r2 and DWARF 5. It imports a fully stripped
copy, curates float/double signatures with **dynamic** storage, saves the
program, and reopens it read-only for two production exports. Ghidra must select
`MIPS:BE|LE:64:64-32addr`/`n32` with four-byte pointers or
`MIPS:BE|LE:64:default`/`default` with eight-byte pointers.

The passing local matrix is both ABIs, both byte orders and five layouts: non-PIE,
PIE, rebased PIE, shared library and rebased shared library. Each case requires:

- Equal repeated sidecar/source bytes, preserved input and program database,
  and the expected installed exporter origin.
- GNU, LLVM and pinned strict validation of compiler and Forge artifacts.
- Named breakpoints plus raw entry breakpoints, typed source-known arguments
  at every visited instruction, typed stored globals, source listing and
  separate `next`/`step` runs and normal exit in QEMU/GDB. N64 non-PIE addresses
  must exceed 4 GiB.
- Explicit shared-library symbols at the actual mapped load bias, with
  automatic shared-library symbols disabled.

The initial automatic PIE separate-symbol sequence exposed a GDB 15.1 warning
when stepping back into the caller, with both untouched compiler DWARF and
Forge DWARF. Explicitly loading libc symbols did not resolve it. Loading the
separate symbol file **after** remote attachment, using the loader's `AT_ENTRY`
minus the original ELF entry address, removes the warning while preserving
exact values. The harness records this independently obtained bias and checks
each resolved function against it. Diagnostic suppression is unchanged.

## Remaining scope

**CONFIRMED final local package:** all 20 cases pass, with 348 compiler and 348
Forge instruction observations, 304 compiler and 200 Forge source-step
observations, 40 repeated native-failure exports and 20 production cancellations.
Failed functions retain symbols and omit unavailable parameters; neighboring
functions still expose exact values. Existing artifacts, original inputs and
program databases remain unchanged. GNU/LLVM and strict validation pass; all
three strict artifacts per case report zero errors, without frame exceptions.
The AArch64 non-PIE ABI and failure/cancellation regression also passes.

The local receipt is `build/n64-profile/final-acceptance-matrix.json`.
The installed JAR SHA-256 is
`7bd05648106b4acc1aa0cb89db2f7a72636e1bb3423e23de09f3d2f36372775a`;
the assembled ZIP SHA-256 is
`a0feab6f26ffde8450e135c228672a6f28bdbcd7f8885a59040d964cc12883a5`.
`mips-wide-abi.py <ghidra> --abi n32|n64 --endian be|le --role <role>
--with-controls` reproduces each case with the matching multilib toolchain and
strict `DWARFDUMP` configured. CI wires these cases into the two existing MIPS
lanes and adds isolated ELF64 producer checks on Linux and Windows.

Hosted exact-head Linux/Windows validation, final review and protected
integration remain pending. This scalar component
does not validate all aggregate/wide/mixed/stack arguments, return transfer,
ISA/FPU/compiler combinations, sectionless N64 inputs or debugger-injected
calls. Existing restrictions on unverified calls remain in place. FPXX/FP64A,
the remaining O32 work and the full N32/N64 ABI requirements remain open under
`TARGET-ABI-COMPLETION-PLAN.md`.

**CONFIRMED separate research defect, outside scalar acceptance:** the next
owned big-endian N32 aggregate/mixed fixture exposes wrong computed storage:
Ghidra places a two-word aggregate on the stack although the caller passes its
values in registers, and allocates mixed floating arguments independently of
integer argument positions. Source-known values disagree with the exported
display. N64's corresponding model is different and its tested aggregate entry
values are correct, with several conservative scalar omissions. The GCC
reference itself has seven premature aggregate-stack displays at entry in both
ABIs. These are retained failing references, not an acceptance exception.
`build/n64-profile/wide-arguments/findings.json` records the exact observations.
Independent raw ABI calibration and a bounded allocation correction are next;
do not extend this scalar support claim to those signatures.
