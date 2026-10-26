# Explicit MIPS FP32 whole-register pairs

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** The production
path can expand a complete Ghidra `f12_13`-style alias into two physical FPR
pieces when the original ELF explicitly describes the tested FP32 profile.
The first twelve whole-alias exports pass compiler/GDB and strict validators
in both byte orders, exec/PIE, rebases and deterministic repeats. Twelve
sectionless exports also pass. This is a bounded profile extension, not a
general MIPS ABI or register-mode inference.

## Evidence required before expansion

[GNU's FP ABI description](https://www.sourceware.org/binutils/docs/as/MIPS-FP-ABI-Variants.html)
distinguishes O32 double-precision pairs from FPXX and the 64-bit FPR profiles.
The fixed-width ABI record follows
[glibc 2.39's ELF definitions](https://raw.githubusercontent.com/bminor/glibc/glibc-2.39/elf/elf.h).
Six separately compiled inputs prove that FP32, FPXX and FP64A may all have
`e_flags=0x70001007`; those header flags alone cannot select pair semantics.

`MipsAbiFlags` observes typed `SHT_MIPS_ABIFLAGS` and `PT_MIPS_ABIFLAGS`
carriers. It accepts one 24-byte version-zero record, including program-only
inputs. If both carriers exist, their exact file interval must agree. Multiple
sections/segments, differing views, compressed sections, unexpected sizes or versions remain
explicitly ambiguous or unsupported. An absent record remains absent. Names
are not used to identify the record; unnamed section tables work. Bounded
reads retain `ElfImage` source-change checks and cancellation.

The initial expansion requires all of these facts together:

- ELF32 MIPS ET_EXEC/ET_DYN, O32 and MIPS32r2 header flags, with only the
  ordinary NOREORDER/PIC/CPIC low bits additionally allowed.
- ABI version zero, ISA level 32/revision 2, 32-bit GPRs and CPR1 registers,
  no CPR2 registers, and FP ABI value 1.
- No ISA extensions, ASEs, unknown flags1 bits or nonzero flags2. The known
  ODDSPREG bit may be set.
- The selected target map has the same byte order as the original ELF.

Other records retain their observed fields without acquiring this expansion.
This does not reinterpret FPXX as FP32, infer a runtime FPU mode from a language
name, or compensate for the failed FP64A compiler/GDB transport reference.

## Storage translation

The isolated target description lists sixteen even/odd FPR pairs. Generic
storage extraction checks the loaded language's full alias size and exact
child names, widths, parent identity and least-significant-bit positions.
Ghidra 12.0.3's `Processors/MIPS/data/languages/mips.sinc` defines the even
register as the low half in both byte orders. DWARF pieces are emitted in
object-memory order: odd/even for big-endian and even/odd for little-endian.
Each child uses its existing audited DWARF register number and a 32-bit,
zero-offset `DW_OP_bit_piece`.

Only a complete alias is expanded. Existing whole-function coverage,
call/opaque guards and physical-register write detection remain mandatory.
Writing either child invalidates the location. This change adds no MIPS
delay-slot lifetime proof, partial-pair recovery, register backup, memory
migration or ABI-only call-preservation rule. Existing analyst-described
pieces retain their separate validation path.

## Local acceptance

`mipsAbiFlagsSmoke` passes 594 synthetic checks covering both ELF widths and
byte orders, section/program carriers, absent/duplicate/conflicting records,
unknown ABI values/flags, cancellation, changed sources and input preservation.
`mipsFp32PairSmoke` passes 190 actual-Ghidra checks: all sixteen pairs in both
orders, partial-alias rejection, unclassified and other-profile rejection, and
real `mtc1` writes to either half. Sixteen freshly compiled suites pass on actual
Java 21 against the isolated production JAR. Its SHA-256 is
`a05b0e860d708f3617421c3a3ef328fe64f2b6f9ee66e71a7f68bc75e05ccb6c`;
Java 21 receipt SHA-256 is
`1db9f2ccf91dc9c73821443e8f49368ad4be05802c7ebec39f7d957fcbfc49e5`.
The metadata suite additionally agrees with all twelve named/sectionless
observations from the six independent compiler inputs.

The same package passes 66 local exports:

| Scope | Exports | Retained run |
| --- | ---: | --- |
| FP32 whole aliases, both MIPS orders | 12 | `run.pJIWEI10` |
| FP32 whole aliases without section headers | 12 | `run.KoJgA2h8` |
| Analyst-described FP32 pieces | 12 | `run.TdtKdvHo` |
| Existing five-target floating profiles | 30 | `run.7s4CKyit` |

Each positive pair artifact passes exact raw DIE type/expression checks, GNU,
LLVM and pinned strict libdwarf, compiler/GDB values before/after stores,
PIE relocation, rebase normalization, deterministic repeats and preserved
inputs. The sectionless fixture retains identical program records and ABI
payload while clearing only the owned copy's section-table header fields.
The original source-built input and export input remain separate, recorded
objects. No proprietary fixture or original user target is modified.

An earlier 66-export run and its review remain retained under
`build/mips-profile-review`. Final review added a compressed-record rejection
guard; all four matrices and sixteen Java 21 suites were rerun against the
final JAR. Production JAR and protected harness identity are shared across
the final four runs. Final independent raw-review receipt SHA-256:
`f628126341a174ead95efc74948a90f442bc393f410669195c24a3dad605c4eb`. Local headless uses
Java 25.0.4.1; actual Java 21 model evidence is separate. Inherited frame messages remain independently
corroborated: seven per AArch64 artifact, six for x86-64 exec and four for x86-64
PIE. The first local audit incorrectly assumed zero x86 messages; its failed
assertion is retained. Corrected review compares the raw original/artifact
diagnostic multisets and `.eh_frame` bytes and checks their recorded hashes.
No unexplained errors are accepted.

Hosted cross-target, actual Windows and GUI acceptance remains required before
integration. FP64A, arbitrary FPXX modes, N32/N64, further ISA/ASE profiles and
general variable migration remain incomplete. This does not publish a release.

## PR59 integration accepted (2026-10-25)

**CONFIRMED:** head `28ae3f0c0b2306490932da8841d161b09bb9490e` passes all
twelve jobs in `40241665541`, exact hosted package/provenance review and
sixteen actual Java 21 suites. Raw five-target artifacts, 37 native Windows
tasks and both GUI hosts pass their applicable checks. Independent review
confirms exact Thumb/VFP clobber boundaries, twelve mixed incoming exports,
36 explicit MIPS FP32 exports across whole aliases/pieces/sectionless inputs,
12 default MIPS regressions, and the corrected architecture guard with five
controls. Native Windows GUI lacks the independent strict checker and Linux
ELF runtime GDB; those omissions remain explicit. Linux GUI checks include
strict validation and GDB. Both hosts' chooser/console screenshots were also
inspected.

Acceptance receipt SHA-256:
`4b03ddc3aeb697d002b41f8bc6def3c9fdc427e7a63b3d28a932b49f2270bcfd`.
Normal merge `2fed5c3c6de79b319b3d6aa3d9c82c88e0fc25ea` has the identical
accepted tree; PR57 and PR58 are integrated through its ancestry. Distinct main
run `40244657118` remains pending. Earlier pending and failed component notes
are historical, and the failed architecture guard is not retroactively
accepted. This does not complete broader lifetimes, ABI modes, linkage/scopes
or optional attachment. No release publication.
