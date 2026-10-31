# MIPS function alias symbol semantics

**CONFIRMED locally; hosted acceptance pending:** classic MIPS32r2 O32 exports
can preserve explicit analyst aliases through supplemental local ELF symbols.
Both big- and little-endian FPXX retained-table exec/PIE/rebased-PIE cases pass
headless export, independent writer comparison, structural validators and
QEMU/GDB behavior. The explicit FP32 matrix also passes those six roles.
This advances P1.7/#66; it does not complete general MIPS mode, ABI or alias work.

## Target boundary

`MipsFunctionAliasSymbols` owns the processor-specific decision; generic ELF
and DWARF code gains no register or byte-order assumptions. The target must be
ELF32 ET_EXEC/ET_DYN with O32 MIPS32r2 flags, allowing only the observed
NOREORDER/PIC/CPIC bits. The existing typed ABI reader must find an unambiguous
version-zero record with 32-bit general and floating registers, FP32 or FPXX,
no coprocessor-2 registers, no ISA extension/ASE, and only known record flags.
These checks authorize symbol-address semantics, not arbitrary injected-call
or floating-variable ABI behavior.

All defined code symbols are inspected in bounded static/dynamic tables.
Processor-specific st_other bits and tagged/unaligned code values prevent
alias insertion even when header/ABI flags contradict those symbols. Only the
ordinary visibility bits are accepted. New alias addresses and extents must be
word aligned. MIPS16, microMIPS, other ISA/ABI profiles, missing or inconsistent
records, and unsupported symbol metadata retain explicit omissions.

The generic planner still checks exact original/program code bytes, ownership,
collisions, a contiguous entry-first body, and one file-backed executable
section. It does not change the primary DWARF definition, source ownership,
types, locations, original symbol records or input bytes. Existing atomic
publication and cancellation apply.

## Fixture and oracle details

The shared C++ fixture is source-built with the target cross compiler. ELF
inspection now handles ELF32/ELF64 in both byte orders. MIPS return guards are
placed on the actual jr ra, whose instruction bytes are independently checked;
the following instruction is its delay slot. The GDB runner selects each
target's private QEMU socket and sysroot.

MIPS PIE puts some function definitions in both dynamic and static tables.
The inventory permits duplicate records only when their semantic fields agree.
Stripping a static table does not imply that original dynamic names disappear:
the oracle records actual defined input symbols and requires that same lookup
behavior after export. The first MIPS PIE attempt exposed the earlier unique-
name parser assumption; its failed case is retained under build/mips-alias-review.

The model suite passes 492 checks in both byte orders: valid profile flags,
FP32/FPXX, unknown header/record fields, contradictory symbol mode bits, tagged
addresses, alignment, malformed table framing, deterministic planning,
cancellation and unchanged input bytes/timestamps. All 30 packaged model suites
pass on actual Java 21; the producer JAR is
`79c1b488919da20a8d9807255c3448529653f287773c99d0c5734f4c6cbfda27`.

The first runtime matrix includes 24 base cases and 18 alias cases across
x86-64, AArch64 and both MIPS byte orders. Independent raw review verifies
192 compiler/Forge base calls and 72 alias calls, unchanged inputs/module,
deterministic outputs, original-record preservation and exact automatic/manual
writer equality. Two previous-exporter controls preserve primary typed lookup
but omit the new MIPS aliases on the same curated programs.

Receipts in build/mips-alias-review:

- Base review: `6082bbb9a6112b9c3f0a926e3a18eeecf6ad70987414682e379fca790dc21b9a`.
- Alias review: `7abd12f6b734f5ce3795ffde10a7d15b5ad58118fa5e29bd6d49d06025a9f2a8`.
- Java 21: `28c2e59877e8f40327953c3e49f434fca446e6620306bb59f67a483a20a296b8`.
- Previous exporter: `09c5f8336110bffd040ac5a9f0c199c874a613357a2ba284b89862180cdfbcfa`.

The additional explicit `-mfp32` matrix passes six base cases (12 exports and
48 compiler/Forge calls) and six alias cases (12 automatic exports, 12 writer
executions and 24 QEMU/GDB calls). Independent byte inspection confirms FP ABI
1 and MIPS32r2/32-bit register metadata in the actual compiler-built inputs.
FP32 base receipt:
`0d63f1f48ceafaedaa23aa2070c008070261c38ce40b673a2a861c328930fd02`;
FP32 alias receipt:
`37254161d9a159cc24e7a84cfc7d7927988e6e3e9d6b52854d7671a1edfccd77`.
The optional fixture flag was added after reviewing the first matrix; both
matrices use the identical production JAR. CI runs both MIPS profiles and
retains the compiler, exporter, validator and GDB artifacts.

## Remaining acceptance and scope

Final package review and the full hosted gate remain required. New aliases
still require an existing static table when named defined dynamic symbols are
present: a partial new static table could hide those originals in GDB. The
runtime matrix proves existing dynamic names survive ordinary stripped exports;
it does not claim new alias insertion for that layout. Sectionless and
discontiguous binding, other MIPS modes/ABIs, and full lexical/class relationships
remain explicit work. Do not close #66 from this component.
