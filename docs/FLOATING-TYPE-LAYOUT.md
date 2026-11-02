# Floating object sizes and value storage

**CONFIRMED locally; hosted acceptance pending:** floating type DIEs now use
Ghidra's aligned object size, while location proofs retain the encoded value
width. This fixes i386 `sizeof(long double)` and array indexing without claiming
that padding bytes have recovered values. It is a follow-up to
[I386-EXTENDED-RETURN.md](I386-EXTENDED-RETURN.md), not completion of #71 or the
full P2.3–P2.3c goal.

## Evidence and representation

The pinned Ghidra 12.0.3 `AbstractFloatDataType` API explicitly distinguishes
`getLength()` (encoded floating payload) from `getAlignedLength()` (compiler
sizeof and array element size). Its `ArrayDataType` uses the aligned length for
fixed-size elements. The original exporter used the encoded length for
`DW_AT_byte_size`: ten instead of twelve on i386 and sixteen on x86-64.

A real previous-package control demonstrates that this affects memory reads,
not only display: GDB reports a ten-byte stride for the three-element i386
`ExtendedAlias` array, even though its total array size is 36. The new fixture
checks every element's value, pointer stride, object sizes and structure offsets
against the independently compiled reference.

`TypeGraph.BaseType` now records both object byte size and meaningful value byte
size. Only floating encodings may have different sizes. Type aliases retain the
aligned object size and resolve the underlying value width for location checks.
`ProgramTypeModel` still requires exact agreement with that value width; it does
not relax complete-piece or lifetime requirements. Thus an 80-bit floating
location continues to prove only 80 value bits, while its DWARF type describes
the ABI's twelve- or sixteen-byte object. Padding has no fabricated location.
The producer API and native sources are unchanged.

## Validation

Selected baseline remains Ghidra 12.0.3, Java 21 and libdwarf 2.3.2.
The tested release-assembled candidate is
`build/i386-floating-layout/ghidra-call-layout-v3`; its JAR SHA-256 is
`11a0b132b9f8d14f50ba201a79df1313fab48d5051c88e5d168abbdbb5d68945`.
Package and production source hashes are retained beside it.

The updated `i386-extended-return-export.py` passes four i386 roles: exec,
sectionless, PIE and rebased PIE. Each performs two real packaged exports,
requires deterministic output, compares compiler/Forge scalar arguments and
returns, and checks long-double globals, typedefs, arrays and a mixed structure.
The x86-64 exec regression checks the corresponding sixteen-byte global layout
and ordinary float/double entry/return values. It deliberately makes no claim
about x86-64 extended-return allocation or synthetic signatures.

Across these five cases, ten exports and fourteen compiler plus fourteen Forge
entry/return observations pass, including every associated type-size, stride,
field-offset and typed-object check. Every original and package byte is
preserved. Persistent Ghidra program files and observed saved types remain
unchanged; only the existing, explicitly enumerated journal/index backup cleanup
is allowed and recorded. Case paths, result hashes and counts are recorded in
`build/i386-floating-layout/review.json`.

GNU ELF/DWARF views and LLVM verification pass. The strict checker accepts the
artifacts without unexplained diagnostics. On x86-64 it corroborates the known
GNU FDE length-alignment diagnostics against identical inherited frame bytes;
these are not reported as raw zero-diagnostic runs. The compiler artifact is
compared with its distinct stripped companion. Sectionless cases retain a
byte-bound sectioned companion for the existing frame-reference contract.

Six model suites and the extension build pass in `models-v3.log`: floating
layout (73 checks across seven actual Ghidra language/compiler combinations),
type graph, variable storage, i386 allocation (926), formal returns (348) and
dynamic parameter storage (232). The model cases prove preservation of the
selected Ghidra types, not correct C long-double ABI coverage for every listed
processor. Runtime ABI claims remain confined to the explicit fixture cases.

The previous PR144 package fails the new GDB oracle at the expected i386
`sizeof(extended_global) == 10` and array stride 10. Its output is retained in
`previous-package-control.log` and the referenced `forge-gdb.json`. It remains a
failed control run; the acceptance receipt records the specific rejection.

Retained intermediate failures include the first candidate's location/declaration
size mismatch (which motivated the explicit value-width model) and the first
x86-64 strict invocation's missing inherited-frame corroboration. No validator
rule was relaxed to admit either run. Workflow actionlint, Python compilation,
architecture-boundary checks and diff checks pass. CI runs the updated fixtures
and the new model suite; exact-head hosted acceptance remains pending.

## Remaining work

**HISTORICAL at PR145:** synthetic decompiler output retained the erroneous
hidden-pointer signature. The subsequent [read-only decompiler correction](I386-DECOMPILER-ALLOCATION.md)
now passes local helper/source-step and override-preservation checks. Its
hosted acceptance and integration remain pending.

Broader libc/vector/aggregate/convention/lifetime requirements, the remaining
AArch64/MIPS/ARM acceptance rows, hosted validation and protected integration
remain open under the original completion plan. This component changes no
release or issue-completion claim.
