# LLDB register pieces and semantic fixture checkpoint (#110)

**CONFIRMED locally; hosted integration PRESENT, UNVERIFIED.** This checkpoint
adds explicit non-PIE x86-64 and QEMU AArch64 consumer checks. It does not finish
the full LLDB matrix or supersede #112's pending protected integration.

## Reproduction and encoding

The previous production sidecar uses two `DW_OP_regx` / `DW_OP_bit_piece`
descriptions for `analyst_composite`. GDB reads `0x1122334455667788` at its exact
function entry. LLDB 18.1.3 instead tries to read eight bytes from `0x11223344`.
This occurs on both selected targets. The original artifact passes structural
validation; a structural pass alone cannot establish consumer behavior.

The pinned [LLDB expression evaluator](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Expression/DWARFExpression.cpp)
extracts a bit field for `DW_OP_bit_piece` but does not collect successive pieces
as its `DW_OP_piece` implementation does. The first probe also mixed continued
SB-process execution with nested CLI commands: CLI frame selection remained at
an earlier stop. Separate CLI commands remove that harness ambiguity and still
reproduce the memory-read failure for the actual split value.

[DWARF 5 section 2.6.1.2](https://dwarfstd.org/doc/DWARF5.pdf) defines byte pieces
and leaves partial-register placement to the target ABI. The target register
description now explicitly permits low-bit byte pieces up to 64 bits for AMD64
and AAPCS64 general registers. The neutral expression planner uses that evidence
only for byte-sized, zero-offset pieces within the permitted width. It does not
infer placement from pointer size, register name or endianness. Both stable
expressions and location lists encode these pieces with `DW_OP_piece`.

Other target descriptions, floating/vector registers, nonzero bit offsets and
non-byte-sized slices retain `DW_OP_bit_piece`. The ARM upper-half scalar test
still emits a 32-bit piece at offset 32 and passes the native producer and
structural validators. This checkpoint makes no LLDB claim for those remaining
bit-piece forms. Memory pieces also retain their explicit bit-piece encoding;
mixed register/memory LLDB compatibility remains part of the open work.

## Semantic checks and honest gaps

`semantic-lldb.py` consumes freshly built compiler references and actual
headless exports. It runs from another working directory and explicitly adds
symbols to the stripped executable. It checks lookup before/after symbol
loading, named and address breakpoints, source listing and a source step,
recursive/pointer/union types, globals, an unassigned analyst local, a stable
register local, initialized stack storage across a 16-byte SP change, and the
split-register value. Each stop produces an asserted JSON observation, and
normal process exit and unchanged input/output hashes are required. A Python
assertion printed by LLDB is a failure even if the debugger exits with zero.

Compiler sources use the fixture's intentional prefix mapping; the harness
sets an explicit source map for that reference only. Forge source lookup uses
the emitted source path without such a mapping. Compiler inline frames are
inspected through their actual enclosing function frame for its locals.

The AArch64 Forge parameter locations end at `forge_stack_normal`, after a
store whose effect is not proved safe for those saved values. The independent
raw location-list check requires that boundary. Both parameters must display
as unavailable at and beyond it. The stack local remains 42 and the stable
register local remains 31. The test does not substitute compiler availability
for stronger evidence than Ghidra has recovered.

LLDB 18.1.3 also diagnoses the compiler reference's `word_view.bytes` union
member and displays it as an incomplete array. The compiler DWARF describes
four one-byte elements in a four-byte union and omits the member location,
as permitted for a union. The pinned
[Clang DWARF parser](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Plugins/SymbolFile/DWARF/DWARFASTParserClang.cpp)
applies its array-bound check to the unset member-offset sentinel. The harness
binds the sole allowed diagnostic to the actual union/member/array DIE offsets,
checks the compiler artifact with LLVM, and records this as a compiler-consumer
limitation. Forge's explicit zero member offset preserves the four-element
array and emits no corresponding diagnostic. Any other warning/error fails.

## Validation and remaining scope

The [local evidence receipt](evidence/lldb-register-pieces.json) records the tested package/JAR, production-source
hashes, raw test paths and preserved failed experiments. Fresh exports and
repeat exports on both targets pass GNU, LLVM and pinned strict validation;
the strict reports corroborate three x86-64 and five AArch64 inherited frame
diagnostics against their original ELFs. Sidecar/source reruns are byte-identical. Both existing GDB
semantic sessions and four compiler/Forge LLDB sessions pass. Reusing the
previous bit-piece artifacts fails specifically at the composite value on each
target, after passing the preceding semantic stops.

The existing composite-flow matrix also passes through the native-inclusive
package on both targets. GDB matches compiler references at 605 x86-64 and 588
AArch64 observations across copies, spills, reloads, aliases, gaps, branches,
loops and calls. Its independent decoder requires byte pieces for general
registers and the unchanged explicit bit pieces for memory. Seven native-free
suites and the isolated upper-register native smoke pass; the decoded Ghidra
join-order suite still covers ARM32 and both MIPS byte orders.

The fixture is source built with Ghidra 12.0.3 and Java 21. The pinned consumer
is LLDB 18.1.3 and the local AArch64 transport is QEMU user 8.2.2. CI adds the
same semantic harness after the production export matrix on both target lanes.
Hosted validation, bitfield values, mixed/sliced storage, broader changing
locations, PIE/shared/rebased/sectionless cases, discovery and the final
consumer support contract remain open under #110. #109 follows that work.

```bash
python3 src/test/integration/semantic-lldb.py build/fixtures \
    build/test-results/lldb-semantic --lldb lldb-18
```
