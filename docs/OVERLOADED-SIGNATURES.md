# Overloaded recovered function signatures

**CONFIRMED locally; hosted acceptance pending:** the new integration
fixture creates two ordinary definitions named `Recovered::nested::combine`
in the same saved Ghidra class/namespace path. One has an explicit analyst
`int(int)` signature, the other `double(double)`. Distinct addresses must keep
their type references, parameter locations and synthetic source correlation
separate even though the qualified display strings match.

The fixture adds unique analyst secondary labels `combine_int` and
`combine_double`, plus the same `ambiguous_alias` label at both entries. The
unique labels must resolve to the correct typed definition. The ambiguous
label must be omitted with the existing precise diagnostic. The shared
primary-name breakpoint must select both functions.

Acceptance requires saved-program observation in fresh headless processes,
byte-identical repeat outputs, preserved input/module/program bytes (apart
from documented Ghidra index/journal backups), GNU ELF/DWARF inspection,
LLVM verification, the strict pinned DWARF checker, and compiler-reference
plus Forge GDB runs. Four real calls check signed arguments, integer/double
return values and sizes, distinct source lines, and both `next` and `step`.
PIE runs also verify a nonzero runtime load bias; rebased imports add an
explicit Ghidra rebase before curation.

The runtime cases use x86-64, AArch64, ARMv7 hard-float and both MIPS32 byte
orders. MIPS selects the existing O32 MIPS32r2 FP32 profile explicitly; these
checks do not certify FPXX floating transfer. ARM/Thumb modes are separate
cases. GDB runs on native x86-64 or QEMU user mode for other targets.

Two initial harness failures are retained locally: the first rebased PIE
assertion incorrectly assumed Ghidra initially loaded PIE at zero; the second
assumed `--strip-all` removed original names from the dynamic symbol table.
The corrected checks account for Ghidra's initial image-base choice and read
the actual input ELF symbol inventory. Neither failure established a production
exporter defect.

This tests display-name identity and existing formal signatures. It does not
claim recovered original C++ class declarations, `this` parameters, inheritance,
or source-language overload resolution. Those richer scope semantics remain
tracked separately under P3.3. P1.7 remains open pending complete evidence and
integration of the remaining changes.

## Local acceptance

All 36 cases pass with the exact PR90 production JAR
`aac48e5563801df85462dd8fb04c23e035da427b9843b78149e421999d8de0da`:
six retained/stripped exec/PIE/rebased-PIE roles for each of x86-64, AArch64,
ARM, Thumb, MIPS BE FP32 and MIPS LE FP32. This is 72 fresh read-only exports,
72 compiler/Forge GDB processes and 288 ordinary calls. The independent raw
review checks the actual type/alias records, output equality, source lines,
return values, validator receipts and protected files. It passes with receipt
`1318930de47d80a26767bfdc67725f09b83046d5ab27abb360bab566714fce26`.
All five fixture reproducibility inventories and workflow lint pass. Commands,
raw logs and prior failures remain under `build/overload-review` and
`build/test-results/overloaded-signatures`. The new pipeline step runs all 36
cases through the same production exporter. Hosted acceptance remains pending.

A separate aggregate-return probe found that exposing the automatic return
buffer as an additional formal parameter permits incorrect injected calls.
That defect has a separate fix under validation; this overload test does not
exercise aggregate returns or claim that P1.7 is complete.
