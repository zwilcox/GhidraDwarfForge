# Analyst function aliases on i386

**CONFIRMED local runtime and independent raw review; package/hosted acceptance
pending (2026-10-31).**
P1.7/#66 remains open. This adds the existing ELF32 little-endian `EM_386`
profile to the direct-address alias policy. It does not establish additional
calling conventions, floating/aggregate injected calls or all x86 modes.

The generic planner retains its original-byte, complete function-range,
ownership and name-collision checks. Local analyst labels are inserted alongside
preserved original symbols. Fully stripped inputs receive only defensible new
labels; dynamic inventories follow the same complete-count policy as other
targets. The default export never modifies the executable or saved program.

## Runtime fixture

The common alias fixture is compiled with a tiny freestanding Linux i386 entry
point, avoiding a dependency on installed 32-bit C++ runtime libraries. Exec,
static PIE and rebased static PIE are tested with retained symbols and full
stripping. Each base case compares compiler DWARF with the real headless export;
each automatic-alias case exercises analyst labels and the packaged writer.
Sectionless stripped exec/PIE/rebase variants use the same production path.

The compiler's PIE entry calls a four-byte PC helper. The oracle independently
decodes its call displacement and verifies exact helper bytes and the stacked
return address before allowing a source `step` to enter it. A source `next`
must still step over it. That distinction exposed the sectionless unwind bug;
the production repair is documented in [SECTIONLESS-UNWIND.md](SECTIONLESS-UNWIND.md).

## Acceptance evidence and limits

Six base and six automatic-alias cases pass GNU/LLVM/strict libdwarf validation,
compiler/Forge GDB lookup, source, types, exact argument/static values, stepping
and returns. Each exporter case repeats deterministically and protects original,
module and saved-project evidence. Three sectionless roles pass after the unwind
repair. The preceding package's explicit omission of both new labels is retained
as the comparison control.

The alias planner passes 374 checks and extraction passes 228 checks across six
Ghidra languages. The unwind candidate passes 34 suites using actual Java 21.
Cross-target sectionless regression checks cover x86-64, AArch64 and MIPS32 in
both byte orders, plus incomplete-count omission and GNU-versioned DSO cases.
The final helper revision also covers older `objcopy` sectionless fixtures on
all five existing profiles. ARM32 uses hash-checked, source-built hosted inputs
because the local cross compiler is unavailable; its candidate export is fresh.
Independent raw inventory/GDB review, 35 corruption controls, 97 captured-evidence
controls and 44 final-checker artifact replays pass. Runtime receipt:
`7af0ac26e8c977b0a3d7f90e5d8ef6a0c1cbc215a2ff7fd5cc0dd5b8481cc3b4`.

The last checker-only adjustment preserves the existing captured-evidence schema.
The runtime matrix's checker snapshot is retained, and all selected artifacts
were rechecked with the final source; the producer JAR is unchanged. The initial
independent audit incorrectly required compiler source stepping to enter the
PIC helper; compiler mapping skips that prologue. Its failure is retained, and
the corrected audit requires the helper witness for Forge PIE source stepping.

CI runs the i386 cases in the x86-64 host lane. This is bounded native Linux
i386 runtime evidence, not a new Windows target or a general ABI guarantee.
ARM/Thumb aliases, broader calling conventions and richer scope relationships
remain separate P1.7 work. No release is published by this change.
