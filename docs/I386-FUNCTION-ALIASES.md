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

## First hosted gate correction

**CONFIRMED failed hosted gate and local correction (2026-10-31):** PR89
run `41178632812` stops before compilation because the architecture scan matches
the generic unwind local variable `pc`. Renaming it to `initialLocation` passes
the unchanged scan. All executable bytecode and other JAR entries match the
runtime-tested candidate; only the local-variable debug name differs. The 896
unwind checks, 34 actual Java 21 suites and a fresh sectionless i386 rebased-PIE
export/validator/GDB case pass. Correction receipt: `9b988bde18f43a0162fe45c25b9ae31b430b987a4d6bde09aafc68015337e7ec`.
The failed run is retained; fresh hosted acceptance remains pending.

## Fixture inventory gate correction

**CONFIRMED second failed gate and local correction (2026-10-31):** PR89
run `41179501376` rejects the new `i386-alias-entry.cpp` because it was missing
from the explicit fixture source inventory. The reviewed entry is now included;
the inventory check remains strict. All five fixture reproducibility lanes pass
with byte-identical rebuilds (including a private ARM cross compiler now located
outside the normal PATH). Production code and the tested JAR are unchanged.
Receipt: `cebe59b1e8f522ed79023627961e0f04855e6d83c90cc8f25bdf32a7a732f905`. Fresh hosted acceptance remains pending; P1.7 stays open.

## Allocation-observer integration correction

**CONFIRMED third failed gate and local correction (2026-10-31):** run
`41180225439` fails x86-64 and AArch64 because the metadata observer and independent
oracle omit the new sectionless `.eh_frame` view, shifting expected note indexes.
The other three target jobs pass; Windows is skipped after the failed target gate.
The observer now derives that view from bounded original header/table/record
framing, retaining the distinction between metadata and code/CFI byte identity.
The independent small-fixture oracle decodes its supported GNU encoding without
using the producer or reading expected values from the candidate.

944 unwind model assertions include all ten allocation-field mutations in both
ELF classes/orders and a changed-CFI-byte metadata-only control. The existing
532 allocation checks and 34 packaged suites on actual Java 21 pass. Twelve
retained x86-64/AArch64 fixture pairs, repeated observations, prefix checks and
twenty unwind-field mutations pass at a 64 MiB heap, as does the sparse >2 GiB
metadata case. This replay does not claim fresh exports. A separate fresh
sectionless i386 rebased-PIE export passes validators and runtime GDB.
Local receipt: `1bfe45faa2985107344d5fd83863b67ed352bc225f14cdb0c950050d501cce67`.

The first new mutation replay exposed an oracle diagnostic-format assumption:
derived segment names display as text, while original names display raw bytes.
The correction checks the exact documented form for each origin. That failed
replay is retained. CI now runs the ten unwind-field mutations whenever the
sectionless fixture has a supported original unwind view. Fresh full hosted
acceptance is still required; this does not complete P1.7.
