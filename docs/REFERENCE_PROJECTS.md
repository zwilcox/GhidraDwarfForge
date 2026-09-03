# Reference project review

These projects are behavioral and implementation references. Their source is
not copied into GhidraDwarfForge, and their support claims do not substitute
for this project's validators and integration tests.

## `cesena/ghidra2dwarf`

- Repository: <https://github.com/cesena/ghidra2dwarf>
- Reviewed commit: `7fc8990815cd24e8fe392572eee240bf88ebaf1f`
- Review date: 2026-09-02

Useful reference patterns:

- GDB/MI-based behavioral assertions for breakpoints, source listing, scalar
  variables, arrays, and structures.
- Decompiler markup/token inspection as evidence for source-line addresses.
- Reusing the input ELF's class, byte order, machine, and other identity fields
  when constructing a debug-bearing copy.
- Ghidra-provided DWARF register mapping lookup as an input to a target-specific
  register translator.

Limitations that GhidraDwarfForge must not inherit:

- Producer flags and ISA selection are hard-coded to 64-bit little-endian x86.
- [Open issue 29](https://github.com/cesena/ghidra2dwarf/issues/29) records an `IndexError` when the input is a valid ELF32
  big-endian MIPS executable with no section-header table. Its writer indexes
  `section_headers[e_shstrndx]` even though all section-table header fields are
  zero. This is a mandatory regression case for Forge's matched-copy writer.
- The address helper attempts image-base normalization, but the test suite does
  not prove PIE or shared-object load-bias behavior.
- Functions are represented by one low/high span rather than address-range sets.
- Source mapping commonly selects one minimum token address per line and cannot
  preserve multiple discontiguous ranges for one line.
- The generated file is a modified copy of the executable, while this project
  requires an unchanged original and a separate sidecar by default.

## `ALSchwalm/dwarfexport`

- Repository: <https://github.com/ALSchwalm/dwarfexport>
- Reviewed commit: `b955cf1e2f5c75aec5b814b652f4d4bbac5c6fe6`
- Review date: 2026-09-02

Useful reference patterns:

- Explicit separation of disassembler register identifiers from DWARF register
  numbers.
- Dedicated stack/register location helpers.
- Iterating decompiler expressions to find defensible source-line addresses.
- Clear examples of building type, function, variable, and line-table DIE data.

Limitations that GhidraDwarfForge must not inherit:

- Architecture handling is switch-based and incomplete; ARM32 is partial and
  AArch64 is unsupported.
- Variable-location logic assumes specific x86 or ARM stack registers and one
  location for the variable rather than a live-range location list.
- Function ranges are flattened to a single start/end interval.
- There is no required PIE/shared-object integration matrix proving runtime
  relocation behavior.
- The project is unmaintained and targets historical IDA/libdwarf APIs.

## Required improvements in GhidraDwarfForge

- Mandatory x86-64 and AArch64 end-to-end pipeline lanes.
- Non-PIE, PIE, and shared-object fixtures with runtime address assertions.
- Address-set/range models preserved until serialization.
- Table-driven, tested target-register mappings.
- Variable location lists or honest omission when storage evidence is
  insufficient.
- Original executable unchanged by default.
- Pinned native producer ABI and independent DWARF validation.
