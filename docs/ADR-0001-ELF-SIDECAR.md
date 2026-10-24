# ADR 0001: Matched non-loadable ELF sidecar

- Status: accepted for the minimal ELF path
- Decision date: 2026-09-02

## Context

The sidecar must describe the original ELF at the same link-time addresses,
work for ET_EXEC and PIE/ET_DYN, preserve ELF32/ELF64, byte order, machine,
ABI flags, and build identity, and never modify the original target.

Two reference approaches were insufficient:

- A new ET_REL object requires target-specific relocation records, a complete
  symbol table, and explicit runtime address calculations for PIE.
- GNU `objcopy --only-keep-debug` behaved correctly in GDB, but retained
  program headers whose referenced interpreter contents were removed; current
  `readelf` reported that structural inconsistency.

Inputs with no section-header table are also required. This is the failure in
`cesena/ghidra2dwarf` issue 29: a valid ELF32 big-endian MIPS executable has
zero `e_shoff`, `e_shentsize`, `e_shnum`, and `e_shstrndx`.

## Decision

Create `<original>.dbg` as a matched, non-loadable ELF sidecar:

1. Read target identity from the original ELF header and program headers.
2. Begin from a copy of the original bytes in a temporary output file.
3. Preserve ELF class, byte order, type, machine, OS ABI, ABI flags, entry
   address, and build-ID note content.
4. Set the sidecar's program-header offset, entry size, and count to zero. The
   original executable supplied to GDB remains the authority for load segments
   and PIE runtime bias.
5. Append Forge-generated debug sections and a correctly typed `SHT_STRTAB`
   `.shstrtab`, then write a new section-header table.
6. When the input has no section headers, begin the new table with `SHT_NULL`,
   preserve nonempty `PT_LOAD` allocation extents as inert generated sections,
   reconstruct identity note sections from `PT_NOTE`, and add debug sections
   and `.shstrtab` from scratch.
7. Resolve producer relocation records before publication. Do not copy or emit
   unresolved `SHT_REL`/`SHT_RELA` sections; inherited relocation headers are
   represented as `SHT_NOBITS` placeholders with no link or target. Allocated
   relocation sections retain their names, addresses, sizes, offsets and
   alignment, with only `SHF_ALLOC` retained, so automatic GDB association can
   match them to the original image. Nonallocated relocation sections are
   retired under `.forge.omitted` names with zero size/address/flags.
8. Publish by atomic replacement only after the complete sidecar validates.

### Automatic association and allocated relocations (2026-10-23)

GDB's [separate-debug-file contract](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html)
expects matching section names, addresses and sizes, while section contents may
be omitted. Renaming and zeroing allocated relocation sections violated this
contract: automatic association warned that sections such as `.rela.dyn` were
missing. Explicit `symbol-file` loading did not exercise that check, and the
previous build-ID regression did not reject warnings.

Preserving allocated relocation extents as `SHT_NOBITS` satisfies that matching
requirement without retaining active relocation records. Only `SHF_ALLOC`
survives; `sh_link`, `sh_info` and `sh_entsize` are zero. Original bytes remain
copied unchanged, but the section has no logical payload. Nonallocated
relocations remain retired. This is a sidecar compatibility fix, not a product
option to modify the original with `.gnu_debuglink`.

### Existing debug metadata policy (2026-10-22)

The Forge sidecar describes the current Ghidra program; it does not merge the
original compiler's DWARF with the new export. Replace matching `.debug_*`
sections with the new uncompressed payloads and clear their old section flags.
Retire unmatched `.debug_*`, GNU-compressed `.zdebug_*`, `.gdb_index`,
`.gnu_debuglink`, `.gnu_debugaltlink`, and `.gnu_debugdata` under
`.forge.stale`-prefixed names. Only one matching section can receive a new
payload; duplicate original names are retired too. Existing relocation
sections continue to follow the neutralization rule above.

This prevents consumers from following the old debug file links or using
indexes/compressed data that describe a different debug view. Original payload
bytes remain in the copied sidecar, but are no longer active debug metadata.
The input itself, build identity, and unrelated sections such as `.eh_frame`
remain unchanged. This does not add optional debuglink attachment to the
original executable.

The subsequent [code address-index policy](ADDRESS-INDEX.md) generates an exact
`.debug_aranges` lookup table to avoid a demonstrated GDB address-map mismatch.
It uses this same replacement policy; inherited index contents are not reused.

### Allocation metadata for inputs without section headers (2026-10-23)

An input without a section table still describes its memory image through
`PT_LOAD`. Retaining only reconstructed allocated notes in the sidecar loses
the code/data allocation extents: consumers cannot recover those extents from
the sidecar after its program headers are removed. In particular, independent
DWARF location checks incorrectly bound the entire image by the note ranges.

For each nonempty original `PT_LOAD`, add a section named
`.forge.load.<program-header-index>`. This explicitly generated name identifies
the original physical program-header index; it does not claim to recover an
original section name or code/data subdivision. The section is `SHT_NOBITS`
with `sh_addr = p_vaddr`, `sh_size = p_memsz`, and `sh_offset = p_offset`.
It has `SHF_ALLOC`, plus `SHF_WRITE` for `PF_W` and `SHF_EXECINSTR` for `PF_X`.
Its link, info and entry-size fields are zero. Alignment is conservatively one:
segment alignment constrains virtual-address/file-offset congruence, so
`p_align` need not divide `p_vaddr` and cannot simply become `sh_addralign`.

These sections describe known allocation extents and have no logical file
payload, including when a segment's memory size exceeds its file size or the
whole segment is memory-only. Original copied bytes and reconstructed notes
remain intact. Zero-memory-size loads and non-load program headers do not
produce allocation sections. Reject a load whose exclusive virtual end exceeds
the supported signed-64-bit address model, or exceeds `2^32` for ELF32, before
creating a staging file. An ELF32 load may end exactly at `2^32`.

This rule applies only when the input section table is absent. Present section
tables, including unnamed sections, retain their existing index/name policy.
The sidecar still has no program headers and remains non-loadable; the original
executable remains the authority for runtime mappings and PIE bias. Generated
allocation metadata does not establish automatic association support for a new
layout or recover source-level facts.

### Extended section numbering (2026-10-23)

Recompute both section-count and section-name-table encodings after appending
the Forge sections. The thresholds are independent: at 65,280 (`0xff00`)
sections, `e_shnum` becomes zero and section zero's `sh_size` stores the count.
Only when the section-name-table index itself reaches `0xff00` does
`e_shstrndx` become `SHN_XINDEX` (`0xffff`), with that index in section zero's
`sh_link`. These are the [gABI extended-numbering rules](https://gabi.xinuos.com/elf/02-eheader.html).

Rebuild section zero as canonical `SHT_NULL`, setting only the required count
and name-index overflow fields. In particular, its old `sh_info` cannot be
retained because the sidecar has no program-header table. Section zero has no
payload; its count metadata is not a byte length to read from the input.
Preserve all original physical section indexes, including inactive entries,
so symbol-table and other section references remain valid.

### Unnamed sections and extended program counts (2026-10-23)

`e_shstrndx == SHN_UNDEF` means a present section table has no section names.
Preserve those sections at their original indexes with empty names; do not
interpret section zero as a string table or guess names from contents. Append
named Forge DWARF and a new `.shstrtab`. Existing typed note sections and
program-header note ranges remain evidence for build identity. Reconstruct
only the portions of `PT_NOTE` not already covered by typed note sections,
so a partially described segment does not duplicate the build ID. A short or
misaligned uncovered interval fails explicitly instead of inventing note data.

For `e_phnum == PN_XNUM` (`0xffff`), read the actual program-header count from
section zero's `sh_info` before iterating the program table. A missing section
zero or an invalid count is an error. See the [ELF header definitions in
elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html). Input decoding and the ability of an OS
or emulator to execute that layout are separate acceptance questions; record
loader restrictions explicitly. The sidecar still has no program headers and
therefore clears section zero's `sh_info`.

Address translation reverses the loader's actual mapping: current Ghidra
image base minus `ElfLoader.getElfOriginalImageBase(program)`. Ghidra 12.0.3
records this original base during import, and its own DWARF importer uses the
same property. Its initial base search examines only the first 20 program
headers; with all load headers later in the table, the recorded base may be
zero while mapped function addresses retain their link-time values. Computing
the delta from the true minimum `PT_LOAD` address would then corrupt every
exported address. Missing or malformed loader metadata fails with a diagnostic
instead of guessing. `ElfImage.preferredImageBase()` still reports the actual
minimum load-segment VA as ELF metadata.

### File-backed I/O and resource bounds (2026-10-23)

Read ELF metadata through short-lived file channels and copy original bytes
to a temporary output through bounded transfers. Plan the complete output
layout, including overflow and resource checks, before creating the temporary
file. Append generated DWARF, names and individual section headers, rewrite
the ELF header, close the channel, then atomically replace the destination.
This removes the original image's Java-array/2 GiB size constraint. Generated
DWARF and extraction models remain memory-resident; this is not a claim of
constant-memory whole-program decompilation.

The reader and writer deliberately impose these resource limits:

| Resource | Supported bound |
|---|---|
| Program or section header count | 262,144 entries per table |
| Raw metadata table | 64 MiB |
| Section-name table and aggregate decoded names | 16 MiB each |
| Individual section name | 65,536 bytes, excluding NUL |
| Convenience `bytes()` / `sectionData()` allocation | 64 MiB |
| File sizes and offsets | Nonnegative signed 64-bit values |
| ELF32 output | Fields fit unsigned 32 bits; file end at most 4 GiB |

These are implementation limits, not ELF format restrictions. Output metadata
must also fit the reader's limits. Out-of-range metadata, truncated tables,
unrepresentable layouts and input/output aliases fail without replacing an
existing destination. Reopened source reads/copies check file identity, size
and modification time to detect ordinary concurrent changes. This check is
not a lock or a defense against a writer deliberately restoring metadata.
ELF64 values outside the signed 64-bit model remain unsupported.

The initial explicit GDB workflow is:

```gdb
file /path/to/original
set auto-solib-add off
symbol-file /path/to/original.dbg
```

`file` supplies executable/runtime mapping. `symbol-file` supplies recovered
symbols, types, and source mappings. Disabling automatic shared-library symbol
loading avoids replacing the deliberately supplied reconstructed symbol view.

The sidecar retains matching build-ID note content so automatic discovery can
be added later. Adding `.gnu_debuglink` to the original remains an optional,
explicit target-modifying operation and is not part of default export.

## Evidence

The test harness injected compiler-DWARF oracle sections through the same Java
container writer and then executed the stripped original while loading the
sidecar explicitly. The matrix passed for:

- x86-64 ELF64 little-endian ET_EXEC and PIE;
- AArch64 ELF64 little-endian ET_EXEC and PIE under QEMU;
- ARM32 ELF32 little-endian ARMv7 hard-float ET_EXEC and PIE under QEMU;
- MIPS ELF32 big-endian ET_EXEC and PIE under QEMU;
- MIPS ELF32 little-endian ET_EXEC and PIE under QEMU; and
- program-header-only/no-section-table ET_EXEC variants of all five targets.

For every case, `readelf -h`, `-S`, `-n`, debug-info, abbreviation, and decoded
line dumps completed without sidecar warnings. GDB broke at `recovered_add`,
reported arguments 19 and 23, stepped source, printed local `sum` as 42, and
observed normal exit. Input hashes remained unchanged.

This evidence validates the container/loading strategy. Until Forge-produced
DWARF replaces compiler-DWARF oracle data, it does not prove the exporter’s
semantic DIE/line/type/location content.

## Consequences

- Product code does not require external `objcopy` or architecture-specific
  ELF relocation encoders to package a linked sidecar.
- The published sidecar has no unresolved relocation sections or incomplete
  relocation-to-symbol-table relationships.
- PIE relocation is handled by GDB using the original executable mapping.
- Sidecars contain copied bytes that are not described as loadable segments;
  this favors correctness and target identity over minimal file size.
- Metadata has explicit resource bounds, and large input bytes are streamed.
  See `VALIDATION.md` for layout/large-file evidence, external loader limits,
  shared-object runtime, build-ID discovery and existing-DWARF replacement.
