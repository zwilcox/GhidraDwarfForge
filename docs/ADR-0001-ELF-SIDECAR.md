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
   reconstruct identity note sections from `PT_NOTE`, and add debug sections
   and `.shstrtab` from scratch.
7. Resolve producer relocation records before publication. Do not copy or emit
   unresolved `SHT_REL`/`SHT_RELA` sections; inherited relocation headers are
   represented as zero-length `SHT_NOBITS` placeholders with no link or target.
8. Publish by atomic replacement only after the complete sidecar validates.

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
so symbol-table and other section references remain valid. This is separate
from support for extended program-header counts (`PN_XNUM`).

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
- Very large files, extended program-header counts, and inputs with section
  tables but no section-name table remain follow-up work. See `VALIDATION.md`
  for extended section-numbering, shared-object runtime, build-ID discovery,
  and existing-DWARF replacement evidence.
