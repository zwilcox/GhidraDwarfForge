# Exact code address index

The exporter emits `.debug_aranges` for the exact union of its exported
function body intervals. This optional DWARF lookup section prevents a
demonstrated GDB 15.1 address-index mismatch. It does not change function/CU
coverage, line rows, global addresses, variable locations or ELF load semantics.

## Evidence and decision

Without the index, GDB 15.1 can warn when formatting a perfectly valid global
address with `print/a` or a typed pointer. Both the previous exporter and the
opaque-register-effect fix reproduce this warning; merely omitting the uncertain
parameter location avoids an automatic formatting trigger, not the cause.

In the [official GDB 15.1 source](https://ftp.gnu.org/gnu/gdb/gdb-15.1.tar.xz),
`gdb/dwarf2/read.c` indexes a global's decoded `DW_OP_addr` when the CU has no
address-coverage flag. Its expanded CU symtab derives code bounds from child
subprograms, so that data address cannot be found in the selected symtab.
`cooked_indexer::check_bounds` sets the flag for CU low/high bounds, but not for
CU range lists. Adding a range list alone therefore does not resolve the
observed behavior. The `.debug_aranges` reader sets the flag after accepting
its lookup tuples and avoids this fallback data-address indexing.

[DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf), Sections 2.17 and 3.1.1, describes
CU/subprogram bounds as instruction coverage. Widening a CU low/high envelope
through globals or gaps would misrepresent that coverage. Instead, Sections
6.1.2 and 7.21 provide the optional address lookup table. A code-only table
matches the actual function coverage and the debugger's code symtab.

## Encoding contract

- Use address-table version 2, as retained by DWARF 5, and DWARF32 section
  offsets. The exporter produces one CU whose **header** begins at
  `.debug_info` offset zero; the first DIE's offset is not the CU header offset.
- Derive four/eight-byte address words and byte order from the ELF target.
  No native producer API, relocation encoding or architecture whitelist is added.
- Sort and merge actual function intervals, including every discontiguous body
  range. Preserve every gap. Never add a global-data interval or a broad envelope
  merely to influence GDB lookup.
- Align tuples relative to the contribution, zero the padding, and terminate
  with one zero address/length pair. Nonzero-length coverage at address zero is
  valid. Split an interval when its length cannot fit one address-sized word;
  a full ELF32 address-space union needs two tuples. Reject target-width overflow.
- Existing function and CU DIE ranges remain authoritative. This table indexes
  them; it does not replace them or establish new source/variable information.
- The matched ELF writer replaces any inherited table using its existing debug
  metadata policy. Original executables remain unchanged.

This supersedes the historical policy requiring `.debug_aranges` to be absent.
It does not add `.debug_names`, recover original compiler facts, promise that
GDB will print a global's name for an arbitrary numeric address, or introduce
multiple-CU/DWARF64/segmented-address support.

## Acceptance

The format smoke covers both widths and byte orders, overlaps/adjacency,
discontiguous functions and gaps, deterministic ordering, zero/high addresses,
full-width lengths and rejecting out-of-range inputs. An independent integration
checker compares raw table headers/tuples against LLVM-decoded subprogram
coverage and rejects wrong CU offsets, malformed lengths/versions/alignment,
truncated/invalid tuples and invented coverage.

Actual compiler/Forge GDB tests must format global/owned-static addresses and
typed pointers across the five existing target profiles, including PIE and
Ghidra rebasing. The AArch64 supervisor-call fixture checks before full CU
expansion for exec and after runtime bias is known for all three roles. The
x86 advanced-entry fixture retains its backward-execution and no-gap assertions.
All existing validators, input hashes and deterministic-repeat checks remain
required; no GDB warning exception is added. Exact local/hosted acceptance is
recorded separately in `VALIDATION.md`; implementation presence is not a passed
runtime gate.
