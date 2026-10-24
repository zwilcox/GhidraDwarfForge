# Active allocated metadata in a Forge sidecar

**CONFIRMED locally; hosted gate pending:** `MatchedElfAllocations` implements
a conservative, read-only comparison of active allocated metadata. Actual Java
21 focused checks and installed comparisons against eighteen retained exporter
pairs pass. Independent source/runtime and local package reviews are clear;
the complete hosted gate remains required.
Ordinary export does not call this helper and gains no additional restrictions.

A copied original prefix cannot establish the addresses in an appended section
table. This helper checks those active records against the original ELF's
metadata under the current matched-writer rules. It compares physical indexes,
target fields and explicit transformations. A matching result does not establish
copied code bytes, file identity, an immutable snapshot, valid DWARF, source
correlation or attachment eligibility. The original metadata itself is not
certified as a complete runtime memory map.

## Observation API

`compare(original, candidate[, cancelled])` returns an immutable result with
status, an optional first issue and a nonblank diagnostic:

| Status | Meaning |
| --- | --- |
| `MATCHING_ALLOCATED_METADATA` | At least one supported allocation record corresponds under the rules below. |
| `DIFFERENT_METADATA` | A target, layout or indexed allocation field differs, or an unexpected allocation appears. |
| `UNSUPPORTED_CASE` | The original requires a transformation or address interpretation outside the conservative comparison contract. |
| `NO_ALLOCATION_EVIDENCE` | No active allocation record supplies comparison evidence; this is not an empty successful identity check. |

Different and unsupported outcomes contain exactly one issue; matching and
no-evidence outcomes contain none. An issue identifies its header, original
section, original segment or candidate section origin, source/candidate indexes,
field, reason, and expected/observed display values. Index `-1` means no
corresponding index. There are no misleading partial-total counts. Malformed ELF
and I/O failures throw `IOException`; cancellation throws `CancellationException`.
Both inputs are parsed before returning a target/layout outcome.

## Normal correspondence

Compare class, byte order, object type, machine, OS ABI, ABI version, flags and
the raw entry-point bit pattern. Unknown machine/flag values need no architecture
whitelist. Do not infer CPU support from equality, compare the candidate's
nonexistent load base, or apply a PIE rebasing adjustment.

Require the current sidecar envelope: zero program-table offset/entry size/count,
and a nonempty canonical section table with a valid nonzero name-table index
starting at or beyond original EOF. Extended counts are resolved by `ElfImage`.
Other copied header bytes remain the separate prefix helper's responsibility.

For a present original section table, each active `SHF_ALLOC` section retains
its physical index, used name bytes, type, full flags, address, offset, size,
alignment, link, info and entry size. Zero-size allocated records and duplicate
or unnamed records still retain their indexes. `SHT_NULL` records are inactive.
Ordinary `SHT_NOBITS`, TLS and unknown section types are compared as metadata;
their sizes are not read as file payloads.

Allocated `SHT_REL`/`SHT_RELA` records have the writer's explicit inert form:
`SHT_NOBITS`, flags exactly `SHF_ALLOC`, retained name/address/offset/size/alignment,
and zero link/info/entry size. This preserves their allocation metadata under a
documented transformation, not executable relocation semantics. Do not extend
that rule to other relocation encodings such as `SHT_RELR`.

Only when the original section table is absent, derive one `.forge.load.N`
record per nonempty `PT_LOAD`, in physical program-header order. Its NOBITS
extent uses `p_memsz`, address uses `p_vaddr`, offset uses `p_offset`, and flags
are ALLOC plus the corresponding write/execute bits; alignment is one and
link/info/entry size are zero. Memory-only loads and ELF32 extents ending at
2^32 are considered under the writer's existing address model. An unnamed or
NULL-only section table is present and does not select this reconstruction.

Any other candidate active allocation must be an explicitly reconstructed typed
note record. Original nonallocated rows cannot acquire ALLOC silently. Missing,
duplicated, shifted or unaccounted allocations fail the comparison. A global
range union or name dictionary cannot replace these indexed checks.

## Notes and conservative exceptions

Typed `SHT_NOTE` ranges establish physical file coverage. Iterate `PT_NOTE`
views in original order and derive only uncovered spans satisfying the writer's
minimum-length and alignment rules as `.note.forge.N` records. Their addresses
follow the segment's virtual-address
plus file-offset displacement; flags are ALLOC and the remaining fields match
the writer's explicit reconstruction. The coverage union is used only to find
gaps, not to erase indexed entries or require disjoint allocated addresses.
Synthesized notes can legitimately overlap synthesized LOAD extents.

Overlaps involving a program-note view must share an allocated
virtual-address/file-offset mapping. Two original section-note views retain
their separate indexed metadata. Nonallocated typed coverage of a program note,
or competing virtual
addresses for the same physical bytes, is explicitly unsupported. The writer
can describe some of these cases, but that is not proof that it preserves every
advertised address view. Note framing, owner, type and build-ID contents remain
the separate typed-note observer's responsibility.

Allocated debug metadata that can be replaced or renamed, and an allocated
original name table, are also unsupported. Do not infer the supplied debug
section map from an untrusted candidate to explain away lost allocation. A
relocation named `.debug_*` can subsequently receive a debug replacement and
must not be accepted merely because its initial placeholder transformation was
known. Ordinary allocated relocation names otherwise follow the rule above.

Used allocated section-name bytes are compared directly. A non-round-tripping
original allocated name is unsupported, not declared invalid ELF. The current
writer decodes names
as UTF-8 and can replace malformed sequences; decoded `String` equality would
hide changed raw bytes. Valid UTF-8, including an actual U+FFFD character, stays
distinct from malformed input. ELF string tables specify NUL-terminated character
sequences and byte offsets; this contract does not invent a universal UTF-8
requirement. See the [gABI string-table definition](https://gabi.xinuos.com/elf/04-strtab.html).

## Resources and composition

Keep the existing metadata bounds: 262,144 entries per header table, 64 MiB per
table, 16 MiB for names and 65,536 bytes per used name. Each separately read raw
name table enforces its own per-name and aggregate bounds. At most 65,536
nonempty note views are processed, with bounded coverage/derived-record counts.
Interval processing is indexed rather than scanning every note against every
section. Retain only the first issue. Do not read complete files or load
payloads; metadata can reside beyond 2 GiB.

The 64 MiB tests concern their specified fixtures, not every maximum metadata
combination. Checked arithmetic and the existing signed file-offset/address
model constrain representable results. Parsing, name reads and cancellation
release owned channels. Cancellation is checked around parser calls and within
record/interval walks, but cannot interrupt a blocked filesystem operation or
every internal parser read. Actual filesystem traversal is preserved. Size,
mtime and file-key observations are best-effort change diagnostics, not a lock
or snapshot; a null key never establishes identity.

Two complementary controls are required: changed code can retain matching
allocation metadata while failing prefix comparison; changed active section
metadata can retain a matching prefix while failing this comparison. A later
preflight must combine these distinct observations with independently computed
hashes, reported claims, build-ID results, validators and the transaction's
identity/backup requirements. This helper does not perform that composition or
modify an executable. P2.8 attachment remains planned.

## Validation scope

Focused checks pass on actual Java 21 with a 64 MiB heap: 532 default assertions
and 535 with the optional large-metadata case. They cover both classes/orders,
unknown target values, all outcome types, physical-index and field differences,
relocation placeholders, sectionless LOAD/note reconstruction, raw-name collisions,
unsupported transformations, cancellation and independent reread budgets. Exact
65,536-note-view acceptance and 65,537-view rejection are tested. Forty-five
retained pairs also match with their ninety selected input snapshots preserved.

The installed independent oracle reuses eighteen previously validated exports
from x86-64, AArch64 and MIPS32 big-endian, covering six roles per target. It
retains all 54 input/output/source byte copies and eighteen full producer logs,
verifies hash bindings and installed class origins, and compares indexed fields
with an independent Python model. Thirty-eight active-metadata mutations preserve
the copied prefix but are rejected by the allocation observer; three changed-code
controls deliberately demonstrate the converse limitation. Six malformed-operand
checks reject with typed errors. These are explicit retained-export replays,
not new Ghidra or GDB executions for this helper.

The x86 oracle separately places section tables and names above 2 GiB in tiny
sparse files, checks a matching allocation and an exact shifted-address rejection,
then removes the inputs. It retains a reconstructible recipe and hashes of the
selected metadata ranges. It does not claim a whole-file hash or a large-prefix
comparison for that test. Both local source and runtime artifact reviews are
clear. CI schedules the same ordinary six-role oracle in all five target lanes,
the sparse case on x86, and the default focused suite on native Windows; these
hosted results remain pending. See `VALIDATION.md` for commands and evidence.
