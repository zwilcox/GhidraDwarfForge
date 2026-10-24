# Read-only ELF build-ID observations

`ElfBuildId.read(Path)` reports an optional unique GNU build-ID value and its
physical note occurrences, with section/program-header provenance. The pure
comparison operation distinguishes matching values, different values, absence
in both files and absence from either member of a pair. These results describe
observed note contents. Equal IDs do not establish file identity, matching load
images, authenticity or eligibility for debuglink attachment. Reads are not an
atomic snapshot. Existing `ElfImage` source-change checks remain best effort;
null file keys cannot establish identity.

The observer is independent of Ghidra analysis and native libraries. Ordinary
export does not call it and its output/report schema is unchanged. It is a
bounded foundation for [ADR-0004](ADR-0004-DEBUGLINK-ATTACHMENT.md); that operation's
receipt, ELF relationship, backup, metadata, refresh and recovery checks remain
separate work.

## Note format and ambiguity

Walk typed `SHT_NOTE` sections and `PT_NOTE` segments, including unnamed or
sectionless files. Section spelling does not determine identity. Recognize the
exact four owner bytes `GNU\0`, type 3 and a nonempty descriptor. Descriptor
length is not fixed to SHA-1. A similarly named section or another owner/type
does not become a GNU build ID.

The audited layout follows GNU binutils 2.42: three target-endian 32-bit header
words, effective alignment at least four, supported alignments four and eight,
and complete padding through the final record. Padding byte values are
unrestricted. Alignment comes from the container rather than ELF class alone.
GNU readelf's display recognition is more permissive than BFD's object-note
recognition; this observer deliberately uses the exact object-note owner rule.

Parse every typed view before deduplicating physical notes. Identical header
and descriptor spans may appear through both tables, including compatible
four/eight-byte trailing-padding views. Identical values at distinct valid
offsets retain separate occurrences. Conflicting IDs and incompatible overlaps
fail rather than selecting one value. Truncated payloads/padding, malformed
owners, compressed note sections and unsupported alignments also fail; they
are not reported as absence.

One explicitly known alternate format uses 64-bit header fields:
IA-64/OpenVMS. An isolated format table keys that exception by the original
machine and OS ABI. Nonempty note views in that format are rejected with an
unsupported-format diagnostic. Note-free inputs remain absent, and neither
discriminator alone rejects standard notes. This is an exclusion from the
observer, not a change to ordinary export or a new target support claim.

The source audit uses the official
[binutils 2.42 archive](https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.xz),
SHA-256 `f6e4d41fd5fc778b06b7891457b3620da5ecea1006c6a4a41ae998109f85a800`:
`binutils/readelf.c`, `bfd/elf.c` and the ELF external/common/IA-64 headers.
This is a documented format reference, not a new runtime dependency.

## Resource and cancellation bounds

The observer permits at most 4,096 nonempty views, 65,536 record visits
including repeated views, a 1 MiB build-ID descriptor and 16 MiB of note bytes
actually read. Unknown descriptors are skipped after validating their ranges.
Retained record metadata is bounded; descriptor data for only the current and
first ID is retained. Reads use chunks no larger than 64 KiB, with checked
offset/alignment arithmetic. `ElfImage`'s existing metadata bounds also apply.
These are explicit resource limits rather than ELF format constraints.

Cancellation is checked before file work, around metadata parsing and during
note iteration and chunk reads. Every operation closes its source channel.
Cancellation cannot interrupt a blocked filesystem operation or an already
running bounded `ElfImage` metadata parse. Observing a high-offset note does
not require reading the intervening file contents.

## Acceptance

**CONFIRMED locally; hosted gate pending:** native-free tests cover ELF32/64,
both byte orders, four/eight-byte layouts, nonzero padding, partial/repeated
container views, absence and owner/type/name decoys. Extended section counts,
extended string-table indices, late `PN_XNUM` notes and offsets above 2 GiB
pass under a 64 MiB Java 21 heap. Exact bounds and over-limit inputs,
malformed records, conflicting IDs, cancellation, source changes and channel
closure are exercised. The specific VMS false-absence reproduction is now
rejected, with paired-discriminator controls.

The independent installed-JAR oracle uses x86-64, AArch64 and MIPS32 big-endian
export pairs. It compares IDs and relationships with GNU
readelf, and checks nameless matched sidecars, sectionless originals, renamed
notes, vendor decoys, repeated identical IDs, conflicts and malformed lengths.
It checks class origins, fixture identities and input bytes/mtimes. GNU tools
write only owned variant outputs. The initial component check consumed earlier
validated artifacts; the final combined local check uses nine freshly exported
pairs from the exact combined JAR. Eight additional saved-program path exports,
three rejection cases and both helper oracles pass on that package. This is
ordinary-export regression evidence, not new exporter integration of the
observer. Native Windows and the complete five-target hosted gate remain
required. P2.8 remains incomplete. See `VALIDATION.md` for exact evidence.
