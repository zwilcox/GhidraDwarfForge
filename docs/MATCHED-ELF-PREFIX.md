# Retained original bytes in a Forge sidecar

**CONFIRMED:** PR #34 head `888406e` passes all twelve jobs in exact hosted
run `40097366322` and merged as `837cec8`. Independent package, all five target
artifacts and both GUI reviews are clear. Thirty pairs and repeated comparisons,
the x86 large-file case and sixteen native Windows focused checks pass. The focused `MatchedElfPrefix` checks pass on actual
Java 21, including an input above 2 GiB under a 64 MiB heap. Independent source
review is clear. Installed-package comparisons pass for eighteen fresh
x86-64/AArch64/MIPS32 big-endian export pairs, with structural validators and
GDB. Independent source, artifact and final local package reviews are clear.
The separate main push remains pending; published releases are unchanged.

The current matched writer first copies every original byte, appends debug data
and a new section table, then changes specific fields in the fixed ELF header.
`MatchedElfPrefix.compare(original, candidate)` checks that particular byte
relationship. It reads the supplied paths and returns an immutable observation;
ordinary export does not call it. It does not alter either file or invoke a
native producer.

A matching result is useful evidence that the candidate retains these original
bytes. It does not establish a stable snapshot, authenticated provenance, file
identity, active allocated-section addresses, DWARF validity, source correlation
or permission to attach the sidecar. Reported and independently computed hashes,
typed build-ID observations and later allocation/receipt checks remain distinct.
A legitimate sidecar from another packaging strategy can fail this check without
being an invalid separate-debug artifact.

## Compared bytes and required layout

Both inputs first pass `ElfImage` metadata parsing. Its existing signed file
offset model and resource limits apply. The class and byte order must agree.
The candidate must be at least as long as the original, have no program-header
table (`e_phoff`, `e_phentsize` and `e_phnum` all zero), and have a canonical,
nonempty section table with a valid nonzero section-name index. That active
table must start at or beyond the original EOF. Extended section counts and
name indices are resolved by `ElfImage`.

Compare bytes through the original EOF, with exactly these half-open exceptions:

| Class | Header byte intervals | Fields |
| --- | --- | --- |
| ELF32 | `[28,36)`, `[42,52)` | Program/section table offsets, entry sizes, counts and section-name index |
| ELF64 | `[32,48)`, `[54,64)` | The corresponding 64-bit header fields |

Their meanings are checked by the layout rules above; they are not arbitrary
ignored bytes. All other fixed header bytes must agree, including target/ABI
fields, entry, flags, padding and `e_ehsize`. An oversized `e_ehsize` does not
enlarge the exception. Old program headers, old section/debug tables, load bytes,
sparse holes and opaque trailing bytes all remain part of the comparison.
PIE/shared-object addresses need no special adjustment for a byte comparison.

These exceptions belong only to a matched, non-loadable sidecar. Never reuse
them for an executable staged for debuglink attachment: that executable must
retain its original program-header table under ADR 0004.

## Results, resources and cancellation

The immutable result contains status, observed file lengths, compared extent,
an optional first differing byte offset and a diagnostic. Status precedence is
class/order disagreement, shorter candidate, required-layout disagreement, then
byte comparison. The outcomes are `DIFFERENT_LAYOUT`, `SHORTER_CANDIDATE`,
`DIFFERENT_PREFIX` and `MATCHING_COPIED_PREFIX`. Malformed ELF, I/O failure and
cancellation throw; they never become a successful empty comparison.

`comparedExtent` is the exclusive original-file offset examined, including the
explicitly exempted header fields. It is zero before byte comparison, one past
the first differing byte, or the original length for a match. A read can look
ahead by one buffer. Lengths and offsets are Java `long` values.

The streaming comparison uses two 64 KiB buffers and owns both input streams,
closing them on success, early difference, cancellation or failure. Tests verify
primary and suppressed exceptions, including second-open and close failures.
Actual path traversal is preserved; paths are not lexically normalized first.
Observed headers are checked again when their bytes reach the comparator, and
size/mtime/file-key checks detect ordinary concurrent changes. These are best
effort diagnostics, not locking or snapshot guarantees. A null file key does
not establish identity.

Cancellation is checked around metadata work and bounded comparison reads.
The existing metadata parser is not cancellable at every internal read, and
the supplied cancellation function cannot interrupt a blocked filesystem call.
The 64 MiB test proves bounded streaming for its fixtures; it is not a promise
that every maximum-size metadata-table combination fits that heap.

## Independent controls and acceptance

The focused suite builds 24 writer-derived containers across ELF32/64 and both
byte orders: named, unnamed, sectionless, extended section counts, `PN_XNUM`
and oversized headers. It checks exception boundaries, preserved-byte changes,
valid-but-different layouts, stream failures and cancellation. The optional
large case records a 2,147,549,185-byte original and a first differing offset of
2,147,549,184 on actual Java 21 with `-Xmx64m`.

The installed oracle uses independent Python metadata and streaming byte reads
for six primary export roles per target: non-PIE, partially stripped, no build
ID, sectionless, PIE and shared object. It retains exact consumed production
transcripts and all executable/sidecar/source bytes before later tests can reuse
shared paths. It checks installed class origins and input preservation, while
the existing pipeline separately runs validators and GDB. The x86 lane also
constructs a sparse input above 2 GiB independently of the Java fixtures.

Two complementary owned mutation controls keep the result's scope explicit:

- A changed original `.text` byte leaves metadata and GNU build ID unchanged;
  the prefix comparison must locate the differing byte.
- A shifted active `.text` address in the appended section table leaves the
  prefix and build ID unchanged. GNU structural reads succeed and the prefix
  must still match, while an independent metadata comparison records the wrong
  address. This is deliberately not claimed as a valid debug artifact.

Native Windows runs the default focused suite. Large-file evidence is attributed
only to the host that runs it. P2.8's product attachment transaction remains
planned; see `ADR-0004-DEBUGLINK-ATTACHMENT.md` and `VALIDATION.md`.
