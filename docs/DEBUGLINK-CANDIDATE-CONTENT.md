# Content observations for a new debuglink candidate

**CONFIRMED locally; full hosted gate pending:** `DebuglinkCandidateContent` is the
packaged consumer of three separate content predicates. It compares explicitly
selected original/candidate ELF files and one selected sidecar. Ordinary export
is unchanged. This component launches no backend, writes no selected file and
does not expose an attachment operation.

The existing private-copy integration workflow already checks program bytes,
allocated metadata and exact debuglink creation bytes before its GDB tests.
Only the program-byte predicate previously had a production implementation.
The research Java probe accepted a candidate with a changed `.text` address or
changed debuglink address/alignment, while the Python test rejected them. This
component closes those test-only gaps without certifying target replacement.

## API and evidence boundaries

`observe(original, candidate, sidecar, expectedBasename[, cancelled])` returns:

| Observation | Scope |
| --- | --- |
| `programBytes` | The existing `ExecutableProgramBytes` result, including its header exceptions and no-LOAD-evidence outcome. |
| `allocatedSections` | Indexed executable allocation metadata and raw used names, within the supported envelope below. |
| `newDebuglink` | One exact GNU initial-creation record for the supplied literal basename and observed sidecar CRC. |
| `sidecarDigest` | Streamed SHA-256, GNU CRC32 and byte count of the explicitly selected sidecar. |

There is no aggregate approval or attachment-readiness flag. Allocation outcomes
are `MATCHING`, `DIFFERENT`, `UNSUPPORTED` or `NO_ALLOCATION_EVIDENCE`; new-link
outcomes are `MATCHING`, `DIFFERENT` or `UNSUPPORTED`. A differing or unsupported
content observation has one bounded issue with physical section indexes, field
and expected/observed values. Index `-1` means there is no corresponding record.
Ordinary differences retain all predicates. Malformed metadata, resource limits,
I/O errors and cancellation throw and produce no result.

All three selected paths must identify regular files before parser or digest
reads begin. Actual host traversal and read-only aliases are retained. The
observations are sequential; attribute checks detect some ordinary changes but
do not establish file identity, a lock or an immutable snapshot. Existing readers
own and close their channels. Cancellation surrounds bounded reads and walks;
it cannot interrupt a blocked filesystem call or every parser operation.

## Executable allocations

Both ELF files need canonical-width section records and a usable name table.
Absent/unnamed tables and opaque larger section records are explicitly unsupported
by this predicate; ordinary export keeps its wider input contract. At least one
active original `SHF_ALLOC` record is needed for positive allocation evidence.

Each original non-NULL allocated record retains its physical index, type, full
flags, address, file offset, size, link, info, alignment, entry size and raw used
name bytes. Candidate-only allocations, promotions, demotions and removed indexes
differ. Duplicate names and overlapping records stay individually indexed.
Changing a string-table offset alone is allowed when it still names identical
bytes. Names are never compared through replacement-decoded Unicode strings.

This is an executable contract. REL/RELA remain REL/RELA; no matched-sidecar
NOBITS conversion, note reconstruction, synthetic LOAD sections or program-table
removal is accepted. Existing NOBITS and zero-sized sections are compared as
metadata without reading their memory extents as file payloads.

Every nonempty, non-NOBITS allocated file extent must fall inside the merged
non-NULL program-payload union; otherwise this initial predicate returns
unsupported coverage. The separate program comparison protects those bytes,
subject to its exact ELF section-table-field exceptions. Equal metadata alone
does not prove bytes outside that coverage or a complete runtime memory map.

## Exact initial GNU debuglink record

The original must contain no raw exact `.gnu_debuglink` section name. An existing
association is unsupported for initial creation, including malformed or duplicate
named records. Refresh and replacement require a separate transaction policy.

The candidate must contain exactly one such name, with `SHT_PROGBITS`, zero
flags/address/link/info/entry size and alignment four. Its exact payload is the
supplied basename bytes, one NUL, zero padding to a four-byte boundary and the
selected sidecar's unsigned CRC32 in candidate byte order. Extra bytes, incorrect
padding, wrong fields, multiple records and stale CRCs differ. This is the pinned
GNU creation contract, which is stricter than some GDB/BFD consumer acceptance.

The caller supplies literal basename bytes. They are defensively copied, bounded
to 1–65,536 bytes and reject NUL, slash, `.` and `..`. No decoding, normalization,
case folding or UTF-8 conversion occurs. POSIX backslash can be an ordinary leaf
byte. The future host/backend boundary must prove the actual filename encoding;
this API does not infer it from a Java `Path` or establish Windows compatibility.
The Linux integration caller uses the host's `os.fsencode` result explicitly.

A plain-data sidecar can have the exact expected CRC and all content predicates
can agree. This deliberate counterexample preserves the separation from receipt
provenance, ELF/DWARF validity, source correlation and debugger usefulness.

## Bounds and remaining work

Existing ELF signed-offset, header/count and table limits still apply. Each raw
name table and its aggregate used-name slices have independent 16 MiB bounds;
each used name is limited to 64 KiB. Repeated offsets are cached, and suffix
slices count toward the aggregate budget. The exact link payload is at most
65,544 bytes. Payload coverage is sorted/merged once and searched by index;
the sidecar is digested with fixed buffers. No universal 64 MiB guarantee is
made for every maximum-metadata combination.

The private consumer requires each documented predicate before its existing
GDB association checks, while Python independently reconstructs the expected
content. Native Windows focused tests validate the read-only API, not a Windows
backend or filesystem transaction. Native Windows and full hosted acceptance
remain pending.

## Local acceptance (2026-10-24)

Source `e30fae3` passes 970 default assertions, or 972 including a sidecar above
2 GiB, on actual Java 21 with a 64 MiB heap. Both ELF widths/orders, indexed
metadata changes, raw names, exact link fields/payloads, resource bounds and
cancellation are covered. Independent review required explicit demotion/removal
controls and a name issue identifying the first differing byte even after a long
shared prefix. The source and related smokes/build pass. The parent program/prefix
callback corrections are incorporated normally; combined build and actual
Java 21 default checks pass again.

Installed JAR
`4dd5f62a3d8fc5d5792e800c2e9ba45895b797147f3bb7f62d6e9c5b60bf3414`
passes nine new private backend candidates from retained x86-64, AArch64 and
MIPS32 big-endian exec/PIE/no-build-ID exports. Independent root and peer audits
verify repeated observations, 27 retained input copies, 135 retained parent
receipt/tool/log files, 72 content controls, six malformed and eighteen invalid
basename cases. All 36 original fixture snapshots remain unchanged. The new
Python oracle compares byte issue values semantically; production's bare hex and
the model's prefixed hex remain equivalent without discarding raw diagnostics.

The existing 27 GDB association checks pass, including native x86 argument values
19/23 and normal exit. A sparse 2,147,614,795-byte selected sidecar has its full
SHA/CRC/count recipe reconstructed independently after cleanup, including the
one-byte mutation that invalidates the candidate's CRC. This is a content fixture;
it is not a DWARF sidecar or a debugger-discovery claim for the large file.
No new Ghidra export, structural-validator or cross-target execution is attributed
to this retained-fixture replay. Final package and exact hosted acceptance remain
required after the corrected program-byte parent is accepted.

Attachment still needs receipt/diagnostic policy, selected export relationships,
external validation, backend process control, host identity/metadata handling,
exclusive backups, durable receipts, atomic replacement and tested recovery.
See `ADR-0004-DEBUGLINK-ATTACHMENT.md` for that separate contract.
