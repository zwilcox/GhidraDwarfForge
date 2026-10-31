# Sectionless unwind discovery: i386 alias acceptance blocker

**HISTORICAL research checkpoint (2026-10-31).** The defect and independent
repair below led to a bounded production implementation. See
[current implementation and validation](../SECTIONLESS-UNWIND.md).
P1.7/#66 remains open; full i386 alias acceptance is pending.

Six fresh i386 retained/fully-stripped exec/PIE/rebase base cases and six
automatic analyst-alias cases pass structural validators and GDB. The same
candidate passes a sectionless non-PIE case, but sectionless rebased PIE fails:
`next` enters the compiler's four-byte PC helper instead of stepping over it.
The planner's i386 restriction is separately reproduced in the preceding
package: both new labels are diagnosed and omitted.

## Controlled evidence

The source-built PIE fixture begins each tested function with a direct call to
`mov (%esp), %eax; ret`. The call displacement, helper bytes and stacked return
address are checked independently. A source `step` can legitimately enter this
helper; the corrected oracle proves the helper and its return before resuming.
It still rejects a `next` that enters the helper. That assertion exposed the
sectionless problem, rather than being relaxed to hide it.

The original sectionless bytes retain `.eh_frame`, but the current writer does
not expose it under that name because the original section table is absent.
Adding only a section-table view of those exact original bytes in an independent
sidecar copy restores the expected `next` behavior. No instruction, source row,
variable location or call-frame instruction is fabricated or modified.

`discover.py` reads only program-header information after section-header fields
are cleared. It decodes the frame pointer and search table, locates their unique
file-backed loads, walks CIE/FDE record boundaries through the last referenced
FDE, and verifies CIE references and the complete set of table-referenced FDEs.
Independent original section headers are used only by the comparison oracle.

Eighteen fixture comparisons cover six i386 cases and twelve x86-64/AArch64/
MIPS32 BE/LE cases. Sixteen have a header and match the original address, file
offset and meaningful frame extent; only zero padding may follow. The two
static i386 exec fixtures have no header, and no extent is guessed. Receipt:
`06158b48878531362675a9d9e09d155a4c65e156e985082ffa29d20a849ad7c4`.

`mirror.py` uses that discovery to add an `.eh_frame` section view to a new
sidecar copy. The failing rebased-PIE case then passes four GDB calls, `next`,
`step`, values, returns, GNU frame decoding, LLVM verification and strict
libdwarf with zero reported errors. Original input/sidecar hashes remain intact.
Receipt: `121ad3467fc0151973954038b0522ae096daa5e79d9268c6008fa61e5c8acd8e`.
Local evidence is under `build/i386-alias-review/discovered-eh-frame/`.

## Format basis and next implementation

The [LSB 4.1 Core specification, §§10.5–10.6](https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.pdf)
defines the header's encoded frame pointer, count and sorted search table.
An FDE's CIE reference is a backward offset from the reference field; record
lengths delimit each entry. The research profile handles version 1, fixed-width
absolute/PC-relative/header-relative pointer forms and ordinary DWARF32 records.
Extended records and other encodings are not established by this experiment.

The research scripts buffer small trusted fixtures. They are **not** safe
production readers. The production change must:

- Read through the original ELF identity and bounded file-backed mappings, with
  cancellation, overflow/extent checks and resource/operation budgets.
- Validate counts, ordering, record boundaries, CIE references, overlap and
  truncation before exposing original unwind bytes. Preserve synthetic load
  indices used by aliases and dynamic mirrors.
- Define explicit handling for absent headers, unsupported encodings and
  malformed metadata; do not invent a frame extent or make the original ELF
  writable. Retain atomic output publication.
- Add synthetic malformed/cancellation cases, actual sectionless i386 PIE and
  rebased-PIE behavior tests, other-target regressions and hosted acceptance.

The i386 alias candidate has 374 planner checks, 228 six-language extraction
checks and 33 actual Java 21 suites passing. Its complete acceptance is held
on this production unwind work. The first PIE harness failure and the later
sectionless `next` failure remain retained as distinct evidence.
