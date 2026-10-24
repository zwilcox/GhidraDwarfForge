# ELF header and program-byte observations

**CONFIRMED locally; full hosted gate pending:** `ExecutableProgramBytes` is a
read-only comparison of two explicitly selected ELF files. Its purpose is to
check bytes that a future debuglink backend must preserve. It does not create
a candidate, attach anything or change ordinary export behavior.

## Evidence behind the scope

The earlier research probe checked the fixed ELF header, program table and
`PT_LOAD` payloads. An owned fixture moves a `PT_NOTE` view outside every load
segment and changes one note-owner byte in the candidate. The old probe passes;
a comparison of all non-NULL program payloads rejects the changed byte. This
controlled layout was not executed and does not establish backend support.

Further Linux GNU 2.42 experiments on disposable copies show ARM32 hard-float
exec and PIE preserving program bytes, indexed allocated metadata and exact
debuglink bytes. Representative x86-64, AArch64 and both MIPS32 byte orders also
pass that research comparison. A UTF-8 ARM basename round-trips on this Linux
host; it says nothing about another host's filename encoding. Sectionless and
unnamed-table inputs are rejected by the configured tools. A PN_XNUM candidate
returns exit zero but moves the program table and changes protected bytes.
An existing debuglink also returns zero with a diagnostic and leaves the old
association unchanged. Exit status alone is insufficient.

The research leaves all 22 protected fixture/tool paths unchanged and uses
distinct explicit output filenames for every backend invocation. Native Windows
backend behavior, filesystem metadata and transaction durability remain unproven.
See `ADR-0004-DEBUGLINK-ATTACHMENT.md` for the separate attachment contract.

## Comparison contract

`compare(original, candidate[, cancelled])` returns a status, an optional first
issue and a diagnostic. Both files first undergo `ElfImage`'s bounded parsing.
Malformed metadata, resource limits, I/O failure and cancellation throw; they
cannot become matching or absent evidence.

| Status | Meaning |
| --- | --- |
| `MATCHING_PROGRAM_BYTES` | All specified byte comparisons match and the original has at least one file-backed LOAD. |
| `DIFFERENT_PROGRAM_BYTES` | A specified header, program-count, table or payload comparison differs. |
| `NO_FILE_BACKED_LOAD_EVIDENCE` | The specified comparisons match, but no original `PT_LOAD` has `p_filesz > 0`. |

Memory-only LOADs, NOTE-only images, absent program tables and inactive records
are not declared invalid ELF by the last outcome. An established difference is
reported before the no-evidence outcome. No architecture whitelist is added.

Comparison has explicit phase order:

1. Compare the complete declared ELF header, including extension bytes through
   `e_ehsize`, except the section-table fields below.
2. Compare resolved program-header counts, including the `PN_XNUM` dependency on
   section zero's `sh_info`.
3. Compare the complete raw program table, including inactive `PT_NULL` records,
   `p_paddr` and larger entry extensions.
4. Compare the ascending merged union of every non-NULL header's file payload,
   excluding already checked header/table spans. This includes non-LOAD and
   unknown program types. Read `p_filesz` bytes, never memory-only `p_memsz` tails.

The only exempt byte intervals are ELF64 `[40,48)` and `[58,64)`, or ELF32
`[32,36)` and `[46,52)`: `e_shoff`, `e_shentsize`, `e_shnum`, `e_shstrndx`.
The candidate still must parse its section metadata. These fields may describe
a rebuilt table before original EOF; a sidecar's appended-table rule does not
apply to a replacement executable. Program-table fields are never exempt.

An issue identifies `ELF_HEADER`, `PROGRAM_COUNT`, `PROGRAM_TABLE` or
`PROGRAM_PAYLOAD`, with expected/observed display values. Byte issues carry a
long physical offset. A resolved-count issue has no common offset because the
two section-zero records can be elsewhere. The byte offset is the first
difference within the first differing phase, not a global minimum across phases.

## Limits and integration

Raw table observations must agree with the metadata used to select protected
payload ranges. Checked arithmetic, bounded buffers and merged intervals avoid
whole-file buffering or repeatedly reading overlapping segments. Owned channels
close on success, failure and cancellation. Existing parser limits still apply;
not every maximum metadata combination is promised to fit a 64 MiB heap.
Cancellation cannot interrupt an already blocked filesystem operation. Actual
path traversal is preserved; attribute comparisons are best-effort change
diagnostics, not file identity or an immutable snapshot.

Matching this property does not approve active section metadata, debuglink
basename/padding/CRC, build-ID notes outside program payloads, DWARF, source paths,
unmapped trailers, runtime equivalence or complete file preservation. An unchanged
ELF with no debuglink can match. Independent altered-section and bad-CRC controls
must retain a byte match to keep those limitations explicit.

The consumer is the existing private-copy automatic-association test:
retain a before-backend copy, use distinct explicit candidate output, retain tool
diagnostics, and compare installed-helper observations before the existing GDB
checks. The old research probe shares the same byte comparison while keeping
its basename/CRC check separate. This adds no product attachment command.

## Local acceptance (2026-10-24)

Initial source `79dbc29` passes 431 focused assertions, or 443 with all four ELF
class/order combinations above 2 GiB, on actual Java 21 with a 64 MiB heap.
Related prefix/allocation/parser smokes, the extension build and architecture
guard pass. Independent source review is clear. A retained-candidate survey
checks sixteen pairs while preserving 27 input/JAR paths. It deliberately
shows that active-section and debuglink-CRC changes can still match this property.

Private installed JAR
`340049330c2c10f51fce63407f1bca342d84318be0b93c659bd92babe029a0e3`
passes nine fresh backend-candidate observations and repeated comparisons in
`build-id-discovery/run.UmBq92Je`. These use retained exec/PIE/no-build-ID exports
for x86-64, AArch64 and MIPS32 big-endian. The independent Python oracle also
checks indexed allocated metadata and exact debuglink creation bytes separately.
Fifteen mutants, three out-of-LOAD NOTE pairs, six malformed operands and the
no-LOAD/header-tail controls pass. The x86 sparse payload test detects byte
2,149,584,912 under 64 MiB; its retained recipe verifies selected regions, not a
whole-file hash. All 36 selected fixture files remain unchanged.

The existing 27 GDB checks pass: addresses, types, source lookup, resolved
breakpoints, mismatched build IDs and no-build-ID CRC rejection. Native x86 exec
also hits both automatic associations with argument values 19/23 and exits
normally. Cross-target execution, new Ghidra export and structural-validator
runs are not attributed to this retained-fixture replay. The corrected research
probe separately accepts its retained ordinary candidate and now rejects the
historical out-of-LOAD NOTE mutation at byte 14676.

Full exact hosted acceptance, including native Windows focused tests, remains
pending. See `VALIDATION.md` for commands and retained evidence.

### Callback exception correction

**CONFIRMED locally:** review of PR #37 found that the post-parser cancellation
poll was inside the catch for malformed ELF metadata. A supplier's
`IllegalArgumentException` was wrapped as `IOException`, changing its type and
identity even though the operation stopped. The older prefix reader had the
same boundary. Commits `c38cd98` and `791631f` move those polls outside the
parser catches. Exact-identity regressions fail the old hosted JAR and pass the
corrections. Byte comparison, malformed-ELF handling and ordinary export are
unchanged.

Actual Java 21/64 MiB now passes 434 default and 446 large program checks, plus
prefix default/large checks and related smokes/build. Corrected installed JAR
`f1c87f29652be3148dc68bb72390f372710279e191bfb03362673e8e59402740`
passes the same nine private-candidate and 27 GDB checks in `run.7eQn9koH`;
all 36 retained fixture snapshots remain unchanged. The initial PR head `e25c148`
and run `40105620219` are intermediate evidence, not final acceptance. The
corrected exact hosted gate remains required.
