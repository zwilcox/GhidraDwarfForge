# ADR-0005: Prepare an owned append-only executable candidate

- Status: **CONFIRMED locally**; exact package/full hosted acceptance pending
- Date: 2026-10-24
- Scope: P2.8 private candidate preparation, not attachment or publication
- Baseline: Ghidra 12.0.3, Java 21; no native ABI or release changes

## Decision

Use a separate native-free append-only writer for the first production candidate
preparation component. This explicitly supersedes ADR-0004's configured GNU
backend selection. Retain GNU-created candidates as independent test references;
do not silently fall back to an external tool. Ordinary export remains unchanged.
Never reuse the matched sidecar writer's transformations for an executable.

Preserve the entire original file prefix except `e_shoff`, `e_shnum` and
`e_shstrndx`. In particular, preserve `e_shentsize`, the full declared header,
all program-header fields, raw program records and payloads. Append the literal
GNU debuglink payload, a new raw section-name table, and a new canonical section
table. Retain every original section at its physical index with its raw record
unchanged, except the new section-zero count/name escape bookkeeping. Append
exactly two nonallocated records: the debuglink and new name table. The new raw
name table starts with all old bytes, followed by deterministic name literals.
This preserves suffix references, duplicate names and non-UTF8 bytes without
re-encoding. Existing relocations and NOBITS semantics remain intact.

The new name table is selected by `e_shstrndx`; it may share `.shstrtab` spelling
with the preserved old table. An allocated old name table remains at its original
index/address/file offset. Its bytes must be covered by the protected program
payloads. Count and name-index escapes are independent at `0xff00`; preserve
`PN_XNUM` and section-zero `sh_info`. Check all arithmetic and each ELF32 encoded
field before creating output, with final file length at most 2^32 bytes.

The first envelope requires ET_EXEC/ET_DYN, canonical-width named section tables,
a nonempty NUL-bounded raw name table, positive file-backed LOAD and allocated
section evidence, and no existing raw `.gnu_debuglink` name. Unsupported inputs
are rejected without narrowing ordinary Forge export's wider ELF contract.
Resource limits and malformed/unsupported distinctions are explicit. Nonzero
unused section-zero count/name/program bookkeeping is unsupported, rather than
silently reset. Alignment padding is written explicitly as zero bytes.

## Owned lifecycle

The factory accepts explicit original/sidecar paths, literal basename bytes, an
existing workspace parent, and optional cancellation. It preflights metadata,
resource/layout limits and selected-file observations before creating a fresh
owned subdirectory with one fixed CREATE_NEW candidate leaf. Inputs are read
only; the existing test consumer supplies its own copies. No additional snapshot
framework or tool runner is introduced.

After bounded copying and serialization, require the existing separate program,
allocation and new-link predicates to satisfy construction postconditions and
require the selected-sidecar digest to agree with construction. Return immutable
workspace/candidate paths and the separate content observations. These are not
an attachment approval, immutable snapshot, valid-DWARF or host-metadata claim.
Literal bytes are not inferred from a host filename encoding.

Successful scratch ownership transfers to the caller, which retains its evidence.
On failure/cancellation, close resources first, remove only the exact created
candidate and empty owned directory, and preserve the original exception with
cleanup failures suppressed and retained-path information. Do not recursively
remove files, overwrite a caller output, publish to a target path, or introduce
an automatic evidence-deleting lifecycle. Cancellation cannot interrupt every
blocked filesystem call; change detection remains best effort.

The test consumer explicitly colocates its selected sidecar beside the returned
candidate and grants execution permission only on its owned test file if needed.
That setup does not establish a production metadata-preservation policy. GNU
reference tool records remain distinct from the writer's actual provenance.

## Evidence for this direction

GNU `timeout` is insufficient as a process-tree owner: controlled normal exit,
TERM and cancellation cases leave descendants after the monitor exits. Actual
Java21 tests show descendant snapshots can be empty while child-held pipes remain
blocked. Verified same-group rescue works in the bounded experiments, but a
production supervisor would need additional ownership, reuse, escape and bounded
drain handling. Java argument encoding also differs under the tested parent
locales. A writer removes those process and argument-codec dependencies.

A separately reviewed Python layout experiment passes twelve retained source-built
pairs (x86-64/AArch64/MIPS32 big-endian, exec/PIE/no-build-ID/shared), twenty
synthetic width/order/layout cases and fourteen pre-creation rejection controls.
Independent review reconstructs all 32 candidates byte for byte and rehashes all
51 protected files. GDB automatically discovers the real sidecars; three native
x86 runs prove arguments 19/23 and normal exit. Other real cases prove lookup,
not runtime. Synthetic allocated-name/count/PN_XNUM cases prove metadata only.
GNU/LLVM checks are on candidates; focused GNU checks use header/notes only.
The unchanged Forge sidecars were not rerun through strict DWARF validation.
There is no positive exact-4GiB artifact test or production implementation claim.

Evidence is retained in the candidate-content worktree under
`build/candidate-content-review/next-candidate-preparation-research/`:
`SUPERVISOR-HANDOFF.txt`, `independent-supervisor-append-review.json`,
`append-layout.rgyyekbf/{result.json,SUMMARY.txt}` and the independent
`build/content-oracle-review/append-experiment-review.json`. Initial research
assertion failures are retained separately; no unexplained layout defect remains.

## Acceptance before implementation is complete

- Actual Java21 tests cover both ELF classes/orders, unknown machine/flag
  preservation, raw duplicate/suffix/nonUTF8 names, old allocated name tables,
  unchanged relocations/NOBITS, header tails, program NULL records and PN_XNUM.
- Independent count/name escapes, exact/over resource and ELF32 arithmetic bounds,
  malformed/unsupported inputs, cancellation and I/O cleanup are tested.
- Independent installed-JAR checks verify full prefix/raw records/appended layout,
  separate content predicates, deterministic reruns and original/sidecar preservation.
  Include corrupted program bytes and active metadata/link controls.
- All five target lanes run the production writer and applicable GDB/runtime
  checks, retain GNU references separately, and use the existing strict export
  validator gates. Native Windows preparation checks must pass independently.
- Large copied inputs and sidecar digests use bounded memory. Do not infer that
  every maximum metadata combination fits the normal 64MiB test heap.

Receipt/diagnostic policy, export relationships, external validation, host encoding,
identity/link/security metadata, independent backups, durable transaction receipts,
atomic target replacement, refresh and recovery remain ADR-0004 prerequisites.
No public attachment option or new release is authorized by this decision.

## Primary format references

The [ELF header specification](https://gabi.xinuos.com/elf/02-eheader.html) defines
section-table fields and independent extended section count/name-index encoding.
The [section specification](https://gabi.xinuos.com/elf/03-sheader.html) permits
multiple string tables and defines indexed section relationships.
The [string-table specification](https://gabi.xinuos.com/elf/04-strtab.html)
defines raw indexes, duplicate/suffix references and NUL boundaries.
The [GDB separate-debug-file contract](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html)
defines the basename, padding and target-endian whole-file CRC payload.


## Local implementation checkpoint

Source `1763ebd` implements the owned writer without changing the ordinary
exporter or native bindings. Actual Java21/64MiB checks pass 1,142 default and
1,148 including one ELF32 big-endian large case. The original is 2,147,549,185
bytes, selected sidecar 2,147,483,665 bytes and candidate 2,147,549,672 bytes.
Full masked-prefix comparison and input/digest preservation pass; an exact
high-offset mutation is detected. Exact 4GiB end is a planner test only.

The private installed package passes twelve real retained-fixture cases with
24 byte-identical deterministic outputs, nine mutation controls, 24 typed
rejections and three plaintext counterexamples. Independent reviews reconstruct
all output bytes and confirm 48 original fixture snapshots unchanged. The
real fixture candidates pass GNU header/program/section/note checks and LLVM completion.
Eighteen GDB transcripts cover automatic lookup and no-ID CRC rejection/restoration;
three native x86 runs check values 19/23. Nine original/candidate execution pairs
pass natively or under QEMU. Shared-object cases prove lookup only.

This replay creates new candidates; it does not create new Ghidra exports or
repeat strict DWARF checks on unchanged sidecars. Source and installed-consumer
reviews are clear. Corrected PR #39 head `a190026` passes exact hosted run
`40116314882`, all twelve jobs, independent package/all-five-target/both-GUI
reviews, and merged normally as `4e050609`. Native Windows passes 21 focused
checks with 1,140 owned-writer assertions; Linux has 1,142. The first run's ARM32
compiler-oracle TCP collision is retained separately; the private-socket helper
correction passes all five targets. Commands, hashes, limits and retained
failures are in `VALIDATION.md`; no attachment or metadata-preservation claim follows.
