# ADR-0006: Explicit build-ID installation with retained source generations

- Status: Proposed transaction; source-relocation component locally validated
- Date: 2026-11-06
- Tracking: #109

## Requirement and evidence

Install a verified Forge sidecar under a user-selected debug root at
`.build-id/xx/rest.debug`, retaining the original executable byte for byte.
An equal build ID is an association key, not proof of identical executable or
export bytes. Installation must bind the selected original, sidecar, source and
report; reject malformed/ambiguous identity; retain provenance; and require an
explicit update/removal policy. Consumer setup and observed discovery behavior
must be stated separately.

**CONFIRMED experiment:** copying the sidecar and source into a new directory
leaves its absolute source references pointing at the former export directory.
With that source temporarily absent, fresh GDB/LLDB/perf processes cannot list
it. Directory substitution restores listing on x86-64 and AArch64; GDB's tested
exact-file substitution does not. Directory substitutions are global debugger
settings and can collide when different installed exports share an old parent.
They are therefore not the selected source-retention contract.

## Selected source representation

Retain an immutable generation containing the selected export sidecar, exact
source bytes, original export report and installation evidence. The installed
sidecar is a derived artifact whose source references name that generation.
Keep the original export artifact/report hashes distinct from the installed
artifact hash. Do not change the report to pretend the derived bytes were its
original output. Retaining the exported input permits later reinstallation even
if its former directory has disappeared.

The source transformation changes only `DW_AT_comp_dir`'s string reference and
the line table's source directory. Append the new string to `.debug_str` rather
than replacing a pooled string that could also name a type or variable. Keep
`.debug_info` length and every DIE offset unchanged. Retain the line program
verbatim and update only its header/unit lengths. Preserve all other DWARF,
CFI, ELF identity, allocated sections, symbols and build-ID notes. The original
executable and original export pair are never rewritten.

**CONFIRMED locally as a section transformer:** `SyntheticSourceRelocation` implements
the pure section transformation for the current Forge single-CU DWARF32/v5
layout, both address widths and byte orders. It requires consistent CU/line
source names and directories and refuses unfamiliar forms/layouts. Legacy
artifacts lacking the compilation directory must be re-exported. Its explicit
limits are 64 MiB per source section, 65535-byte source strings, 65536
abbreviations and 128 attributes per abbreviation. This component does not
validate arbitrary DWARF or approve installation. Structural validators and
actual consumer checks remain mandatory.

The [local receipt](evidence/build-id-source-relocation.json) binds the tested
JAR and its 211 production source files to ten real exec/PIE cases across all
five target lanes. Each case passes structural validation and GDB automatic
lookup with its old source absent; x86-64/AArch64 also pass LLDB and offline perf
source lookup. The actual producer sections pass 210 refusal controls and
5,108 cancellation boundaries. Independent checks preserve the complete line
program, existing strings, DIE offsets and all original input hashes. The latest
smoke checks also prove deterministic repeats and idempotent relocation.
The full new-head hosted gate remains **PRESENT, UNVERIFIED**.

The initial oracle used an independent test-only ELF packager. **CONFIRMED
locally:** the production `SyntheticSourceSidecar` now writes an unpublished
stage while preserving unrelated bytes and each changed section's compression
and alignment. It refuses active source relocations and header/payload overlap;
it does not invent relocation records or reconstruct loadable segments. GNU
objcopy rejected the earlier non-loadable matched-sidecar experiment. The
current oracle independently checks decoded sections and all original ELF bytes
against the production stage. See `SOURCE-SIDECAR-RELOCATION.md` and its twenty
plain/zlib runtime cases. This does not implement publication, metadata
preservation, pair binding or the installation transaction below.

## Planned identity and publication contract

- Require explicit selected input/report/sidecar/source paths and a debug root.
  Reuse bounded build-ID parsing, export hash binding, matched ELF allocation
  and prefix checks, and native host identity/metadata checks. Recheck inputs
  before publication. Missing build IDs produce a diagnostic and the existing
  debuglink/explicit-loader alternatives; never inject an ID into the target.
- Derive a generation key from the original/sidecar/source content hashes and
  transformation schema. Runtime timing fields in a report must not cause a
  new generation for otherwise identical export bytes. Keep the accepted report
  as provenance, with its own hash, rather than as a generation identity oracle.
- Prepare the retained source and derived sidecar under a private owned stage.
  Validate the derived artifact against the original executable, preserve the
  supported permission/metadata contract, and durably commit the generation
  and its immutable evidence before publishing the searchable entry.
- Publish the complete sidecar into the absent build-ID name with an atomic
  no-replace operation. A crash before that operation must not expose a partial
  searchable file. A crash after it must be reconcilable from the installed
  artifact hash and previously committed evidence. Do not claim a multi-file
  transaction from two unrelated atomic renames.
- Serialize cooperating changes for a build ID. An explicit update must verify
  the previous installed bytes/evidence and the same original executable hash.
  Refuse unrelated artifacts, modified generations, ambiguous ownership and
  aliasing paths. No admin bypass or silent overwrite of foreign debug files.
- Removal unregisters only the verified selected installation. Retain old
  generations needed by already-loaded debugger sessions; document retention
  and any later explicit pruning operation. Do not delete user-selected inputs
  or unrelated files. Interrupted preparation/recovery must never guess ownership.

These are acceptance obligations, not implemented transaction guarantees.
Existing host helpers supply native file identities and atomic file publication;
directory publication, locking, recovery records and complete generation
verification still require implementation and failure-injection tests. The
installer must report actual host durability limits and propagate sync failures.

## Consumers and completion

Print setup for the chosen root. A user directory is not automatically searched
merely because it contains the right name. Test fresh GDB sessions without
`symbol-file` or `add-symbol-file` for exec/PIE/shared and applicable sectionless
inputs, including wrong identity, refresh, missing source and absent old exports.
Independently check LLDB and perf with their actual search/cache rules. The LLDB
18 sectionless UUID limitation remains distinct from installer correctness.
Offline perf source queries do not establish perf record/report behavior.

Before closing #109, the production CLI/GUI or documented launcher, host
metadata/atomicity/recovery controls, source relocation, identity/update/removal
cases, independent validators, GDB/LLDB/perf behavior and protected integration
must all pass. This ADR and its source component do not complete that issue.
