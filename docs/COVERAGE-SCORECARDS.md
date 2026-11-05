# Export coverage and evidence scorecards

**CONFIRMED locally:** the production exporter emits per-function source,
variable-location and type scorecards in schema-two reports. The installed CLI
and GUI display, save and compare that evidence. Structural validators, GDB,
actual curation regressions, failure/cancellation controls and report-limit tests
pass locally, including five-pair SQLite/U-Boot measurements. Windows host and
workload acceptance also pass at `3829626`. Final review corrected an unavailable
variable-inventory display and a malformed terminal test fixture; the corrected
host/target gate and protected integration remain pending for issue #108.
The [acceptance map](COVERAGE-ACCEPTANCE.md) distinguishes the required evidence
from completed local checks and pending hosted review.

These are static export-coverage metrics, not execution coverage, probability of
correctness, original compiler knowledge or complete semantic equivalence.
Generated C remains synthetic decompiler output. No combined confidence score is
calculated. Coverage never upgrades validation status or authorizes attachment.

## Populations and exact units

Each scorecard describes one primary exported function identified by link-time
entry and its exported identity. Alias names refer to the same scorecard rather
than multiplying aggregate denominators. Per-function overlap is legitimate;
whole-program instruction totals use the union of decoded instruction starts.
No metric represents execution frequency or probability of correctness.

Capture the decoded instruction-start inventory from Ghidra's current listing
inside the complete function body AddressSetView. Count starts, not bytes or the
entry-to-maximum span. Preserve function ranges and unrecognized/non-instruction
bytes as separate context. Address translation happens at the existing explicit
ELF serialization boundary; no processor-specific instruction length assumptions.

Two source metrics must remain separate:

- `anchoredInstructions / decodedInstructions`: distinct decoded starts that
  have an actual emitted row backed by the corresponding function's decompiler
  token mapping. A fabricated function declaration row is not a token anchor.
- `lineVisibleInstructions / decodedInstructions`: distinct decoded starts inside
  the actual emitted line sequences, at or after a row and before end_sequence,
  where the debugger carries a line forward. Identify these as line-table
  visibility; they do not imply a direct token mapping or exact original source.

Both use the final line planner, including lowest-line collision selection,
range clipping and discontiguous sequences. Track declaration-only rows, dropped
mappings and mappings outside decoded starts separately. A row chosen from an
intersecting other function cannot become a token anchor for this function just
because its address matches. Failed/omitted source functions retain their decoded
instruction denominator and an explicit disposition; no source means zero mapped
coverage, while zero decoded instructions means not applicable, not 100 percent.

Variable population must expose both recovered and emitted declarations:

- Inventory parameters, automatic locals and qualifying function-owned statics
  with their kind and explicitly reported binding. Show per-kind totals. Namespace
  globals are a separate program-level inventory, not every function's locals.
- `variablesWithLocation / recoveredVariables` counts each declaration once when
  its emitted DIE has at least one usable location for the full value. Show
  `emittedVariables` alongside it so symbol-only failures or filtered declarations
  cannot disappear from the denominator. Distinguish recovered-but-not-emitted
  from emitted-without-location. Empty populations are not applicable.
- Full-value storage follows the actual expression/list emission decision.
  Register slices that do not cover the value, incomplete composites, a rejected
  list, and locations filtered by scope or failed source do not count. Retain the
  documented existing conservative omission behavior; scorecards do not silently
  repair or broaden storage support. Any future partial-value metric is separate.

For location extent, use half-open link-time address-byte ranges, explicitly labeled
as static address coverage (not instruction counts, live execution, or time):

- Per variable, `coveredScopeBytes` is the union of emitted usable location
  ranges intersected with that declaration's evidenced visibility/scope ranges.
- `knownScopeBytes` is the union of those evidenced scope ranges, including
  intervals where storage is unavailable. Do not construct the denominator from
  the available locations themselves. A range-restricted expression/list must
  not be treated as spanning the complete function by a reporting shortcut.
- Record unknown scope/lifetime explicitly. A lexical visibility range is not
  evidence of value availability. If complete visibility cannot be established,
  present known-range totals and an unknown indicator, withhold the whole-variable
  percentage, and report available intervals descriptively.
- Across variables the unit is variable-address-bytes. Sum only comparable known-scope
  populations and show excluded unknown-scope variables. Do not hide exclusions
  in a single overall percentage. Function-static physical address availability
  does not imply evidenced lexical visibility.

Type population starts from recovered function return/parameter/local/static type
roots; collect canonical reachable nodes with an iterative, cycle-safe walk.
Roots count distinct canonical type identities, not uses or variable declarations.
Track emitted roots/nodes separately after signature filtering. Types allocated
elsewhere in the compilation unit do not count for a function unless reachable
from that function's actually emitted roots. The scorecards measure:

- `resolvedEmittedNodes / recoveredNodes`, excluding implicit void from both.
  A resolved node means a represented non-`OpaqueType` model node; it does not
  certify every size, array bound, ABI rule or analyst inference. Qualifier chains,
  aggregate members and subroutine parameters do not inflate the canonical count.
- `opaqueEmittedNodes` and `notEmittedNodes` partition the rest of `recoveredNodes`.
  A pointer to an opaque aggregate contributes one resolved pointer and one opaque
  target, not a completely described graph.
- `opaqueFreeEmittedRoots / recoveredRoots` requires every reachable canonical
  node and expected reference to be represented, without an opaque node.
  Missing repeated member/parameter references invalidate this claim even if
  their shared target node is still present. Recursive graphs terminate. This
  is graph coverage, not independent validation of all type semantics.
- `implicitVoidNodes` and `emittedImplicitVoidNodes` record `VoidType` separately:
  the producer intentionally omits its DIE and the corresponding `DW_AT_type`.
  A void-only population has no DIE-required denominator; it is not 100 percent.

The type index accepts an explicit semantic emission map, not an allocation list.
Reference multiplicity is preserved for completeness checks; node totals are
deduplicated. Invalid/unknown roots and inconsistent edges are rejected instead
of inventing types. The actual producer provides the map, including explicit
implicit-void decisions, after successful population. Independent raw-DIE/GDB fixtures validate the public report graph and roots,
including resolved/opaque swaps hidden by equal totals and types allocated globally
but unattached to a failed-source function.

Unknown instruction/token populations are counted explicitly and suppress the
corresponding summary percentages. An unavailable signature means its variable
inventory is unknown, not known empty: per-function variable/scope displays say
Unknown. Aggregate variable displays disclose the missing function inventories
and label remaining counts as the observed subset. Unknown signatures also
suppress aggregate type percentages. Known empty denominators are not applicable.

Transient Ghidra arrays use the existing class/path/size fallback and equivalence/
collision checks. Their inherited process-generated IDs do not establish persisted
identity. Named analyst/imported types retain their persistent universal IDs.
Canonical keys are reported correspondence, not proof of historical lineage.

## Provenance, serialization and failure boundary

Declaration/storage categories such as USER_DEFINED, IMPORTED, ANALYSIS and
DECOMPILER remain visible alongside omission reasons and target restrictions.
Per-type or per-line provenance stays unknown when extraction did not capture it.
An emission state does not upgrade recovery provenance.

The producer supplies actual line, declaration, location and type-reference
facts after filtering. The exporter joins those with recovered populations and
captured decoded starts. It serializes and strictly reads the complete report
while sidecar/source artifacts are staged. Rejection, failure and cancellation
preserve the previous final generation; successful retry is deterministic. The
optional GDB companion participates in the same boundary.

| Format | Coverage behavior |
| --- | --- |
| Report schema one | Legacy bytes/readers remain compatible; coverage is unavailable and the coverage field is forbidden. |
| Report schema two, metric definition one | Original scorecards and source/variable evidence; no individual type graph. |
| Report schema two, metric definition two | Current production format, adding shared `typeNodes` and per-function `functionTypeRoots`. |
| Terminal schema-two report | Null coverage and artifact claims; failure/cancellation is not successful export evidence. |

Counters are canonical nonnegative decimal strings through `Long.MAX_VALUE`;
unavailable counters use null plus a reason. Addresses are canonical hexadecimal
strings. YES/NO and KNOWN/UNKNOWN strings preserve the strict lexical grammar.
Flat variable/type tables avoid recursive JSON. Repeated storage-evidence text
uses `storageEvidenceDetails` without dropping range boundaries or multiplicity.

Readers recompute unions, location intersections, graph/root consistency and
function totals. Unknown/duplicate fields, unsupported versions, invalid
ownership, contradictory counts and dangling edges are rejected. Every reader
validates coverage; `readWithCoverage` retains it. A valid report remains a claim,
not independent artifact authentication.

Admission bounds the whole UTF-8 report to 64 MiB, each string to 65,536 UTF-16
units, depth to eight, and each array to 250,000 entries. Legacy values retain a
one-million allowance; coverage gets a scoped five-million allowance within the
six-million full-document limit. Child readers cannot reset budgets. Writers
reject unpaired surrogates and check cancellation throughout.

## Read-only CLI

```bash
support/ghidra-dwarf-forge-report --ghidra-dir="$GHIDRA_INSTALL_DIR" \
    --report=sample.dbg.report.json
support/ghidra-dwarf-forge-report --ghidra-dir="$GHIDRA_INSTALL_DIR" \
    --report=sample.dbg.report.json --function=0x401136
support/ghidra-dwarf-forge-report --ghidra-dir="$GHIDRA_INSTALL_DIR" \
    --report=after.json --before=before.json
```

Default output is a readable summary and per-function TSV rows; `--summary`
omits rows. `--function` selects a normalized ELF-link-time entry and shows the
same bounded evidence details as the GUI, with an explicit display-limit notice.
Names and diagnostics cannot inject ANSI/bidi controls into terminals or split
TSV cells. The original JSON remains the complete evidence record. The launcher
uses Java 21+ and the installed extension plus Ghidra's existing Gson/JNA jars;
it starts no Ghidra analysis or native producer.

On Windows, use `support/ghidra-dwarf-forge-report.ps1` with `-ReportFile`, optional
`-BeforeFile`, `-Function` or `-Summary`, and `-GhidraDirectory`. Paths travel as
canonical Base64 UTF-8 across Java's Windows launcher boundary. Arguments are
passed directly to a separate process, and output streams without retaining the
complete comparison in the PowerShell parent. Hosted Windows GUI and large-report
CLI acceptance pass at `3829626`; see the receipts below.

## Comparison correspondence and limits

Comparison requires matching reported original SHA-256, target description,
Ghidra language and compiler profile. The strict reader admits supported metric
and address models. Functions correspond by ELF-link-time entry; moved outputs
and ordinary Ghidra rebases do not change those addresses. Function/body/decoded
population changes are disclosed. Anchor/line-visibility losses and gains compare
starts decoded in both reports; unknown evidence never becomes zero.

Variables correspond through reported bindings within the function:

- Parameter ordinal.
- Local internal name and lexical block.
- Function-static internal name, lexical block and normalized storage address.

Display name, declaration/type/provenance facts, omission diagnostics and storage
evidence are compared separately. Exact scope/location additions and removals
remain visible when totals match. Coverage loss/gain uses only the intersection
of both independently known scopes. Evidence tuples retain multiplicity;
ordering alone is not a change. Unknown populations are not empty lists.

These bindings do not prove declaration lineage. Local rename/rekey appears as
removed/added. Ghidra database/symbol IDs can be reused after undo and a different
declaration, so they cannot justify inferred renames.

Definition two compares individual type state, name, size, definition kind,
diagnostic, roots and reference multiplicity by canonical key. Offsetting
resolved/opaque transitions remain visible despite equal totals. Rekeyed types
appear as removed/added. Definition-one comparisons explicitly mark individual
type evidence unavailable. Member names, qualifiers and all layout semantics are
not exhaustively compared. Zero changes is not proof of semantic equivalence.

Both CLI and GUI open only the selected reports, never referenced executables,
source files or sidecars. They grant no attachment authority.

CLI exit codes are 0 for displayed results, 1 for read/output errors, 2 for
incomparable reports, 11 for cancellation and 64 for usage errors. Zero does not
mean absence of regressions or successful validation. Output before failure or
cancellation can be incomplete.

## GUI presentation and comparison

The coverage window shows summary, function rows and selectable evidence details.
Unknown/empty populations are explicit; ratios round down so incomplete coverage
cannot round to 100 percent. Details are bounded plain text. The console gets a
concise summary rather than a report larger than its buffer.

**Save report** writes the captured full JSON in a background task using atomic
create-if-absent publication. It refuses existing files and aliases, checks
cancellation and cleans temporary output. Cancellation cannot leave a partial
final report; a completed publication remains a complete file.

**Compare report...** selects an earlier report and compares it with the captured
current export in a background worker. **Cancel comparison** or closing the window
requests cooperative cancellation. Errors and incomparability are explicit, and
retry is supported. Results are modeless plain text with a 64 KiB UTF-16 detail
prefix. Comparison continues counting after clipping and shows the exact change
total; the CLI provides the complete changes.

## Validation evidence and remaining acceptance

Retained receipts distinguish component/protocol controls from actual artifacts
and debugger behavior:

| Evidence | What it establishes within its recorded scope |
| --- | --- |
| [Type report](evidence/coverage-type-report.json) | Strict definition-two graph/roots, raw-DWARF/GDB checks and production staging controls. |
| [Variable comparison](evidence/coverage-variable-comparison.json) | 65,536 interval controls plus actual x86-64/AArch64 PIE rebase/use-site-edit/rename pairs, raw location lists and GDB values. |
| [Type pairs](evidence/coverage-type-pairs.json) | Real producer resolved/opaque swaps, attachment loss after source failure, independent DIE predictions, CLI and GDB. |
| [GUI comparison](evidence/coverage-gui-comparison.json) | Actual Linux chooser/save/comparison/error/retry flow and full export/preparation/cancellation/validator/GDB/CLI journey. |
| [Whole-report limit](evidence/coverage-whole-report-limit.json) | Actual 64 MiB rejection from captured Ghidra data on x86-64/AArch64, pair/companion preservation, deterministic retry and validators/GDB. |
| [Array identity](evidence/coverage-array-identity.json) | Reproduced fresh-process nondeterminism, cross-target live/reopen correction, large SQLite artifact validators/GDB and CLI. |
| [Large workloads](evidence/coverage-large-workloads.json) | Five alternating pairs each for SQLite and U-Boot, deterministic reports, identical artifacts, validators/GDB and preserved inputs/projects. |
| [CI follow-ups](evidence/coverage-ci-followups.json) | Corrected terminal fixtures, complete JFR phase sets, and screen-bounded GUI save/comparison at 1024x768. |
| [Windows host](evidence/coverage-ci-3829626-windows.json) | Actual GUI save/comparison/error/retry in three modes, visible controls, artifact bindings and independent GDB. |
| [Windows measurement control](evidence/coverage-windows-measurement-control.json) | Audited derivation from the exact published main package, clean-build class equality and rejecting package/class controls. |
| [Windows workloads](evidence/coverage-ci-3829626-workloads.json) | Ten alternating pairs, two profiled exports, actual large-report CLI, strict validators on both hosts and compiler/Forge GDB. |
| [Final review fixes](evidence/coverage-final-review-fixes.json) | Unknown-inventory presentation regression and packaged CLI checks; valid terminal versus malformed retained-coverage preparation controls. Fresh hosted acceptance remains required. |

**CONFIRMED locally:** median export wall time increases from 34.62 to 39.28 seconds
for SQLite and 114.82 to 126.58 seconds for U-Boot. Median process maximum RSS
increases from 873,916 to 1,083,056 KiB and 1,119,508 to 1,889,664 KiB,
respectively. Full reports grow from 3,164,193 to 23,768,866 bytes and 1,929,776 to
58,740,566 bytes. The extra evidence has a material memory cost. Timings exclude
import, validators and the CLI; the receipt includes CPU, individual pairs and
separate report-tool observations. U-Boot retains its one known decompilation
failure. Strict frame diagnostics are corroborated against the original, with
zero unexplained errors.

**CONFIRMED on Windows:** median export wall time is 87.08/87.34 seconds for
SQLite and 184.17/192.16 seconds for U-Boot. Median peak job commitment is
1.31/1.33 GB and 1.35/2.40 GB respectively; this includes the process tree and
is not Linux RSS. Five alternating pairs preserve identical sidecar/source bytes
and deterministic reports. Separate summary/self-comparison takes 2.23/3.74
seconds for SQLite and 3.64/6.55 seconds for U-Boot; those are single CLI
observations. Only Ghidra index/journal backups change in the saved projects;
program data and original inputs remain unchanged. Both actual JFR recordings
and independent Linux GDB consumer checks pass.

The current five-target gate and protected integration remain required. The
measurement baseline has the same isolated array-key correction as the candidate to isolate
scorecard cost while retaining exact artifact equality. Failed runs are retained
and excluded from successful measurements. One host's measurements do not imply
a general speed or memory guarantee.

The Windows workflow uses production main `1bb4c14` plus the same audited array
correction as an explicitly non-release measurement control. It preserves the
original package, records source/class hashes and requires unchanged-source
classes to remain byte-identical. It measures the coverage revision as a whole,
including any independently rebuilt native differences recorded in its inventory;
it no longer labels this comparison as phase-instrumentation overhead. Export
timing excludes report archival, large-report CLI, profiling and validation.

[Historical development checkpoints](history/COVERAGE-DEVELOPMENT.md) preserve
component stages, admission experiments and superseded limitations.
