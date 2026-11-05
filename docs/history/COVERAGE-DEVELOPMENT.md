# Historical coverage development checkpoints

**HISTORICAL:** this is the development record through the array-key correction.
Its checkpoints describe different stages and include superseded limitations.
Use [the current coverage contract](../COVERAGE-SCORECARDS.md) for behavior and
remaining acceptance. Retained receipts record failures as well as passing checks.

# Proposed coverage contract for issue 108

## Production whole-report bound

**CONFIRMED locally — #108 whole-report byte bound:** 1,500 saved Ghidra locals
with individually legal 48,084-unit derived type paths exceed the unchanged 64 MiB
production report budget. x86-64 and rebased AArch64 PIE reject before publication,
preserve existing pair/companion files, and pass deterministic retry plus validators
and native/QEMU GDB checks. The original string-limit regression still passes.
The cross-architecture coverage controls now include this byte-bound test. See
`docs/evidence/coverage-whole-report-limit.json`. Repeated final large-workload
overhead and hosted acceptance remain pending.

## Paired native type regression evidence

**CONFIRMED locally — #108 paired native type regressions:** actual production
exports swap two canonical types between resolved and opaque while preserving all
summary totals. Independent raw-DIE traversal predicts the exact CLI state changes
in both directions. A source-failure export retains allocated type DIEs but correctly
reports all three types as unattached to the function. GNU/LLVM/pinned strict
validators and GDB pass for all three artifacts; sidecar, source and report bytes
are deterministic on rerun. This is an isolated controlled-model emission test,
not a Ghidra extraction/identity claim. See `docs/evidence/coverage-type-pairs.json`.
Repeated final large-workload overhead, whole-report byte stress and hosted
host/target acceptance remain pending.

## GUI report comparison

**CONFIRMED locally — #108 GUI comparison:** the coverage window now offers
Compare report, with a background read/compare task, cooperative cancellation,
explicit incomparability/errors, and a bounded result view that preserves the exact
change count after display clipping. The real Linux GUI passes identical/changed/
legacy/malformed/retry cases and preserves selected report files. The full export,
save, attachment preview/preparation, cancellation, validator/GDB and packaged CLI
journey also passes. Component cancellation and clipped-count checks pass; Windows/
hosted acceptance, paired native type regressions and large-workload overhead
remain pending. See `docs/evidence/coverage-gui-comparison.json`.

Choose **Compare report...** in the export coverage window, then select an earlier
saved JSON report. The comparison direction is earlier selected report → current
captured export. It uses the same source, variable, type and compatibility logic
as the CLI. It opens neither report's referenced executable, source nor sidecar,
and does not grant attachment authority. Schema-one coverage remains unavailable,
with an explicit incomparable result rather than a zero-change claim.

The selected report is read and compared in a background task. **Cancel comparison**
and closing the parent window request cancellation; a cancelled or failed operation
does not display a partial result as complete. The result window is modeless plain
text. The change-detail prefix is bounded to 64 KiB of UTF-16; an explicit notice
states when it is clipped, while the total includes all compared changes. The
saved input reports and the report CLI provide the complete evidence/comparison.
The view does not label zero changes as proof of semantic equivalence.

Sixty-one component cancellation checkpoints pass, including after display clipping;
exact totals, unknown/incomparable/malformed inputs, Unicode paths and unchanged
selected report bytes are checked. The real GUI harness drives the actual button,
chooser and result dialogs for identical reports, an explicitly report-only function
rename, a legacy incomparable report, malformed input and successful retry. It saves
the result text and screenshots. The final package also passes the surrounding
export/save/preparation/decline/cancellation journey and native validation. A live
GUI comparison-worker cancellation race has not been stress-tested; component
cancellation and the reviewed close guards are the current evidence for that path.

## Reported variable binding and range comparison

**CONFIRMED locally — #108 variable comparison and real curation:** CLI comparison
now exposes declaration/type/provenance/storage changes and exact location ranges
at explicitly reported variable bindings. Coverage loss/gain uses only common
evidenced scope; unknown populations remain unavailable. Parameter ordinals,
local internal-name/block pairs and static name/block/address tuples are reported
correspondence, not declaration lineage. Renamed locals appear as removed/added.
65,536 interval controls and all 149 variable-comparison cancellation points pass.
Real production exports before/after rebase, saved use-site curation and rename
pass raw-DWARF, validators, GDB and CLI checks on x86-64 and rebased AArch64 PIE.
The selected curated function is unchanged by rebase; exact lost inner-local
ranges match raw DWARF and GDB's unavailable value. GUI comparison, paired type
regression evidence, large-workload overhead and hosted acceptance remain pending.
See `docs/evidence/coverage-variable-comparison.json`.

The existing `--before` workflow now compares individual variable rows as well as
function/source/type evidence. The matching basis is always printed. Parameters
are compared at their ordinal, locals at their internal name and lexical block,
and function statics at their name, block and link-time storage address. Scope,
type or provenance equality does not establish historical identity. A display-name
edit at one reported binding is visible, but an internal local rename/rekey is
an explicit removal/addition. Same display names in separate blocks stay separate.
Database/symbol IDs are deliberately not used as lineage proof after the actual
undo/reuse counterexample documented below.

For matched reported bindings, the comparison exposes declaration emission,
recovered/emitted type keys, displayed/internal names, declaration provenance,
omission reason, diagnostic, scope completeness/evidence, and the complete storage
evidence multiset with exact interval boundaries and multiplicities. Storage row
ordering alone is not a semantic change.

`VARIABLE_LOCATION_RANGE_REMOVED/ADDED` describe differences in reported location
availability. `VARIABLE_SCOPE_RANGE_REMOVED/ADDED` describe changed evidenced
populations. `VARIABLE_COMMON_SCOPE_COVERAGE_LOST/GAINED` compares locations only
inside the intersection of both reports' evidenced scope. A scope removal therefore
does not masquerade as a coverage loss. Partially known scope contributes only its
explicit known intervals; no whole-variable percentage is invented. An unknown
recovered declaration population does not become an empty list of removed locals.
Half-open link-time ranges are subtracted directly without enumerating bytes or
filling function gaps. Output remains reported evidence, not artifact authentication
or an exhaustive semantic equivalence verdict.

The exhaustive eight-byte bit-set oracle checks all 65,536 interval pairs. Additional
controls cover equal-total shifted intervals, shadows, rename ambiguity, parameter
renames, static moves, missing declarations, unknown scope/populations, repeated
storage evidence, the signed-64 address boundary, 20,000 intervals, strict report
reading, CLI output and every cancellation checkpoint.

The new integration journey starts with a saved lexical fixture and uses the real
installed exporter four times. It rebases the program, changes the inner local's
saved first-use from a proven STORE to a decoded non-definition use, then renames
that local while explicitly preserving its independent lexical scope. These edits
remain in memory during read-only project processing. Original binaries, original
artifacts and saved program data remain unchanged (normal index/journal backups
are recorded separately). Raw DWARF proves the exact loss of location while the
scope remains; GDB proves the local becomes unavailable even though raw process
memory still contains 23. The outer local remains readable as 11. The CLI's lost
ranges match the independently decoded list exactly. Both x86-64 and AArch64 PIE/
QEMU pass. Rebase equality is asserted for the curated function; autogenerated
function-name changes elsewhere are disclosed. This is actual export/curation
acceptance, not a mutation of a report to simulate a new artifact.

## Metric definition two: individual type evidence

**CONFIRMED locally — #108 individual type reporting and comparison:** production
schema-two reports now use metric definition two, with a shared canonical type
graph and per-function recovered/attached roots. The strict reader recomputes
function and union counts; legacy definition-one bytes remain compatible. CLI
comparison exposes individual resolved/opaque/missing states and reference changes
by reported canonical key, including offsetting changes hidden by equal totals.
The raw-DWARF/GDB fixture, packaged x86-64 and rebased AArch64 PIE journeys, and
20 staging failure/cancellation controls per target pass locally. Individual
variable/range correspondence, GUI comparison, repeated large-workload overhead
and hosted acceptance remain required. See
`docs/evidence/coverage-type-report.json`.

Definition two keeps the existing numerators and denominators and adds required
`typeNodes` and `functionTypeRoots` arrays. Definition one forbids those fields and
continues to read/write byte-identically. The enclosing report schema stays two;
schema-one reports still have no coverage. Unknown definitions are rejected.
Object-field order does not control decoding. New fields use the existing exact
string counts, YES/NO flags, canonical addresses and shared safety limits.

Nodes record canonical key, name, definition kind, byte size, resolved/opaque/void
classification, successful emission, omission diagnostic and recovered/emitted
reference multiplicities. Per-function root sets are sorted and unique. The graph
is serialized once; per-function node states are derived from roots. A type
allocated for another function is not credited to an untyped symbol-only function.
The strict reader validates graph edges, root ownership, declaration type roots,
per-function counts and the canonical union. These remain reported claims and do
not authorize attachment or authenticate artifacts.

Comparison uses canonical keys as its explicit correspondence basis. It reports
node addition/removal, individual state changes, size/name/definition/diagnostic
changes, root changes and exact reference multiplicities. A renamed or rekeyed
definition appears as removal/addition; the tool does not invent historical type
identity. Comparing with definition one retains comparable source/count metrics
and explicitly marks individual type evidence unavailable. No exhaustive semantic
equivalence claim is made; member names, qualifiers and layouts beyond the recorded
node facts are not fully compared. Per-type recovery provenance remains unknown
unless independently captured; a node state does not change that policy.

The deterministic component fixture swaps one resolved type to opaque and another
the other way, preserving all aggregate counts. Both changes are exposed. It passes
15 malformed graph/version controls, 4,514 reader cancellation checkpoints and
108 type-comparison cancellation checkpoints. The independent native fixture now
checks the public definition-two graph and roots against raw DIEs, not only the
internal evidence object. Existing legacy/detailed report regressions pass. A fresh Linux GUI run saves a
93,317-byte definition-two report, strictly reads it back, previews/declines
attachment and prepares a fresh report, with validators/GDB and packaged CLI
checks passing. Both production targets pass the real string-bound rejection
controls as well as the 20 injected failure/cancellation controls.

The existing declaration identity and earlier wire-format checkpoints below are
historical where superseded by this section. Full issue acceptance remains open.

## Declaration identity and individual type evidence

**CONFIRMED locally — #108 comparison evidence:** real Ghidra database probes on
x86-64, AArch64 and both MIPS32 byte orders reproduce reuse of the same database/
symbol ID after undo and a different declaration. Those IDs cannot prove local
identity across reports. A canonical type graph evidence component retains
individual resolved/opaque/absent states and reference multiplicities, including
implicit void and failed-function attachment gaps. Component cancellation/deep
shared-graph checks and independent raw-DWARF/validator/GDB checks pass. Production
wire-format integration and individual comparison remain planned; #108 remains
incomplete. See `docs/evidence/coverage-identity-and-type-graph.json`.

The 72-check identity probe uses actual ProgramDB transactions, rename/retype,
rebase, deletion, undo, branching and immutable save/reopen/copy. Ordinary edits
preserve record keys; a new declaration after undo can reuse a key observed in an
earlier export. The test retains both observations. Database/symbol pairs alone
are therefore insufficient for historical identity. Comparison must disclose
reported binding correspondence and ambiguous renames/replacements, rather than
claim continuity or modify the analyst database to manufacture it.

The type evidence component stores one canonical node dictionary and exact
recovered/emitted edge multiplicities. A function view follows its actual attached
roots; allocation for another function does not credit a failed function. An
opaque-to-resolved swap alongside a resolved-to-opaque swap leaves counts unchanged
but changes both individual states. A 20,001-node shared graph completes iteratively;
all construction/view cancellation checkpoints pass. The native fixture checks
five serialized type DIEs, implicit void, each type reference and function-relative
state against independent raw DIE inspection. This component checkpoint does not
yet change production metric definition one.

## Read-only CLI and partial comparison checkpoint

**CONFIRMED locally on Linux; complete comparison remains PLANNED.** The packaged
`support/ghidra-dwarf-forge-report` opens only explicitly selected report files.
It uses the strict versioned reader, preserves schema-one coverage as unavailable,
and never opens referenced ELF/source paths or grants attachment authority.
The PowerShell counterpart is **PRESENT, UNVERIFIED** locally; both host GUI
integration harnesses now invoke the respective packaged launcher.

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
complete comparison in the PowerShell parent. Native Windows acceptance is pending.

Comparison requires matching reported original SHA-256, target description and
Ghidra language/compiler profile. The strict reader admits only the supported
metric definition/address model. Function correspondence uses ELF-link-time entry,
so names and artifact paths may change. Body/decoded-population changes are
reported separately. Lost/gained anchors and line visibility are compared over
instruction starts decoded in both reports; unknown evidence is never converted
to zero. Output includes each changed PC, not just a net total, so offsetting gains
do not hide losses. Function additions/removals, signature/provenance/diagnostic
changes and variable/type count changes are also reported.

**Known incompleteness:** definition one's local identities are export-local and
its type metrics omit individual graph-node states. The current comparison cannot
establish local renames, individual variable location-range regressions or every
resolved-to-opaque type transition. It prints these limitations on every matching
comparison, including when no supported field changed. Extending identity/evidence,
independent real curation/rebase regression fixtures and an actual GUI comparison
remain required. This checkpoint does not satisfy all issue #108 comparison criteria.

Exit codes are 0 for successful display (including reported changes), 1 for
read/output errors, 2 for incomparable reports, 11 for cancellation and 64 for
usage errors. Exit zero never means validator success, semantic equivalence or
absence of regressions. Output preceding failure/cancellation may be incomplete.

Java 21 component checks pass all 49 comparison cancellation checkpoints, exact
point changes with equal totals, population changes, unknowns, moved paths, renames,
incompatibility, legacy reports, terminal escaping and broken-output handling.
Ten packaged-launcher cases use a real GUI export and explicit report-only
mutations; these mutations are protocol controls, not new raw-DWARF regression
artifacts. A fresh full GUI export/preparation/decline/cancellation journey and
GNU/LLVM/pinned strict/GDB checks pass. Release-package determinism/manifests and
launcher contents/modes pass. The initial invalid nested-set test fixture remains
retained; the strict writer correctly rejected it. See
[`coverage-cli-comparison.json`](../evidence/coverage-cli-comparison.json).

## GUI presentation checkpoint

**CONFIRMED locally; full #108 and hosted acceptance pending.** GUI exports print
an approximately one-screen summary instead of sending the entire JSON through
Ghidra's bounded console. The modeless **GhidraDwarfForge export coverage** window
has one row per exported function. Select a row to read its complete metrics,
declaration/storage provenance and omission reasons. Unknown populations remain
unknown; empty denominators show N/A. Percentages show exact counts and round
down so incomplete coverage never appears as 100%. No combined confidence score
is calculated. Table rows retain export order; percentage strings are not sorted
lexicographically. Narrow columns do not lose evidence: selected-function details
include the same metrics. Detail display is bounded at 32 KiB of UTF-16 text with
an explicit truncation notice; the report retains all fields and ranges.

Choose **Save report...**, then a new filename, to save the complete schema-two
JSON. This is an explicit extra output, not an automatic change to the default
artifact pair. Saving runs off the event thread, stages UTF-8 in the selected
parent, and publishes with an atomic create-if-absent link. Existing regular files,
symlinks, hard links and racing directory entries are never replaced. Closing the
window requests cancellation; a save already published remains a complete file.
On a filesystem without hard-link support, saving reports an error and leaves
existing files intact. No in-place or overwrite fallback is used.

Headless exports retain the complete JSON report line. Fresh GUI attachment
preparation retains the full report directly in its existing capture/records flow;
it prints the short summary without opening an intervening coverage window.
Coverage remains informational and does not upgrade NOT_RUN validation or
PARTIAL status, or authorize modifying an executable.

Java 21 builds and focused ratio/unknown/overflow/Unicode/cancellation/racing-file
checks pass. Real Linux Script Manager ordinary-pair and companion journeys save
82,250-byte reports while keeping console text to 5,110 and 5,567 characters.
Each saves through the actual chooser, strictly reads the full report, compares
artifact hashes, previews/declines attachment, prepares a fresh export with
retained coverage, and cancels a separate export. GNU/LLVM/pinned strict checks
and GDB function/type/source/breakpoint/next/step/normal-exit checks pass for both
exported and prepared pairs. The separate packaged headless regression passes.
Four initial harness failures and the earlier console defect remain retained.
Windows presentation, native target attachment on the new report path, comparison,
CLI presentation and large-workload overhead remain pending. Exact package,
commands/harnesses, raw paths and hashes:
[`coverage-gui-presentation.json`](../evidence/coverage-gui-presentation.json).

## Production staging checkpoint

**CONFIRMED follow-up:** `coverage-staging.py --real-limit` now exercises a real
derived pointer type with a category path over 68,000 characters. Named types use
compact universal IDs; the retained initial named-typedef probe therefore did not
exceed the serialized limit and failed its fixture assertion. The derived pointer
has no universal ID and exceeds the actual 65,536 UTF-16-unit string limit during
staged report writing. Both x86-64 and rebased AArch64 PIE pass rejection/preservation,
cleanup, deterministic retry, validators and GDB for pair and companion modes.
This is actual string-bound acceptance, not a complete 64 MiB byte-limit stress test.

**HISTORICAL GUI defect, now resolved locally as described above:** a fresh real Script Manager export logs a
complete schema-two report and produces hash-matching artifacts, but the 82,321-
character report line exceeds the 50,000-character console buffer. The retained
console and screenshot show only the JSON tail and the script completion text;
the report marker and preceding status lines are gone. The GUI harness fails
before attachment preparation. The next presentation work must make coverage
readable and the complete JSON accessible without enlarging the console buffer
or weakening the GUI assertions. The preparation assertion additionally requires
retained schema-two coverage once that journey can proceed. Evidence:
[`coverage-report-limits-and-gui.json`](../evidence/coverage-report-limits-and-gui.json).

**CONFIRMED locally; hosted and full #108 acceptance pending.** The ordinary
installed script captures actual decoded starts, assembles coverage from successful
native emission, and serializes/strictly reads back schema two while the artifact
and source files are staged. Report paths name the final generation; digests come
from the staged bytes. Report failure or cancellation prevents publication. The
same callback serves ordinary pairs, companions and fresh attachment preparation.
Terminal reports contain null coverage and no completed artifact claims. The
legacy writer remains byte-compatible and readers accept both supported versions.

The packaged exporter passes x86-64 and rebased AArch64 PIE lexical journeys:
23/27 runtime observations, GNU/LLVM/pinned strict checks and byte-identical reruns.
Each target also passes 16 production staging controls: cancellation and injected
exceptions during instruction capture, assembly, writing and strict readback, for
both pair and companion modes. Controls inspect stages at interruption, preserve
the prior complete generation, verify cleanup and retry deterministically. Both
retried generations pass validators and GDB; originals and saved program contents
remain unchanged. This tests injected failure isolation, not a real oversized
workload rejection or a GUI attachment journey.

Run `coverage-staging.py <private-ghidra> <validated-lexical-case>` or pass
`--coverage-controls` to `lexical-shadow-export.py`. The workflow requests these
controls on both x86-64/AArch64 rebased PIE lanes. An initial harness run correctly
finished all controls but read the GDB diagnostic log from the wrong directory;
the corrected complete runs are retained separately.

Three additional JFR phases measure instruction capture, assembly and report
preflight. The phase reader accepts either the complete older phase set or all
three additional phases; partial/mixed records remain rejected. No elapsed phase
measurement alone establishes incremental memory or CPU cost.

`coverage-workload.py` now defaults to the unmodified installed production script.
Use `--historical-instrumented` only with an earlier schema-one installation to
reproduce the exploratory probes below. Repeated overhead, actual resource-limit
failures, fresh GUI/attachment checks, comparison/presentation and the full matrix
remain pending. #74 is complete; #108 now has integration priority after its remaining acceptance work.

The first ordinary production saved-workload runs also pass report preflight,
validators and GDB. SQLite covers 1,539 functions in a 23,061,568-byte report;
U-Boot covers 6,375 functions in a 56,530,307-byte report and retains its one
known decompilation failure. Every coverage JSON field equals the respective
earlier instrumented result. Original, saved-project and installed-module hashes
are preserved (344/347 protected files). Single process observations are
36.15/117.84 seconds and peak RSS 973,108/2,022,028 KiB. These are not repeated
overhead medians; U-Boot memory cost remains a specific acceptance concern.
See [`evidence/coverage-production-staging.json`](../evidence/coverage-production-staging.json)
for package/script identities, raw acceptance receipts and comparison hashes.

## Historical component checkpoints

Status: **PRESENT, UNVERIFIED end to end.** The first source-coverage component
retains the exact encoded line plan and measures direct token anchors separately
from line-table visibility. Native-free tests independently decode generated
DWARF5 line bytes for both address widths and byte orders; baseline comparisons
preserve all four section byte streams. This is not an exposed scorecard yet.
The instruction capture helper passes 44 checks using actual Ghidra databases
for x86-64, AArch64 and both MIPS32 byte orders. Per-function token provenance is
preserved before declaration rows are merged. Source text, existing mappings and
function boundaries remain byte-identical in a parent comparison. These helpers
are not yet connected to a public report. Canonical type accounting now passes
29 native-free checks for opaque targets, filtered roots, missing/repeated edges,
implicit void, cycles, cancellation and a 20,000-node shared chain. Its emission
input now also comes from successful producer emission through `ExportResult`.
Location-list results now retain their actual immutable range/expression plan;
the exporter threads cancellation into planning/encoding. Independent byte checks
and real x86-64/AArch64 lexical-variable regressions pass for this refactor.
Report integration, variable/type
coverage, CLI/GUI comparison and full validator/GDB/performance acceptance remain
planned.
Issue 74 retains integration priority; no public schema has changed.

## Actual emission boundary

`ExportResult.emission()` now carries immutable successful-production facts:
the exact encoded line plan, represented canonical type references (including
implicit void), and per-function emitted signatures/declarations. A symbol-only
function has a null signature and no invented parameter/local roots. Parameter
ordinals, internal versus displayed local names, lexical ownership, artificial
return-buffer carriers and function statics retain their separate identities.
No native pointers survive the producer lifetime.

Location facts distinguish an actual expression, an actual referenced list with
its exact ranges/expressions, and an explicit omission. They are recorded only
after the relevant attribute calls succeed. Expressions do not invent PC ranges;
the future scorecard must obtain evidenced visibility independently. Type edges
are retained after their node's population succeeds, not merely allocation.
Native-phase cancellation still finishes the producer and leaves a prior output
unchanged; a succeeding repeat in the same isolated JVM remains deterministic.

The source-built `emission-evidence` fixture independently inspects actual ELF
line bytes, DIE ownership/type edges, location expressions and lists. Its nine
declarations have four emitted full locations and five explicit omissions;
the reachable graph has five canonical DIE nodes, including one opaque target.
The recursive graph and implicit-void function retain their distinct semantics;
the failed function has no emitted signature despite globally allocated types.
Native GDB confirms parameters/changing-register local values, the static object,
types/source, `next`/`step`, unavailable partial/mixed storage, failed-function
lookup and normal exit. These are producer facts, not a public scorecard yet.

Run with Java21, the selected Ghidra installation and pinned native/checker paths:

```bash
python3 src/test/integration/emission-evidence.py <ghidra> <libdwarf> <libdwarfp>
```

The harness retains command logs and `acceptance.json` under
`build/test-results/emission-evidence/run.*`. The first GDB oracle attempted to
source-step after returning to an unexported caller; adding a separate return
line to the fixture corrected that harness error. The corrected full journey
passes. A separate same-path parent/candidate production comparison preserves
complete sidecar and source bytes (`build/emission-baseline/result.json`).
The later nine-declaration scope fixture has its own byte-identical comparison
at `build/location-coverage-baseline/result.json`.
The updated package also passes the two real headless lexical-variable journeys
below; current evidence is `build/emission-package/local-review.json`.
The follow-on workflow now includes the instruction/source/type/location smoke
tasks and the isolated native evidence fixture in the x86-64 target lane. Workflow
lint and the isolated-process harness pass locally; this unpublished branch has
not run those additions on hosted CI.

## Location extent and known-scope totals

`LocationCoverage` measures unions/intersections of half-open link-time PC-byte
ranges. It receives actual enclosing DIE ranges and recovered visibility as
separate inputs. A missing declaration, an emitted declaration without a location,
a full expression and a referenced list remain distinct. Complete known visibility
clips located ranges; unknown visibility retains owner-bounded ranges as descriptive
information and withholds a whole-scope percentage. Some known visibility intervals
do not make the rest of an unknown lifetime disappear.

`VariableCoverageTotals` retains all recovered declarations in the location-count
denominator, including failed-function declarations. Extent totals include only
complete known-scope populations and disclose the excluded unknown-scope count.
Their unit is variable-PC-bytes. Checked aggregate overflow produces null extents
with `OVERFLOW`, not wrapped values or fabricated zero; individual variable counts
remain available. Empty denominators are not applicable.

The component passes 21 local checks, including discontiguous/overlapping ranges,
independently enumerated PCs, absent/omitted declarations, unknown/partial/empty
scope knowledge, maximum addresses, aggregate overflow and cancellation. The
actual producer fixture now records explicit root visibility for `moving` and
`late`. Raw DWARF and GDB confirm `late` is unavailable at entry and available
after the move: 2 covered PC-bytes out of 5 visible PC-bytes. The static object
has a usable memory location but unknown visibility, so it gets no scope percentage.
Across the fixture's ten recovered declarations (including the failed function's
unemitted parameter), nine are emitted and four have locations. Four variables
have complete known scopes; six have unknown scopes. The known population totals
12 covered variable-PC-bytes out of 21. These numbers are independently checked
in `emission-evidence.py`; they are not yet published by the production report.

Root static ownership alone does not establish a visibility interval: the existing
static-binding record has no root-scope fingerprint. Nonempty explicit lexical
block evidence and explicit local bindings can establish ranges. The public
inventory builder must retain that distinction and declaration/storage provenance;
it must not infer visibility from available storage. Current native evidence is
`build/test-results/emission-evidence/run.6dwshckm/acceptance.json` and local component
output is `build/location-coverage-validation.log`.

## Recovered declaration inventory

**CONFIRMED locally:** `VariableCoverageInventory` now joins the original
recovered model to actual producer declarations, with per-function and per-kind
counts. Parameter ordinals distinguish duplicate/blank names; scoped internal
local names distinguish shadowed display names; statics retain their memory
address and lexical owner. These are export-local keys, not proof that renamed
locals correspond across different reports. Globals remain outside the function
variable denominator. Missing recovery is explicit, distinct from a known empty
signature. Unmatched/ambiguous inventories and stale lexical bodies are rejected.

Formal parameters use function-body scope, explicitly bound locals use their
recorded visibility, and block statics use explicit lexical ranges. Unbound locals
and root statics keep unknown visibility even if storage exists. Recovered but
unemitted declarations retain their denominators and an omission reason. Storage
ranges preserve their individual evidence categories and unavailable-prefix
reasons. Signature provenance is labeled as signature evidence; compound source
diagnostics remain verbatim with unknown category rather than guessed provenance.

Twenty-seven component checks pass, including every one of 273 cancellation
checkpoints, discontiguous scope clipping, duplicate/shadowed names, failed
functions, per-kind totals and immutable deterministic ordering. The existing
native fixture independently verifies the automatic inventory against raw DIEs,
locations and GDB: ten recovered declarations, nine emitted, four located, and
12/21 known-scope variable-PC-bytes with six unknown scopes. Evidence is
`build/test-results/emission-evidence/run.5d5c7_h0/acceptance.json`; build and
component checks are in `build/variable-inventory-validation.log`. Public schema,
comparison, UI, large-workload cost and hosted acceptance remain pending.

## Source populations and missing evidence

**CONFIRMED locally:** `SourceCoverageInventory` combines the actual line plan,
per-function token provenance and decoded listing inventories. It retains the
exact unique decoded/anchored/line-visible starts and exposes independent
availability for the listing denominator and direct token numerator. A missing
listing yields null counters; missing token provenance leaves anchors null while
preserving known line visibility. Known empty inventories have zero counts and
no percentage. Failed/omitted source retains its disposition and decoded
instruction denominator. Unknown evidence is never converted into zero coverage.

Program observations use unions of starts, so overlapping functions do not
inflate totals. The union discloses unknown instruction/token populations and
withholds the corresponding whole-program percentage. Aliases cannot enter the
primary population twice. Mismatched bodies, extra/duplicate evidence, token
rows outside their function's source boundaries and unavailable functions with
token mappings are rejected. Per-function overlap still retains its own token
provenance; a row belonging to another function cannot become its direct anchor.

Sixty-four component checks pass across both widths and byte orders, including
all observed cancellation checkpoints. Exact points also match the existing
independent raw-line decoder. The actual native fixture independently parses
DWARF line opcodes, disassembles its original ELF, and checks every inventory
point: six decoded instructions, two direct token anchors and four line-visible
instructions, with source/type/value/step GDB checks still passing. Evidence:
`build/test-results/emission-evidence/run.a6jba2sk/acceptance.json` and
`build/source-inventory-final-validation.log`. The initial Python oracle omitted
standard `DW_LNS_set_file`; the corrected oracle checks its zero-based file index
and the full rerun passes. Public report assembly/schema/comparison and measured
large-workload overhead remain pending; exact point retention is not yet a
public serialization contract.

## Combined scorecard assembly

**CONFIRMED locally:** `ExportCoverage` combines actual per-function emission,
source inventories, recovered variable populations and canonical type coverage.
A failed function keeps its recovered type denominator even when that type is
emitted elsewhere. Aggregate function types use a canonical union, not the sum
of per-function graphs. Missing recovered signatures produce null per-function
type metrics and an explicit unknown-signature count; whole-population type
percentages are withheld while any signature is unknown. Recovered globals stay
in a separate inventory, with no claim that all of them were emitted.

Signature evidence retains the recorded convention separately from the actual
post-policy effective convention and debugger-call restriction. Signature source
is not propagated into invented per-type provenance. The assembler is designed
to run inside artifact staging before publication; it is not yet connected to
the ordinary script/report path and is not a public wire format.

The combined smoke passes all 148 cancellation checkpoints and checks unknown
model/source/listing evidence, failed functions, canonical unions, separate
globals and post-policy restrictions. Native raw-DWARF/GDB inspection verifies
the assembled fixture's per-function type/source/variable metrics and its union
of five DIE-required canonical nodes (four resolved, one opaque) plus implicit
void. Evidence is `build/coverage-assembly-validation.log` and
`build/test-results/emission-evidence/run.nw9dlv3j/acceptance.json`.
Versioned bounded serialization/reading, exact comparison identity, presentation,
large-workload overhead and full hosted acceptance remain pending.

## Proposed coverage payload and reader boundary

**CONFIRMED locally; ordinary report integration pending:** `CoverageReportJson`
serializes the assembled scorecards into a proposed definition-version-one
payload for report schema two. It has explicit Ghidra language/compiler-spec
identity and `ELF_LINK_TIME` addresses. Counters use canonical nonnegative decimal
strings through `Long.MAX_VALUE`; unavailable counters use null with their
reason. Addresses use canonical hexadecimal strings. YES/NO and KNOWN/UNKNOWN
strings preserve the current lexical grammar without introducing JSON booleans.
The definition version is the only numeric literal in this payload.

Function records carry exact source starts, type metrics, signature restrictions
and variable totals. A flat variable table references its owner entry and retains
scoped identities, provenance, unavailable storage and evidenced/located ranges.
Recovered globals stay separately labeled. This shape fits the existing depth
eight limit when embedded in a report. Exact comparison identities and production
integration are still required before this becomes a public contract.

Serialization checks cancellation throughout and bounds actual UTF-8 output to
64 MiB before appending each character, including split surrogate pairs; it
rejects unpaired surrogates and strings beyond 65,536 UTF-16 units. Exact budget
boundaries, escaped/Unicode text, null versus zero, `Long.MAX_VALUE`, aggregate
overflow and all 2,260 observed cancellation points pass. The final report still
needs a shared full-document value/array/byte budget check before publication;
the payload budget alone is not that check.

The existing schema-one streaming reader now shares its strict primitive methods
through `ReportValueReader`. Child decoders share the original value budget and
owned stream, so introducing a coverage decoder cannot reset the document limit.
The nested-budget/array/cancellation/close controls pass, as do all 429 original
malformed-report controls, 432 detailed-reader checks and existing writer checks.
The schema-one acceptance contract and existing report bytes are unchanged.

The isolated native fixture also verifies payload counters, addresses, ranges,
nulls and ownership against its already independently checked raw-DWARF/GDB
metrics. Evidence: `build/coverage-json-final-validation.log` and
`build/test-results/emission-evidence/run.m6oa17f2/acceptance.json`.
The strict `CoverageReportClaims` decoder now retains the proposed payload and
recomputes source unions, variable totals and location intersections. It rejects
missing/unknown/duplicate fields, noncanonical counters, invalid ownership,
contradictory availability and impossible type-union bounds. A consistent report
remains a claim: it does not authenticate source anchors or canonical type identity
against artifacts and grants no attachment authority. Embedded decoding shares
the enclosing report's value budget rather than resetting it.

Local checks pass 503 malformed controls and 287 sampled cancellation points,
exact UTF-8/value budgets, reordered fields and stream closure. The actual native
fixture round-trips its coverage object and serialized bytes through this reader;
GNU/LLVM/pinned strict validation and GDB behavior still pass. Evidence:
`build/coverage-claims-final-validation.log` and
`build/test-results/emission-evidence/run.ui63r2z2/acceptance.json`.
The versioned root reader now accepts schema two with a required coverage object
on completed reports and explicit null on terminal reports. Schema one rejects
that field and still requires the previously accepted complete legacy shape.
All three reader paths validate the payload; `readWithCoverage` retains it, while
the lightweight and diagnostic-retaining results discard it. A schema-one result
has unavailable coverage, never zero. A function population mismatch is rejected.
The seven-field legacy claims API and diagnostic inventories remain unchanged.

`ExportReport.toJsonWithCoverage` explicitly writes schema two. It shares one
bounded UTF-8 stream with the payload and completes strict full-document preflight
before returning. The existing `toJson()` still emits byte-compatible schema one.
Report writing checks cancellation throughout serialization and preflight; byte,
value and depth overflow fail without returning publishable text. The production
script must call this during staging before replacing the artifact pair.

Local migration checks include all reader paths, reversed fields, null/version
rules, complete-document budgets, 256 sampled read/write cancellation points,
terminal statuses and selected-file hash binding. Matching coverage cannot hide
changed sidecar bytes, upgrade PARTIAL/NOT_RUN or bypass malformed-report rejection
before artifact inspection. Native fixture `run.lngcyr7b` round-trips the complete
schema-two report; Python independently checks its embedded metrics and all three
file hashes against the validated DWARF/GDB fixture. Production script staging,
CLI/GUI/comparison and large-workload overhead remain planned. No ordinary export
emits this proposed payload yet. The retained payload's
large-workload cost is unmeasured; old diagnostic-inventory retention limits do
not automatically constrain these additional structures.

### Exploratory workload admission evidence

**HISTORICAL initial limitation; production wiring remains pending:** the original
one-million-value document budget accepts a sparse 10,000-function payload but
rejects a denser synthetic 6,375-function payload with 12 decoded instructions
and four full-scope locals per function. The latter contains 1,447,193 payload
values in 27,677,206 UTF-8 bytes. This is a deliberate bounded-reader rejection,
not a JVM failure or permission to publish a partial scorecard.

The reproducible probe runs without Ghidra extraction or native production:

```bash
./gradlew coverageReportWorkload -PcoverageWorkloads=1000:32:4,6375:12:4
```

Shapes are `functions:instructions:locals`. The probe reports acceptance or
rejection explicitly; successful process exit does not mean every shape fits.
It also writes `build/coverage-report-workload-classpath.txt` for isolated JVM
measurements. A test-only `-Dforge.workload.values=2000000` override admits the
dense shape with both 256 MiB and 768 MiB Java heaps. Single cold observations
take approximately 0.62 seconds for complete report writing/preflight; standalone
process peak RSS is 398,148/619,892 KiB respectively. These include probe/JVM costs,
are not repeated benchmark medians and establish no exporter speed or memory
improvement. The Gradle client's `/usr/bin/time` RSS is not the worker JVM's RSS.

Raw command/output/timing hashes and observations are recorded in
`docs/evidence/coverage-report-admission-probe.json`. The decision below supersedes
this initial admission policy. Merely passing sparse fixtures is insufficient
evidence for large-program acceptance.

### Lossless evidence dictionary and scoped admission

**CONFIRMED locally; production staging and hosted acceptance pending:** actual
saved SQLite/U-Boot probes show that repeated storage evidence text dominates the
initial payload. SQLite repeats three exact detail tuples across 167,163 ranges;
its original payload is 56,392,815 bytes and 2,210,528 values. U-Boot's initial
payload exceeds the 64 MiB writer cap. Neither rejected probe counts as coverage
acceptance, and neither changes the original inputs or saved projects.

The proposed payload now includes `storageEvidenceDetails`, an ordered dictionary
of exact category/source/omission-reason/diagnostic tuples. Each variable's storage
evidence consists of `[start, end, detailIndex]` triples using canonical hexadecimal
addresses and decimal-string indices. Dictionary order follows first occurrence;
all range boundaries, evidence text and per-variable order are preserved. Readers
reject missing/out-of-range references, duplicate or unused details, overlapping
ranges and malformed tuples. Object-field order does not matter. This revises the
unpublished proposal; ordinary schema-one exports are unchanged.

One shared input budget now tracks three counters: at most **1,000,000 legacy
values**, **5,000,000 coverage values**, and **6,000,000 total values**. Coverage
cannot spend the legacy allowance or reset a counter when entering another child.
The unchanged 64 MiB byte cap, 65,536 UTF-16 units per string, depth eight and
250,000 elements per array still apply to the entire document. Old schema-one
reports still reject their 1,000,001st value, tested at the actual boundary as well
as with small scoped budgets and reversed field order. The five-argument test
limits retain their original exact whole-document ceiling.

The five-million coverage ceiling admits the measured compact U-Boot population
of 4,395,987 values without raising the document byte cap. These are explicit
resource limits, not a claim that every possible input size fits. A bound violation
must fail before ordinary output publication, never truncate the scorecard.

| Saved workload | Functions / decoded instructions / recovered variables | Payload bytes / values | Complete report bytes |
| --- | --- | --- | --- |
| SQLite 3.46.1 | 1,539 / 199,606 / 7,064 | 19,897,363 / 1,709,055 | 23,061,568 |
| U-Boot 2025.01 sandbox | 6,375 / 544,845 / 19,781 | 54,600,521 / 4,395,987 | 56,530,307 |

Both instrumented saved-project probes now pass full report preflight, GNU/LLVM/
pinned strict validation and their existing GDB behavior journeys. SQLite's
independent before/after comparison proves every range/detail and all other
coverage fields unchanged; the two compact U-Boot payloads are byte-identical
across separate processes/output directories. Original/module/project snapshots
match before/after (343/346 protected files). U-Boot retains its one failed
decompilation, and unknown variable scopes remain explicit.

Single observations place coverage assembly at 0.20/0.35 seconds and full report
writing/preflight at 1.04/2.23 seconds for SQLite/U-Boot. Whole-probe peak RSS is
1,243,528/1,946,200 KiB; this includes Ghidra, native decompilation, evidence capture,
serialization and parser work, not isolated incremental reporting memory. These
are not repeated benchmark medians or a general speed/memory improvement claim.

Commands and bound raw evidence are retained by `src/test/performance/coverage-workload.py`:

```bash
python3 src/test/performance/coverage-workload.py sqlite <saved-sqlite-case> <private-ghidra>
python3 src/test/performance/coverage-workload.py uboot <saved-uboot-case> <private-ghidra>
```

See `docs/evidence/coverage-workload-admission.json`, the native fixture
`run.lph7dfjx`, and `build/coverage-admission-final-validation-2.log`. The component
passes 828 payload rejection controls, 117 migration/binding rejections, legacy
429 malformed/432 detailed-reader checks, attachment/receipt checks, cancellation
and the native raw-DWARF/GDB fixture. Ordinary production staging, meaningful
comparison/presentation, repeated overhead controls and the full matrix remain
required; this does not complete #108.

## Current component checks

With the supported Java21/Ghidra12.0.3 environment, run:

```bash
./gradlew ghidraInstructionEvidenceSmoke syntheticSourceSmoke sourceCoverageSmoke sourceCoverageInventorySmoke dwarfLineTableSmoke typeCoverageSmoke locationEmissionPlanSmoke locationCoverageSmoke variableCoverageInventorySmoke exportCoverageSmoke coverageReportJsonSmoke reportValueReaderSmoke dwarfLocationListsSmoke buildExtension
```

Observed local results: instruction evidence passes 44 checks across four
profiles; source provenance and independent line-byte coverage checks pass;
the extension builds. The ordinary exporter/report path does not yet invoke
instruction capture or publish metrics. Baseline comparisons cover four line
encodings and synthetic source/mapping/boundary bytes. Full serialized ELF/DWARF,
GDB, report compatibility, GUI and performance acceptance is still outstanding.

The location-plan refactor additionally passes 237 native-free checks across both
address widths/byte orders. The retained intervals and expressions match an
independent raw decoder. Single partial registers, rejected mixed lists, invalid
piece widths, unavailable ranges and unresolved stack coordinates do not acquire
phantom list coverage. A stable full expression remains distinct from a list.
Four parent/candidate section streams are byte-identical (combined dump SHA-256
`e4c09ff79358e887b78908efd2de18e8bcae81d1b016c309c8a417d3941734a6`).

Using the current locally assembled package in a private Ghidra12.0.3/Java21
installation and the pinned libdwarf checker, these commands passed:

```bash
python3 src/test/integration/lexical-shadow-export.py <private-installation> x86_64 --discontiguous --controls
python3 src/test/integration/lexical-shadow-export.py <private-installation> aarch64 --role pie-rebased --discontiguous
```

Both run the actual exporter twice, GNU/LLVM/libdwarf checks, compiler-reference
and Forge GDB journeys. The AArch64 journey uses QEMU. There are 23 x86-64 and
27 AArch64 instruction-boundary observations: outer value 11, inner value 23,
uninitialized unavailable states and correct scope-gap lookup. x86-64 also passes
stale/coalesced evidence, actual decompiler failure and copy-cancellation controls.
Repeated report/sidecar/source bytes and 14 protected hashes per case match.
Exports honestly remain `PARTIAL` for unrelated existing recovery omissions.
Strict checks have zero uncorroborated errors; the only accepted diagnostics
match the original's unchanged inherited frame records. This validates unchanged
debugger behavior, not public scorecard numbers. Evidence:
`build/coverage-package/local-review.json`, `build/coverage-location-validation.log`
and `build/location-plan-baseline/result.json`. Hosted acceptance remains pending.

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
  with their kind and stable scoped identity. Show per-kind totals. Namespace
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

For location extent, use half-open link-time PC-byte ranges, explicitly labeled
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
- Across variables the unit is variable-PC-bytes. Sum only comparable known-scope
  populations and show excluded unknown-scope variables. Do not hide exclusions
  in a single overall percentage. Function-static physical address availability
  does not imply evidenced lexical visibility.

Type population starts from recovered function return/parameter/local/static type
roots; collect canonical reachable nodes with an iterative, cycle-safe walk.
Roots count distinct canonical type identities, not uses or variable declarations.
Track emitted roots/nodes separately after signature filtering. Types allocated
elsewhere in the compilation unit do not count for a function unless reachable
from that function's actually emitted roots. The current component measures:

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
implicit-void decisions, after successful population. The hand-counted fixtures
are complemented by the raw-DIE/GDB producer fixture above; public report accuracy
is still unverified.

## Provenance and identity

Reuse existing source categories (USER_DEFINED, IMPORTED, ANALYSIS, DECOMPILER)
without calling them probabilities. Missing per-type or per-line provenance is
reported as unknown unless extraction actually records it. Preserve omission
reasons, decompilation failure and target-profile restrictions alongside counts.

Names alone are not stable keys. Use normalized original-image-relative function
identity, parameter ordinal, lexical ownership, and the existing disambiguated
local identity. Preserve the displayed name separately. Explicitly detect
ambiguous correspondence across reports instead of merging same-named/shadowed
variables. A display-name edit should remain visible as a rename where identity
is otherwise proven. Per-function type sets deduplicate canonical identities.

## Required implementation boundary

The producer computes emitted signatures, line sequences and location lists after
target-specific restrictions and now returns their immutable evidence through
ExportResult. Consuming that summary in report creation remains planned. Do not
rebuild a second, slightly different approximation from the pre-filtered extraction
model. Line-map provenance is preserved before declaration rows are merged.
Cancellation is checked during instruction/type accounting, list planning and
the new producer evidence loops. Report serialization/reading now check
cancellation; production staging and comparison loops remain to be implemented.

The current native-free probe proves why this boundary matters: model-level
hasDefensibleLocation() is true for a partial register slice and a mixed list
that the expression/list planners omit. The old aggregate counts distinct model
records, not ranges. The probe is not serialized-DWARF or GDB validation.

## Schema and report comparison

Introduce an explicit new report version and metric-definition version. Keep the
current valid schema-one reader and raw report bytes/hash receipts working.
Intentionally rejected older schema-one shapes stay rejected. A v1 report has
coverage unavailable, never inferred zero. Keep attachment validator/artifact
binding requirements identical; coverage is informational and cannot authorize a
write or bypass rejection.

Specify bounded nonnegative integer representation deliberately: reader limits
are depth 8, 64 MiB, one million legacy values plus the scoped coverage allowance
above, 250,000 array entries, 65,536 string
characters and ten-digit numeric literals. New counts/range sums may exceed the
old integer limit. Use checked arithmetic and define overflow/unavailable status,
not wraparound or an accidental unlimited parser. Ratios are presentation only;
serialize exact counts and explicit unavailable/not-applicable reason strings.

Compare reports only when original identity, target/profile, metric version and
population rules are compatible. Account for ordinary Ghidra rebases and moved
output directories through link-time identities. Incompatible or ambiguous
comparisons are explicit, not zero-change reports. Show lost anchors, newly
unavailable variables/ranges, and resolved-to-opaque type regressions, even when
a total elsewhere improves. Avoid a fabricated combined quality score.

## Independent acceptance matrix

- Tiny source-built positives with known decoded starts, source token anchors,
  declaration rows, entry rows, duplicate rows and discontiguous bodies; decode
  emitted line programs independently and compare exact expected populations.
- Aliases and overlapping function bodies: unchanged primary denominator,
  explicit per-function overlap, union-based whole-program instruction counts.
- Stable full locations, changing full locations, unknown gaps, truncated register
  slices and incomplete pieces: independently decode DIE locations/loclists and
  use GDB at inside/outside boundary PCs; no score for merely modeled storage.
- Failed/omitted decompilation, missing signatures and symbol-only output: retain
  function and recovered populations, show actual emitted absence explicitly.
- Shadowed/same-named locals, function statics and recursive/opaque type graphs:
  raw DIE ownership/type-edge inspection plus useful debugger type/value checks.
- Valid v1 and v2 report binding; terminal reports; malformed/oversized/corrupt
  coverage; old rejected v1 shape; byte-identical preservation of prior receipts.
- Comparable curation/rebase/path-move reports and deliberately incomparable
  originals/profiles: meaningful CLI and actual GUI regression summaries.
- Repeated pinned large-workload measurements with exact same artifacts and
  report determinism, recorded added wall/CPU/memory cost, cancellation at each
  new expensive phase and unchanged atomic failure behavior.

Source inventory/provenance, source/type accounting and producer emission evidence
exist; public scorecards remain unimplemented. No final schema approval or
end-to-end scorecard acceptance is claimed by this draft. Review the open scope/identity details
against fixtures before making these definitions a public contract.
