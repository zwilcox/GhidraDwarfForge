# Proposed coverage contract for issue 108

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
line bytes, DIE ownership/type edges, location expressions and lists. Its eight
declarations have three emitted full locations and five explicit omissions;
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
The updated package also passes the two real headless lexical-variable journeys
below; current evidence is `build/emission-package/local-review.json`.
The follow-on workflow now includes the instruction/source/type/location smoke
tasks and the isolated native evidence fixture in the x86-64 target lane. Workflow
lint and the isolated-process harness pass locally; this unpublished branch has
not run those additions on hosted CI.

## Current component checks

With the supported Java21/Ghidra12.0.3 environment, run:

```bash
./gradlew ghidraInstructionEvidenceSmoke syntheticSourceSmoke sourceCoverageSmoke dwarfLineTableSmoke typeCoverageSmoke locationEmissionPlanSmoke dwarfLocationListsSmoke buildExtension
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
the new producer evidence loops; report/comparison loops remain to be implemented.

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

Specify bounded nonnegative integer representation deliberately: existing reader
limits are depth 8, 64 MiB, one million values, 250,000 array entries, 65,536 string
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
