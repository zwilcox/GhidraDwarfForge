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
are not yet connected to a public report. Report integration, variable/type
coverage, CLI/GUI comparison and full validator/GDB/performance acceptance remain
planned.
Issue 74 retains integration priority; no public schema has changed.

## Current component checks

With the supported Java21/Ghidra12.0.3 environment, run:

```bash
./gradlew ghidraInstructionEvidenceSmoke syntheticSourceSmoke sourceCoverageSmoke dwarfLineTableSmoke buildExtension
```

Observed local results: instruction evidence passes 44 checks across four
profiles; source provenance and independent line-byte coverage checks pass;
the extension builds. The ordinary exporter/report path does not yet invoke
instruction capture or publish metrics. Baseline comparisons cover four line
encodings and synthetic source/mapping/boundary bytes. Full serialized ELF/DWARF,
GDB, report compatibility, GUI and performance acceptance is still outstanding.

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
roots; collect canonical reachable nodes with a cycle-safe walk. Track emitted
roots/nodes separately after signature filtering. Proposed metrics are
`resolvedEmittedNodes / recoveredReachableNodes`, with explicit opaque and
not-emitted counts, and an additional count of roots whose entire reachable graph
is emitted and non-opaque. A pointer to an opaque aggregate has a resolved pointer
node but not a fully resolved root graph. Recursive non-opaque graphs terminate
and may be fully resolved. Void/no-type and missing roots require an explicit
representation, not an invented one-byte base type. Formalize these distinctions
against the actual TypeGraph node vocabulary before freezing the schema.

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

The producer already computes emitted signatures, line sequences and location
lists after target-specific restrictions. Return an immutable emission summary
(or a shared immutable emission plan) through ExportResult; consume that in report
creation. Do not rebuild a second, slightly different approximation from the
pre-filtered extraction model. Preserve line-map provenance before declaration
rows are merged. Thread cancellation through inventory/planning/report loops.

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

Only the source-coverage component exists. No final schema approval or
end-to-end scorecard acceptance is claimed by this draft. Review the open type/scope/identity details
against fixtures before making these definitions a public contract.
