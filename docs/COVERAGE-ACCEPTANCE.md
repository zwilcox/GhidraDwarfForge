# Issue 108 acceptance map

**CONFIRMED:** issue #108's implementation is accepted at tested code revision
`6e0cb9549ce77895b3d988e4ecd801322086516a`. All fifteen integration jobs and all
five performance jobs pass. PR #164 merged normally as
`41e85b9e83e775e76313d16f6865ec21fc7d0529`; its tree is identical to the tested
head. Strict `required-validation` remained enforced and no admin bypass was
used. This document publishes the final acceptance record; earlier pending
checkpoints are historical within this scope.

The [consolidated receipt](evidence/coverage-ci-6e0cb95.json) binds 27 scoped
review records, seven rehashed archives, fourteen hosted artifacts, the actual
job results and the protected merge. This is development-branch acceptance,
not release publication or completion of the remaining thread goal.

The [metric contract](COVERAGE-SCORECARDS.md) defines populations, units,
exclusions and comparison limits. Coverage describes exported static knowledge;
it is neither execution coverage nor confidence in correctness. Independent
validation and attachment authority remain separate.

| Issue 108 requirement | Reviewed evidence at the tested code revision | Final acceptance |
| --- | --- | --- |
| Exact numerators and denominators | Nineteen component suites actually execute; source bindings still match 31 reviewed production files. Independent x86-64 emission/type-pair inspection and x86-64/AArch64 curation/staging review check raw lines, locations, type references and report artifact identities. | Confirmed by all five target jobs and the strict aggregate gate. |
| Discontiguous bodies, aliases, duplicate rows, partial pieces, failed functions, unknown lifetimes and zero denominators | Component controls exercise unions, exclusions and unavailable inventories. Real saved-program curation, rebase and rename cases preserve or expose evidence as specified. Unknown-only and mixed inventories no longer display a misleading empty percentage. | ARM32 final artifact and applicable regressions reviewed. |
| Provenance and omissions without a combined confidence score | Linux and Windows GUI save/comparison/error/retry journeys and packaged CLI readback pass. Screenshots show visible controls. Unknown populations and failed/filtered declarations retain reasons. | All supported target jobs pass. |
| Schema compatibility and independent attachment evidence | Schema-one compatibility and strict schema-two metric definitions retain their contracts. Reviewed report triples bind input, sidecar and source hashes; closed validator captures and terminal controls distinguish valid cancellation/failure from malformed retained coverage. Fifteen early attachment cases cover all five target families. | Full ARM32 job and artifact reviewed in addition to the early cases. |
| Independently checked numbers and exposed regressions | Four curation phases and three staging suites per x86-64/AArch64 target retain actual raw-DWARF and runtime-GDB evidence. Type-pair exports expose resolved/opaque swaps despite equal totals. CLI comparison reports individual ranges/types under documented correspondence limits; GUI comparison preserves exact totals after display clipping. | Current five-target gate and raw comparison review pass. |
| Useful CLI/GUI, measured bounded overhead, deterministic output and failure/cancellation behavior | All three x86-64 GUI modes pass the actual task-dialog cancellation journey. Windows host and consumer jobs pass. Real string/64 MiB rejection and preserved-generation retry controls are reviewed. Five alternating workload pairs per workload preserve artifact bytes and deterministic reports; separate JFR recordings and compiler/Forge GDB consumers pass. | ARM32 passes; PR164 is integrated and this record publishes final acceptance. |

## Current runs and retained evidence

- [Integration run 42103738813](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42103738813): both native builds, component/build/package, Linux reference, Windows host/attachment consumers and all five target jobs pass. ARM32 and required-validation also pass.
- [Performance run 42103738984](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42103738984): all five jobs pass at the same tested code revision. Reviewed evidence covers all 22 reports, ten measured pairs, two binary JFR recordings with nine phases each, native Windows report CLI and four independent compiler/Forge GDB consumers.
- The native-inclusive package has 356 manifest entries. Its 587 production class files match the independently reviewed base and workload candidate; classes target Java 21. This is a package review, not a release publication.
- The publication evidence index binds review records, hosted artifact IDs/digests, source hashes and compact retained archives. It keeps each review's scope and observation time explicit. Earlier pending-gate statements are historical.

ARM32 review checks 594 complete strict reports, three report/artifact triples,
42 primary snapshots, three closed validator captures, five applicable QEMU/GDB
transcripts, four terminal controls and ten packaged CLI cases. Its primary
oracle leaves clobbered register/composite locations unavailable and checks the
evidenced stack markers. The system-DSO string-table warning matches the separate
compiler-DWARF control exactly. Large saved-project databases were not reopened
locally; the receipt records bounded extraction of the digest-verified artifact.

## Measured costs and limitations

Current Windows median wall times are 96.98 to 104.00 seconds for SQLite and
226.18 to 238.55 seconds for U-Boot. Median peak job commitment grows from
1.14 to 1.33 GB and 1.33 to 2.32 GB respectively. Windows job commitment is not
Linux RSS. Candidate reports are 23,768,801 and 58,740,503 bytes. These are
material costs; two workloads do not establish a general speed/memory guarantee.
The [Linux workload receipt](evidence/coverage-large-workloads.json) separately
records Linux measurements, provenance and the shared audited array correction
used to isolate scorecard cost.

Original executables and saved program data remain unchanged in the reviewed
workflows. Ghidra index/journal backup rotation is recorded separately. Exact
artifact/report repeatability and complete report reading are required; a report
that exceeds the configured bound must fail before replacing a valid generation.

Inherited strict-check frame diagnostics are accepted only with exact original
frame identity and diagnostic corroboration. No unexplained strict errors are
accepted. Successful tool exit and a high coverage percentage are insufficient.

Source review is bounded, and individual comparisons use reported correspondence
rather than claiming historical variable/type lineage. Component/model fixtures,
real Ghidra curation, runtime GDB and host GUI tests prove different parts of the
contract; none substitutes for all the others.

## Earlier checkpoints

The existing [source review](evidence/coverage-source-review.json),
[final corrections](evidence/coverage-final-review-fixes.json),
[variable comparisons](evidence/coverage-variable-comparison.json),
[type-pair regressions](evidence/coverage-type-pairs.json) and
[whole-report limit](evidence/coverage-whole-report-limit.json) retain the
implementation rationale and local controls. Windows `3829626` host/workload
receipts remain historical evidence; its failed terminal-fixture integration run
is not an accepted gate.

The accepted gate includes every supported validation path. Normal protection
remained strict and enforced; no admin bypass was used. See
[PR 164](https://github.com/zwilcox/GhidraDwarfForge/pull/164) for live integration
state. Annotation/context, CFI, LLDB and build-ID installation remain separate
goal items, and this feature does not complete them.
