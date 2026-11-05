# Issue 108 acceptance map

**PRESENT, UNVERIFIED as a complete feature:** local acceptance below is
confirmed, as are the Windows host/performance gates at `3829626`. A later review
corrected unknown-inventory presentation, and the MIPS32LE lane exposed another
malformed terminal fixture. The corrected host/target gate, final artifact review
and protected integration remain pending.
PR [164](https://github.com/zwilcox/GhidraDwarfForge/pull/164)
remains a draft. Evidence below identifies its exact tested revision; the review
fixes require a fresh gate rather than inheriting earlier check status.
This document does not close #108 or any later goal issue.

The [metric contract](COVERAGE-SCORECARDS.md) defines the actual populations,
units, exclusions, report formats and comparison limits. The table maps all six
acceptance items from [issue 108](https://github.com/zwilcox/GhidraDwarfForge/issues/108).

| Requirement | Evidence required and local result | Remaining gate |
| --- | --- | --- |
| Exact source, variable, scope-range and resolved/opaque type numerators and denominators | Explicit contract; hand-counted component cases; independent raw `.debug_line`, DIE and `.debug_loclists` decoding in `emission-evidence.py`; raw-DIE type-pair comparisons. Local producer artifacts, strict validators and GDB pass. | Review the current hosted emission-evidence artifact and component results. |
| Static versus execution coverage; discontiguous bodies, aliases, duplicates, partial pieces, failures, unknown lifetimes and zero denominators | `SourceCoverageSmoke`, `SourceCoverageInventorySmoke`, `LocationCoverageSmoke`, `VariableCoverageInventorySmoke` and `ExportCoverageSmoke` exercise these exclusions and unions. Real Ghidra capture checks use multiple language profiles and rebases. The production report keeps unknown populations and failed declarations explicit. | Confirm the current component gate and architecture regressions, rather than treating switch statements or isolated model checks as target support. |
| Provenance and omission reasons without a fabricated confidence score | Summary and per-function details expose provenance, unknowns and omissions. `CoveragePresentationSmoke`, terminal-control tests and actual GUI save/compare journeys pass locally. Static coverage is labeled separately from execution coverage and validation. | Inspect current Windows and Linux GUI/CLI output and retained screenshots. |
| Versioned schema/readers/fixtures without invalidating legacy reports or attachment evidence | Schema-one bytes remain compatible; schema-two metric definitions one/two are explicit. Strict reader, malformed/cancellation, report binding and attachment tests retain independent artifact identity. Corrected terminal fixtures distinguish valid terminal status from malformed retained coverage. | Complete the current five-target report/attachment tests and Windows GUI/preparation/consumer checks. |
| Independently validated numbers and exposed regressions between comparable exports | Raw ELF/DWARF decoding checks actual emission. x86-64 and rebased AArch64 PIE curation/rename/rebase pairs expose exact location losses; type-pair exports expose resolved/opaque swaps despite equal totals and attachment loss after source failure. CLI/GUI comparisons pass locally. | Inspect current hosted raw artifacts and actual debugger transcripts for the comparison fixtures. |
| Useful CLI/GUI, bounded large-fixture cost, deterministic output and preserved failure/cancellation behavior | Linux GUI/CLI and 1024x768 controls pass locally; Windows GUI passes hosted review. Five alternating SQLite/U-Boot pairs on each host preserve exact artifact bytes and deterministic reports while recording material runtime/memory cost. Windows large-report CLI/JFR and downstream GDB review pass. Actual string and 64 MiB rejection, cancellation, preservation and deterministic retry pass locally on x86-64 and rebased AArch64 PIE. | Complete full target review, Linux hosted GUI, and the up-to-date required-validation gate. |

## Evidence and scope

- [Type report](evidence/coverage-type-report.json): graph/roots and strict reader
  controls plus production staging. Its historical remaining-work statements
  describe that checkpoint; later receipts below supply subsequent evidence.
- [Variable comparison](evidence/coverage-variable-comparison.json): independent
  interval controls and actual saved Ghidra use-site edits, renames and rebases,
  with raw location lists, CLI comparisons and native/QEMU GDB.
- [Type pairs](evidence/coverage-type-pairs.json): production producer exports,
  independent raw-DIE edge/state predictions and GDB. This proves emission and
  comparison, not a separate Ghidra database type-edit journey.
- [Whole-report limit](evidence/coverage-whole-report-limit.json): actual captured
  data exceeds the unchanged production byte bound; previous pair/companion
  generations survive and retries remain deterministic.
- [Large workloads](evidence/coverage-large-workloads.json): measured Linux wall,
  CPU, RSS and report sizes, individual pairs, full artifact equality, validators
  and GDB. Known U-Boot decompilation failure remains included. No broad memory or
  speed guarantee follows from two workloads on one host.
- [GUI/terminal/JFR follow-ups](evidence/coverage-ci-followups.json): retained
  hosted failures, local screen-size correction, terminal controls and parser
  rejection tests. [Actual production JFR](evidence/coverage-production-jfr.json)
  additionally proves all nine phases on one thread without overlap; its artifact
  passes validators and GDB. That single export is not a timing benchmark.
- [Windows measurement control](evidence/coverage-windows-measurement-control.json):
  exact published baseline derivation, independent clean-build class equality,
  source/class audit and negative controls. The separate Windows workload
  receipt below supplies actual hosted execution.
- [Windows host review](evidence/coverage-ci-3829626-windows.json): exact-head
  native GUI, compressed and companion exports, report save/comparison/retry,
  and downstream Linux GDB checks pass. Download digests, all 930 protected
  consumer-file hashes and all three GUI report artifact bindings were checked.
  Summary/comparison screenshots show the controls within the Windows desktop.
  One post-test teardown message is retained with its uncertain exact cause;
  the matching OpenJDK Java2D catch path is linked in the receipt. This GUI
  review does not substitute for full target-matrix acceptance.
- [Windows workloads](evidence/coverage-ci-3829626-workloads.json): all five
  performance jobs pass. Exact-head download/manifest checks, all 22 report
  bindings, ten measured pairs and two separate binary JFR recordings pass
  review. Actual Windows CLI and independent Linux compiler/Forge GDB checks
  pass. Strict inherited-frame messages are corroborated on both hosts with
  no unexplained errors. Runtime and substantial memory costs remain explicit;
  Windows job commitment is not Linux RSS. Project data stays unchanged while
  Ghidra rotates index/journal backups.
- [Cross-target attachment review](evidence/coverage-ci-3829626-attachments.json):
  fifteen early hosted cases cover non-PIE, PIE and no-build-ID inputs on all
  five targets. Artifact/report bindings, actual inherited frame bytes, raw
  GNU/LLVM/strict/GDB evidence and CLI readback pass. All 22 strict diagnostics
  are corroborated against original frames; none are unexplained. This does
  not complete the later tests in those still-running architecture jobs.
- [Bounded source review](evidence/coverage-source-review.json): exact source
  hashes and findings for source/location/type populations, comparison,
  reader budgets, emission integration, staging and GUI behavior. Extended review
  found the unknown-inventory presentation defect; its correction and terminal
  fixture follow-up are in [final review fixes](evidence/coverage-final-review-fixes.json).
  Local regression, packaged CLI and preparation controls pass. Outstanding
  runtime gates remain required.

Strict validator messages inherited from original frame sections require the
existing exact section identity and diagnostic corroboration. A successful tool
exit alone is insufficient. Reported validation stays `NOT_RUN` until independent
evidence is separately obtained; coverage percentages cannot grant attachment
authority.

## Current integration evidence to review

- Prior production host/target run: `42088664715`, head `3829626`; MIPS32LE
  fails at the malformed terminal fixture, so this run cannot be an accepted gate.
- Performance/Windows workload run: `42088664392`, same head; all five jobs pass
  and the workload/consumer artifacts have been reviewed.
- **CONFIRMED:** component tests and both native builds pass. The
  [exact-head package review](evidence/coverage-ci-3829626-package.json) verifies
  the downloaded artifact digest, all 348 release-manifest entries and equality
  of all 587 production class files with the locally validated package. The
  Windows baseline-control derivation step also passes. These checks do not
  complete the running target gates. Windows host and downstream GDB
  jobs now pass, with artifact review recorded above.
- Prior failed runs remain evidence of defects, not accepted gates. In particular,
  the older MIPS32BE job in `42080744656` was still installing tools at the latest
  observation; elapsed time alone is not a reason to restart or call it complete.

Review must bind the downloaded release/artifacts to the corrected exact head, inspect all
five target lanes and both host paths, retain compiler/native-control provenance,
and corroborate original preservation and deterministic reports. After every
applicable check passes, complete the source review and normal protected merge.
Do not bypass required validation or describe later comments/disassembly, CFI,
LLDB or build-ID work as completed by this feature.
