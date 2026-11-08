# Issues 116 and 114 acceptance map

**CONFIRMED:** the annotation and optional instruction-context implementation is
accepted at `21f8da3d529e1fb1009af8a46fdd529a03cae6c0`. All fifteen integration
jobs and the performance workflow pass. PR166 merged normally as
`8041fdabb58837bb29eb0bf46f33fcae33973419`, with an identical Git tree. Strict,
enforced `required-validation` remained enabled; no admin bypass was used.
The separate main-push run is `42210149331`; its result is not implied by the
accepted PR run. This is development-branch integration, not a release.

The [consolidated receipt](evidence/annotation-ci-21f8da3.json) binds exact
artifacts, review counts, retained archive digests, job results and merge identity.
The [design and implementation history](ANALYST-ANNOTATIONS.md) records policy
and intermediate failures. Earlier pending statements there and in the handoff
files are historical within this acceptance scope.

## Issue 116: comments and named constants

| Requirement | Implementation and validation evidence |
| --- | --- |
| Audited APIs, categories and ownership, including failed functions | `GhidraAnnotationInventory` uses the pinned Listing and EquateTable APIs. All five comment categories, exact address spaces, operands and dynamic hashes survive saved-program extraction. Independent readback, real native failures and default-export tests exercise comments absent from decompiler output. See [inventory](evidence/annotation-inventory.json), [equate evidence](evidence/equate-evidence.json) and [failed source](evidence/failed-source-context.json). |
| Evidence-backed placement and honest provenance | Unique instruction/token ownership permits statement placement; ambiguous, unmapped and failed-function observations use a labeled catalog. Stored comments are not assumed to be human-authored. Existing decompiler text and stored annotations retain distinct provenance. See [placement](evidence/annotation-placement.json). |
| Escaping and non-executable comments with correct line remapping | Reversible Unicode/control/delimiter encoding, bounded composition and independent decoded-line projections preserve executable address/source-text pairs. Inserted comment rows have no executable addresses. See [text](evidence/annotation-text.json), [composition](evidence/annotation-composition.json) and [default exports](evidence/annotation-default-export.json). |
| Width, signedness, scope and naming conflicts | Stored bit patterns, validated enum widths and operand/high-p-code evidence remain distinct. Stable ASCII aliases and qualified lookup preserve ambiguous/conflicting names. Synthetic constants carry no fabricated storage or lifetime. See [constant encoding](evidence/equate-constants.json) and [default integration](evidence/equate-default-export.json). |
| Consumer-tested encoding | The selected representation is synthetic constant DIEs plus a reversible source catalog. It does not claim recovered preprocessor definitions, global macro validity or automatic breakpoint display via `DW_AT_description`. GDB evaluates actual constants; macro lookup is not applicable to this selected encoding. |
| Useful debugger lookup amid conflicts | Installed exporter/GDB checks cover list, typed values, live frames, Unicode, operand-specific values, retained C++ function names, local/global/type/enum conflicts and discontiguous mappings. Unsupported conflicting-local lifetimes remain unavailable rather than fabricated. See [default integration](evidence/equate-default-export.json). |
| Determinism, preserved inputs, validation and cancellation | Fresh-process pairs, saved-program/input hashes, structural validators and seven default or eleven context-enabled cancellation stages pass. Real Linux/Windows GUI journeys use the shared production path. See [cancellation and desktop](evidence/equate-cancellation-gui.json) and the current hosted review below. |

## Issue 114: optional assembly and p-code context

| Requirement | Implementation and validation evidence |
| --- | --- |
| Bounded triggers and explicit controls | Off/Assembly/P-code/Both modes use native warning, intrinsic and failed-function evidence with documented per-function/export limits and omission markers. Default is off; the GUI remembers explicit choices in the session. See [context policy](evidence/source-context.json). |
| Exact ranges, bytes and architecture/mode information | Existing decoded instructions, actual bytes, body boundaries, language/context registers, delay slots and overrides are observed without modifying the program. Missing bytes or decode evidence produce omissions. ARM mode/literal gaps and both MIPS delay-slot byte orders pass dedicated controls. See [boundary tests](evidence/context-boundaries.json). |
| Source/map composition without fake executable rows | Context uses the same compositor as annotations. Independent address/source-text projections match off-mode, including real intrinsic exports. GDB list/next/step checks pass. See [intrinsics](evidence/intrinsic-context.json). |
| Symbol-only failure and isolation | All-failed and mixed native-decompilation failures retain diagnostics and function symbols without invented signatures or executable rows. A DWARF5 file table permits diagnostic listing from another working directory. Successful neighboring functions retain stepping. See [failed source](evidence/failed-source-context.json). |
| Positive and negative controls | Unmapped warnings, discontiguous/gapped bodies, actual CPUID versus ordinary same-spelled function calls, mode/delay-slot boundaries, budgets, escaping, cancellation and independent deterministic exports are exercised. See the context, intrinsic, boundary and cancellation receipts. |
| Real exporter and debugger behavior | Installed headless and actual Script Manager journeys exercise all four modes, Cancel and retry. Validators, input preservation and native/QEMU GDB pass in the applicable target lanes. The current host/workload gate completes the earlier local-only checkpoints. |

## Current hosted and artifact review

[Integration run 42190916610](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42190916610)
passes all five target lanes (x86-64, AArch64, ARM32 and both MIPS32 byte orders),
native builds, extension/package checks, Windows host and attachment consumers,
and the required aggregate gate. This matrix does not imply every feature case
runs on every target; the harness and receipts retain their exact scopes.

Independent bounded archive review re-parses 2,277 complete passing strict
reports and inspects seventy annotation/context receipts. Original/raw report
bindings, output hashes, cancellation completion, executable source projections
and recorded GDB behavior are checked where supplied. Protected inputs bind to
retained bytes, exact-head sources or the reviewed release package, with zero
unbound paths in these selected receipts. Invalid/self-test receipts are not
counted as passing exports. The final four intrinsic reports are intact; earlier
overwritten-report runs remain failed and archived.

The package review checks 385 manifest entries, both pinned native manifests,
635 Java 21 production classes and 187 production Java source files. The Windows
host archive has three recorded GUI journey completions and LLVM verification.
Its primary harness explicitly does not run independent dwarfdump; this is not
reported as a passed check there. Windows workload strict diagnostics and the
separate Linux GDB consumers supply their own evidence.

[Performance run 42190916484](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42190916484)
also passes. Independent review binds eleven samples per workload, 1,139
unchanged protected inputs, paired DWARF identity, annotation-only source
differences, original unwind bytes and four compiler/Forge GDB traces. The known
U-Boot decompilation timeout remains explicit. These workload observations do
not establish a general time or memory guarantee.

This review is not a local rerun of every hosted test or every Windows attachment
transition. No existing release is replaced. Issue112 unwind synthesis, issue110
LLDB validation and issue109 build-ID installation remain separate incomplete
goal items; the badges remain low priority.
