# Lifetime and scope completion audit

**CONFIRMED incomplete pending final combined acceptance.** The objective remains
all six P1.11a lifetime/storage rows followed by all six P3.3 scope rows in
`LIFETIMES-AND-SCOPES-PLAN.md`. Issues #67 and #73 remain open. Local evidence
now covers the previously identified call-local, caller-memory, independent-piece
and lexical/failure/cancellation compositions. Those implementation gaps are
historical; the remaining acceptance gates below are current.

The combined candidate is `work/local-call-lifetimes`, based on protected main
`dfb5c2e06822fd40e9ae55928318307976a5aded` and including scope PR102. Its full
hosted gate must exercise the final combined source/package. PR102's separate
scope-only run is useful evidence but cannot validate the later call-memory code.
No release publication or umbrella closure is implied by the local checkpoints.

## P1.11a requirement map

| Original requirement | Inspected implementation and local/accepted evidence | Remaining acceptance |
| --- | --- | --- |
| Later-start identity and overwrite boundaries | `RegisterDefinitionFlow`, `MergedLocalLifetime`; `LOCAL-DEFINITION-CONTROL-FLOW.md`, `MERGED-LOCAL-MAPPINGS.md`, `LOCAL-CALL-LIFETIMES.md`. Recorded starts, exact completed definitions, branch/loop agreement, body holes, before-definition and after-loss gaps; calls are no longer rejected wholesale. | Final combined hosted package and raw local-call observations. |
| Register migration and additional call/control-flow shapes | `RegisterCopyLifetime`, inspected `DirectLeafCalls`, `RegisterDefinitionFlow.localSuccessors`; repeated handoffs and closed flow are integrated through PR97–PR101. `LOCAL-CALL-LIFETIMES.md` and `CALL-MEMORY-EFFECTS.md` add saved locals, branches/loops/split bodies, nested inspected calls and physical clobber controls. | Final combined runtime and host/model gate. Unresolved calls retain gaps. |
| Register/stack migration | `StackValueFlow`, `CallMemoryEffects`; `STACK-VALUE-TRANSITIONS.md`, `CALL-MEMORY-EFFECTS.md`, `CALL-MEMORY-BOUNDARIES.md`. Callee-entry-relative writes/releases and exact return SP preserve only proven nonoverlapping slots; actual partial/adjacent writes, unknown pointers/SP and incompatible return SP are exercised. | Final combined package/runtime review and all required lanes. |
| Stack-local identity and reuse | `StackLocalLifetime`, `MergedLocalLifetime`; `STACK-LOCAL-DEFINITIONS.md`, `STACK-LOCAL-EFFECTS.md`, `MUTABLE-STACK-MAPPINGS.md`, `MUTABLE-CALL-MEMORY.md`. Initialization, reuse, updated logical identity, stale slots/register copies and conflicting owners have signed 32/64-bit compiler/GDB controls, including calls. | Final combined raw values and negative-control review. |
| Independently migrating mixed pieces | PR101 accepted `COMPOSITE-VALUE-LIFETIMES.md`; `PIECE-CALL-MEMORY.md` adds twelve runtime configurations with two memory pieces across a safe call and whole-value gaps after losing one half. Exact widths/order, spills/reloads, branches/loops/split bodies and stale pieces remain checked. | Final combined hosted twelve-case matrix and ARM mixed-prefix regressions. |
| Behavioral acceptance | Source-built compiler/Forge fixtures, actual Java 21, GNU/LLVM/pinned strict validation, instruction-boundary values/gaps, immutable programs/originals, deterministic outputs and failure/cancellation receipts exist for each component. `LEXICAL-CALL-LIFETIMES.md` composes the failure paths with the call-containing program. | All final target/host jobs, package/source identity, independent raw review, protected integration and reconciliation below. |

## P3.3 requirement map

| Original requirement | Inspected implementation and local evidence | Remaining acceptance |
| --- | --- | --- |
| Lexical blocks and shadowed locals | `GhidraLexicalScopes`, `LexicalScopeModel`, exporter scope/range intersection; `LEXICAL-SCOPE-EVIDENCE.md`, `LEXICAL-CALL-LIFETIMES.md`. Explicit saved ownership, discontiguous visibility, initialization gaps, stale/coalesced rejection and unwound caller lookup retain the correct identity. | Final combined hosted lexical matrix, genuine failure and cancellation receipts. |
| Namespace/class/method/object relationships | `GhidraClassBindings`, `GhidraClassScopes`, `ClassScopeModel`, identity-bound producer specifications; `CLASS-SCOPE-EMISSION.md`, `OBJECT-PARAMETERS.md`. Actual recorded ownership is separate from layout/type provenance. Cold lookup and rejected-binding controls preserve analyst C11 lookup without fabricated layouts. | Final combined class/object runtime, models, native producer and host review. |
| Thunk/alias specification and origin | `GhidraFunctionRelations`, `FunctionRelations`, producer trampoline/import relationships; `FUNCTION-RELATIONSHIPS.md`. Saved target IDs and accepted aliases reference canonical definitions without borrowed body/source/storage. Unsupported inline origins are not inferred. | Final combined target lanes, including ARM32 unavailable locally, and existing naming/body/source regressions. |
| Static-local scope and identity | `GhidraStaticBindings`, `GhidraStaticRecovery`, same-pass extraction; `STATIC-SCOPE-EVIDENCE.md`, `RECOVERED-STATICS.md`. Saved labels/memory locals and explicit lexical ownership retain curated-type precedence; inferred types do not invent ownership. Negative identity/overlap/stale records and real source failure are covered. | Final combined static/failure/cancellation artifacts and runtime review. |
| Artificial/object parameters | Exact automatic THIS/return-storage kinds and `DW_AT_object_pointer`; `ARTIFICIAL-OBJECT-ROLES.md`. A method with both roles passes six local address configurations, with ordinary-name lookalikes and declaration/failure controls. Other artificial semantics require actual Ghidra identity evidence, not guessed names. | Final combined-role fixture and existing hidden-return/declaration/failure checks on the exact package. |
| Same-name disambiguation | `GhidraTypeGraph`, canonical scope/type IDs and collision-aware lookup; `SAME-NAME-TYPES.md`. Recursive classes, typedefs/enums, analyst category renames and namespace globals pass six local roles. Category paths are not claimed as original namespaces. | Final combined same-name runtime plus existing class/global/function/enumerator collision regressions. |

## Current source and local receipts

The audit rechecked current production code: `inspectBody()` permits decoded
calls and uses inspected summaries; saved register/stack paths consume that
contract. `DirectLeafCalls.Leaf` now carries `CallMemoryEffects.Summary`.
`StackValueFlow` applies call memory writes/releases and exact return SP after
CALL's own raw effects, rather than retaining arbitrary caller memory.
The historical b71bfd9 findings about blanket call rejection and absent memory
summaries are resolved in source and tested; they are not current failures.

The pre-neutrality-correction local production package has JAR SHA-256
`5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`.
At that checkpoint its archive sources matched all 85 production Java files; 318 classfiles
target Java 21 and the prior nine-suite actual-Java-21 receipt matches the JAR.
The latest tests add no production/native changes.

| Local checkpoint | Receipt SHA-256 | Coverage added |
| --- | --- | --- |
| `build/call-memory-review/checkpoint.json` | `4c7a4599ab04b86de1d1e31ec3d9fbe8ede3241f19b843716f548efb729c9219` | Twelve register/stack roles, twelve regressions and nine actual Java 21 suites. |
| `build/call-return-boundaries/checkpoint.json` | `bdb94aee25404fce67a9b5d4ccba07dc870fa7e6b7c66c3529572ae5c943b753` | Six outgoing-control roles, including incompatible returns, and four regressions. |
| `build/mutable-call-review/checkpoint.json` | `6fab4c59b5cd291752cc3423c94ff16b7561e3c9b78578f7724ab5a49a51e199` | Twelve call configurations across both widths/targets and four no-call regressions. |
| `build/piece-call-memory-review/checkpoint.json` | `8e6c4febb307a37ff0a1e2a6a32342f8c3709bdf647d2f7acc1f1bf2d2a891dc` | Twelve aggregate configurations and two predecessor comparisons. |
| `build/lexical-call-review/checkpoint.json` | `73dce963805a7e3940cddcff3c7b4ac3b3de3c6c2a97f31fcb8170745192dc8a` | Six call configurations, 42 exports, six cancellations and two no-call regressions. |

Each component document names the checked-in reproduction commands, evidence,
failed attempts and bounds. These ignored local receipts are not substitute
hosted artifacts. The final accepted source must reproduce the required tests
through the real packaged exporter in CI.

## Outstanding completion gates

- [ ] Run the complete required workflow on the final combined commit. Inspect
  every required job/step, including x86-64/AArch64 runtime, ARM32, both MIPS
  byte orders, Linux/Windows native/model/installed-host checks and GUI evidence.
  Passing a target's existing lane does not imply that all new lifetime proofs
  have equivalent runtime coverage there; preserve documented profile bounds.
- [ ] Download that run's package and diagnostics; match source revision,
  production source archive, Java 21 classes, pinned native identities and
  manifests. Recheck applicable actual-Java-21 packaged suites.
- [ ] Review raw DWARF and compiler/Forge observations against every row above,
  including cold name lookup, current values, stale gaps and scope ownership.
  Confirm original hashes, deterministic reruns, rebases, cleanup and all
  failure/cancellation paths. Explain inherited validator diagnostics using
  unchanged original bytes; do not accept unexplained warnings.
- [ ] Review the final implementation against the original requirements and
  cross-component regressions. Resolve any discovered gap with code and tests;
  a green workflow alone is insufficient for umbrella completion.
- [ ] Integrate through the up-to-date `required-validation` protection and
  normal merge history. Verify the integrated tree is the accepted tree. Do not
  bypass protection. Supersede scope-only PR102 only after combined integration.
- [ ] Reconcile TODO, project context, this audit and issues #67/#73 with the
  actual accepted evidence. Close an umbrella only when every applicable row
  is proven. Release publication is separate.

## Historical failed inventory gate

PR102 run `41253600321` failed all five target lanes at source-fixture inventory,
before scope export. Commit b71bfd9 corrected the explicit list; unknown-file
rejection and deterministic rebuild checks remain. The replacement scope run
`41254453232` is independent of the final combined gate. Neither the failed run
nor unobserved completion of the replacement can count as final acceptance.

## Combined-gate terminology correction

**CONFIRMED failed precompilation gate:** PR103 run `41260845931` rejected the
standalone token `sp` in two generic classes under the architecture-neutrality
scanner. Both variables already came from Ghidra's compiler-spec stack pointer;
there was no named-register lookup or target-specific register number. Rename
those locals to `pointerNode` and expand the comment to “stack pointer”. The
scanner and its audited boundaries remain unchanged; all seven scanner controls
and the real source check pass.

The rebuilt JAR is
`1a0a8471a87407a3cc5b56c7eccbbe441c752168056cca0081174114b645760d`.
Exactly two classfiles differ (`CallMemoryEffects`, `StackValueFlow`); their
`javap -c -p -s` executable disassembly/signatures are byte-identical, and all
other 316 classfiles are byte-identical. The source diff is restricted to local
identifiers and comments. Nine relevant model suites and the extension build
pass, followed by the same nine suites against the rebuilt JAR on actual Java
21 with production class origins checked. Evidence is retained in
`build/combined-acceptance/neutrality/`. Earlier runtime receipts retain their
original package identity; they are not relabeled as tests of the rebuilt JAR.
The corrected commit requires a new complete combined hosted gate.
