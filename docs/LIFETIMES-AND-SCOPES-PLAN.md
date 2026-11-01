# Variable lifetime and scope completion plan

The active user goal is to finish P1.11a, then richer class and lexical scopes
(P3.3). This plan preserves both umbrella issues, #67 and #73. A passing
component does not complete either umbrella. The starting main commit is
`6c37222304c2abd081b2c800f2354afe3b28c5c0`; Ghidra 12.0.3 and Java 21-compatible
bytecode remain the supported baseline. No native ABI change is proposed.

**CONFIRMED implemented, validated and integrated:** all original rows below
have accepted implementation, target and host evidence through PR103 at
`7387a61`, normally merged as `8f6031c`. See `LIFETIME-SCOPE-ACCEPTANCE.md`
and `LIFETIME-SCOPE-COMPLETION-AUDIT.md` for exact receipts and profile bounds.
The original criteria remain unchanged. Subsequent component checkpoints are
historical; their partial/pending status does not supersede final acceptance.
This documentation reconciliation precedes closing issues #67/#73. Release
publication remains separate.

## P1.11a requirements

| Requirement | Starting evidence | Original acceptance criteria |
| --- | --- | --- |
| Later-start variable identity | Curated read-start and definition-start register locals have tested prefixes. | Extend evidence-backed later lifetimes and overwrite boundaries, including discontiguous bodies and additional control flow. Test before definition, every transition and after loss. |
| Register migration | Two incoming copies and one inspected direct-leaf call have bounded accepted proofs. | Compose further copies, then support additional proven call/control-flow shapes. Track value identity rather than register spelling. |
| Register/stack migration | One incoming scalar spill has accepted straight-line evidence. | Extend saves, loads and storage changes only while instruction and selected ABI effects prove the same value. Unknown aliases/calls must terminate the affected fact. |
| Stack-local identity and reuse | Nonzero first-use is currently diagnosed and omitted. | Establish initialization and slot-reuse boundaries for distinct locals. Stale bytes before initialization and after reuse must not become a location. |
| Mixed pieces | Attached incoming register/stack joins have bounded prefixes. | Track independently proven pieces and transitions with exact size/order. Do not present a whole value across a missing or stale piece. |
| Behavioral acceptance | Existing compiler/Forge oracles cover bounded profiles. | Add source-built compiler-oracle fixtures, positive/negative instruction-boundary values, unavailable gaps, real exporter validators, preservation, determinism, cancellation and required target/host CI. |

**HISTORICAL planned sequence:** repeated register handoffs; later-local migration;
stack identity and spill/reload transitions; control-flow joins and
discontiguous bodies; additional inspected call effects; mixed-piece lifetime
composition. The sequence may change when evidence exposes a dependency, but
all rows remain required. Unsupported observations must remain explicit gaps;
the mere existence of a Ghidra high variable is not proof of a compiler lifetime.

## P3.3 requirements after the location core

The initial inferred-static API research and local production evidence remain
in `research/STATIC-RECOVERY.md` and `RECOVERED-STATICS.md`. Final combined
acceptance now covers every original row below; see the acceptance document.

| Requirement | Original acceptance criteria |
| --- | --- |
| Lexical blocks and shadowed locals | Establish scope ownership and defensible address ranges; GDB must select the correct shadowed object without leaking its lifetime. |
| Namespace/class/method/object relationships | Go beyond qualified display strings using actual recorded relationships, while preserving existing analyst lookup and synthetic C source behavior. |
| Thunk/alias specification and origin | Relate only identities established by evidence. Preserve the accepted P1.7 naming, body, type and source ownership rules. |
| Static-local scope and identity | Preserve explicit function-owned statics; extend decompiler/inferred and lexical ownership only with established identity and genuine-failure behavior. |
| Artificial and object parameters | Preserve tested hidden return-storage behavior; add evidence-backed `this` and other artificial semantics without inventing original source facts. |
| Same-name disambiguation | Retain distinct types and variables from different recorded categories/scopes; verify GDB lookup without treating category paths as original namespaces. |

**HISTORICAL initial plan:** inspect saved Ghidra and decompiler APIs for the evidence needed by
each row, implement a scope model with explicit provenance, then validate
lexical, class/object, static and same-name fixtures. If an API lacks required
evidence, record that gap and develop an explicit evidence provider rather
than silently redefining completion as qualified display names alone.

## Historical component: repeated incoming register handoffs

**CONFIRMED locally:** the new decoder fixture fails against the previous
two-backup implementation. Composing the existing exact-copy proof passes
424 checks across x86-64/AArch64, signed 32/64-bit storage, three/four/twelve
handoffs, reused physical registers, lost-value tails and cancellation.
Existing copy, prefix, direct-leaf-call, stack-spill and later-local decoder
suites also pass. These Gradle runs use Java 25. Thirteen suites also pass against the exact
packaged production JAR on actual Java 21, with class origins verified.

**CONFIRMED locally:** all six x86-64/AArch64 exec/PIE/rebased-PIE cases pass
12 candidate exports, six preceding-package comparisons and 2,052 GDB
instruction observations. Independent review rechecks raw location intervals,
original/module/source hashes, deterministic output pairs and actual Java 21
class origins. The old two-copy package becomes unavailable at the third
handoff; the candidate retains the exact signed value through the fourth.
Both targets' existing two-copy exec regressions also pass. GNU/LLVM and the
pinned strict checker pass; inherited compiler-frame diagnostics are matched
to original bytes and diagnostics. Controlled decompiler failure and
cancellation after 16 MiB preserve the original and previous output pair.

**CONFIRMED integrated:** both required runtime lanes and Linux/Windows model
lists pass in PR97 run `41209712240`, with all twelve jobs, exact package/raw
review and both GUI hosts. Normal merge `8d9e980` retains accepted `caa9da00`'s
tree. Receipt: `430f5aa877f6e0f0b638187ad1ccdff1a92d958f30f9bbfb170efba29a7c3b4e`.
P1.11a and P3.3 remain incomplete. PR98's closed-control-flow local component is
in hosted validation. Saved merged-local identity/mutations have local six-role
acceptance; see `docs/MERGED-LOCAL-MAPPINGS.md`. All other requirements above
remain in scope.

Reproduction:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew registerCopyChainSmoke secondRegisterCopySmoke
python3 src/test/integration/second-register-copy-export.py /path/to/private-packaged-ghidra x86_64 --handoffs 4 --role exec
python3 src/test/integration/second-register-copy-export.py /path/to/private-packaged-ghidra aarch64 --handoffs 4 --role pie-rebased
```

Run all three roles on both targets with the pinned `DWARFDUMP` described in
`support/validation/README.md`. Optional `--previous-ghidra` selects the accepted
two-copy package for the four-handoff comparison. Local evidence is retained
under `build/register-copy-chain-review`, including `runtime-acceptance.json`
and the six listed result directories. Tested JAR SHA-256:
`7e8fbb5535ca5ce38e2e9d400766479ee77c446dcd6c2ec0ef9b5ccb6fb6ac7b`.

The initial failed decoder run proves the preceding limit. Initial runtime
setup failures are also retained: a symlinked launcher selected the shared
installation instead of the private package, and the system checker lacked the
pinned consumer fixes. Neither failed attempt is counted among the six passing
cases; the corrected private runtimes and pinned checker are used throughout.

Each composed proof starts at the preceding proven handoff and must agree on
the next physical write boundary. Completed handoffs strictly advance through
the decoded function. No fixed copy-count limit is used; no fact is recovered
after its identity is lost. Calls remain outside the additional-handoff path.
This component does not establish mutable-local, stack, branch or mixed-piece
identity; those requirements remain listed above.

## Current component: stack/register control flow

**CONFIRMED locally; hosted acceptance pending:** closed branches, loops and
body holes now use exact state intersection, repeated-definition retirement
and executed saved-owner boundaries. Twelve runtime cases and 21 actual Java 21
suites pass; see `STACK-CONTROL-FLOW.md` for validators, GDB observations,
negative controls and retained setup failures. Early and self-copies also pass.
Broader inspected calls, mutable stack mapping identity, mixed pieces and every
remaining P3.3 row above remain in scope. PR99's correction has been normally
merged into this development branch; routine hosted integration is still needed.

## Current component: inspected direct-call graphs

**CONFIRMED locally; hosted acceptance pending:** fully decoded call graphs now
cover branches, loops, nesting, recursion and body holes. The 36 runtime cases,
512 new decoder checks and 22 actual Java 21 suites pass; see
`INSPECTED-CALL-GRAPHS.md` for exact evidence and retained failures. Call memory
facts and physically written registers are retired unless separately proved.
Mutable stack mapping identity, mixed pieces and every P3.3 row remain required.

## Integration checkpoint

PR99 is accepted at `d69b0747`, normally merged as `0b76f40a`; run
`41222554336` and exact hosted review pass. The current development branch
normally includes that main merge and all locally tested stack/control-flow/
inspected-call commits. The combined head still needs its own required gate.
No remaining row is removed from either umbrella.

## Current component: saved mutable stack mappings

**CONFIRMED locally; final package/hosted acceptance pending:** explicit stack
identity with later register assignments passes 12 real target/width/address
cases, including branches/loops, stale unsaved slots and conflicting owners.
All 23 actual Java 21 suites pass. See `MUTABLE-STACK-MAPPINGS.md` for provenance,
physical proof boundaries, exact validator/GDB evidence and retained failures.
Mixed-piece migration and every P3.3 requirement remain in scope.

## Current component: independent incoming pieces

**CONFIRMED locally; hosted acceptance pending:** independent pieces pass all
six x86-64/AArch64 address roles, 12 candidate/six previous exports, 8,235 caller
and 72 callee instruction observations, 24 actual Java 21 suites and ten runtime
regressions. Loss, aliases, branches, loops, body holes, call preservation,
validators, original preservation, determinism and cleanup pass. See
`COMPOSITE-VALUE-LIFETIMES.md` for exact bounds and evidence. Final package and
hosted integration gates remain required. Every P3.3 row remains in scope.

## Scope API evidence checkpoint

**CONFIRMED research; implementation pending:** the checked-in probe passes
four headless imports and compiler GDB oracles on both runtime targets.
`research/SCOPE-EVIDENCE.md` records actual class/THIS identities, flattened
shadow locals, lost lexical boundaries and the imported static namespace trap.
Use the explicit saved-program evidence-provider direction plus real Ghidra
relationships; do not infer scopes from first-use, suffixes or qualified names.
All six P3.3 rows and remaining lifetime integration requirements remain open.

## Saved lexical evidence provider checkpoint

**CONFIRMED locally; exporter hookup pending:** `GhidraLexicalScopes` stores
explicit lexical ownership separately from physical location proofs. Five real
language models pass 430 checks, actual Java 21 class origins, persisted/rebased
identity, immutable reopen, stale/malformed records and cancellation. See
`LEXICAL-SCOPE-EVIDENCE.md`. This is the provider component, not emitted lexical
scopes or GDB acceptance. Every P3.3 row and pending lifetime gates remain open.

## Initial lexical emission checkpoint

**CONFIRMED locally; full scope/hosted acceptance pending:** six runtime roles,
twelve exports and 138 GDB instruction observations validate explicit nested
scope lookup, initialization gaps and rebased bounds. Eight actual Java 21
suites and structural validators pass. See `LEXICAL-SCOPE-EVIDENCE.md` for the
precise coverage and remaining discontiguous, negative, failure, package and
hosted gates. Every other P3.3 row and lifetime integration gate remains open.

## Discontiguous lexical and failure checkpoint

**CONFIRMED locally; final package/hosted acceptance pending:** six address roles
pass explicit discontiguous visibility, stale/coalesced records, genuine native
decompiler failure and production copy cancellation. There are 42 candidate
exports, six previous-package comparisons and six cancelled attempts. The native
failure exposed orphan location lists, now removed by sharing emitted-signature
selection. See `LEXICAL-SCOPE-EVIDENCE.md` for exact boundaries and regressions.
This does not complete the pending lifetime integrations or other P3.3 rows.

## Object parameter checkpoint

**CONFIRMED locally; class and hosted acceptance pending:** explicit automatic
THIS metadata survives as a reference to its exact artificial formal parameter.
Six target/address roles pass twelve production exports and compiler/Forge
values, ordinary-name controls, validators and deterministic immutable reopen.
Actual Java 21 isolated producer checks include declaration-only references and
symbol-only failure; hidden-return behavior passes. See `OBJECT-PARAMETERS.md`.
Class-owned method declarations and every other remaining row remain required.

## Class layout and association checkpoint

**CONFIRMED research; implementation pending:** fourteen x86-64/AArch64 layout
cases pass strict validation and actual GDB values. A class-owned declaration
and qualified root definition preserve C11 lookup. Two headless probes establish
that automatic THIS pointee selection can change with category preferences
while class/method identities remain fixed. Separate saved ownership, current
inferred typing and explicit type binding. See `research/CLASS-LAYOUT.md`.
All remaining class/exporter/hosted requirements remain in scope.

## Completion audit

**Current class model checkpoint:** identity-based ownership and separately
evidenced layout bindings pass 51 model checks and ten actual Java 21 suites.
Nonempty graphs survive compiler-default and both MIPS policy copies. See
`CLASS-SCOPE-MODEL.md`. Saved evidence, native class emission and all remaining
scope/hosted requirements are still required; the model alone completes none
of the umbrella rows.

For every row, record implementation/evidence files, exact reviewed source and
package identity, validator results and GDB outcomes, including explicit
negative controls. Require source-built fixtures, unchanged original targets,
deterministic reruns and cancellation/failure cleanup. Pass the existing
up-to-date `required-validation` protection and normally integrate reviewed
changes. Reconcile TODO/context and the corresponding issue only after all
requirements for that umbrella are proven. Release publication is separate.

## Explicit saved class-binding checkpoint

**CONFIRMED explicit class-binding provider; extractor/emitter pending:**
400 real ProgramDB checks across five language profiles pass on actual Java 21,
including identity collisions, stale records, edits, rebasing, immutable reopen
and cancellation. Missing and rejected evidence remain distinct; export reads
do not repair records or infer replacement identity. Eleven Java 21 suites and
four existing producer regressions pass. See `CLASS-BINDINGS.md`. Actual
class extraction/emission and all remaining lifetime/scope rows stay required.

## Saved class extraction checkpoint

**CONFIRMED saved class extraction; native class emission pending:** the
production extractor now retains actual namespace/class/method identities,
addressless external methods and separately evidenced canonical layouts. All
290 real ProgramDB checks across five profiles and twelve actual Java 21 suites
pass, including conflicts, stale records, cancellation, rebasing and immutable
reopen. Four real exports retain GDB values and validate; two previous-package
comparisons are byte-identical. See `CLASS-SCOPE-EXTRACTION.md`. The writer
still needs class declaration/specification emission; no umbrella is complete.

## Native class emission checkpoint

**CONFIRMED local class emission; hosted/full-scope acceptance pending:**
actual saved ownership now emits class declarations and canonical definitions,
with identity-bound method specifications and collision-aware C lookup aliases.
Twelve x86-64/AArch64 target/address/binding cases pass 24 deterministic real
exports, strict validators and compiler-correlated GDB values. Fourteen actual
Java 21 suites and isolated class/failure/collision checks pass. Fresh debugger
queries catch and verify the correction of a lazy-lookup defect missed by the
earlier research query order. See `CLASS-SCOPE-EMISSION.md`; remaining
class controls, lifetime integration and all other scope requirements stay open.

## Rejected class-binding and cancellation checkpoint

**CONFIRMED locally; hosted/full-scope acceptance pending:** twelve real
stale/conflicting binding cases pass 24 deterministic exports and twelve copy
cancellations across both runtime targets and all three address roles. Unbound
classes now remain queryable without a fabricated layout; a fifth isolated
collision case preserves the existing qualified structure and synthetic scope
separately. GDB's incomplete-size presentation and failed test expectations are
recorded in `CLASS-SCOPE-EMISSION.md`. Same-name runtime fixtures, static and
alias/origin relationships and all outstanding integration gates remain open.

## Static-object evidence provider checkpoint

**CONFIRMED provider; extraction/emission and hosted acceptance pending:**
explicit memory-label/function/lexical-block relationships pass 460 ProgramDB
checks across five profiles and sixteen actual Java 21 suites. Identity-based
records survive rebase and reject stale scope, type, symbol and function data.
All 300 existing exporter classes are byte-identical. See
`STATIC-SCOPE-EVIDENCE.md` for the next extractor/model/emitter and GDB matrix;
this provider does not complete inferred statics or any umbrella requirement.

## Lexical-static emission checkpoint

**CONFIRMED locally; hosted/full-scope acceptance pending:** explicit memory
objects retain function/lexical ownership through extraction and native emission.
Six target/address roles pass 66 production exports, six isolated producer
artifacts, six cancellations and 378 GDB observations. Rejected/conflicting and
coalesced scope controls plus genuine decompiler failure retain only surviving
parent/global lookup. Seventeen actual Java 21 suites and existing static,
class/object and discontiguous-local regressions pass. See
`STATIC-SCOPE-EVIDENCE.md`. Inferred/decompiler-only statics, alias/origin,
same-name type/category behavior and outstanding integration/audits remain open.

## Saved function relationship checkpoint

**CONFIRMED locally; hosted/full-scope acceptance pending:** direct saved thunk
identities and accepted analyst aliases have explicit destination references,
without duplicate function ranges or inherited source/storage. The 21 Java 21
suites, 28 isolated artifacts, six thunk roles and 24 alias roles pass; see
`FUNCTION-RELATIONSHIPS.md`. Local ARM runtime is unverified because the
cross-toolchain is unavailable; its hosted gate stays required. Same-name
runtime fixtures, artificial-semantics audit and all pending lifetime/scope
integration requirements remain open.

## Same-name type and qualified global checkpoint

**CONFIRMED local same-name identities; hosted/full-scope acceptance pending:**
six x86-64/AArch64 exec/PIE/rebase roles preserve recursive classes, enums,
typedefs and analyst-renamed category types through immutable saved-program
exports and actual GDB values. Qualified namespace globals now have a canonical
lookup definition and addressless namespace association; collision controls
preserve existing global/function/type/enumerator lookup. See
`docs/SAME-NAME-TYPES.md` for scope, reproduction and remaining gates.
Neither P1.11a nor P3.3 is complete.

## Integrated stack/control-flow/call core

**CONFIRMED integration:** PR100 head `53e182e31f5abe38327f43647b30d502a5372395`
passes all twelve jobs in run `41234746854` and independent exact-package,
raw-runtime and host review. Normal merge `97a50d1a3c826e639e7754cffed9a98c199616a6`
preserves the tested tree. Stack transfers, explicit definitions/reuse,
closed control flow and inspected calls are accepted within their documented
bounds. Receipt: `1c1879493f65c7afe8ffec26cf4ec606a8d4b360033929fb7d634aeb838e6e80`.
See `LIFETIME-CORE-ACCEPTANCE.md`. Earlier pending PR100 notes are historical.
The separate main-push run `41245137186`, mutable-stack/mixed-piece hosted gate
and richer scope work retain their own acceptance requirements. P1.11a and
P3.3 remain incomplete.

## Integrated mutable-stack and independent-piece lifetimes

**CONFIRMED PR101 integration:** exact head
`c8e48213e339dd845abeb9afaafd58a043fdcad4` passes all twelve jobs in run
`41245301749`, independent hosted package/Java 21/raw-runtime/host review,
and normal merge `dfb5c2e06822fd40e9ae55928318307976a5aded` with the same tree.
Eighteen aggregate-piece/mutable-stack roles contribute 10,530 compiler/Forge
instruction observations, with stale-piece/slot, unknown-alias and conflicting
owner controls. ARM mixed prefixes, stack/call regressions and both hosts also
pass their documented checks. See `docs/LIFETIME-CORE-ACCEPTANCE.md` for the
receipt and exact bounds. Earlier pending PR101 component notes are historical;
the separate main-push gate and combined scope acceptance remain distinct.
P1.11a/#67 and P3.3/#73 stay open pending the full requirement audit.
