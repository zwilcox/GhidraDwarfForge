# Lifetime and scope completion audit

**CONFIRMED incomplete.** The active objective remains the full P1.11a lifetime
and storage-migration work followed by P3.3 scope relationships. This audit
does not replace or narrow `LIFETIMES-AND-SCOPES-PLAN.md`. It separates accepted
components from missing composition and validation. Issues #67 and #73 stay
open; PR102 remains a draft pending its combined review.

## Requirement evidence

| Requirement | Current evidence | Outstanding proof or work |
| --- | --- | --- |
| Later-start register identities and overwrite boundaries | Saved read/definition starts, branch/loop agreement and discontiguous ranges have compiler/Forge evidence in `LOCAL-DEFINITION-CONTROL-FLOW.md` and `MERGED-LOCAL-MAPPINGS.md`. | Compose saved-local identities with supported call effects; current local decoders reject calls. |
| Register migration and call effects | Repeated copies and inspected direct-call graphs are integrated through PR97–PR101; see `LIFETIME-CORE-ACCEPTANCE.md`. | Incoming-value preservation does not by itself establish later-local preservation. Reuse exact identity and selected-ABI proofs in the local path. |
| Register/stack transfers and stack reuse | `STACK-VALUE-TRANSITIONS.md`, `STACK-LOCAL-DEFINITIONS.md`, `STACK-LOCAL-EFFECTS.md` and `MUTABLE-STACK-MAPPINGS.md` have accepted instruction-value and stale-slot controls. | Calls currently discard every memory fact. Establish memory/stack effects before retaining a caller slot across a demonstrably nonaliasing call; unknown effects must still retire it. |
| Independently migrating pieces | PR101 validates exact piece order/width, spills/reloads, control flow and whole-value gaps; `COMPOSITE-VALUE-LIFETIMES.md`. | Apply any new call-memory proof to every piece independently. Retaining one piece must not expose a complete composite after another is lost. |
| Lexical blocks and shadowed locals | Explicit saved ownership, stale/coalesced controls, discontiguous visibility, genuine source failure and cancellation pass locally; `LEXICAL-SCOPE-EVIDENCE.md`. | Exact combined PR102 hosted package, runtime and host acceptance. New local-call lifetime changes must preserve these scope intersections. |
| Namespace/class/method relationships | Persistent scope identities, explicit/inferred layout provenance, rejected bindings, canonical specifications and cold lookup have local model/headless/GDB evidence; `CLASS-SCOPE-EMISSION.md`. | Combined hosted acceptance and final cross-component regression review. |
| Thunk/alias relationships | Saved direct target IDs and addressless imports of accepted aliases preserve canonical bodies/source; `FUNCTION-RELATIONSHIPS.md`. | Combined hosted acceptance, including the locally unavailable ARM32 toolchain lane. No unsupported inline origin is inferred. |
| Static-local identity and recovery | Function/lexical bindings, actual saved labels/memory locals, curated-type precedence and same-pass inferred types pass local positive/negative and failure tests; `RECOVERED-STATICS.md`. | Combined hosted acceptance and preservation through final source-failure paths. |
| Artificial/object roles | Exact automatic THIS and return-storage kinds, ordinary-name controls, class declarations and the combined aggregate-return method pass locally; `ARTIFICIAL-OBJECT-ROLES.md`. | Exact-head CI for the new combined-role fixture and final existing hidden-return/declaration/failure regressions. Arbitrary compiler-generated locals lack supporting Ghidra identity evidence and must not be invented. |
| Same-name types and variables | Distinct recursive layouts, typedefs/enums, category-only analyst renames and collision-safe qualified globals pass six local address roles; `SAME-NAME-TYPES.md`. | Combined hosted acceptance. Category paths remain separate from original namespace claims. |
| Validation and integration | PR101 has all twelve exact-head jobs, downloaded-package/Java 21/raw/host review and a normal protected merge; scope components have detailed local receipts. | Finish implementation gaps, exact final package/source identity, all required target/host jobs, raw runtime review, deterministic originals/outputs, cancellation/failure controls, normal integration and final issue/TODO reconciliation. |

## Confirmed call-composition gaps

The audit inspected production source, not just historical TODO wording:

- `RegisterDefinitionFlow.decodedBody()` calls `decodedInstructions(..., false,
  ...)`; its ordered-control check rejects a p-code CALL in that mode.
- `StackLocalLifetime` and both saved register/stack paths in
  `MergedLocalLifetime` use that no-call decoder. The incoming-value call matrix
  does not execute those local proof paths.
- `DirectLeafCalls.Leaf` summarizes physical register nonwrites and selected
  ABI unaffected registers. It has no callee memory/stack-effect summary.
- `StackValueFlow.apply()` explicitly invalidates memory on CALL and removes
  all nonregister or unproven register facts. The behavior is honest but does
  not finish caller-slot survival where a stronger proof can be established.

These are **CONFIRMED implementation limits**, not validator failures. Do not
reinterpret existing successful incoming-register tests as coverage of these
paths. No claim is made that arbitrary aliases or unanalyzed callees are safe.

## Next implementation and acceptance

1. Add a source-built compiler/GDB fixture with an explicitly saved later-local
   definition, register preservation across a fully inspected call, a clobber
   control, branch/loop/body-hole cases and checks before definition/after loss.
   Establish the preceding package's behavior before changing the local path.
2. Compose inspected calls with the local worklist and ownership model, treating
   call-return successors separately from callee entry edges. Require exact
   selected-ABI and physical-effect agreement; retain unknown gaps.
3. Model caller/callee stack and memory effects sufficiently to prove selected
   memory-preserving calls. Do not assume stack direction, call-frame size,
   restored pointer offsets or nonaliasing from a callee name. Include unknown
   stores, passed aliases, partial overlap, released slots and incompatible
   effects as negative controls. Test every supported transition against actual
   machine bytes and GDB values on both primary runtime targets.
4. Revalidate composition for independently tracked pieces and scope-owned
   locals, then complete the remaining target/host/package and normal-integration
   gates. Reconcile the original checklist only after evidence covers it.

PR102's combined scope run can provide useful independent evidence while this
work proceeds. A green scope run alone cannot complete P1.11a or the active goal.
