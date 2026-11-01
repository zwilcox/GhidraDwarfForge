# Lifetime and scope acceptance

**CONFIRMED implemented, validated and integrated.** PR #103 merged normally as
`8f6031c92496550e733b59f8589ce7f3e5428e8a` after all twelve exact-head CI jobs
and independent source/package/target/host reviews passed. Its tree is identical
to tested candidate `7387a61dd79c6753998c9c89271a42ed295f6ac4`.

The scope is all six P1.11a lifetime/storage requirements followed by all six
P3.3 scope requirements in `LIFETIMES-AND-SCOPES-PLAN.md`, tracked by issues
#67 and #73. Issue closure follows integration of this documentation reconciliation. Release
publication is separate from feature acceptance.

## Accepted source and independent evidence

- Candidate: `7387a61dd79c6753998c9c89271a42ed295f6ac4`, PR #103.
- Required workflow: [run 41261018738](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41261018738).
- Supported host baseline remains Ghidra 12.0.3 and Java 21-compatible bytecode.
- Tested production JAR SHA-256:
  `72bf198b807dd5877f1ced4b2395de1077657bf0c3b864ca6fda192103839ce5`.
- Exact package review:
  `19792896dfb81d1e803541a0f74f09a5d488046f6034fa8eb483bf5dc48896c2`.
- Combined target/raw review:
  `32b1c1af783bad9e42bd83344886f5c14a51259393e47690b6ef746c3d4fb9d8`.
- Original twelve-row target evidence audit:
  `eeb6e24459186451b243a2b54777999d19ed57d33b62a9f00fb8993290213bff`.

The package's source archive matches all 85 production Java sources. Its 318
classes target Java 21. All 48 selected suites pass against the exact packaged
JAR on an actual Java 21 runtime, with production class origins checked. Nine
isolated native-producer artifacts pass GNU, LLVM and the pinned strict
validator. The pinned native ABI and producer signatures are unchanged.

All five target lanes pass: x86-64, AArch64, ARM32, MIPS32 big-endian and MIPS32
little-endian. New lifetime runtime claims are limited to the explicitly
tested x86-64/AArch64 profiles. Existing ARM/MIPS acceptance does not imply
equivalent coverage of every new lifetime proof.

## Original requirement evidence

| Requirement | Implementation and observed behavior | Reviewed evidence |
| --- | --- | --- |
| Later-start identity | Saved definitions and assignments establish identity; joins and discontiguous bodies retain before-definition and after-loss gaps. | Call-local, mutable migration and excluded-body controls. |
| Register migration | Successive copies compose through decoded call/control-flow graphs only when ABI declarations and physical writes justify survival. | Call-local and inspected-call matrices, including branching, loops, recursion, nesting, body holes and clobber controls. |
| Register/stack migration | Callee-relative memory effects and exact return stack state preserve proven slots; unknown writes, partial overlap, releases and incompatible returns retire affected facts. | Call-local, stack transition and migration matrices; actual bytes and compiler/Forge values at boundaries. |
| Stack-local identity/reuse | Initialization and explicit assignment changes govern the logical owner; stale slots, stale register copies and conflicting owners do not become locations. | Mutable-stack and stack-local matrices, signed 32/64-bit values and negative controls. |
| Independent mixed pieces | Each piece has its own proven location and lifetime; losing one piece makes the whole value unavailable. | Twelve aggregate configurations, including two pieces in memory across safe calls; x86/AArch prefix and ARM mixed-prefix regressions. |
| Behavioral acceptance | Real packaged exports have validator, debugger, preservation, deterministic repeat and genuine failure/cancellation evidence. | All target reviews and package/Java 21/native receipts; Windows host review and protected integration also pass. |
| Lexical ownership/shadowing | Saved scope identities and defensible ranges restrict existing storage proofs; scope metadata does not invent availability. | Eighteen lexical configurations, discontiguous visibility, unwound caller lookup, rejected bindings and failure/cancellation. |
| Class/method/object relationships | Recorded class/layout identities and declaration/specification references preserve class and method lookup without borrowing unsupported layouts. | Twenty-four class configurations, object-role interactions, cold lookups, rejected bindings and failed methods. |
| Thunk/alias relationships | Proven identities reference canonical definitions through imports or supported thunk relationships; body, source and storage ownership remain separate. | Applicable alias, thunk and sectionless matrices across all five targets; isolated relationship and collision controls. |
| Static identity and scope | Explicit and same-pass recovered statics retain identity, curated type precedence and lexical ownership; real source failure does not restore unsupported children. | Eighteen explicit/recovered/control configurations, raw parent/address checks, GDB values and failure/cancellation. |
| Artificial/object roles | Actual Ghidra THIS and RETURN_STORAGE_PTR kinds remain distinct; ordinary parameters with similar names remain ordinary. | Twelve combined-role/same-name configurations plus existing object, hidden-return, declaration and failure checks. |
| Same-name disambiguation | Canonical type identities and actual scopes distinguish recursive types and variables; category paths are not fabricated original namespaces. | Same-name runtime matrix and isolated namespace/global/type/function/enumerator collision checks. |

The counts above describe fixture configurations, not independent suites.
The combined raw review includes 18 call-local cases, 36 migration cases,
18 lexical cases, 12 type/object-identity cases, 18 static cases, 24 class
cases and six isolated scope configurations. Additional inherited reviews
cover 36 inspected-call cases, six excluded-body controls and 42 stack cases.

## Meaning and limits

The generated C remains synthetic decompiler output. Exported identities and
locations describe current Ghidra knowledge; they are not claims to recovered
original compiler facts. Unresolved calls, unknown aliases, unproven stack
restoration, conflicting owners and missing pieces retain unavailable gaps.
The feature does not infer arbitrary original artificial locals or inline
instances from names or decompiler display flags. Automatic object roles are
limited by the actual Ghidra API evidence documented in
`ARTIFICIAL-OBJECT-ROLES.md` and `ADR-0003-INLINE-EVIDENCE.md`.

Tests run the real exporter against source-built fixtures and compare debugger
values with the compiler reference at relevant instructions. Raw locations,
scope/type references, cold lookup and rebases are independently reviewed.
Default exports preserve original inputs and saved project contents; only
documented Ghidra index/journal backup rotation is allowed. Repeated exports
must produce identical artifact/source pairs. Failure and cancellation tests
verify the previous output pair survives and temporary output does not remain.
Inherited compiler-frame validator diagnostics are accepted only when matched
to unchanged original bytes and diagnostics, not merely because CI is green.

## Reproduction and retained evidence

The authoritative final commands are the exact candidate's
`.github/workflows/ci.yml` and checked-in integration harnesses. In particular:

- `src/test/integration/local-call-lifetimes-export.py`
- `src/test/integration/mutable-stack-mappings-export.py`
- `src/test/integration/composite-value-flow-export.py`
- `src/test/integration/lexical-shadow-export.py`
- `src/test/integration/object-parameter-export.py`
- `src/test/integration/object-return-export.py`
- `src/test/integration/same-name-types-export.py`
- `src/test/integration/lexical-statics-export.py`
- `src/test/integration/recovered-statics-export.py`
- `src/test/integration/namespace-globals-native.py`

Use the standard packaged Ghidra 12.0.3 installation, actual Java 21, the pinned
`DWARFDUMP`, and all workflow-selected target/address/control variants. Running
one default fixture invocation is not equivalent to the complete matrix.
The workflow retains target artifacts, compiler/Forge GDB observations,
prepared models, raw DWARF checks, preservation hashes and failure diagnostics.
Local independent review receipts are retained under
`build/combined-acceptance/`; their SHA-256 identities above distinguish them
from the public workflow artifacts and earlier component checkpoints.

## Host and integration acceptance

All twelve jobs in run `41261018738` pass, including the required
`required-validation` check. Windows independently passes 43 overlapping
lifetime/scope model suites, isolated producer, headless export, file-lock
publication rollback, Script Manager discovery/export/cancellation and clean
installed-package export. Downloaded Windows ELF artifacts pass LLVM and the
pinned strict checker on Linux. The standalone strict checker is unavailable
on the Windows runner, and Linux ELF runtime GDB checks run on Linux/QEMU;
neither is misreported as a Windows-host runtime check.

Both Linux and Windows GUI screenshots were inspected: installed script
selection/descriptions, the chosen output directory, export result/hash/count
presentation and cancellation are correct. A structured PARTIAL report for
uncertain omitted locations is expected, independently of successful artifact
publication. The reports do not claim every variable has a recovered location.

Host review receipt:
`4c3918ff915788c67ab1ed1c7ed71b8b4a8e744ad12101f9e37c4b804afe7df7`.
Final premerge acceptance receipt:
`0da7787cea81a074d1cb6a27e051e769499322f96d4f7ddb1fc4fb5dcd4cff43`.
The protected merge preserves tree
`0bc209ff7f63228e77fe3c6d7e6b77d05af95c58` and both normal parents. Strict
up-to-date `required-validation` and administrator enforcement remained enabled;
no administrative bypass or history rewrite was used. GitHub automatically
marked ancestor scope PR #102 merged as part of this integration; there was no
separate scope-only merge.

This acceptance is tied to the exact source, package and workflow above.
Separate main-push and documentation-only workflow runs retain their own
identities; they do not relabel the original acceptance receipts. This
reconciliation changes no production code, fixtures, workflow, native ABI or
support-profile boundaries. Historical component documents retain their original
receipts, failed attempts and then-current remaining-work lists; this acceptance
and `LIFETIME-SCOPE-COMPLETION-AUDIT.md` supersede those status lists.
