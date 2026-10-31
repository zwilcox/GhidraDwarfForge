# Variable lifetime and scope completion plan

The active user goal is to finish P1.11a, then richer class and lexical scopes
(P3.3). This plan preserves both umbrella issues, #67 and #73. A passing
component does not complete either umbrella. The starting main commit is
`6c37222304c2abd081b2c800f2354afe3b28c5c0`; Ghidra 12.0.3 and Java 21-compatible
bytecode remain the supported baseline. No native ABI change is proposed.

## P1.11a requirements

| Requirement | Starting evidence | Remaining acceptance |
| --- | --- | --- |
| Later-start variable identity | Curated read-start and definition-start register locals have tested prefixes. | Extend evidence-backed later lifetimes and overwrite boundaries, including discontiguous bodies and additional control flow. Test before definition, every transition and after loss. |
| Register migration | Two incoming copies and one inspected direct-leaf call have bounded accepted proofs. | Compose further copies, then support additional proven call/control-flow shapes. Track value identity rather than register spelling. |
| Register/stack migration | One incoming scalar spill has accepted straight-line evidence. | Extend saves, loads and storage changes only while instruction and selected ABI effects prove the same value. Unknown aliases/calls must terminate the affected fact. |
| Stack-local identity and reuse | Nonzero first-use is currently diagnosed and omitted. | Establish initialization and slot-reuse boundaries for distinct locals. Stale bytes before initialization and after reuse must not become a location. |
| Mixed pieces | Attached incoming register/stack joins have bounded prefixes. | Track independently proven pieces and transitions with exact size/order. Do not present a whole value across a missing or stale piece. |
| Behavioral acceptance | Existing compiler/Forge oracles cover bounded profiles. | Add source-built compiler-oracle fixtures, positive/negative instruction-boundary values, unavailable gaps, real exporter validators, preservation, determinism, cancellation and required target/host CI. |

**PLANNED sequence:** repeated register handoffs; later-local migration;
stack identity and spill/reload transitions; control-flow joins and
discontiguous bodies; additional inspected call effects; mixed-piece lifetime
composition. The sequence may change when evidence exposes a dependency, but
all rows remain required. Unsupported observations must remain explicit gaps;
the mere existence of a Ghidra high variable is not proof of a compiler lifetime.

## P3.3 requirements after the location core

| Requirement | Remaining acceptance |
| --- | --- |
| Lexical blocks and shadowed locals | Establish scope ownership and defensible address ranges; GDB must select the correct shadowed object without leaking its lifetime. |
| Namespace/class/method/object relationships | Go beyond qualified display strings using actual recorded relationships, while preserving existing analyst lookup and synthetic C source behavior. |
| Thunk/alias specification and origin | Relate only identities established by evidence. Preserve the accepted P1.7 naming, body, type and source ownership rules. |
| Static-local scope and identity | Preserve explicit function-owned statics; extend decompiler/inferred and lexical ownership only with established identity and genuine-failure behavior. |
| Artificial and object parameters | Preserve tested hidden return-storage behavior; add evidence-backed `this` and other artificial semantics without inventing original source facts. |
| Same-name disambiguation | Retain distinct types and variables from different recorded categories/scopes; verify GDB lookup without treating category paths as original namespaces. |

**PLANNED:** inspect saved Ghidra and decompiler APIs for the evidence needed by
each row, implement a scope model with explicit provenance, then validate
lexical, class/object, static and same-name fixtures. If an API lacks required
evidence, record that gap and develop an explicit evidence provider rather
than silently redefining completion as qualified display names alone.

## Current component: repeated incoming register handoffs

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

## Completion audit

For every row, record implementation/evidence files, exact reviewed source and
package identity, validator results and GDB outcomes, including explicit
negative controls. Require source-built fixtures, unchanged original targets,
deterministic reruns and cancellation/failure cleanup. Pass the existing
up-to-date `required-validation` protection and normally integrate reviewed
changes. Reconcile TODO/context and the corresponding issue only after all
requirements for that umbrella are proven. Release publication is separate.

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
