# Class ownership model

**CONFIRMED model component; saved-program extraction and class emission remain
PLANNED.** `ClassScopeModel` separates namespace/class ownership, method
identity and canonical layout bindings. This implements the model selected
after `research/CLASS-LAYOUT.md`; it does not claim that production exports
already contain class-owned methods.

Scopes retain actual symbol IDs, parent IDs, names and namespace/class kinds.
Methods have their own saved IDs and an exact reference to either an image
function's name/address pair or an external declaration's name/key. External
declarations have no image address. Matching names alone never merges types,
classes or methods. Nested classes are ordered after their parents without
recursive traversal, and output ordering is independent of input list order.

A class/layout binding is separate from ownership. It carries a canonical
structure reference, provenance text and either explicit-saved or
current-automatic-THIS evidence. An inferred binding requires at least one
current object parameter pointing to that structure. Any contradictory object
parameter rejects the model rather than silently changing its type. Explicit
bindings can represent static-only classes without inventing an object
parameter. Qualified and typedef-wrapped pointers/references retain their
canonical object type. A class without a binding still has recorded ownership;
that absence does not establish a byte layout.

Validation rejects missing/cyclic parents, duplicate saved identities,
multiple owners of one canonical type or function, ambiguous/missing function
targets, cyclic object aliases, non-structure bindings and unsupported
inferences without an object witness. Signature lookup uses indexed exact
references rather than scanning all functions for every method.

`ProgramTypeModel` now retains this graph. Existing constructors supply an
empty graph; the Ghidra compiler-default and both MIPS calling-convention
policies preserve nonempty graphs when they copy signatures. The existing
extractor currently uses the empty-compatible constructor. The explicit saved binding provider is implemented and tested separately in
`CLASS-BINDINGS.md`. Collector conflict diagnostics and native class
declaration/specification emission still need implementation and real exporter
tests.

## Validation

`ClassScopeModelSmoke` passes 51 checks, including distinct same-named types,
nested classes, external methods, explicit/inferred binding conflicts, sixteen
input-order permutations and a 4,096-level ownership chain. The three existing
call-policy suites now use nonempty class graphs and verify that policy copies
retain them. They exercise six language profiles, both MIPS byte orders and
their existing ABI/cancellation cases.

Ten relevant suites pass on actual Java 21 against the production JAR, with
class origins checked. The isolated lexical and object-parameter producer
fixtures, including their symbol-only failure variants, pass GNU/LLVM/pinned
strict validation. These are regressions of existing emission, not class
emission acceptance. The new model task is included in both host CI lists;
its hosted gate is pending.

Both x86-64 and AArch64 real object-parameter regressions pass four candidate
exports, validators and compiler/Forge GDB values. Two previous-package exports
of those same saved projects to the same destinations produce byte-identical
sidecar/source pairs. This confirms the existing empty-class-model path retains
its output; it is not a substitute for future class-owned emission tests.

Local receipt: `build/class-model-review/acceptance.json`, SHA-256
`6b8a5beeff9c309f3b980eaa6c41419047916f6798003bae0e1d9d3d48f863e2`.
Tested JAR SHA-256:
`7f318dc1be6d962e4d8156ffef3e57d9d861a49ceadf6b13421d41ddce494c8a`.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew classScopeModelSmoke compilerCallPolicySmoke mipsFloatingCallPolicySmoke mipsAggregateCallPolicySmoke
```

Local commands, logs and receipts are retained under `build/class-model-review`.
The initial Java 21 class-origin audit correctly stopped when the three policy
tests began using the new shared test fixture. Its explicit test-helper
allowlist was updated; production classes must still load from the tested JAR.
That initial failed audit remains under `initial-origin-check` and is not
counted as acceptance.

Next: connect actual saved ownership and separately evidenced type bindings,
validate immutable reopen/rebase/stale/conflicting records, then implement the
tested class-owned declaration and qualified root definition layout. Class
values and lookup need independent native/real-exporter GDB acceptance. All
remaining rows in `LIFETIMES-AND-SCOPES-PLAN.md` stay in scope.
