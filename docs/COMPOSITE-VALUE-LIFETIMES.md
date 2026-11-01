# Independently migrating incoming pieces

**CONFIRMED integrated through PR101:** all twelve exact-head CI jobs and
independent package, raw runtime and host reviews pass. Normal merge
`dfb5c2e06822fd40e9ae55928318307976a5aded` preserves the tested tree. See
`LIFETIME-CORE-ACCEPTANCE.md` for the acceptance receipt; earlier pending-hosted
notes below are historical. The implementation bounds and full-goal audit
remain unchanged.

**CONFIRMED locally; hosted acceptance pending.** Every piece of an incoming
register/register or register/stack value is tracked independently through the
ordered value-flow engine. The complete attached Ghidra parameter, formal and
storage sizes, exact register slices, stack-space identity, join order and
nonoverlapping carriers are validated before seeding any fact. The exporter
does not manufacture detached scalar parameters to bypass these checks.

Ghidra's significance-ordered join becomes DWARF memory-ordered pieces according
to the program's byte order. Composition intersects the pieces' proven
instruction intervals. Every piece must be available; a surviving half never
becomes a location for the whole object. Body holes remain absent. An existing
valid prefix is retained and only its unavailable intervals are refined.

The shared engine interprets exact affine stack-pointer changes in p-code order
for incoming values. Allocation does not discard a caller's valid incoming
slot. Release retires overlapping slots according to
`CompilerSpec.stackGrowsNegative()`; unknown or partial pointer writes retire
memory facts. Local identity retains its conservative frame-change policy.
Calls invalidate memory and require both selected-ABI preservation and the
fully inspected callee graph before retaining a register fact. No native ABI
change is involved.

## Local acceptance

`CompositeValueFlowSmoke` passes 1,032 checks on actual Java 21 against the built
production JAR. The x86-64/AArch64 models cover 32/64-bit pieces, register/register
and explicit register/stack storage, spills, loads, delayed incoming loads after
allocation, partial writes, unknown and known nonalias stores, released slots,
surviving memory backups and lost halves. Public extraction, detached-identity
rejection, missing instructions and cancellation are checked. ARM32 little- and
big-endian decoder models check piece order with a terminal self-loop. These
models do not establish a new supported runtime profile. All 24 related Java 21
suites pass, with source hashes and loaded class origins recorded.

The dedicated `composite-value-flow.c` fixture supplies two actual compiler-
described scalar arguments. Its curator explicitly groups their observed
storage into one custom `AnalystPair`. This is analyst-defined knowledge, not a
claim about the original C signature or automatic debugger-call compatibility.
The compiler oracle establishes argument values and local-slot coordinates;
GDB checks physical fields, complete aggregate values and original instruction
bytes throughout each execution.

All six x86-64/AArch64 exec/PIE/rebased-PIE cases pass. Each includes nine
functions and eleven invocations: register/register and register/stack inputs,
independent spills and reloads, partial overwrite and stale reload, unknown
aliases, both branch outcomes, repeated loops, a discontiguous function body,
and positive/negative call-preservation cases. The latter distinguish actual
callee preservation plus ABI-unaffected storage from caller-saved storage that
happens to retain its bits in this particular execution.

- Twelve candidate and six preceding-package exports pass structural checks.
- 8,235 caller and 72 callee instruction observations pass across compiler,
  candidate and preceding-package executions. Candidate GDB displays 1,851
  complete values; 1,689 of those are unavailable with the preceding package.
- All 66 stale-first-field controls leave the entire aggregate unavailable even
  though its second field survives. Twelve unknown-alias controls remain
  unavailable despite the original first field physically remaining in memory.
- Independent raw location-list decoding requires both 64-bit pieces, exact
  memory order, expected transition kinds and loss boundaries. No interval
  covers a discontiguous body hole. PIE/rebased-PIE normalized lists agree.
- GNU/LLVM and the pinned strict checker pass. Inherited compiler-frame
  diagnostics are corroborated against original bytes/messages. Target identity,
  build IDs and the non-loadable sidecar layout agree with the original.
- Repeated exports produce byte-identical sidecars and sources. Original inputs,
  module, fixture/harness hashes and saved program observations are preserved.
  Types, source lookup, `next`, `step` and normal exit pass on both targets.

Ten additional runtime regressions pass twenty exports and 6,328 compiler/
candidate observations: mutable stack identities, stack write/alias effects,
closed control flow, scalar spills and nested inspected calls on both targets.
Controlled decompiler failure and cancellation after 16 MiB pass with the
original and prior output pair preserved. Architecture neutrality and seven
negative controls, fixture inventory/reproducibility and workflow lint pass.
Both required target lanes run the new address-role matrix; both host model
lists contain the new suite.

Earlier narrow compiler-copy acceptance remains useful regression evidence:
eight computed/custom exports and 48 GDB observations pass on both targets,
as do their dynamic composite-storage regressions. The compiler-copy harness
now requires the available copied fields rather than its old unavailable tail.
The prefix-only API retains its direct tests; public extraction composes the
stronger physical proof.

Evidence in `build/composite-value-review`:

- `migration-final-acceptance.json`: SHA-256
  `9c121b2a531a0df6a6ead4960933a2285dc58ae563826ce8eebbdb565b91b6d5`.
- `regression-acceptance.json`: SHA-256
  `68c9c706e7e3c7a2a7c9b90317d8a71fd2eba6619a5b5764a171f266ed9e0667`.
- `java21/acceptance.json`: SHA-256
  `e0ee36237b00dcaff49c824d3d24ae6f4ea1638c5485957b1b753d004ecd0498`.
- Tested production JAR: SHA-256
  `e6aa343c10648b2fccd9b290defe5fd389abfe4e050d90fe4fe99c88a6f1939e`.

## Reproduction

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew compositeValueFlowSmoke
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/composite-value-flow-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Run all three roles on both targets with actual Java 21 and the pinned
`DWARFDUMP` described in `support/validation/README.md`. Optional
`--previous-ghidra` compares the preceding package using the same saved program.
Integration requires an exact final package audit and the up-to-date hosted
`required-validation` gate, followed by raw target and host review. This local
component does not complete P1.11a or any P3.3 requirement by itself.

## Retained failures and limits

The initial model failures retain the old stack-allocation loss, old public-
prefix expectation, and a negative test that actually still had a valid incoming
memory backup. The latter now has separate positive and explicitly clobbered
negative cases. ARM `bx lr` remains rejected by the existing ordered control
proof; byte-order models use an actual decoded self-loop instead. Gradle's
initial Java 25 runs remain separate from actual Java 21 acceptance.

The initial runtime harness requested the address of a register-resident
compiler argument. It now observes addresses only for actual stack objects,
and the fixture no longer requests an unused memory operand for register
arguments. A shared readelf parser required whitespace before the attribute
colon and missed `DW_AT_data_member_location`; it now accepts readelf's compact
format. The no-argument C leaf initially lacked an explicit saved ABI; its
compiler-default ABI is now recorded and checked, while the custom aggregate
callers make no default-ABI assertion. The original caller-saved call expectation
was replaced by explicit positive ABI-unaffected and negative caller-saved
cases, without relaxing the producer's proof. The first fixture-inventory
invocation omitted its target argument; the corrected x86-64 invocation passes.
Failed attempts are retained and are not counted among the final six cases.

The real migration matrix establishes two 64-bit fields on the selected
x86-64/AArch64 profiles. Additional widths and byte orders have the model scope
stated above. It does not establish arbitrary piece splitting/reassembly,
restored caller-saved register proofs, mutable composite assignment identities,
or uncertain call-memory nonaliasing. Never infer those locations from this
acceptance. Richer scopes remain in `LIFETIMES-AND-SCOPES-PLAN.md`.
