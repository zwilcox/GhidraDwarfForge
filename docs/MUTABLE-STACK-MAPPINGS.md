# Saved mutable stack mappings

**CONFIRMED integrated through PR101:** all twelve exact-head CI jobs and
independent package, raw runtime and host reviews pass. Normal merge
`dfb5c2e06822fd40e9ae55928318307976a5aded` preserves the tested tree. See
`LIFETIME-CORE-ACCEPTANCE.md` for the acceptance receipt; earlier pending-hosted
notes below are historical. The implementation bounds and full-goal audit
remain unchanged.

**CONFIRMED locally; final package and hosted acceptance pending.** A saved
stack-backed canonical local can retain its identity through explicitly recorded
register assignments, saves and reloads. The proof handles closed branches and
loops. It omits conflicting owners and unproved storage. This component does not
complete P1.11a or P3.3.

## Evidence and implementation

Ghidra 12.0.3's `SoftwareModeling-src.zip` establishes the saved-symbol contract:
`LocalSymbolMap.grabFromFunction` creates an address-tied map for a stack local,
and `mergeNamedSymbols` can append register mappings to that canonical symbol.
It rejects an address-tied subsequent mapping. Extraction consumes this public
Ghidra result; it does not infer identity from matching names or machine bytes.

The stack map has an empty encoded range list. Its exact canonical listing
symbol supplies a positive first-use address; the physical proof requires a
completed initializing STORE. Register assignments retain their exact encoded
definition addresses. `AddressXML.encodeAttributes` uses
`Address.getUnsignedOffset()`; matching the encoded address now uses that API.
This matters for negative stack offsets in a 32-bit address space.

Each recorded full-register assignment retires previous stack/register copies
and establishes the new logical value only after the instruction completes.
A proven store of that current value may save it to a stack slot; a completed
load may recover it after register loss. Must-state intersection at branches
and loops retains only common carriers of the current logical value. An
unrecorded overwrite or unknown alias retires the identity, including surviving
old register copies. Conflicting nonmember storage owners reject the group
proof; automatic recovery of their ownership boundaries is not established.
Calls remain excluded from this mutable-local path. No native ABI changed.

## Local acceptance

The saved-identity suite passes 80 checks across x86-64, AArch64 and both MIPS32
byte orders. The new physical decoder suite passes 284 checks for signed 32/64
x86-64/AArch64 storage, saved/unsaved updates, unknown/partial writes, offcut
definitions, conflicting owners, public extraction and cancellation. All 23
relevant suites pass against the built production JAR on actual Java 21, with
source hashes and loaded origins checked. Initial Gradle runs use Java 25 and
are recorded separately.

`mutable-stack-mappings.c` retains compiler-described stack and working-register
objects linked by the analyst's explicit saved identity. Five functions cover
saved updates, unsaved stale slots, both branch outcomes, repeated loop updates
and a conflicting saved owner. GDB checks every executed instruction, exact
original bytes, physical storage, compiler object values and candidate logical
values. It verifies the intended branch/loop execution counts. The conflicting
owner leaves the canonical variable unavailable even where physical bits exist.

Twelve cases (two targets, signed 32/64-bit widths, exec/PIE/rebased PIE) pass:

- 24 candidate and 12 preceding-package exports, with byte-identical repeated
  sidecars and synthetic sources.
- 7,560 compiler/candidate/previous instruction observations, including 1,329
  available candidate values, 57 stale-slot controls and 189 owner-conflict
  controls. At 765 checked post-assignment observations, the previous package
  displays stale values or has no location.
- Exact independently decoded DWARF location lists, GNU/LLVM and pinned strict
  validation, matched ELF identity/build IDs and absence of program headers.
  Inherited frame diagnostics are corroborated against original bytes/messages.
- Unchanged original inputs, module and fixture/harness hashes, unchanged saved
  program evidence, and identical normalized PIE/rebased-PIE locations.
- GDB types, source listing, `next`, `step` and normal exit. AArch64 runs under
  QEMU with the same production export path.

Six additional merged-register-local, stack-write/alias and stack-control-flow
runtime regressions pass 12 exports and 8,208 compiler/candidate observations.
Controlled decompiler failure and 16 MiB cancellation pass with the original
and previous pair preserved. Architecture neutrality and seven negative controls,
workflow lint and fixture inventory/reproducibility pass. Both CI target lanes
now invoke all widths/address roles; both host model lists include the new suite.
The exact combined hosted gate still must pass before integration.

Evidence in `build/mutable-stack-review`:

- `runtime-acceptance.json`: SHA-256 `6a379b18ad5c81100fc519ccd60b29a7dade36dbc3123ea6e56e66efaf7cd7a8`.
- `regression-acceptance.json`: SHA-256 `5baf3cd017d9799772eeb88ebd2a789d1b1771cd5a0f886a38a0b763ea5ca7bd`.
- `java21/acceptance.json`: SHA-256 `d8d15719d3221f817404c453866f1adb2b4cf142a55b910d2ba127fcc40cdc4c`.
- Tested production JAR: SHA-256 `ea4bf5c7b2df8cb6c705e53678004e79b6b845f8934d4b8f6587f92a1838ed77`.

## Reproduction

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew localMappingsSmoke mutableStackMappingsSmoke
python3 src/test/integration/mutable-stack-mappings-export.py /path/to/private-packaged-ghidra x86_64 --width 32 --role exec
python3 src/test/integration/mutable-stack-mappings-export.py /path/to/private-packaged-ghidra aarch64 --width 64 --role pie-rebased
```

Run both widths and all three roles on both targets. Select actual Java 21 in
the private installation and the pinned `DWARFDUMP` from
`support/validation/README.md`. Optional `--previous-ghidra` compares the
preceding inspected-call package. The harness first measures compiler stack
storage, saves the canonical stack definition and register assignments, then
observes the saved program without mutation during each export.

## Retained failures and remaining work

Initial model failures demonstrate the old stack-group rejection and the
32-bit signed/unsigned offset mismatch. One diagnostic assertion was updated
when its negative case progressed from unsupported encoding to missing explicit
definition evidence. The first architecture-guard command used the wrong
filename; the corrected shell guard passes. The first failure-isolation attempt
used nonexistent unversioned native filenames; the corrected invocation uses
both packaged `2.3.2` files and passes. Failed attempts remain outside acceptance.

PR100's separate hosted AArch64 gate exposed older semantic-harness expectations
for unavailable parameters; the new scalar spill proof supplies their actual
values. That correction and exact-head hosted validation remain separate from
this component's local acceptance. Independently migrating mixed pieces and
all richer-scope requirements remain in `LIFETIMES-AND-SCOPES-PLAN.md`.
