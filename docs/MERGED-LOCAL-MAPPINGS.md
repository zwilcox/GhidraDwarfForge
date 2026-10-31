# Saved local identities and storage changes

**CONFIRMED locally; hosted acceptance pending:** this component preserves Ghidra's explicit
saved local merge identity and proves locations for its recorded register
definitions. It is part of P1.11a. General inferred locals, memory migration,
stack reuse, additional calls, mixed pieces and all P3.3 requirements remain.

## Identity evidence

Ghidra 12.0.3 `LocalSymbolMap.grabFromFunction` applies its own saved merge
contract: equal typed mappings named `value`, `value$1`, `value$2`, and so on
can belong to one canonical symbol. `HighFunctionDBUtil` preserves that contract
when committing variable changes. The exporter asks Ghidra to construct that
model; it does not infer identity by independently removing a name suffix.
`HighSymbol.getStorage()` exposes only the first mapping. The public
`HighSymbol.encodeMapSym` emits every mapping. A typed encoder captures the
address spaces, storage widths and recorded definition addresses directly,
without reflection, XML parsing or a new native binding.

A source-built x86 probe demonstrates one symbol with a definition in R10D,
a later R11D copy, and a subsequent R11D arithmetic assignment. Saved and
native-decompiled models agree on all three mappings. The native decompiler
also warns that some instance varnodes were optimized away; this is not used
as evidence of an inferred lifetime. A separate all-varnode inspection found
no attached high variables for twelve explicitly curated control-flow fixtures.
Representative varnodes alone cannot establish migration identity.

The new extraction requires every encoded mapping to match exactly one
attached USER_DEFINED local with the same type and full register width. It
retains typed addresses through analysis. Unsupported or ambiguous groups keep
the listing declarations and receive diagnostics where a multi-mapping group
was observed. A stack mapping with no recorded definition address is not
converted into an invented initialization point.

## Latest-value proof

For a recognized group, export one canonical local declaration, as Ghidra does,
and retain the contributing saved names/definitions in diagnostic provenance.
Every mapped definition must be a complete decoded register write. The shared
closed-flow guard rejects incomplete bodies, outside entries, calls, overrides,
opaque effects and unmodeled instruction control. Other variable identities
cannot overlap any participating physical register.

At instruction entry, a location is valid only when every reachable predecessor
agrees on a register holding the current logical value. Completion of each
recorded definition establishes its register and invalidates all previous
carriers. This applies to copies and mutations: an old register that still
contains the previous value must never survive a subsequent assignment as the
current local. Unrecorded writes kill a location. Joins with different carriers
remain unavailable, and body holes receive no location. Each loop visit uses
the latest recorded assignment. Original lexical scope is not inferred.

## Current evidence and remaining acceptance

**CONFIRMED locally:** 64 saved-model checks cover x86-64, AArch64 and both MIPS
byte orders, actual canonical grouping, same-register later mappings, mismatched
types, missing ordinals, unrelated names, uncurated provenance, stack omission,
nonmutation, named typedef preservation and encoder cancellation. Another 248 real x86/AArch64 32/64-bit
instruction checks cover register moves, updates, stale backups, lost current
carriers, divergent joins, loops, offcut assignments, overlapping identities and
one canonical exported declaration. Existing 380 control-flow, 28 definition
and 108 later-local checks pass after factoring the shared physical guard.
These Gradle runs use Java 25. Sixteen suites also pass against the corrected
packaged production JAR on actual Java 21 with class origins verified.

**CONFIRMED diagnostic probe only:** one packaged x86-64 non-PIE case preserves
the named `analyst_count` typedef, emits one canonical local, follows R10D to
R11D and observes the update from 26 to 31. Every instruction is checked in GDB,
including the old-register kill, source lookup, return and process exit. GNU,
LLVM and the pinned strict checker pass; four inherited frame diagnostics match
the original ELF. This single probe does not establish cross-target acceptance.

**CONFIRMED locally:** all six x86-64/AArch64 exec/PIE/rebased-PIE cases pass
12 candidate exports, six previous-package exports and 16,632 compiler/Forge/
previous GDB instruction observations. All 48 calls per variant check both
branch paths, every loop assignment and three signed input pairs. Exactly one
canonical typed local is exported; raw loclists match the independently
labeled machine boundaries and registers. The previous package gives old or
unavailable values at 396 checked updates. Original targets, saved program
mappings and installed modules remain unchanged, repeated output pairs are
byte-identical, and PIE/rebased-PIE normalized instruction/interval evidence
agrees. GNU/LLVM and the pinned strict checker pass; inherited frame diagnostics
are corroborated against the original. The raw review receipt is
`build/merged-local-review/runtime-acceptance.json`.

Controlled decompiler failure and cancellation after 16 MiB are tested with the
packaged exporter. The failure path retains symbol-only output, and cancellation
preserves the original and previous output pair. Both fixture inventories and
workflow lint pass. Required x86-64/AArch64 CI lanes include all three roles;
Linux/Windows include the two new model suites. Exact final packaging and hosted
acceptance remain required before integration.

Reproduction:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew localMappingsSmoke mergedLocalLifetimeSmoke buildExtension
python3 src/test/integration/merged-local-mappings-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/merged-local-mappings-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Use all three roles for both targets and the pinned `DWARFDUMP` described in
`support/validation/README.md`. `--previous-ghidra` optionally compares the
preceding control-flow package. Tested production JAR SHA-256:
`3ddf1c6f31ac491d35333f705422324d72457b8148b306a7f9b3f05a67557762`.
Saved-model checks include both MIPS byte orders; this does not establish MIPS
runtime support for the new merged-local proof.

Retained initial failures: setting the same variable name with a weaker source
does not change Ghidra's provenance, so that negative fixture now uses the
symbol's explicit source setter. Initial test compilation used incorrect model
accessor names; corrected to the existing model API. A named-typedef regression
reproduced a null name-transformer crash in Ghidra encoding; an explicit identity
transformer fixes it. The first typedef probe script path accidentally included
private installation trees; a scripts-only path corrected the curation setup.
The first failure-isolation invocation requested a nonexistent producer soname;
it is retained as a setup failure and the corrected invocation uses the exact
packaged `libdwarfp.so.2.3.2`. The first cross-target C fixture used macro argument names that collided with
assembler label suffixes; renaming those macro parameters fixed compilation.
The corrected package is `candidate-v2.zip`; its diagnostic receipt is
`build/merged-local-review/probe-v2/acceptance.json`. No failed attempt counts
as acceptance. Evidence is under `build/merged-local-review`; research probes
are in the root checkout's `build/lifetime-evidence/merged-locals`.

## Hosted guard correction (2026-10-31)

**CONFIRMED failed hosted gate:** PR99 run `41221918712` stopped at the
architecture-neutrality check. The generic saved-definition address field
`Encoded.pc` matched the guard's prohibited register-name pattern. Renaming it
to `definitionAddress` preserves the model and leaves the guard unchanged.
The guard and its seven negative controls now pass. The three affected model
suites pass 64/248/380 checks; sixteen packaged suites pass on actual Java 21.

**CONFIRMED locally:** the renamed production JAR passes six fresh x86-64/
AArch64 exec/PIE/rebased cases on full JDK 21, with twelve exports and 11,088
compiler/Forge instruction observations. Raw location review, GNU/LLVM/strict
validation, output determinism and input/program/module preservation pass.
This rerun does not repeat the preceding-package comparison; its earlier
396 old/unavailable updates remain separately recorded above. JAR SHA-256:
`62e0a3898d98dccbe9f297a7f2cc2583caac09ac24b2da25bcdc7ea9068879f7`.
Receipt: `1c9b57c9c0fb9843d6f5d121f5ad0ce01ffef613579da4911fcc66ab32dc8c24` in
`build/merged-local-review/architecture-fix/runtime-acceptance.json`.
A fresh exact-head hosted gate remains required; the failed run is not acceptance.
