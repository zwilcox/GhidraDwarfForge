# Recovered static types and saved memory locals

**CONFIRMED locally; hosted/full-scope acceptance pending.** The production
exporter now carries inferred memory-object types from its successful decompiler
pass, and preserves saved function-owned memory locals as static declarations.
This extends the explicit lexical-static component without treating a reference
or namespace spelling as ownership. The API evidence and its limitations are
recorded in [`research/STATIC-RECOVERY.md`](research/STATIC-RECOVERY.md).

`GhidraStaticRecovery` examines all associated high variables found in memory
spaces, instead of relying on `HighSymbol.getHighVariable()`'s largest partial
object. Every candidate must have a definite, matching type and size, a complete
set of same-address/same-size instances, and whole-object or zero-offset access.
The saved symbol must belong to the actual decompiled Function ID. The pass
records symbol ID, owner ID, name, source, Ghidra address and inferred type;
ELF address normalization remains at extraction. No native/JNA ABI or producer
operation was added.

Extraction rechecks current identity, exact memory-local width where applicable,
loaded memory extent, overlapping defined listing content and intervening saved
symbols. It never applies inferred Data to the saved program. Defined listing
objects and definite saved variable types retain precedence. An explicit static
binding that is rejected cannot be replaced by inferred ownership or typing.
Same-spelling plain namespaces and dynamic unowned globals remain ineligible.
Inference is identified in diagnostics and model provenance, not presented as
original compiler information.

Saved single-memory-location locals with zero first-use offset retain their
actual function identity and, when present, valid saved lexical ownership and
display names. They become one static object with an absolute normalized memory
address; the temporary local-model entry is removed before publication. Stale
or dropped lexical evidence omits these statics instead of moving them to the
function root. Unsupported first-use/storage/identity cases are omitted. The
existing same-scope conflict policy and symbol-only decompiler-failure policy
apply to both recovered labels and saved memory locals.

## Local acceptance

Seventy new real ProgramDB checks pass across x86-64, AArch64, ARM32, MIPS32BE
and MIPS32LE language profiles, together with the existing hundred lexical-static
extraction checks. They exercise missing/stale recovery, saved type precedence,
overlapping objects/symbols, namespace collisions, lexical memory-local ownership,
single-declaration behavior and cancellation. Eighteen suites compile and run
against the exact production JAR on actual Java 21, with loaded-class origins
checked. Model coverage on five profiles does not claim new inferred-static
runtime support on all five targets.

The runtime matrix covers x86-64 and AArch64 non-PIE, PIE and rebased PIE:

- Undefined Function-owned memory labels recover the independently observed
  integer type and correct value/address from actual decompilation.
- Five saved memory locals retain nested/sibling/function visibility, selecting
  `11`, `21`, `31`, `41`, `51` and the distinct global `101` at all nine markers.
- Stale explicit bindings, same-name plain namespaces and overlapping defined
  data leave the rejected function static absent; GDB sees the surviving global.
- An analyst-defined unsigned type remains unsigned despite recovery evidence.
- A renamed memory local invalidates its lexical binding; GDB sees only valid
  surviving owners. A genuine native instruction-limit failure leaves its
  function symbol-only and omits its statics without affecting the next function.
- Cancellation during copying of a separately imported padded fixture preserves
  the prior output pair, original bytes and saved program, with no temporary
  publication residue.

The matrix comprises 96 real exports, 432 GDB observations and six cancelled
attempts. Every completed variant is exported twice with identical output-pair
hashes. GNU/LLVM and the pinned strict checker pass without unexplained errors.
Raw DIE checks establish exact type, parent, range and address, and reject
duplicate local/global declarations at the same fixture object address. GDB
values/types/addresses are compared with the original source-built compiler
oracle. Independent review rereads actual artifacts and recorded observations,
checks protected input/module hashes and validates all six target/address roles.
Existing class/object and discontiguous lexical-local regressions, including
genuine failure and cancellation, pass on both runtime targets.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew staticRecoverySmoke staticScopeExtractionSmoke buildExtension
python3 src/test/integration/lexical-statics-export.py /path/to/installed-ghidra x86_64 --role exec --controls --recovered
python3 src/test/integration/lexical-statics-export.py /path/to/installed-ghidra aarch64 --role pie-rebased --controls --recovered
```

Run all three address roles on both targets with the pinned `DWARFDUMP`. To use
an existing accepted lexical-static fixture, pass its printed result directory
to `recovered-statics-export.py <case> <ghidra>`, then run it with
`--controls-only`. Both target CI lanes include these commands; the new model
suite is in Linux and Windows host task lists. Workflow lint passes.

Local evidence is under `build/static-recovery-runtime`. Reviewed receipt:
`093b5561da2d50994b0eab22d90f29ea6cdf753ec2ac6011053bde4a7d32631d`.
Tested production JAR:
`3575449356c0286b3588ca2780ba59ab3616b1f76abafc98cf6dcee51b57ecd9`.
Actual Java 21 receipt:
`194629d48d720b6004f99ee646eacaaa001cccf2ce4e1d43ee37c856c1239239`.

Retained failed attempts are excluded from these counts: the model test used
the wrong record accessor, its cancellation monitor initially disabled
cancellation, and the first runtime harness copied executable bytes without
preserving execute permission. The corrected tests pass. The independent
review also handled the positive receipt's older schema, which predated the
explicit zero-cancellation count; no result file was rewritten to claim a pass.

## Remaining acceptance

This is local component acceptance, not a completed P3.3 or P1.11a umbrella.
Exact hosted package/host validation and normal integration remain required.
Thunk/alias specification and origin, same-name type/category runtime fixtures,
remaining class/artificial semantics and full requirement audits remain open.
When no saved or explicit owner exists, these APIs do not establish a static
scope; the exporter must continue to preserve that uncertainty.
