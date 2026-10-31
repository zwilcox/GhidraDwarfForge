# Scope evidence in Ghidra 12.0.3

**CONFIRMED research; implementation and exporter acceptance pending.** This
investigation supports every P3.3 row in `LIFETIMES-AND-SCOPES-PLAN.md`. It does
not complete P1.11a, replace its hosted gates, or reduce lexical scopes to
qualified names. The baseline remains Ghidra 12.0.3 and Java 21.

## Reproducible observations

`src/test/research/scopes/probe.py` builds one small C++ fixture for x86-64 and
AArch64, checks compiler DWARF with LLVM, and executes both through GDB (QEMU
for AArch64). It imports the compiler binary and a stripped copy into separate
headless projects and records listing/decompiler symbols, their actual owners,
auto-parameter kinds, type identities and typed memory labels. It checks input
and probe-source hashes. It does not call the Forge exporter.

```bash
python3 src/test/research/scopes/probe.py \
    /path/to/ghidra-12.0.3-with-java21 \
    build/scope-evidence-new
```

The output directory must be new. Linux prerequisites are `g++`,
`aarch64-linux-gnu-g++`, their binutils, `llvm-dwarfdump`, `gdb-multiarch`,
`qemu-aarch64-static` and `/usr/aarch64-linux-gnu`. The QEMU oracle uses the
existing private UNIX socket helper. Commands, compiler/Ghidra/GDB logs,
observations, original hashes and installed API source hashes are retained.
This research is separate from CI's production-export acceptance matrix.

**CONFIRMED locally:** `build/scope-evidence-final-2/acceptance.json` passes
four real imports and both compiler GDB oracles on Java 21.0.13. SHA-256:
`f5e9de511d444cb878961d5588bf589cb3ea94874d8450c962d16605c3f9a67c`.

| Evidence | Observed on both targets | Consequence |
| --- | --- | --- |
| Nested shadowed locals | Compiler GDB selects `shadow=11`, then `23`, then `11`, with a smaller nested block range. Ghidra saves `shadow` and `shadow_1` directly under the function; both first-use offsets are zero. Both high-symbol mappings have null first-use addresses. | Listing/high-variable first-use cannot recover the nested lexical end or the original duplicate spelling. Do not strip suffixes or use storage intervals as lexical ranges. |
| Class and namespace | The imported method has an actual `CLASS` owner under a `NAMESPACE`, with persistent symbol IDs. | These relationships are usable evidence; a qualified string alone is not. |
| Object parameter | The method uses `__thiscall` and a parameter explicitly marked `AutoParameterType.THIS`, typed as a pointer to the canonical `Counter` structure. Its database symbol is null. | Read the parameter contract, not a name of `this` or an assumed database symbol. Null symbol identity is valid for automatic parameters. |
| Function static | GDB reads `visits=1`. Ghidra imports a typed memory label beneath a plain `NAMESPACE` called `inspect_scope`, with a different ID from the actual function. | Matching the namespace spelling to the function is insufficient ownership evidence. Existing Function-owned static policy must stay distinct. |
| Same-named types | Two `Same` structures survive with distinct categories and sizes 4 and 8. Global objects reference the respective types. | Preserve canonical type identities. Categories alone do not establish original namespaces. |
| Stripped input | Neither the method name nor these three source types survives default analysis. | Absence of evidence must not manufacture original scopes/classes. Curated evidence needs its own provider. |

Decompiler text also folds the two constants into arithmetic; its display does
not preserve the original nested block. The compiler fixture establishes what
was present before stripping, not an entitlement to inject that knowledge into
ordinary exports.

## Installed API source audit

The probe fingerprints these files from the selected installation's source
ZIPs, in addition to the ZIP hashes themselves:

- `LocalSymbolMap.decodeScope()` in SoftwareModeling reads the local symbol
  table but skips the parent path and address range (lines 290–305).
- `HighFunction.decode()` skips nested scope elements (lines 283–287); its
  comment describes function statics rather than a retained lexical tree.
- `HighSymbol.getNamespace()` uses a matching saved database symbol, if any
  (lines 148–164). `getPCAddress()` returns the first storage mapping address
  (lines 223–232), not a lexical end or tree.
- `GhidraClass` supplies the class namespace kind; it exposes no direct
  datatype association. A matching datatype name/category must not silently
  substitute for that missing relationship.
- `DWARFFunctionImporter.processLexicalBlock()` reads ranges but passes only
  the first range's start offset to its children (Base, lines 475–494).
  `processFuncChildren()` adds local variables to the containing function's
  list (lines 328–363). The observed flattened ownership agrees with this
  code; it is not evidence that the original lexical scopes were absent.

These are specific findings for the installed baseline, not a claim about
all possible Ghidra plugins or future versions.

## Selected implementation direction

**PLANNED:** add a scope model with separate identity, ownership, ranges and
provenance. Preserve the existing location engine: lexical visibility restricts
where an object may be selected; it never proves where its bytes reside.
Do not change the synthetic C11 language contract just to make C++ lookup pass.
Before choosing class/declaration emission, test producer layouts with GDB's
qualified lookup, method type, object pointer and existing alias behavior.

For lexical evidence missing from the selected APIs, implement an explicit
saved-program provider rather than inventing a tree from first-use offsets or
names. The provider must bind records to actual function/local symbol identities
and current types/storage. It needs stable block IDs, parent IDs, provenance,
explicit display names and address sets. Persist ranges in a form that survives
program rebasing; resolve them to Ghidra Address/AddressSet objects before
extraction. A stale record, conflicting owner, cycle, out-of-body range or
unsupported mapping is diagnosed and cannot become an emitted lexical scope.

The provider is an additional way to preserve analyst knowledge, not a required
manual step for ordinary exports and not the only acceptable evidence source.
Existing saved namespace/class/auto-parameter relationships should work directly.
An imported or decompiler-only static still needs a defensible identity/owner
association. The probe's same-name plain namespace must remain a negative
control; future evidence providers must not approve it by spelling alone.

Next implementation acceptance must prove:

1. Nested and discontiguous lexical blocks, shadow selection and unavailable
   values before initialization/after loss; no location leaks across a block.
2. Saved-program persistence/rebase and stale-evidence rejection, with distinct
   same-name objects and no type/category-name deduplication.
3. Actual method/class/object relationships, including explicit `THIS`, while
   retaining the accepted analyst lookup and hidden return-storage behavior.
4. Static ownership and genuine decompiler-failure behavior; preserve explicit
   Function-owned statics while extending defensible inferred associations.
5. Evidence-backed thunk/alias specification or origin relationships without
   borrowing another function's source/body/type ownership.
6. Production exporter validators, GDB values/lookup/stepping, determinism,
   original preservation, cancellation and required target/host gates.

All P3.3 requirements remain open. The probe is a starting fixture and a source
of negative controls, not a substituted definition of completion.

## Retained failed probes

The initial research script assumed every parameter had a database symbol and
failed on the valid automatic `THIS` parameter. The corrected script records
its absent symbol explicitly. A later assertion expected the imported static's
owner to be a Function; actual evidence showed a separate plain namespace.
The failed logs remain under `build/scope-evidence` and
`build/scope-evidence-final`. Neither is counted as passing evidence. The final
probe asserts the observed limitation instead of promoting an invented owner.
