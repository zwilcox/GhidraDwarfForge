# Recovered static identity and type evidence

**CONFIRMED API research; production recovery remains PLANNED.** Twelve actual
Ghidra 12.0.3/Java 21 decompilations cover six variants on x86-64 and AArch64.
This closes an evidence question for P3.3, not exporter acceptance or either
umbrella issue. Existing explicit lexical-static emission is described in
[`STATIC-SCOPE-EVIDENCE.md`](../STATIC-SCOPE-EVIDENCE.md).

The probe starts with the source-built lexical-statics fixture, its independent
compiler/GDB object addresses and a saved, analyzed stripped program. Each
variant changes only a read-only headless session. The on-disk program, original
executables, production module and probe sources retain their hashes. All nine
project files on each target were unchanged, including optional index backups.

| Variant | Saved ownership | Saved map type | High variable | Explicit binding |
| --- | --- | --- | --- | --- |
| Typed memory label | Actual Function ID | int, four bytes | int, four bytes | VALID |
| Undefined listing | Same actual Function ID | undefined, one byte | int, four bytes | ABSENT |
| Undefined listing with old record | Same actual Function ID | undefined, one byte | int, four bytes | REJECTED |
| Same-spelling plain namespace | Different Namespace ID | undefined, one byte | int, four bytes | ABSENT |
| Deleted label | Dynamic global label | undefined, one byte | int, four bytes | ABSENT |
| Saved memory local | Actual Function ID, Local Var symbol | int, four bytes | int, four bytes | ABSENT |

The last case uses a real `LocalVariableImpl` with memory storage and ANALYSIS
provenance. Both the local and global high-symbol maps refer to its saved symbol
ID. The global map has a generated display name, while the saved symbol and local
map preserve `inferred_static`. Recovery must use saved identity/name rather
than selecting whichever map happens to be iterated first. The current static
extractor handles typed LABEL symbols, so this memory-local representation is
an implementation gap, not a newly supported export.

The local high-symbol map also contains the typed and undefined Function-owned
LABEL symbols. It contains neither the same-spelling namespace case nor the
unowned case. Every global-map observation reports `isGlobal() == true`, even
when the saved parent is a Function. Map membership alone therefore cannot
classify source scope.

## Inspected API behavior

The installed SoftwareModeling source archive and six relevant source entries
are hashed in the receipt. `HighSymbol.getNamespace()` follows the saved symbol
returned by `getSymbol()`; it does not reconstruct an owner from references.
`GlobalSymbolMap.populateSymbol()` constructs a `HighCodeSymbol` from a saved
CodeSymbol using its listing Data. That path does not substitute the supplied
inferred type and size. Consequently, an undefined byte in the listing can
coexist with a four-byte inferred `HighGlobal` access at the same address.

`HighSymbol.getHighVariable()` returns the largest associated high variable,
which may still describe only part of an object. A representative varnode alone
is insufficient to infer a whole-object layout. In these fixtures every instance
matches the four-byte memory access. The undefined cases have offset zero; typed
whole-object cases have offset minus one. Neither value alone proves complete
storage for arbitrary input.

## Recovery decision

**PLANNED:** carry recovered memory-object evidence from the same successful
decompiler pass that supplies synthetic source. Keep saved symbol/function IDs,
actual memory addresses, candidate types and inference provenance separate.

- Actual Function ownership or an already valid explicit binding is required
  for static-local ownership. A single referencing function, qualified name or
  same-spelling Namespace is not sufficient.
- A saved, definite type takes precedence. Infer a replacement only for
  undefined/missing type evidence, with exact storage, size and overlap checks.
  Do not enlarge a candidate across other defined objects or instructions.
- Check all relevant high-variable instances and partial offsets. Reject
  conflicting or incomplete candidates rather than manufacturing a whole type.
- Preserve the saved name/identity when maps disagree about display names. Emit
  one object, without duplicate local/global declarations.
- A REJECTED static binding remains rejected even if decompilation produces a
  plausible type. The distinct ABSENT case permits separately established
  ownership; rejected evidence never falls back to inferred root scope.
- Missing or failed decompilation supplies no inferred type. Retain existing
  symbol-only failure, explicit saved-scope and cancellation behavior.
- Record inference in diagnostics; do not write inferred types back to the
  analyst's saved program or claim original compiler facts.

Production acceptance still requires extraction/model tests and emitted
DWARF/GDB checks for inferred Function-owned labels and memory locals, curated
type precedence, partial/conflicting storage, stale bindings, wrong namespaces,
duplicate maps, failure/cancellation and deterministic reopen. Use both runtime
targets and exec/PIE/rebased-PIE roles. These requirements remain part of P3.3.

## Reproduction and retained evidence

Create one accepted fixture per target using
`src/test/integration/lexical-statics-export.py`, with an installed candidate and
the pinned strict validator. Supply the printed result directories:

```bash
python3 src/test/research/static-recovery/probe.py /path/to/private-ghidra \
    build/static-recovery-probe /path/to/x86-case /path/to/aarch64-case
```

The output directory must be new. The probe checks the existing fixture's input
hashes, uses one worker per project, retains commands/logs/observations and
asserts all six distinctions above. Actual Java 21 is required. It performs no
export and claims no new validator or debugger acceptance.

Local receipt: `build/static-recovery-audit/acceptance.json`, SHA-256
`e85675e54e583f0ff86fe45243699e9e7a64832357e29155a19e5ca6c414ca25`.
The initial `build/static-recovery-review` attempt failed script compilation
because `getNumMapEntries()` does not exist and `getSymbols(name, namespace)`
returns a List. The marker check detected the failure despite the launcher
returning zero. That failed attempt is retained and excluded from passing counts.
The intermediate ten-observation probe established the API shape; the final
twelve-observation probe adds explicit ABSENT/REJECTED separation and recorded
preservation checks.
