# Automatic object and return-buffer roles

**CONFIRMED locally; hosted acceptance pending:** a method with both automatic
THIS and return-buffer parameters passes six x86-64/AArch64 exec, PIE and
rebased-PIE cases. The existing exporter already preserves the distinct roles;
this checkpoint adds an interaction regression and API audit, not new production
behavior. Neither umbrella issue is complete.

## Evidence and representation

The installed Ghidra 12.0.3 SoftwareModeling sources define exactly two
`AutoParameterType` values: `THIS` and `RETURN_STORAGE_PTR`. `Parameter` exposes
their kind and `isAutoParameter()`; the general `Variable` interface has no
artificial-variable flag. The audit reads the installed sources rather than
inferring semantics from names, source priority or a decompiler temporary.
Source archive SHA-256:
`ae94f7ede157d57b865eaa7caefd72c9f98bfed04e122db6909dface0bd22748`.
Per-file hashes are retained in `build/object-return-audit/api-audit.json`.

Extraction records both kinds separately for definitions and curated external
declarations. Emission keeps THIS as an artificial formal parameter and makes
`DW_AT_object_pointer` reference that exact child. The return buffer is an
artificial scoped variable, with its pointer type and independently proven
location; it is not an additional formal argument. Class method declarations
retain the same roles without acquiring executable locations. Existing
object-only, external-declaration, hidden-return and genuine-source-failure
tests remain applicable; see `OBJECT-PARAMETERS.md` and
`AGGREGATE-RETURN-CALLS.md`.

An ordinary parameter named `this` or `__return_storage_ptr__` remains an
ordinary formal parameter. No original compiler-generated local identity is
inferred from a name or an undefined/decompiler-only declaration. The current
API evidence supports the two automatic roles above; it does not establish
arbitrary original artificial locals. Inlining has its separate evidence
policy in `ADR-0003-INLINE-EVIDENCE.md` and is not manufactured from a function's
decompiler-inline flag.

## Combined runtime fixture

`object-return.cpp` supplies a `Counter` method returning a 24-byte `Result`.
Ghidra imports both automatic kinds: x86-64 uses RDI/RSI for return buffer/THIS,
while AArch64 uses x8/x0. These are fixture observations, not new generic-code
register assumptions. A separate ordinary function has its two pointer
arguments analyst-renamed to the automatic spellings. Preparation confirms
the original ordinary kinds, saves the exact class/layout binding, and checks
the distinct formal pointee types.

The harness reopens the saved project without analysis or mutation twice.
Both exported models equal the prepared model; output pairs are byte-identical.
Raw DWARF checks require:

- A canonical 24-byte result type and an 8-byte object type.
- A method definition and its class declaration with exactly THIS and amount
  as formal arguments, and a separate artificial return-buffer variable.
- `DW_AT_object_pointer` resolving to THIS, never to the return carrier.
- No locations on class declarations, and actual independently proven carrier
  and object locations on the definition.
- Three ordinary formal parameters on the name-control function, with no
  artificial flags or object-pointer attribute.

GDB observes the two actual incoming machine carriers, the exported pointer
values at entry, THIS/amount after the labeled prologue, the completed return
buffer `{10, 4, 21}`, and the ordinary function's result 42. Compiler and Forge
run the same stripped executable with explicit symbol files. The compiler's
post-prologue parameter locations are not treated as valid at entry. Existing
no-injected-call restrictions for `__thiscall` remain unchanged; executed
returns are observed using the known fixture ABI.

All six roles pass twelve exports and twelve compiler/Forge GDB processes
(24 method/ordinary observations), source lookup, GNU/LLVM/pinned strict
validation, original/module/harness preservation, immutable project data and
deterministic outputs. Ghidra index/journal backup rotation is the only allowed
project-file change. The runtime uses actual Java 21. The tested production
JAR remains
`64c91bc6756cac18b9e471949563839fa53be30c39c2afccbbd3006c5c8ac36d`.
Independent local review receipt SHA-256:
`b90659bd1d755bd61ecbc55a5ff40b2622c774e94586a850d2ed6deebf309d82`
(`build/object-return-audit/acceptance.json`).

## Reproduction

Use the standard Ghidra 12.0.3 packaged installation and the pinned strict
checker from `support/validation/README.md`:

```bash
python3 src/test/integration/object-return-export.py /path/to/packaged-ghidra x86_64 --role exec
python3 src/test/integration/object-return-export.py /path/to/packaged-ghidra aarch64 --role pie-rebased
```

Run exec, PIE and rebased PIE on both targets. CI includes all six roles beside
the existing object-parameter checks. **PRESENT, UNVERIFIED:** the newly added
combined-role workflow still needs its exact-head hosted gate. This does not
broaden artificial-variable, C++ ABI or other-target runtime claims beyond the
documented evidence.
