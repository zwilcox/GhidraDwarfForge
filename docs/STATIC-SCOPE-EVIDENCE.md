# Saved static-object scope evidence

**CONFIRMED provider component; extraction/emission and GDB acceptance pending.**
`GhidraStaticBindings` records an explicit relationship between a current typed
memory label and a current image function, optionally selecting one of that
function's saved lexical blocks. Ghidra 12.0.3 and Java 21 remain the baseline.
This does not change the default exporter yet and does not complete P3.3.

## Evidence contract

The earlier `research/SCOPE-EVIDENCE.md` probe found an imported static under a
plain namespace whose spelling matched a function. That namespace had a distinct
identity; neither its spelling nor a decompiler reference proves original
function ownership. The new provider lets an analyst record the missing
relationship without rewriting the symbol namespace or the original executable.
Ordinary exports still use actual recorded Ghidra relationships where available.
Decompiler-only/inferred ownership requires separate evidence and remains open.

Each record is keyed by the memory symbol's ID in the flat program options group
`GhidraDwarfForge Static Bindings v1`. The bounded `GDFSB1:` envelope stores the
symbol and function IDs, original symbol name/namespace, reversible entry-relative
memory offset, data type ID/path/universal ID when present, data length, explicit
display spelling, optional lexical block ID, lexical evidence fingerprint and
provenance. There is one explicit owner per symbol. An explicit save can replace
an association; read/export paths never write or repair it.

The label must be current, primary, named and backed by complete defined data in
loaded memory. It must belong to the same program and address space as its
owner. An existing Function namespace belonging to a different function rejects
the assertion. Cross-program objects, stale identities and unsupported storage
cannot be bound. Current type contents remain authoritative; changes in type
identity, path or stored size invalidate the record. Function renaming preserves
the same function ID; symbol renaming or namespace changes require reconfirmation.

An empty block means the function's root scope. A nonempty block must exist in a
valid `GhidraLexicalScopes` snapshot. Its complete saved payload is fingerprinted,
so any tree/local-evidence update requires reconfirming the association. The
fingerprint and memory offset remain unchanged by program rebasing. This is a
visibility/ownership assertion, independent of the physical location engine.

Reads distinguish `ABSENT`, `VALID` and `REJECTED`. Rejected explicit evidence must
not become permission to infer a different owner. Export integration must retain
that distinction and diagnose unavailable relationships. The provider's remove
operation is explicit; normal export never removes records.

## Local validation

The ProgramDB test passes 460 checks across x86-64, AArch64, ARM32, MIPS32 big
endian and MIPS32 little endian. It creates actual memory, symbols, data,
functions and discontiguous lexical blocks, then checks:

- A same-named plain namespace does not create implicit ownership.
- Explicit root/block bindings retain actual identities and distinct display names.
- Same-name/address replacement symbols and functions cannot inherit old records.
- Changed types, deleted data, moved symbols, incompatible Function ownership,
  lexical changes and reduced function bodies reject stale evidence.
- Foreign-program objects, malformed/oversized/trailing/versioned records and
  incompatible option types are rejected without mutation.
- Deterministic saves, function renaming, rebasing, cancelled saves/reads/removal,
  explicit removal and immutable database reopen preserve the expected state.

Sixteen suites pass against the packaged production JAR on actual Java 21,
including this provider, the existing 430-check lexical provider, class binding,
class extraction and isolated native producer regressions. Class-load origins
are checked. All 300 preexisting production classes are byte-identical; only
four provider classes were added. This establishes absence of an exporter change,
not acceptance of static-scope DWARF. Linux and Windows CI model lists include
the new task; their hosted results remain pending.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew staticBindingEvidenceSmoke buildExtension
```

Actual Java 21 compile/run commands and logs are retained in
`build/static-binding-review`. Local receipt SHA-256:
`07edff01254ed5e6a88abad4e2929e4b1edb1da7c2452b086dba5b1f295efccd`.
Tested JAR SHA-256:
`0c223706291a551ed8f90c7eec094ebaee5843e229e4a27986bed8502831980c`.
The installed SoftwareModeling source audit includes `Symbol.getID/getProgram`,
`FunctionManager.getFunctionAt/removeFunction`, address arithmetic and typed data;
actual database tests verify identity behavior rather than relying on API names.

## Next integration acceptance

Wire valid bindings into `GhidraTypeGraph` without duplicating the object as a
global. Reject skipped/coalesced lexical evidence and namespace conflicts.
Extend the model/emitter to place statics under the corresponding lexical DIE,
while keeping root statics and genuine decompiler-failure omission intact.
Validate same-name statics in sibling/nested blocks, distinct function-owned
objects and a same-named global. Prove exact values and visibility before,
inside and after blocks on x86-64/AArch64 exec/PIE/rebased PIE, including
negative records, determinism, original preservation, cancellation and all
required host gates. Inspect further decompiler/importer evidence for inferred
and decompiler-only statics; the explicit provider does not complete that row.
All remaining lifetime, class, alias/origin and same-name requirements stay open.
