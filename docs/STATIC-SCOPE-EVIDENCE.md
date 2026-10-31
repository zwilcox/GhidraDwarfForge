# Saved static-object scope evidence

**CONFIRMED locally; hosted/full-scope acceptance pending.**
`GhidraStaticBindings` records an explicit relationship between a current typed
memory label and a current image function, optionally selecting one of that
function's saved lexical blocks. Ghidra 12.0.3 and Java 21 remain the baseline.
The exporter now consumes valid associations and emits static objects under their
recorded function or lexical block. This does not complete P3.3.

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

## Provider checkpoint validation

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

**HISTORICAL provider-only checkpoint:** sixteen suites passed against the
then-packaged production JAR on actual Java 21,
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

## Extraction and emission acceptance

`GhidraTypeGraph` reads explicit bindings before ordinary static/global selection.
Rejected records are diagnosed and cannot fall back to a global or inferred
owner. A valid block association requires that the lexical tree survived
extraction; skipped or coalesced local evidence cannot move its statics to the
function root. Missing exported owners are also diagnosed. Normalization uses
the existing ELF/Ghidra address model and preserves the original image.

The static model carries its lexical block ID, with an empty ID retaining the
existing function-root behavior. Parameters, locals and statics may shadow names
in parent or sibling blocks, but conflicting declarations within the same block
retire every conflicting static with a diagnostic. This is independent of symbol
iteration order. The native writer uses the actual emitted lexical DIE as the
static's parent and its independently known absolute memory location. The
existing decompiler-failure policy omits statics belonging to a failed function;
it does not recreate a lexical tree or signature for that symbol-only function.
No JNA signatures or native producer calls were added; existing pinned libdwarf
2.3.2 variable, address and lexical DIE operations are reused.

One hundred extraction/model checks pass on five real language profiles. They
cover four shadowed statics plus a separate same-named global, rejected evidence,
missing owners, changed lexical evidence, same-block conflicts,
parameter/local collisions, normalization after rebase and deterministic immutable
reopen. Seventeen suites pass against the exact production JAR on actual Java 21.

Six real x86-64/AArch64 non-PIE, PIE and rebased-PIE roles pass. Each compiles an
independent compiler-DWARF oracle, observes six distinct static/global object
addresses, then tests the isolated producer before importing the stripped ELF
and running the production exporter. GDB selects values `11`, `21`, `31`, `41`,
`51` and `101` through nested/sibling scopes and another function, returning to
the correct parent/global object at every exit. The raw checker validates exact
parents, types, location addresses and range boundaries; malformed parent,
bounds and address controls are rejected.

The six-role control matrix includes corrupted inner bindings, conflicting
inner/sibling names, a valid tree dropped during local coalescing, genuine native
decompiler instruction-limit failure and cancellation after ELF copying starts.
GDB must select only the surviving parent/global declaration. It must never
recover a rejected static's address through fallback ownership. All controls
preserve the original files, saved program and previous successful output pair.
Repeated outputs are byte-identical; reopening the pristine program reproduces
the baseline pair after every disposable mutation.

The reviewed matrix comprises 66 real exports, six isolated producer artifacts,
six cancelled attempts and 378 GDB observations, including the compiler oracle.
GNU/LLVM and the pinned strict checker pass with no unexplained diagnostics.
Six existing function-static roles also pass; the AArch64 inherited frame errors
are corroborated against their unchanged original bytes by the strict checker.
Both targets' class/object and discontiguous lexical-local regressions, including
genuine source failure and cleanup controls, pass. The combined CI-style driver
also passes separately on x86-64. CI runs the six roles and all controls in the
required x86-64/AArch64 lanes; the extraction model runs on both host platforms.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew staticScopeExtractionSmoke buildExtension
python3 src/test/integration/lexical-statics-export.py /path/to/installed-ghidra x86_64 --role exec --controls
python3 src/test/integration/lexical-statics-export.py /path/to/installed-ghidra aarch64 --role pie-rebased --controls
```

Local commands, raw observations and independent review are under
`build/static-emission-review`. Receipt SHA-256:
`b081160372f1bbdac5a56b480d88bc52f771bdc605620174c1d22cd2abff0f05`.
Tested JAR SHA-256:
`40069ab3f114cd4e1a0ee1a7cec30865e0c64e57c80953847f9188df3b8af340`.
These results supersede the provider-only JAR above for exporter behavior.

## Remaining scope

Hosted exact-package/host gates and normal integration remain required. The
provider preserves explicit analyst evidence; inferred and decompiler-only
static ownership still requires defensible evidence from those APIs. Do not
promote a lone reference or matching namespace name into a recovered owner.
Additional same-name type/category fixtures, thunk/alias specification/origin
relationships, remaining class/artificial semantics and the full P1.11a/P3.3
requirement audits remain open. This static component closes no umbrella issue.
