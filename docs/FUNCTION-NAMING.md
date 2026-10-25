# Function naming policy

**CONFIRMED implementation:** Forge preserves a function's recorded
Ghidra namespace/class path as its analyst-facing display name. For example,
`analysis_left` → `nested` → `curated_same` becomes
`analysis_left::nested::curated_same`. The path comes from actual parent
namespaces, never datatype categories, mangled-name parsing or decompiler text.
Current target acceptance and pending hosted gates are recorded separately in
[VALIDATION.md](VALIDATION.md).

**CONFIRMED locally; class follow-up hosted gate pending (2026-10-25):**
class ancestors now retain the same display treatment as plain namespaces.
This extends current-name preservation, not C++ class or method semantics.

The function remains a `DW_TAG_subprogram` directly under the compilation unit;
only its `DW_AT_name` uses the qualified display. The CU remains truthful C11
for synthetic decompiler source. This policy preserves analyst display
identity; it does not reconstruct original-language namespaces, emit function
namespace parents, or imply full P3.3 scope support. No alias DIE,
`DW_AT_linkage_name` or C++ language substitution is introduced.

`FunctionSymbol.name()` retains the lexical name. An immutable
`namespacePath()` supplies `qualifiedDisplayName()`. Source declaration-line
matching, signatures and variable locations retain their existing lexical
name/address keys; function-owned statics retain their actual owner. Existing
constructors use an empty path, and ordinary global function names are
unchanged. Namespace-global data behavior is also unchanged.

## GDB commands

After loading the original executable and its sidecar, use the complete
display name for a scoped function:

```gdb
break analysis_left::nested::curated_same
ptype 'analysis_left::nested::curated_same'
list 'analysis_left::nested::curated_same'
print &'analysis_left::nested::curated_same'
```

For a function-owned static, with the inferior available, quote the whole
**function** name and append the variable outside the quotes:

```gdb
print 'analysis_left::nested::curated_same'::private_count
print &'analysis_left::nested::curated_same'::private_count
```

The tested C11 lookup rejects the entirely quoted variable path
`'analysis_left::nested::curated_same::private_count'` and the fully unquoted
expression `analysis_left::nested::curated_same::private_count`. The compiler
C++ oracle uses different quoting; its syntax is not the synthetic C11 contract.

No short-name alias is emitted. `break curated_same` can still select a real
global function named `curated_same`; it does not select these scoped
definitions. A scoped function without such a global requires its full display
name. Existing global names and function-local shadowing remain applicable.

## Ambiguity and unsupported scopes

Ghidra permits literal `::` within a name. Forge retains that spelling and the
separate path components. If distinct `(namespace path, lexical name)` pairs
produce the same display string, export fails with an explicit collision
error. For example, a global literal `left::f` conflicts with lexical `f` under
namespace `left`. Same-path/name definitions at different addresses retain the
existing duplicate-name behavior; Forge does not invent a distinguishing name.

Collision checks run during Ghidra extraction and at the public exporter
boundary. The latter preserves existing input/native-file preconditions, then
rejects before ELF parsing or native loading. The negative smoke uses regular
invalid ELF/native files and proves an existing destination and all inputs
remain unchanged with no temporary residue.

Every ancestor must have the recorded `NAMESPACE` or `CLASS` kind. Library or
function scope retains the lexical display with an omitted-scope diagnostic.
Class display paths do not create class DIEs, inheritance, `this` relationships
or original linkage names. Class semantics, thunks, aliases,
distinct linkage names, lexical blocks and qualified namespace-global lookup
remain outside this change. The existing failed-decompilation policy for
function-owned statics is unchanged.

## Class-owned display follow-up

An x86-64/AArch64 baseline probe reproduces a lookup defect: two analyst-curated
class-owned functions and an unrelated global all emit the same lexical
`curated_same`. The two full class names and their private-static expressions
cannot resolve; a bare-name breakpoint selects all three definitions. Compiler
runtime oracles, validators and deterministic repeated exports pass, so a clean
artifact is insufficient. Baseline raw-review receipt SHA-256:
`f21253ed05bd4e796b14471c57f765d45a0162c5ef04b4a743a35f134c6d54f7`.

The bounded correction accepts real Ghidra class ancestors in the existing
immutable display path. Lexical source/signature keys, address normalization,
collision rejection, C11 CU ownership and the producer API remain unchanged.
Literal-name/path collisions still fail before native production. Same-named
overloads within one owner retain the existing duplicate-name behavior.

The real ProgramDB smoke now covers x86-64, AArch64, ARM32 and both MIPS byte
orders: classes containing namespaces, classes inside namespaces, nested
classes, duplicate method names, unchanged global names and rejecting class
display collisions. Three packaged suites pass on actual Java 21 from JAR
`4087b89299fe3e55692455c3577cd54aec33360725f0fe76b2c774dff3396642`;
receipt `7c9aff8fcc570a5b8d1f99efd564f0beef71c380a67511b122283f43bb5c9cc0`.

The existing source-built static-scope fixture gains an explicit class-owner
mode. It creates real class parents, checks the loaded extractor's origin,
exports a saved curated project again read-only, checks input/program/module
preservation, and retains exact single-breakpoint/address/source/prototype and
private-static/global-value assertions. The compiler oracle remains independent;
the names are analyst choices and are not labeled original C++ facts.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew qualifiedFunctionNameSmoke
FORGE_SCOPE_QUALIFIED=1 FORGE_SCOPE_CLASS_NAMES=1 \
    src/test/integration/function-static-scopes-export.sh "$GHIDRA_INSTALL_DIR" \
    x86_64 aarch64 mips32be mips32le
```

Final run `run.fNIwYKQj` passes twelve exec/PIE/rebased cases on these four
targets (24 exports). Raw DIE review confirms exact compiler function and
owned-static addresses, separate full names and retained CU ownership.
Original/module/harness hashes, saved-program preservation and byte-identical
reruns pass. Ordinary and plain-namespace x86 regressions also pass all three
roles. Raw-review receipt SHA-256:
`9758704cc32894d8c311f84689f8ad676521b2075c0eff89bd58b07d8906ddfc`.
Local headless uses Java 25.0.4.1, separately from actual Java 21 focused tests.
ARM32 runtime and native Windows remain required hosted checks; the ARM32
cross-compiler is unavailable locally. Existing compiler frame diagnostics are
corroborated by the strict checker; no unexplained diagnostics are accepted.

The first baseline GDB probe incorrectly expected a missing Python breakpoint
to throw; this GDB instead returns an object with no locations. A second probe
incorrectly equated source breakpoints with function entries despite prologue
skipping. Final assertions require no full-name locations and compare the three
selected function blocks with independently observed compiler entries. Both
unsuccessful transcripts are retained. An initial build command named absent
task `functionScopeSmoke`; corrected actual tasks pass. No pass is claimed for
these unsuccessful checks or for the pending hosted gate.

## External-function omission inventory

**CONFIRMED locally; hosted acceptance pending:** the separate inventory correction
passes the checks below. Ghidra 12.0.3's `getFunctions(true)` excludes external functions. The previous
external/import branch inside that iterator therefore missed genuine external
functions, while the integration check accepted memory-thunk diagnostics alone.
Earlier claims of complete external-function diagnostic coverage were incorrect.

The correction reads `getExternalFunctions()` explicitly. Each external function
receives one `EXTERNAL_IMPORT` skipped row and its diagnostic uses Ghidra's
qualified name, including library scope. Rows retain deterministic name/reason
ordering. An unreferenced function is included, while a typed external data
object stays in the existing external-data declaration path. Distinct functions
are not deduplicated by name; memory thunks remain separate `THUNK` rows even
when several point to one imported function. Diagnostic names describe the
current Ghidra inventory and do not assert original linkage or DWARF scopes.

`functionsSkipped` includes these additional rows; exported/decompiled/function-
signature counts still describe real exported definitions. Existing PARTIAL
status follows the same inventory rules. The correction emits no external
function DIE, fabricated address, variable location or synthetic declaration.
External functions are not selected for decompilation. The saved-program comparison
proves identical old/fixed/repeat `.dbg` and `.dbg.c` bytes, with nine exported,
decompiled and typed definitions unchanged and skipped rows increasing from five
to nine. External signature preservation remains separate consumer-gated work.

The focused check uses real ProgramDB iterators for x86-64, AArch64, ARM32 and
both MIPS byte orders. It also covers duplicate fully qualified names, nested
library scope, unchanged selected types, SUCCESS-to-PARTIAL status, stable report
ordering, and cancellation during collection and diagnostic emission. Actual
Java 21 passes; the prior installed JAR fails the intended missing-inventory
assertion. Five fresh primary ET_EXEC exports pass independent validators and
existing native/QEMU GDB checks. The common fixture creates two unreferenced
USER_DEFINED functions with the same leaf name in different libraries, then
compares the complete API inventory to exact production report rows. Nine
malformed-log/inventory controls reject. See the detailed local record in
`docs/VALIDATION.md`. Final head `296395e` passes all twelve jobs in
`40126794530`, including fifteen primary inventories across five targets and
exec/PIE/no-ID roles, both GUI hosts and 23 native Windows suites. PR #42 merged
as `0d2cbc5`; separate main push `40129499500` remains pending.

## Research basis and evidence

The isolated x86-64 probes used Ghidra 12.0.3 APIs, GNU GDB/gdb-multiarch
`15.1-1ubuntu1~24.04.1`, GCC/G++ `13.3.0-6ubuntu2~24.04.1`, GNU readelf 2.42 and
the pinned libdwarf 2.3.2 producer. These are observed tool versions, not a new
debugger support baseline.

With a C11 CU, ordinary namespace-parented function DIEs passed structural
validation but failed qualified GDB lookup; a bare duplicate-name breakpoint
selected two locations. Putting an already-qualified name under a namespace
also left initial lazy-index type lookup unreliable. CU-owned qualified names
passed initial type/address lookup, separate single-location breakpoints and
runtime returns. Nested probes also preserved owner-static values 37/83,
their distinct compiler addresses, and a separate global value 19. This
isolated evidence did not establish production source mapping or target-wide
acceptance. [DWARF 5 §§2.15 and 3.2.2](https://dwarfstd.org/doc/DWARF5.pdf)
distinguish entity naming from namespace hierarchy; the flat analyst display
is this project's explicit synthetic-name policy.

External-function declarations remain a separate consumer gate. GDB 15.1
failed to expose the prototype from an actual GCC declaration-only DIE even
with library DWARF disabled, leaving a PLT minimal symbol and unknown return
type. The primary upstream
[function-declaration patch discussion](https://sourceware.org/pipermail/gdb-patches/2026-July/228416.html)
describes the same gap. Its inclusion in any newer debugger release was not
established here; a future baseline must pass the compiler oracle first.

The original ignored research is retained under
`/home/ziggy/GhidraDwarfForge-worktrees/reviewed-todo-integration/`:

- `build/function-scope-research/HANDOFF.txt`: full findings and API references.
- `build/function-scope-research/`: tool versions, producer controls and lookup logs.
- `build/function-scope-research/nested-statics/`: nested ownership/runtime oracle.
- `build/external-function-audit/`: compiler declaration, exact command and input hash.

Those records describe their historical research scope. The implemented model,
extraction and collision controls are covered by `qualifiedFunctionNameSmoke`;
the production exporter/GDB matrix remains separately attributable to its
tested commit and artifacts in the validation record.

## Curated external declaration follow-up

**CONFIRMED locally; hosted gate pending:** external functions with non-default
signatures now have separate addressless declaration DIEs. The library/nested
Ghidra display name is retained as a flat metadata name, without claiming a
language namespace or linkage relationship. Definition omission inventory and
its multiplicity remain intact. See
[EXTERNAL-FUNCTION-DECLARATIONS.md](EXTERNAL-FUNCTION-DECLARATIONS.md) for the
current policy and the compiler-confirmed GDB lookup limitation. This
supersedes the earlier unimplemented-declaration status for this bounded slice.
