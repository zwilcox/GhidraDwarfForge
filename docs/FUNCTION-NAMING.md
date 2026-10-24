# Function naming policy

**CONFIRMED implementation:** Forge preserves a function's recorded plain
Ghidra `Namespace` path as its analyst-facing display name. For example,
`analysis_left` → `nested` → `curated_same` becomes
`analysis_left::nested::curated_same`. The path comes from actual parent
namespaces, never datatype categories, mangled-name parsing or decompiler text.
Current target acceptance and pending hosted gates are recorded separately in
[VALIDATION.md](VALIDATION.md).

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

Every ancestor must be a plain `Namespace`. A class, library or function scope
causes the existing lexical display to be retained with an omitted-scope
diagnostic. Class semantics, external-function declarations, thunks, aliases,
distinct linkage names, lexical blocks and qualified namespace-global lookup
remain outside this change. The existing failed-decompilation policy for
function-owned statics is unchanged.

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
`docs/VALIDATION.md`; PIE/no-ID and both-host hosted acceptance remain required.

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
