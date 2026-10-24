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
