# Linkage identity and curated lookup investigation

**CONFIRMED negative local evidence (2026-10-25):** adding a linkage name to
our flat C11 subprogram model can hide the analyst's curated name in GDB.
P1.7/P3.3 remain incomplete. No production binding or exporter behavior changes
follow from this investigation.

## Ghidra identity evidence

Two source-built ELF inputs, x86-64 and AArch64, define a unique C++ function
and another function with a real ELF alias. Debug information is removed before
headless analysis. Ghidra 12.0.3 demangles the definitions to ANALYSIS names,
retaining the original mangled names as secondary IMPORTED labels. Curating
the function names preserves those labels. The aliased entry has two equally
imported labels. A deliberately added analyst label can also carry IMPORTED
source despite having no corresponding original ELF symbol.

The independent review compares every retained imported name and address with
`readelf -sW`, proves the added label is absent from that original table, and
checks unchanged input hashes. SourceType.IMPORTED alone is therefore
insufficient to claim an original linkage identity. Selecting the first label
would arbitrarily choose between legitimate aliases.

Inspection of Ghidra's installed source archives finds that
`ExternalLocation.getOriginalImportedName()` describes external locations.
In-image symbols lack that dedicated original-name field. `DemangledObject`
creates its preferred in-image name with SourceType.ANALYSIS. Label history
is not an unambiguous original-ELF binding either.

## Isolated producer and GDB counterexample

The producer experiment checks the shipped libdwarf 2.3.2 source archive
SHA-256 `7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`,
pinned at `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`.
`libdwarfp.h` lines 362–367 declare `dwarf_add_AT_string_a` as returning int,
with opaque debug/DIE handles, Dwarf_Half attribute, char pointer and two
opaque pointer outputs. The isolated JNA mapping uses pointer wrappers,
Java short, String and PointerByReference. The implementation explicitly
accepts DW_AT_linkage_name. Existing producer declarations remain covered by
`LIBDWARF-ABI.md`; this additional call is never loaded inside Ghidra.

A private copy of the existing standalone producer smoke adds the string
attribute and uses a one-byte symbol-only range at the compiler-observed
function entry. Each target receives two separate-debug artifacts, with and
without DW_AT_linkage_name. Inputs are fully stripped private copies, so
inherited symbol tables cannot conceal missing lookup. Actual Java 21
init/create/attribute/transform/relocation/get-sections/finish completes without
a native crash. GNU, LLVM and strict checks pass; inherited frame diagnostics
are corroborated by the original ELF.

| DWARF attributes | Curated expression | Original linkage expression |
| --- | --- | --- |
| name = `observed::curated_0` | Resolves exact entry | No symbol |
| same name plus linkage_name = `_ZN8observed6uniqueEi` | No symbol | Resolves exact entry |

The expressions are `&'observed::curated_0'` and
`&'_ZN8observed6uniqueEi'`. Both targets show the same regression. A further
experiment adds a CU-owned DW_TAG_imported_declaration with the curated name
and DW_AT_import referring to the linkage-named subprogram. It still fails
curated lookup; GNU/LLVM accept the representation. It is not a solution.
A third experiment adds a second ordinary subprogram DIE with the curated
name at the same range. LLVM rejects the overlapping function ranges on the
first x86-64 artifact, so the experiment stops before GDB and AArch64. That
representation is also rejected; the validator is not relaxed to admit it.

These are symbol-lookup experiments, not runtime stepping or complete type/
variable acceptance, and not a Windows-host claim.

## Retained evidence and remaining work

The root worktree retains `build/linkage-identity-research/` with source-built
`identity.cpp`, `scripts/ObserveLinkageIdentity.java`, command runners, pinned
header/implementation snapshots, experimental `ProbeProducer.java` and the
modified standalone smoke source. Commands and their stdout/stderr remain
with the generated artifacts:

- `run.cebhj2op`: both real Ghidra imports and private program edits.
- `producer.uwlt0vl7`: four strict-checked isolated sidecars and GDB lookups.
- `import-alias/producer.o0md98_m`: unsuccessful import-alias alternative.
- `parallel-alias/producer.0v0tv939`: LLVM-rejected duplicate function range.

Independent metadata receipt SHA-256:
`bfa1dcbe3fa37d719069e4413aed3ac1b2740b543f21663f3a6e9b0b49c2f591`.
Independent isolated-producer receipt SHA-256:
`5ecd21fdfc60c6654b602bf6a4a1a5effd6bc7f9ca10e78f09fe58ffc055fdc1`.
Earlier failed attempts remain: an unversioned library filename was absent,
`info address` did not accept the expression-style quoting, and the initial
positive lookup assertion exposed the real curated-name regression. No failed
attempt is reported as feature acceptance.

**PLANNED:** bind an original ELF symbol's exact name, defined section, type
and normalized address before classifying linkage evidence. Specify duplicate,
alias, truncation, sectionless and rebase behavior. Then prove a consumer policy
that retains curated lookup, source/type lookup and variables as well as the
original identity, without duplicate/ambiguous breakpoints. Unknown linkage
stays absent. Do not infer a linkage name from a datatype category, spelling,
label iteration order or imported-source flag, and do not switch the synthetic
CU language to C++ merely to influence lookup.

## Preserved ELF symbol lookup direction

**CONFIRMED local research:** retaining the original ELF symbol table lets both
x86-64 and AArch64 symbol-only probes resolve the curated and original mangled
expressions to the same entry without `DW_AT_linkage_name`. Fully stripped
controls lose only original-name lookup. Adding the attribute still hides the
curated expression. Actual Java 21 and GNU/LLVM/strict checks pass, with exact
inherited-frame corroboration; receipt SHA-256
`cd967421f3fa0347ed3bd0f05a24b23bf1180853a276b88ace2357372a214aee`.
Evidence is in the root's
`build/linkage-identity-research/retained-symbols/producer.4ehb14p2/`.

The separate [i386 shared profile](../I386-SHARED-PROFILE.md) extends this
direction to real exports, explicit library load bias, typed variables and
runtime/source behavior for three curated global C names alongside their
preserved dynamic symbols. Its local raw review passes; hosted acceptance is
pending. Neither experiment invents missing ELF symbols or establishes arbitrary
C++/alias/namespace semantics. Distinct linkage-attribute emission remains planned.
