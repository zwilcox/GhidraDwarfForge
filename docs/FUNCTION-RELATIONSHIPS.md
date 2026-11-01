# Saved function relationships

**CONFIRMED locally; hosted/full-scope acceptance pending:** saved direct thunk
identities and accepted analyst aliases now have explicit DWARF relationships.
This addresses the P3.3 thunk/alias relationship row without changing the accepted
P1.7 naming, code-body, type, source or variable-location ownership rules. It does
not complete P1.11a, P3.3, reconstructed inlining, or release acceptance.

## Representation and evidence

A saved Ghidra thunk is a distinct code body, not a second spelling for the
same source-level definition. `GhidraFunctionRelations` reads the current
`Function.getID()` and `getThunkedFunction(false)` identities, retaining the
immediate target rather than collapsing a chain. The target must independently
survive the exported definition or curated external-declaration inventory.
Missing targets are diagnosed; an omitted intermediate cannot be bypassed.
Renames and rebases preserve identity while updating current names and normalized
addresses. No relationship is inferred from names, a decompiler's substituted
text, or a guessed destination address.

`FunctionRelations` rejects self-links, cycles, conflicting IDs, multiple targets
for one origin, same-entry definitions, missing references and excessive graphs.
Its immutable, sorted graph survives all three compiler/MIPS call-policy copies.
The emitter uses `DW_AT_trampoline` to reference the actual destination DIE;
external declarations remain addressless. Failed source generation still leaves
the thunk symbol and relationship, without inheriting a target signature, locals,
source rows or parameter locations. Ordinary accepted thunks retain their own
curated signature and the existing deliberate source-omission policy.

For analyst aliases, the target-specific ELF planner still establishes complete
body ownership, original-code hashes, name uniqueness and target symbol semantics.
Only an accepted supplemental alias acquires a CU-owned
`DW_TAG_imported_declaration`, its current qualified name and `DW_AT_import` to the
canonical function DIE. It has no executable range, type, source or locations of
its own. ELF aliases remain present for existing GDB lookup behavior. Original
ELF aliases are preserved as before; this component does not infer new DWARF
relationships for names rejected by the planner because they already exist in
the original symbol table.

The choices follow [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf), §3.3.9
(trampoline references, including chains) and §3.2.3 (imported/renamed
declarations). `DW_AT_abstract_origin` describes a different relationship and is
not a substitute for a thunk target. Class method declaration/definition
relationships continue using the existing evidence-backed `DW_AT_specification`.
Actual compiler inline-instance origins remain conditional work under
`ADR-0003-INLINE-EVIDENCE.md`; no inline instance is invented here.

No native ABI declaration was added. The existing fixed-width
`dwarf_add_AT_reference_c` mapping and support for `DW_AT_import`/`DW_AT_trampoline`
were checked against the pinned libdwarf 2.3.2 header and producer implementation
(commit `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`, archive SHA-256
`7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`).
New native attributes first passed in an isolated Java 21 process before the
saved-program extractor was exercised through headless Ghidra.

## Local acceptance

The exact production JAR SHA-256 is
`6e23c20c8abfe37899a0218f5643adee88a6f2ee435c12ca4b67c38d23a2a5ab`.
Receipts and retained diagnostics are under
`build/function-relationship-runtime/`; they are local evidence, not committed
binaries or a substitute for the eventual exact-head hosted gate.

- Thirteen graph checks and sixty real ProgramDB extraction checks pass. The
  extraction cases cover x86-64, AArch64, ARM32 and both MIPS byte orders,
  including direct chains, selected/omitted external targets, renames, changed
  targets, rebasing, immutable reopen and cancellation. The existing curated
  thunk suite passes 175 checks. All 21 selected suites pass on actual Java 21
  with production class origins checked.
- The isolated production emitter passes 28 artifacts across x86-64/AArch64
  non-PIE and PIE. The plain/related variants have compiler-correlated GDB
  lookups, one breakpoint per name, exact thunk entry, the same instruction
  transfers, argument 19 and return 39. Additional serialization controls cover
  an addressless external target, failed source generation, wrong body hash,
  wrong owner and original-name collision. External serialization controls do
  not claim that the executable actually transfers to that external function.
- Six saved-program thunk roles pass twelve deterministic exports: non-PIE,
  PIE and rebased PIE on x86-64 and AArch64. Raw references resolve to the exact
  saved destination; GDB retains curated lookup and the thunk's own entry.
  No destination source or parameter location is borrowed.
- Twenty-four alias roles pass on x86-64, AArch64, MIPS32 big-endian and MIPS32
  little-endian: retained/stripped symbols crossed with non-PIE, PIE and rebased
  PIE. These include 96 Forge runtime call observations, source navigation,
  original/analyst names, private variable ownership and return values. Actual
  aliases resolve to exact original-code-backed definitions with one breakpoint.
- The alias oracle independently compares the pre/post-curation DIE trees after
  resolving references and string offsets. The only added declarations are the
  two addressless imports; existing DIEs, line/location/range sections and source
  bytes remain unchanged. An independently invoked ELF writer uses the exported
  DWARF plus compiler-derived symbol records and reproduces the complete artifact
  byte-for-byte. It does not serve as the oracle for the new DWARF relationships.
- GNU inspection, LLVM verification and the pinned strict libdwarf checker pass
  in the relevant harnesses. Original targets, installed modules, harness inputs
  and saved programs retain their recorded hashes, apart from explicitly allowed
  Ghidra journal/index backup rotation. Repeated exports are byte-identical.
- Class/object and discontiguous lexical-scope regressions pass on both runtime
  targets. Their genuine decompiler-failure and production-copy cancellation
  controls preserve the previous complete output pair and original executable.
  These are shared-path regressions, not a claim of every possible thunk-failure
  or chained-thunk runtime scenario.

**PRESENT, UNVERIFIED locally:** ARM32/Thumb runtime relationship behavior. The
local ARM fixture stopped before compilation because `arm-linux-gnueabihf-g++`
is unavailable; unattended sudo is also unavailable. No artifact from that
attempt is accepted. Five-profile model checks do not replace the required
hosted ARM/Thumb/mixed-mode runtime matrix. The workflow retains those lanes,
adds the relationship model suites on Linux/Windows, and runs the isolated
producer controls against the packaged JAR in both x86-64/AArch64 lanes.

**PLANNED acceptance:** review the final combined source/package and all required
hosted target/host checks, including existing sectionless, discontiguous-body,
ARM mode, GUI and preservation gates. Same-name type/category runtime fixtures,
remaining artificial-variable semantics and the full lifetime/scope requirements
audit remain in scope. Neither umbrella issue is closed by this component.

## Reproduction

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew \
    functionRelationsSmoke functionRelationExtractionSmoke curatedThunkSmoke \
    compilerCallPolicySmoke mipsFloatingCallPolicySmoke mipsAggregateCallPolicySmoke \
    buildExtension

python3 src/test/research/function-relationships/probe.py \
    /path/to/private-packaged-ghidra /path/to/jdk21 /path/to/native-linux \
    /path/to/fresh-results --target x86_64 \
    --jar /path/to/private-packaged-ghidra/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar

python3 src/test/integration/curated-thunk-export.py \
    /path/to/private-packaged-ghidra --target aarch64 --role pie-rebased
```

Repeat the isolated probe for AArch64 and the thunk fixture for both targets and
all three roles. Set `DWARFDUMP` to the pinned strict checker. The existing
`retained-function-aliases-export.py` plus `local-symbol-merge-integration.py`
sequence builds the six fresh cases per target; the ARM follow-up uses
`arm-function-aliases.py`. Keep failed attempts and validator/GDB logs.
