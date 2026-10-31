# Class declarations and canonical layout emission

**CONFIRMED locally; full scope and hosted acceptance pending.** The native
writer now emits the recorded class graph from `GhidraClassScopes`. Ghidra
12.0.3, Java 21 bytecode, DWARF 5 and synthetic C11 remain the baseline.
No native ABI or binding declaration changes are introduced. The existing
producer calls and `DW_AT_specification` were checked against pinned libdwarf
2.3.2, source commit `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`.

## Emission and lookup contract

Actual namespace/class ancestors own class declarations. Each bound canonical
structure definition remains at compilation-unit scope and references its
recorded declaration through `DW_AT_specification`. Its existing type identity,
name, members and byte size are populated once. An unbound class retains only
a declaration, without an invented layout or byte size. Nested classes retain
their actual parent declaration.

Saved method identities select class-owned leaf declarations. Existing
qualified function definitions reference those declarations and retain their
own executable ranges, source and location data. Curated external methods
stay addressless. Return and formal types, supported calling-convention
restrictions, artificial parameters and exact object-pointer references are
preserved. Declarations carry no invented executable locations. Genuine source
failure excludes the corresponding class-owned method declaration as well as
the definition's signature, preventing indirect signature inheritance.

`ClassScopeNames` adds deterministic synthetic C typedef aliases for actual
class spellings when unambiguous. These are debugger lookup conveniences, not
claims about original source typedefs. It never replaces or renames a curated
canonical type to accommodate an alias. A conflicting leaf or qualified alias
is omitted with a diagnostic; distinct classes retain qualified lookup when
available. An unbound class whose qualified spelling collides with an existing
type gets an explicitly synthetic name. Type-category paths do not become
source namespaces.

## First-lookup failure found during implementation

The earlier `research/CLASS-LAYOUT.md` probe expanded compilation-unit symbols
before querying classes and methods. Its passing results did not establish
first lookup in a fresh debugger. A canonical type nested directly in a
namespace passed all structural validators but failed fresh GDB 15.1 C11
lookup; running `info functions` first hid the defect. Changing the structure
tag or adding imported-declaration DIEs did not correct it.

The current layout keeps the canonical definition at compilation-unit scope,
with a specification reference to its real nested declaration. Fresh GDB
processes now check each canonical class, qualified alias and qualified method
independently, before any broad symbol expansion. The alias-collision fixture
preserves an unrelated eight-byte `Counter`; the two-class fixture exposes
both distinct qualified identities and requires ambiguous bare `Counter` to
remain unavailable. Production remains C11; it does not invent linkage names.

## Local validation and reproducible CI

Fourteen suites pass against the production JAR on actual Java 21, including
400 saved-binding checks, 290 saved-extraction checks and 12 naming-plan checks.
Production class origins are checked. Isolated class producer variants cover
normal emission, source failure, an unrelated-name collision and two same-name
classes. Nested static methods, addressless external methods, exact
specification/object/type references and malformed-reference negative controls
are checked. GNU readelf, LLVM verification and the pinned strict checker pass;
existing lexical/object producer regressions also pass.

Twelve real target/address/binding cases pass: x86-64 and AArch64, each with
non-PIE, PIE and rebased PIE, using both inferred and explicitly saved bindings.
Twenty-four production exports preserve the original files and saved projects
apart from documented Ghidra backup bookkeeping, and repeated output pairs are
byte-identical. GDB independently resolves classes/methods, breaks and lists
the method, reads object member `7` and argument `3`, and retains ordinary
integer parameter `this = 41`. The AArch64 checks execute under QEMU. Known
QEMU supplied-DSO diagnostics must match the untouched compiler reference.

Six additional genuine native-decompiler failure cases pass twelve deterministic
exports on the same explicit-binding projects. A one-instruction decompiler
limit produces a real failure; raw DIE checks confirm no failed method
signature or specification survives. GDB still resolves its symbol but cannot
read `this` or `amount`, while the later ordinary function retains value `41`.
Originals, successful outputs and saved project data remain unchanged; strict
validators pass and GDB diagnostics match the compiler reference. Failed
experiments are retained, not counted as acceptance.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew classScopeSmoke classScopeNamesSmoke buildExtension
python3 src/test/integration/class-scope-native.py /path/to/installed-ghidra
python3 src/test/integration/object-parameter-export.py /path/to/installed-ghidra x86_64 --role pie --explicit-binding --failure-control
```

Use the same runtime command for AArch64 and each address role. The isolated
runner compiles its test with `javac --release 21` and uses the installed
production JAR and native libraries. CI includes the four native class variants,
fresh-debugger lookup, both binding modes and genuine-failure controls. Local
commands/results are retained under `build/class-emission-alias-final` and the
per-case `build/test-results` directories. The first genuine-failure driver
attempt used a qualified display name where the internal model stores a leaf
name; its retained failed log is superseded by the corrected fixture selection.

The reviewed runtime receipt is
`c00c4a8b05bca35273ecc5fd88bba9c506f77dc74d987f2501d9e1f6b50e9bc1`.
The actual Java 21-tested production JAR is
`a1d4ddcad5a6426e404c5579c4702b2e0b593b0419de4607fff37f2a07b57b01`.

## Remaining work

This component does not complete P1.11a or P3.3. Hosted acceptance and normal
integration remain required. Real saved-program class conflict/stale-binding,
additional same-name, cancellation and class/static/alias/origin relationships
still need their complete behavior matrix. The full requirements remain in
`LIFETIMES-AND-SCOPES-PLAN.md`; no umbrella issue is closed here.
