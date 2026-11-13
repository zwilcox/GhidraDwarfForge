# C++ inheritance and vtable export

**CONFIRMED:** the development exporter retains explicitly evidenced
class inheritance, virtual methods, complete-object vtables and saved adjustment
thunk relationships for little-endian Itanium x86-64 and AArch64. Ghidra 12.0.3,
Java 21 and DWARF 5 remain the baseline. Synthetic source remains C11; it is not
relabeled as original C++. The focused compiler/native and ordinary saved-export
steps pass on both targets in
[CI run 43411765598](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43411765598).
These results do not replace the full regression gate or final issue acceptance.

Ordinary export preserves the executable and writes the matched `.dbg` plus
synthetic `.dbg.c`. No separate compiler-symbol insertion step is needed.
An explicit C++ layout profile does not establish every calling convention,
class recovery heuristic or debugger capability.

## Analyst configuration

`ghidra_scripts/GhidraDwarfForgeCxxProfile.java` supplies `inspect`, `check` and
`apply` actions for the current analyzed program. In the Script Manager, run it
and choose an action; `check` and `apply` then ask for the selection JSON file.
In headless Ghidra, pass the action and its argument as script arguments:

```text
-postScript GhidraDwarfForgeCxxProfile.java inspect Mixed
-postScript GhidraDwarfForgeCxxProfile.java check /absolute/path/selection.json
-postScript GhidraDwarfForgeCxxProfile.java apply /absolute/path/selection.json
```

`inspect [name-filter]` prints an inventory of existing class namespaces,
functions, memory labels and structures, including their saved IDs. The optional
case-sensitive substring filter limits candidates, not existing configuration.
Each candidate category is capped at 1,024 entries; `candidates_truncated` tells
you to narrow the filter. No symbols, functions, types or program options are
created by inspection. Copy the **`selection` object**, rather than the enclosing
inventory, into a JSON file. An unconfigured program has `abi: "UNSPECIFIED"`;
you must replace that with an evidence-backed profile before checking/applying.

The supported profiles are `ITANIUM_X86_64` and `ITANIUM_AARCH64`, both for the
validated 64-bit little-endian targets. Selecting an ABI is an analyst assertion;
a class name, vptr-shaped field, compiler-spec name or function-pointer array does
not establish that assertion. Microsoft C++ ABI and construction vtables are not
covered. The eventual ELF export independently checks target and table admission.

This example shows the complete schema for a class with an implemented virtual
method and an addressless pure-virtual declaration. **All IDs are examples**:
replace them and the target header with the current inventory and supply your
actual evidence. The existing Ghidra functions must already have defensible
signatures and `this` types; configuration does not manufacture them.

```json
{
    "schema": 1,
    "program_id": "123456789",
    "language": "x86:LE:64:default",
    "compiler": "gcc",
    "abi": "ITANIUM_X86_64",
    "inheritance_mode": "replace",
    "classes": [
        {"class_id": "10", "type_id": "72057594037927936", "evidence": "Analyst-confirmed Mixed layout"}
    ],
    "declarations": [
        {"method_id": "12", "class_id": "10", "evidence": "Existing external declaration belongs to Mixed"}
    ],
    "bases": [],
    "virtual_methods": [
        {"method_id": "11", "slot": 0, "access": "PUBLIC", "virtuality": "VIRTUAL", "evidence": "Confirmed primary slot 0"},
        {"method_id": "12", "slot": 1, "access": "PUBLIC", "virtuality": "PURE_VIRTUAL", "evidence": "Confirmed pure declaration at slot 1"}
    ],
    "vtables": [],
    "remove": {"classes": [], "declarations": [], "vtables": []}
}
```

IDs and signed offsets use canonical decimal **strings** to avoid JSON number
precision loss. `schema`, `order`, `slot`, `byte_size` and `table_offset` are
nonnegative JSON integers. Unknown/missing fields, duplicate keys/identities,
wrong target headers, malformed UTF-8 and excessive input are rejected. Input is
limited to 1 MiB, 8,192 characters per string and 4,096 entries per array.

Additional record shapes:

- A base contains `derived_class_id`, `base_class_id`, `order`, `access`,
  `location` and `evidence`. Access is `PUBLIC`, `PROTECTED` or `PRIVATE`.
  Fixed location: `{"kind":"fixed","offset":"8","occupied_bytes":"8"}`.
  `occupied_bytes` describes the evidenced occupied base extent, accounting for
  ABI tail-padding reuse. Virtual location:
  `{"kind":"virtual","vptr_offset":"0","slot_offset":"-24"}`; the slot is
  relative to the vtable address point and its contents supply the dynamic base
  displacement. The two location shapes cannot be combined.
- A vtable contains `symbol_id`, `class_id`, `mangled_name`, `lookup_name`,
  `byte_size`, `points` and `evidence`. Each point contains `table_offset`,
  `subobject_offset` and `evidence`. For example, a primary address point may be
  `{"table_offset":16,"subobject_offset":"0","evidence":"Confirmed primary address point"}`.
  The symbol must already exist at backed memory, and the byte extent,
  offset-to-top headers, class relationships and target profile must agree.
  Mangled names use complete-object `_ZTV...` spellings; names alone do not prove
  a semantic association. Each table is limited to 1 MiB, with 64 MiB total.

`check` runs the same current-program checks as `apply`, then rolls back its
metadata transaction. `apply` retains the configuration; save the Ghidra program
to persist it. Neither action changes target bytes, namespaces, signatures or
data types. Cancellation and validation failure roll back the operation.
The script starts with no other program mutations; Java API callers must isolate
this operation from unrelated enclosing transactions because Ghidra nested
transactions participate in their parent's commit/rollback.

`inheritance_mode: "replace"` deliberately replaces the **complete** saved base
and virtual-method model, including when those arrays are empty. Selected class,
declaration and vtable records are applied by ID; unselected records remain.
Remove unwanted IDs explicitly in the corresponding `remove` arrays. An ID
cannot be both selected and removed. Every retained record must still be valid;
stale or conflicting evidence must be corrected/reselected or explicitly removed.
Inspection diagnoses rejected saved records instead of repairing them.

Checking configuration validates current Ghidra evidence, not DWARF or debugger
behavior. Run the ordinary exporter afterward and inspect its diagnostics. Table
admission against the original ELF, structural validators and actual debugger
checks remain required before claiming a particular recovered program works.

## Saved evidence and export admission

`GhidraClassBindings` supplies canonical class/type identities.
`GhidraInheritanceBindings` stores ordered direct bases, access, fixed occupied
extents or virtual-base lookup expressions, and virtual methods with explicit
slots/purity. Records carry analyst provenance and saved IDs. The model rejects
missing/conflicting methods, duplicate direct bases, incomplete ordering and
cycles while allowing diamonds, empty bases and reused base tail padding.
Automatic `this`-type guesses cannot establish inheritance.

Snapshots include program/language/compiler identity, explicit ABI, physical
class layouts, and method ownership/signatures. Display names, categories,
comments and image addresses are excluded. Identity-preserving renames and
rebasing can remain valid; a rename that changes Ghidra's actual automatic
`this` type is rejected. Snapshot traversal, record sizes and inventory counts
are bounded and cancellable. Reads do not repair stale records. If a required
layout or method is missing/conflicting during extraction, the relationship
unit is omitted with a diagnostic; independent class/signature information
remains available.

Ghidra external functions live in external namespaces. For a canonical class
with both local and addressless methods, `GhidraDeclarationBindings` explicitly
associates an existing external Function ID with a saved canonical class ID.
The automatic `this` parameter must point to that exact saved type. Namespace,
signature and layout changes invalidate the association. No function, namespace,
type or address is manufactured. The emitted addressless declaration and local
method declaration share one canonical class DIE; the local definition refers
to its own declaration.

Pure virtuality requires explicit evidence. The fixture contains
`Abstract::pure_value() = 0` and an implemented `Abstract::base_value`. GCC emits
ordinary virtuality for the pure declaration; the harness records the stronger
fact from this known source and retains the compiler's original value. Missing
code alone never establishes pure virtuality. The pure declaration has no
executable address, and `Concrete` retains its separate overriding method.

`GhidraVtableBindings` captures explicit symbol/class/lookup identities, byte
extent, address points, offset-to-top headers, FileBytes mapping and original/
loaded byte hashes. Relocation context is part of the witness, so legitimate
loaded PIE bytes can differ from original bytes. A record cannot restore class
ownership or inheritance rejected by another check. Orphaned saved records are
also diagnosed; reads do not silently discard them.

`VtableSymbols` admits the ELF object symbol and canonical lookup alias together.
It checks the original ET_EXEC/ET_DYN target, selected ABI, unique non-TLS
allocation, full file-backed extent, exact original offset and SHA-256.
Sectionless inputs use the matched writer's PT_LOAD allocation identities.
Conflicting/overlapping tables, reserved function/global names, ambiguous lookup
names and mismatched original symbols are rejected. An existing object symbol
is reused only when name, address, extent, type and allocation agree. An imported
global for the same table is accepted only at its exact global definition and
extent. No lookup alias is introduced solely for rejected table evidence.

Qualified lookup aliases refer to the exact canonical class DIE, including
same-spelling classes in different namespaces. Renaming a class does not change
its saved table identity. The generic exporter never guesses an Itanium mangled
name from a recovered display name.

## Adjustment thunks and failure isolation

Only explicitly analyst-named saved memory thunks are selected for export.
`GhidraFunctionRelations` preserves the direct saved target using
`DW_AT_trampoline`; the thunk keeps its own name, address and extent. Destination
source is intentionally omitted from the thunk, and destination parameter
locations are not borrowed. Source omission is distinct from decompiler failure.

The fixture saves two fixed secondary-base thunks and one virtual-base thunk.
Compiler and Forge debugger sessions stop at each entry, inspect the incoming
subobject pointer, single-step to the saved target, check the adjusted complete
object pointer and validate the real return register. The tested adjustments are
-16, -32 and -16 bytes. Every executed thunk instruction must have no borrowed
source line or `this` location. x86-64 uses three/four/three steps; AArch64 uses
two/four/two. PIE runs require nonzero runtime load bias.

**Known consumer limit:** recovered `__thiscall` signatures retain the existing
conservative `DW_CC_nocall` policy. The layout profile does not audit arbitrary
inferior method calls. GDB `finish` therefore warns that it cannot automatically
display these return values. The test records that exact expected restriction
and verifies the actual return register independently; no calling-convention
restriction is relaxed to make the display appear complete.

`InheritanceDecompilerFailureExport.java` requests a real native decompiler
instruction-limit failure for `Diamond::root_value`. The normal source/type/
producer path must emit only its qualified symbol and address extent, with no
borrowed signature, parameters, locals, source lines or virtual-slot declaration.
The fourteen other virtual methods, base relationships, table lookup and three
thunk links remain. Later functions still decompile, and GDB continues to show
correct dynamic types/inherited values and execute the unchanged virtual calls.
The failed method's diagnostic appears in synthetic source. Repeated failure
exports must be byte-identical.

The failure harness opens the fixture through a read-only project handle from
an empty temporary host project, as the supported wrapper does. Plain Ghidra
`-readOnly` processing can still rotate project bookkeeping and is insufficient
for the exact preservation claim. Every saved project file and executable is
hashed before and after the final harness.

## Validation and limits

The source-built fixture contains eleven canonical classes, fifteen virtual
methods, seven complete-object table groups and three explicit adjustment
thunks. Structural checks use GNU readelf, LLVM verification and the pinned
libdwarf checker. Runtime checks use GDB and QEMU user emulation for AArch64.

| Validation | Local evidence |
| --- | --- |
| Analyst configuration | 140 ProgramDB checks: strict input, target mismatch, explicit replacement, retained/removable stale evidence, rollback after writes, cancellation and immutable inventory. |
| Saved method association | 262 checks across five target descriptions; these establish neutral ownership behavior, not extra C++ ABI support. |
| Saved inheritance | 188 evidence checks; model admission separately covers 80 cases. |
| Saved vtable evidence | 164 checks, including an explicitly associated addressless-only virtual owner with no base/local-virtual edge and rejection when that association disappears. |
| Compiler consumer reference | 48 sessions across two targets, non-PIE/PIE, RTTI/no-RTTI and six debug-copy arrangements. |
| Native producer | Eight profiles and six deliberately wrong-base controls. |
| Public configuration and ordinary export | Eight profiles plus four rebased PIE cases; exact metadata restoration, original/project preservation and deterministic reopening. |
| Adjustment-thunk execution | The same twelve ordinary cases, each compared with compiler-debug behavior. |
| Native decompiler failure | Both targets with no-RTTI PIE, ordinary and rebased; two identical exports per case. |
| Naming/rejection variants | Fourteen current-fixture local cases: both targets with rebased no-RTTI PIE. The full four-profile matrix is in hosted CI. |
| Table witnesses and standalone lookup | 56 imported table witnesses and forty naming cases. |

Missing, stale and conflicting table variants require the correct **static**
type to remain. Renamed, qualified, duplicate-name and retained-symbol variants
require the exact canonical layouts and runtime dynamic type. Oracles inspect
sizes, members, inherited values, `ptype` and `info vtbl` before broad expansion
can mask lookup gaps. No artifact is made to pass by inserting compiler symbols
after Forge export.

The Script Manager chooser itself has not been exercised locally. Every integrated
revision must pass the full hosted regression gate. ARM32, MIPS, Microsoft C++ ABI,
construction vtables, covariant-return thunks and other class-recovery schemes
are not established by this C++ matrix. General architecture support elsewhere
in the project does not imply these C++ layout profiles.

The Linux/Windows smoke lists include configuration and saved-evidence tests.
The x86-64/AArch64 pipeline invokes `reference.py`, `produce.py`, `storage.py`,
`names.py`, `extract.py --adjustment-thunks`, the rebased extraction variant,
`failure.py` and all seven naming/rejection variants. Local runs must use the
storage guard, shared cache and bounded result directories:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 -B src/test/research/inheritance/extract.py \
    --ghidra "$GHIDRA_INSTALL_DIR" --references /path/to/reference-results \
    --models /path/to/producer-results --adjustment-thunks \
    --results "$PWD/.forge-work/scratch/inheritance-extraction"
```

Set `LIBDWARF`, `LIBDWARFP` and `DWARFDUMP` to the pinned built libraries/checker.
`failure.py` takes `--ghidra`, `--extraction` (a completed thunk-enabled export
matrix) and a new `--results` directory. `--targets` and `--roles` select bounded
subsets. Commands, validator/debugger observations, hashes and preservation
receipts are retained with the results; unavailable/skipped lanes are not passes.

## Compiler and debugger evidence

**CONFIRMED locally:** `src/test/research/inheritance/reference.py` compares
single, multiple and diamond-shaped virtual inheritance, plus an abstract base
and concrete pure-virtual override, on x86-64 and AArch64.
Each target tests non-PIE and PIE, with and without compiler RTTI. Six separate
debug artifacts per build vary CU language and retained ELF symbols, for 48
fresh GDB sessions. AArch64 executes through QEMU user emulation. All artifacts
pass LLVM and the pinned libdwarf checker; original reference/runtime hashes
remain unchanged.

The stripped runtime is always the executable. Experimental edits affect only
owned debug copies. The C11 variants also change the recorded source suffix;
the source remains compiler C++ test text, not generated Forge C. Dynamic-type
queries run before broad type expansion, followed by type displays, inherited
member values, virtual-base access and `info vtbl`. The program then executes
its virtual calls and exits successfully.

| Debug-copy contents | Observed behavior on all eight target/build profiles |
| --- | --- |
| Compiler DWARF and ELF symbols | Correct derived types through primary, secondary and virtual-base pointers. |
| Compiler DWARF with ELF symbol payloads removed | Base member values remain correct; dynamic-type queries retain the static base type. |
| Same DWARF with only fixture vtable object symbols restored | Derived-type detection is restored without method, RTTI-object or other executable symbols. |
| C11 language with vtable symbols | Derived-type detection and virtual-base values work; C type lookup uses `struct Diamond`, rather than bare `Diamond`. |
| C11 language without vtable symbols | Static base types remain; no derived type is invented. |

These results also hold for `-fno-rtti`. They establish that this tested GDB path
can use proven vtable identities; absent RTTI alone does not establish either
the presence or absence of usable runtime-type evidence. They do not establish
support for ambiguous classes, stale bindings, construction vtables or other
C++ ABIs.

The [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable)
describes vtable address points, base adjustments and secondary tables. The
[GDB print settings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Print-Settings.html)
document dynamic object printing. The experiment distinguishes those contracts
from actual debugger behavior on the selected toolchains.

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    env DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 -B src/test/research/inheritance/reference.py \
    --results "$PWD/.forge-work/scratch/inheritance-reference"
```

Requires G++, AArch64 G++, the corresponding binutils, GDB multiarch, QEMU user
and LLVM. `--targets x86_64` selects the native subset. Commands, validator logs,
symbol inventories, debugger observations and protected hashes are retained in
the selected bounded workspace. This is compiler-reference research, not an
exporter acceptance result.
