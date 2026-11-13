# C++ inheritance and vtable export

**PRESENT, UNVERIFIED end to end:** issue #113 extends saved class/type ownership
with explicit base, virtual-method and vtable relationships. Ordinary Ghidra
extraction and native emission now retain validated saved inheritance and vtable
witnesses. The production-path checkpoint below is locally validated; broader
#113 acceptance remains incomplete. Analyst configuration is available through
the script described below. Ghidra 12.0.3, Java 21 and
synthetic C11 remain the baseline.

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

**CONFIRMED locally:** the configuration smoke test passes 140 checks across
x86-64 and AArch64 ProgramDB fixtures, including rollback after actual metadata
writes, stale-record retention/removal, target mismatch, strict input parsing,
complete relationship replacement and immutable reopen. Twelve ordinary-export
cases (eight target/RTTI/PIE profiles plus four rebased PIE cases) clear the
independently curated bindings and restore them through the public script.
Preview leaves no bindings behind; apply recreates the original records exactly;
a further preview preserves those records. GNU, LLVM and pinned libdwarf
validators, GDB/QEMU behavior, original preservation and deterministic read-only
reopen pass. The Script Manager chooser itself has not been exercised locally.

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

## Implementation requirements

- Reuse persistent class and canonical-type identities from `GhidraClassBindings`.
  Require explicit provenance for bases, virtual slots, address points and
  adjustments; a class name or function-pointer array is insufficient.
- Add validated inheritance and virtual-method metadata without replacing
  existing method ownership, object parameters or canonical types. Virtual-base
  locations require evidenced ABI expressions rather than fixed object offsets.
- Preserve or emit only proven vtable symbol identities. The local ELF
  symbol model now admits validated non-TLS objects; extraction must still prove
  the identity, byte extent and target address before requesting such a symbol.
- Keep C11 unless further consumer evidence requires a deliberate language
  change. Test qualified/duplicate names and fresh debugger lookup using the
  existing class-scope representation; the global-class experiment does not
  settle those cases.
- Validate stripped/PIE/rebased exports, secondary vptrs, adjustment thunks,
  missing or conflicting evidence, deterministic reruns, original preservation
  and cancellation through the production exporter and required hosted gates.

No issue #113 acceptance item is complete solely because this reference passes.

## Production ELF packaging checkpoint

**CONFIRMED locally:** `package.py` uses `MatchedElfSidecarWriter` to package
compiler DWARF with explicit fixture vtable records. Its 16 cases cover both
reference targets, all four build profiles, and both CU languages. GNU readelf,
LLVM and the pinned libdwarf checker validate the artifacts. Fresh GDB sessions
match the compiler reference for dynamic types, inherited values, base offsets
and language behavior. These tests do not yet exercise Forge inheritance DIEs
or Ghidra binding admission.

The writer admits `ElfLocalObjectSymbol` only inside a non-TLS allocated section,
with a positive, fully contained extent. It preserves original symbol records,
checks name conflicts, handles extended section indexes, and retains the same
cancellation and atomic publication rules. ELF32/64 and both byte orders have
independent smoke coverage, including NOBITS and rejected TLS/overflow cases.

The experiment also exposed valid copy-relocated C++ runtime objects whose
version identity comes from VERNEED while their storage is defined in the
executable. The dynamic mirror now reads bounded VERNEED chains alongside
VERDEF, including program-header-only inputs, and emits the required single
`@VERSION` spelling. Original dynamic tables remain byte-identical. Malformed
chains, duplicate/conflicting identifiers, missing tables and cancellation have
regression controls. This matches the distinction documented in the
[binutils copy-relocation handling](https://sourceware.org/pipermail/binutils-cvs/2015-November/040929.html).

After generating the compiler reference and running Gradle's
`prepareInheritanceHarness` task through the storage guard:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    env DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 -B src/test/research/inheritance/package.py \
    --references "$PWD/.forge-work/scratch/inheritance-reference" \
    --classpath build/inheritance-classpath.txt \
    --results "$PWD/.forge-work/scratch/inheritance-packaging"
```

## Inheritance model checkpoint

**CONFIRMED locally:** `InheritanceModel` records direct bases by persistent
class IDs, declaration order, access, provenance and either a fixed subobject
extent or a virtual-base lookup. Virtual methods refer to saved method IDs and
explicit slots. Admission requires canonical structures from explicit saved
class bindings and validates virtual methods against existing object parameters.
Current automatic THIS-type guesses cannot establish inheritance.

Fixed subobject extents deliberately differ from the complete base type's byte
size: reusable tail padding, empty bases and shared virtual bases make a simple
non-overlap or `sizeof(base)` containment rule incorrect. Declaration order is
retained independently of address order. The graph validator is iterative and
rejects duplicate direct bases, missing order entries and cycles while allowing
diamonds. Virtual slots reject conflicting ownership or missing methods.

`CxxAbiProfile` currently describes the x86-64 and AArch64 little-endian Itanium
layouts used by the compiler reference. A profile must be explicitly selected
and checked against the target; a machine number alone is not ABI evidence.
Virtual-base entry geometry is checked against that profile. These model tests
do not establish emitted inheritance support on either target or change the
existing support claims for other architectures.

`inheritanceModelSmoke` passes 80 admission checks, including an 8,192-edge graph,
and is included in the Linux and Windows smoke lists. Existing saved class
bindings and extraction still pass on x86-64, AArch64, ARM32 and both MIPS byte
orders (400 binding and 290 extraction checks). Existing class-model/name tests
also pass. Hosted checks for this checkpoint remain pending.

The saved relationship and native emission checkpoints below extend this model.
The later vtable checkpoints extend this model with saved byte evidence and export admission.

## Saved relationship snapshot

**CONFIRMED locally:** `GhidraInheritanceBindings.save/read/remove` stores an
explicit bounded relationship record in the caller's program transaction.
The record is tied to the program identity, language, compiler specification,
selected ABI, saved class/type identities and saved method IDs. It captures a
physical type graph and method ownership/signature snapshot; changed nested
storage, missing/rebound classes, or moved/deleted methods are rejected. Reads
never repair records or replace rejected evidence with an inference.

The snapshot excludes display names, category paths, comments and image addresses.
Base-type/member/method renames that preserve identity and rebasing remain valid.
A class-layout rename can make Ghidra's fuzzy automatic THIS lookup select a
different structure. That changes the actual object parameter: it is rejected
rather than treating an unchanged byte size as sufficient evidence.

The format limits encoded data to one MiB, each relationship inventory and
referenced class inventory to 4,096, and aggregate snapshot traversal/component
work to bounded totals. It uses iterative type traversal and stops at pointer
target identity rather than following an entire reachable object graph.
Cancellation occurs before the final options write; immutable reopening leaves
saved database bytes and timestamps unchanged.

This API currently persists bases and virtual-method slots. Ordinary type
extraction reads the snapshot after resolving canonical layouts and method
signatures. A stale record is omitted with a diagnostic. A valid snapshot whose
required method or layout is absent/conflicting in this export is also omitted
as a unit; independent class ownership and signatures remain intact. Reads never
repair saved evidence or replace rejected relationships with inference.

Vtable address-point/byte persistence is validated below. Export admission and
configuration UI/script remain **PLANNED**. The dedicated saved-program smoke is in both hosted test lists;
its local results do not substitute for the full #113 runtime acceptance.

## Native emission checkpoint

**CONFIRMED locally:** `produce.py` supplies the production native exporter with
an explicit model decoded independently from the compiler fixture. The emitter
adds ordered `DW_TAG_inheritance` children to canonical class definitions, fixed
or ABI-specific virtual-base locations, accessibility, virtuality, containing
types and vtable slots on the existing method declarations. Object parameters
and declaration/definition identities are retained. The selected C++ profile
must match the original ELF before native production begins.

Eight cases cover x86-64/AArch64, non-PIE/PIE and RTTI/no-RTTI. GNU readelf, LLVM
and the pinned libdwarf checker accept the packaged artifacts. Fresh GDB/QEMU
sessions compare derived types, base offsets and member values with compiler
references, inspect `ptype` and `info vtbl`, and run the original virtual calls.
Repeated native exports to the same destination are byte-identical. Cancellation
at early/middle/late checkpoints preserves existing output or leaves no new
final artifact; wrong-target profiles preserve the prior generation. Originals
remain byte-identical.

The fixture includes standalone virtual-left and virtual-right objects in
addition to a diamond. Without them, a valid alternative path through the
diamond could hide an incorrect base expression. Deliberately incorrect fixed
and individual virtual-base offsets remain structurally valid but must fail
the runtime oracle. These negative controls are part of the harness.

The native test packages proven compiler vtable object identities through the production
ELF writer after native DWARF emission. It does not prove their extraction from
Ghidra. Qualified/duplicate class names, recovery configuration and full source
failure behavior still need acceptance. Saved-program results are described below.
Secondary/thunk entries may display addresses instead of recovered thunk names;
this checkpoint does not claim complete thunk reconstruction. The corresponding
x86-64/AArch64 CI step is present but has not yet run on the hosted branch.

After generating the reference and preparing the Java harness:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    env JAVA_HOME=/path/to/jdk21 LIBDWARF=/path/to/libdwarf.so \
    LIBDWARFP=/path/to/libdwarfp.so DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 -B src/test/research/inheritance/produce.py \
    --references "$PWD/.forge-work/scratch/inheritance-reference" \
    --classpath build/inheritance-classpath.txt \
    --results "$PWD/.forge-work/scratch/inheritance-native"
```

## Saved-program export checkpoint

**CONFIRMED locally:** `extract.py` imports the stripped compiler runtime, applies
independently decoded fixture evidence, saves the relationships, and runs the
ordinary `GhidraDwarfForge.java` exporter. A second export uses the supported
existing-project wrapper, which opens the saved program through a read-only
project handle. Both `.dbg` and `.dbg.c` are byte-identical across reopening;
the original runtime and every saved project file retain their hashes.

The fixture preserves compiler-declared methods with no code bodies as actual
Ghidra addressless declarations under external-only classes. Dropping those
declarations caused GDB to lose polymorphic recognition for the corresponding
base types even with correct vtable symbols. No function addresses are invented.
This fixture does not exercise a class mixing local methods and addressless
declarations; the preparation script rejects that shape explicitly.

GNU/LLVM/pinned validators and fresh GDB/QEMU sessions check single, multiple and
diamond inheritance, individual virtual-base branches, dynamic types, member
values, `ptype` and `info vtbl`. The export report can be PARTIAL because ordinary
startup/import functions and unsupported call conventions are diagnosed; the
test separately requires retained inheritance, complete fixture source generation
and successful runtime/structural checks. Vtable object symbols are still added
from compiler evidence in a separate production-writer step. This is not yet
end-to-end validation of recovered Ghidra vtable identities.

The harness also supports `--rebase`: it changes the image base after saving the
relationships and does not refresh their snapshot. The hosted x86-64/AArch64
steps run the four ordinary build profiles plus PIE/no-RTTI rebased cases.
Hosted validation remains pending.

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    env JAVA_HOME=/path/to/jdk21 LIBDWARF=/path/to/libdwarf.so \
    LIBDWARFP=/path/to/libdwarfp.so DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 -B src/test/research/inheritance/extract.py \
    --ghidra /path/to/ghidra-with-current-extension \
    --references "$PWD/.forge-work/scratch/inheritance-reference" \
    --models "$PWD/.forge-work/scratch/inheritance-native" \
    --classpath build/inheritance-classpath.txt \
    --results "$PWD/.forge-work/scratch/inheritance-extraction"
```

## Vtable evidence and lookup experiments

**CONFIRMED locally:** `storage.py` imports all eight compiler runtime profiles
and observes six complete-object vtable groups in each. It checks every mapped
byte through Ghidra's `MemoryBlockSourceInfo` and `FileBytes` against the original
ELF file offset, then repeats after rebasing by `0x200000`. File mappings,
original bytes, loaded bytes and recorded relocations stay stable across this
rebase. For all four PIE profiles, loaded vtable bytes differ from file bytes
because Ghidra applied relocations at import. The four non-PIE profiles have
matching loaded/file bytes in this fixture. These are observed profiles, not a
claim that every relocation or loader behaves identically.

The binding design must therefore retain separate original-file and loaded-byte
witnesses, along with normalized addresses and explicit class identity. A single
"bytes equal ELF" check would reject legitimate PIE imports. Reads should reject
changed loaded bytes, changed backing-file mappings or changed class evidence;
the original ELF must be checked independently at emission. Rebinding must be an
explicit operation, not an automatic repair during export.

**CONFIRMED locally:** `names.py` compares five naming arrangements for every
target/build profile, using the production emitter/writer and fresh GDB sessions:

| Arrangement | Observed result |
| --- | --- |
| Plain `vtable for Class` object names | Static types only; negative control. |
| Explicit mangled symbols for renamed types | Correct recovered derived types. |
| Original mangled symbols plus unambiguous class lookup aliases | Correct renamed canonical types. |
| Namespace-qualified mangled names and lookup aliases | Correct canonical types through qualified lookup. |
| Distinct qualified aliases for nine same-spelling canonical types | Correct individual sizes and direct members, not merely matching printed names. |

All 40 artifacts pass GNU/LLVM/pinned validators. The 32 positive debugger cases
retain virtual-table inspection and member values; the eight negative cases
retain static types as expected. Original binaries remain unchanged. The fixture
labels are explicit experimental identities, not evidence recovered from a table
of pointers. The synthetic C11 language remains unchanged.

**PLANNED production contract:** persist an explicit symbol/class association,
bounded table extent, address points and provenance; validate the selected ABI,
class snapshot, memory/file witnesses and complete-object table geometry. Use
the binding's explicit mangled identity and a collision-checked lookup alias to
the canonical type when needed. If a qualified lookup is ambiguous, diagnose and
omit that table rather than assigning it to another class. Do not infer identity
from `_ZTV` spelling alone or guess mangling for arbitrary recovered names.
Address points and offset-to-top checks must follow the selected
[ABI profile](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable), including
secondary tables; construction tables require separate evidence and handling.
This persistence/admission path is not implemented yet.

Run `storage.py --ghidra <installed-ghidra> --models <native-results> --results
<new-directory>` through the storage guard. `names.py` takes the same `--models`
and `--results` plus `--classpath build/inheritance-classpath.txt`, with the Java
and native/validator environment used by `produce.py`.

## Saved vtable witness checkpoint

**CONFIRMED locally:** `GhidraVtableBindings` persists explicitly supplied
complete-object table identities, their canonical class IDs, bounded extents,
primary/secondary address points and provenance. It requires valid saved
inheritance that includes the selected class, a saved memory label, direct
contiguous FileBytes backing, and the selected validated C++ ABI. Read-only
Ghidra demangling checks that the supplied mangled name corresponds to the
supplied consumer lookup name; it never infers class ownership from that name.
Construction tables are outside this complete-object record format.

The witness captures the original ELF address, exact backing-file offset,
separate original-file and loaded-memory SHA-256 fingerprints, and a context
fingerprint covering program identity, inheritance, file mapping and relocation
records. The ABI checks offset-to-top words against the explicit subobject
geometry in both byte views. A PIE loader can legitimately change pointer words;
comparing its loaded table directly with original file bytes would be incorrect.
Rebasing does not require subtracting a new image base from those old pointer
words. Table-symbol renames do not change the explicit linkage identity.

Reads reject missing/stale inheritance, changed layouts, moved/deleted labels,
changed image-base provenance, changed mappings or byte patches. Reads never
refresh a witness. Record size, table bytes, address points and relocation work
are bounded. Save requires the caller's transaction and checks cancellation
before publishing metadata. No executable or source output is changed by this
API, and it does not yet authorize an ELF symbol or type alias.

The real ProgramDB smoke passes 144 checks across x86-64 and AArch64, including
separate relocated bytes, geometry/name rejection, absent backing, malformed or
oversized records, cancellation, deterministic saves, rename/rebase preservation
and byte-identical immutable reopening. The existing inheritance suite still
passes 188 checks. Both suites are in the Linux/Windows workflow; current hosted
validation of these new changes remains pending.

`storage.py --bindings` additionally tests all eight imported compiler profiles
(non-PIE/PIE, RTTI/no-RTTI, x86-64/AArch64), six tables each. It applies independent
fixture class/relationship evidence, saves each table, requires a patched
function pointer to invalidate its witness, restores it, and rebases without
refreshing records. All 48 witnesses preserve their independently observed
original address, file offset and both byte fingerprints. Original ELF files
remain byte-identical. This checkpoint does not emit new DWARF; ordinary-export
and debugger acceptance still require the admission work below.

The next checkpoint connects these witnesses to the original ELF and ordinary
export. Configuration/recovery flows and the remaining conflicting-evidence,
pure-virtual, mixed local/addressless-method, thunk and source-failure acceptance
cases remain required before closing #113.

## Ordinary vtable export checkpoint

**CONFIRMED locally:** ordinary class extraction now reads saved vtable witnesses.
The inventory includes orphaned symbol records so deleted or stale evidence is
diagnosed. It requires the class and inheritance to survive normal extraction,
and bounds aggregate encoded records and byte-witness work before reading them.
A vtable record cannot restore inheritance or canonical ownership rejected by
another extraction check.

`VtableSymbols` makes the ELF symbol and its canonical lookup association one
admission decision. It checks the selected ABI, original ET_EXEC/ET_DYN target,
unique non-TLS allocation, complete file-backed extent, exact FileBytes offset
and original-byte SHA-256. Sectionless inputs use the writer's shared PT_LOAD
allocation identities. Conflicting/overlapping table records, reserved function
or global names, and ambiguous canonical lookup spellings are omitted with a
diagnostic. No table alias is retained solely on behalf of rejected evidence.
Independent pre-existing class aliases and original ELF symbols remain governed
by their existing preservation rules.

Accepted lookup names become typedef aliases to the exact canonical class DIE
only when needed; synthetic C11 and existing class/method ownership remain
unchanged. The native exporter appends validated object symbols through the
ordinary matched writer. An original symbol with matching name/type/address/
extent/section is reused; conflicting identities are rejected. Both static and
applicable dynamic inventories are checked, with bounded repeated-name handling.
Default export never modifies the executable or adds a debuglink.

`vtableSymbolsSmoke` passes 166 checks for both selected targets, including
original-byte changes, incorrect mappings/targets, TLS/NOBITS/overlapping
allocations, table and canonical-name conflicts, distinct qualified lookups for
same-spelling types, matching/conflicting original symbols, sectionless mapping,
determinism, input preservation and cancellation. Regression suites pass:
saved vtables 144, saved inheritance 188, class names 12, class extraction 300,
class model 51 and local symbol merge 1,752. Extension build and workflow lint pass.

`extract.py` now saves fixture vtable witnesses and consumes the normal export
artifact directly. It no longer inserts compiler symbols in a second packaging
step. Eight standard profiles and four rebased PIE profiles pass GNU readelf,
LLVM verification, the pinned libdwarf checker and GDB/QEMU runtime comparisons.
The checks require exactly the expected object symbols and their addresses/
extents, canonical inheritance/object parameters, derived types through primary,
secondary and virtual-base pointers, inherited member values, `ptype`, `info vtbl`
and successful original virtual calls. These fixtures run with and without RTTI.

Every case reopens the saved program through the supported read-only wrapper,
requires identical sidecar/source bytes, hashes every project file, and checks
that the original executable is unchanged. The final local runs use the current
development extension; hosted checks for these C++ changes remain pending.
The subsequent checkpoint covers production rejected/naming runtime variants.
The full recovery/configuration workflow, pure-virtual/mixed-method cases and
genuine decompilation-failure behavior still remain #113 work.

## Rejected evidence and recovered-name runtime checkpoint

**CONFIRMED locally:** seven additional variants pass on x86-64 and AArch64,
non-PIE/PIE and RTTI/no-RTTI: 56 ordinary-export cases. Every variant rebases the
saved program before exporting and then repeats export through the read-only
wrapper. All pass GNU readelf, LLVM and the pinned libdwarf checker, preserve
original executable/project bytes, and produce identical sidecar/source bytes
on reopening.

- **Missing:** explicitly removed vtable records produce no new table symbols.
- **Stale:** patched Ghidra table-pointer bytes invalidate the saved witness;
  export diagnoses the omission without refreshing the record.
- **Conflicting:** two explicit records claim each table. Both claims are omitted,
  rather than selecting whichever was visited first.
- **Renamed:** coordinated class/layout renames preserve their identities and
  original vtable records; the original lookup names resolve to renamed canonical
  types through the admitted aliases.
- **Qualified:** explicitly supplied qualified linkage names resolve to the
  intended canonical types. The fixture's ASCII mangling helper is not a
  production inference or mangling API.
- **Duplicate:** nine distinct canonical layouts share the name `Shared` in
  separate namespace/category paths. Qualified table identities resolve each
  exact type. The oracle checks sizes and member names, not merely display names.
- **Retained:** the owned runtime fixture already contains the six object symbols.
  Export reuses them once each with their exact addresses and extents.

All 24 rejection cases require GDB's dynamic-type query to retain the correct
static type. Inheritance DIEs, virtual-method/object-parameter metadata, member
access and original virtual-call execution remain valid. Positive cases require
correct dynamic types before broad type expansion, exact layouts, `ptype`,
object printing and `info vtbl`. This matrix tests ordinary extraction/emission;
it does not add symbols to the exported artifact afterward.

The retained-symbol fixture found a real collision-policy defect: Ghidra's
imported global for the same table was treated as a competing object. Admission
now permits that global only if it is a definition in the global namespace with
the exact same address and extent. Another address, size, declaration, namespace
or lookup-name collision remains rejected. Qualified global names are checked
as well as leaf names. The admission smoke now passes 218 checks for the two
profiles. After the qualified-global check was added, a further 12 retained,
qualified and duplicate cases revalidate the final build across both targets,
non-PIE and no-RTTI PIE.

The hosted architecture-boundary gate initially rejected processor names in the
new isolated `CxxAbiProfile`. Its exact path is now in the audited boundary, and
signed offset-to-top decoding resides inside that profile. The gate and local
80 inheritance-model/144 saved-vtable checks pass; the corrected hosted
extension-build job also passed. This does not replace the remaining full hosted
acceptance gate for the final PR head.

## Pure-virtual method acceptance

The source-built fixture includes `Abstract::pure_value() = 0` and a concrete
override. GCC's DWARF describes the abstract declaration as `virtual`, so the
harness records the stronger pure-virtual fact explicitly from this known
fixture source. It does not infer purity from a missing body. The compiler's
slot, signature and layout remain the independent reference, and the model
records both the compiler virtuality and the explicit source witness.

The checks require exactly one `DW_VIRTUALITY_pure_virtual` method with an
object parameter and no executable address/ranges. The concrete override has
its own method identity and code. GDB must identify `Concrete` through the
abstract pointer, show both layouts, read inherited/member values and display
the concrete vtable; the original program executes the virtual call and returns
the expected value. Missing or rejected table evidence must retain `Abstract`
as the static type. These checks apply to x86-64 and AArch64, non-PIE/PIE,
RTTI/no-RTTI, saved-program reopening and rebasing.

The fixture now has eleven classes, fifteen virtual methods and seven emitted
table groups per build. Native and ordinary-export checks require the pure
method count to be one, preventing a vacuous pass when compiler metadata omits
the stronger flag. The mixed-method association below extends this fixture with
an implemented method in the same abstract class. The analyst configuration
workflow remains required work for #113.

**CONFIRMED locally:** the expanded fixture passes 48 compiler-reference GDB
sessions, eight native-producer profiles with six deliberately incorrect-base
controls, and twelve ordinary exports (eight standard and four rebased PIE).
All seven production naming/rejection variants also pass on both targets using
rebased no-RTTI PIE, for fourteen additional ordinary exports. Each export
passes the structural validators, preserves the input and saved program, and
repeats deterministically. The standalone naming harness passes forty cases,
and imported-storage validation checks 56 table witnesses across eight profiles.
The full four-profile naming/rejection matrix remains in hosted CI; these local
results do not replace its required validation at the final PR head.

## Mixed local and addressless methods

Ghidra requires external functions to have external namespaces. A class with
local code therefore cannot directly own a genuinely addressless Ghidra
function. `GhidraDeclarationBindings` records an explicit association from an
existing external function ID to an explicitly bound canonical class ID. The
caller supplies provenance in a program transaction. No function, namespace,
type, executable bytes or code address is created or changed by the association.

The existing automatic `this` parameter must point to that exact saved class
type. The record snapshots program/target identity, the external function's
namespace, calling convention, parameter/return types and physical class layout.
Changes reject the association with a diagnostic. Renames that preserve those
identities and geometry, and image rebasing, retain it. Reads never refresh
stale records. Rejection leaves the independent function signature available
without inferring replacement class ownership.

Both ordinary class extraction and saved inheritance use this association.
The addressless method retains its external declaration key; a local method
retains its own executable address and definition. Emitted method declarations
share the one canonical class DIE, and the local definition references its
own declaration. The fixture explicitly confirms this for `Abstract::pure_value`
and the implemented `Abstract::base_value`; absence of a body is never used to
guess a class or pure-virtual status.

`declarationBindingEvidenceSmoke` passes 262 checks across x86-64, AArch64,
ARM32 and both MIPS byte orders: exact type/namespace/signature validation,
malformed metadata, cancellation, rejected-record preservation, coordinated
renaming, rebasing and immutable saved-program extraction. These neutral
ownership checks do not add C++ ABI support claims beyond the selected x86-64
and AArch64 profiles. Full issue #113 acceptance and hosted validation remain
pending.

The mixed fixture passes the same 48 compiler-reference sessions, eight native
profiles/six incorrect-base controls, twelve ordinary exports and fourteen
rebased no-RTTI naming/rejection cases described above. Structural inspection
requires the pure declaration and implemented method declaration to share a
canonical class, and exactly one local definition to reference the implemented
method declaration. Forty standalone naming cases and 56 imported table
witnesses pass as well. Coordinated rename fixtures use saved declaration IDs
to rename the external namespace alongside the canonical class; they do not
join unrelated classes by spelling.
