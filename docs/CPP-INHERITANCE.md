# C++ inheritance and vtable export

**PRESENT, UNVERIFIED end to end:** issue #113 extends saved class/type ownership
with explicit base, virtual-method and vtable relationships. Ordinary Ghidra
extraction and native emission now retain validated saved inheritance. Vtable
evidence admission remains incomplete. Ghidra 12.0.3, Java 21 and
synthetic C11 remain the baseline.

## Compiler and debugger evidence

**CONFIRMED locally:** `src/test/research/inheritance/reference.py` compares
single, multiple and diamond-shaped virtual inheritance on x86-64 and AArch64.
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
Actual vtable/address-point evidence and its export integration remain incomplete.

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

Vtable address-point/byte evidence and configuration UI/script are still
**PLANNED**. The dedicated saved-program smoke is in both hosted test lists;
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
