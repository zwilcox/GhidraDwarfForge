# C++ inheritance and vtable export

**PLANNED:** issue #113 extends saved class/type ownership with explicit base,
virtual-method and vtable relationships. The current exporter does not emit
those relationships. Ghidra 12.0.3, Java 21 and synthetic C11 remain the baseline.

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
