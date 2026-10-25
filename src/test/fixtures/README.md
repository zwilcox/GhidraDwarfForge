# Integration fixtures

`semantic.c` and `shared_semantic.c` are redistributable source-built fixtures
shared across target architectures. They intentionally contain functions,
globals, parameters, locals, arrays, an enum, union, typedef, function pointer,
and recursive structure. `semantic.c` supplies the ET_EXEC and PIE programs,
including their `main`; `shared_semantic.c` supplies the ET_DYN library and
intentionally defines no `main`. The separate `shared_driver.c` executable
loads the stripped library and calls its exported `recovered_add` function.

The integration preparation script applies explicit analyst register storage
to `recovered_add` parameters using each target ABI's input registers. The
exporter may emit those locations only when its instruction/p-code scan proves
the register is not written, the function contains no calls, and no opaque
instruction effects invalidate the proof. The current
x86-64 and MIPS functions retain their input registers; AArch64 overwrites
`x0`/`x1`, providing the negative case where locations must remain absent.
ARM32 overwrites `r0` but retains `r1` in the executable/PIE roles; its shared
object overwrites both, and the role-specific tests require honest omission.
The compiler fixture also receives a fourth, otherwise-unused argument whose
ABI input register contains 31. The preparation script models that entry-live
storage as the analyst-defined local `analyst_register`; the same whole-function
overwrite/call scan must prove it stable before the exporter emits a location.

`opaque-register-effects.c` is a Linux AArch64 negative regression. A real
`getpid` supervisor call changes x0 through outputless p-code while the compiler
saves the input `-19` elsewhere. The exporter must preserve both explicit
parameter names/types with no locations and report `UNKNOWN_LIFETIME`; it must
not infer syscall purity or the compiler's register move. The GDB oracle checks
entry, before the call, after the call and return, the stored global, source
stepping and normal exit. The dedicated harness tests exec, PIE and rebased PIE
with fresh-import deterministic repeats and strict validators. Its optional
`baseline-reproducer` mode records the old wrong value and never counts as
fixed acceptance. The current harness also requires the exact code-address
index, so historical packages predating that index need their retained
historical harness to replay the old wrong-value case. The direct
global-address formatting regression is now checked without warning suppression.

`recovered_composite` receives a known 64-bit value split across the third and
fourth ABI input registers. The preparation script models those varnodes as
`analyst_composite` in Ghidra's most-significant-piece-first join order. The
exporter reverses the completed list on little-endian targets to produce
DWARF's object-memory order and retains it on big-endian targets. GDB
reconstructs `0x1122334455667788` on x86-64, AArch64, and both MIPS profiles.
ARM32 overwrites an input piece, so its composite is deliberately locationless.

`composite-register-prefix.c` exercises an incoming sixteen-byte aggregate
whose first physical register is partially overwritten on x86-64 or overwritten
through W0 on AArch64. Its dedicated ET_EXEC harness requires both typed fields
through the writing instruction and a whole-value unavailable tail beginning
at the next instruction. It compares compiler DWARF with computed and custom
Ghidra storage, repeats saved/reopened exports, and checks original instruction
bytes and complete location-list pieces. It does not infer composite backups
or surviving pieces; see `docs/COMPOSITE-REGISTER-PREFIX.md` for the acceptance
status and proof boundary.

The preparation script also applies a user-defined `analyst_stack` name to the
compiler fixture's `sum` stack slot. Its Ghidra incoming-stack-pointer offset is
translated with Ghidra's instruction-level stack-pointer-depth analysis. The
resulting DWARF 5 location-list expressions are checked for the target stack
register and read as 42 by GDB on every target lane without relying on unwind
information.
The function also includes two assembly marker addresses around a balanced
16-byte stack-pointer adjustment. GDB reads `analyst_stack` as 42 both before
and during the adjustment, proving two distinct location-list expressions.

The preparation script adds a favorite Ghidra `packed_flags` structure with
3-bit and 5-bit unsigned fields. This exercises real Ghidra bit-field
extraction and target-endian `DW_AT_data_bit_offset` emission; every target
lane validates the DIE and GDB `ptype` result.

Build the current non-PIE reference and stripped inputs with:

```bash
make -C src/test/fixtures all
```

The default matrix is x86-64, AArch64, ARM32, MIPS32 big-endian, and MIPS32
little-endian, each as non-PIE `ET_EXEC` and PIE. The ARM32 profile is ARMv7
hard-float, little-endian ARM state. Reference files retain compiler DWARF 5
for test-oracle and diagnostic use. Most `.stripped` files have all symbols
removed and are the inputs intended for Ghidra. The
`semantic.partial.stripped` case instead removes compiler debug sections while
retaining its normal symbol table; every target lane imports, exports, validates,
and debugs this partially stripped input as a distinct regression.

| Fixture | Source | Behavior exercised |
| --- | --- | --- |
| `semantic.exec.*` | `semantic.c` | Fixed-address executable, full semantic model, and fully stripped input |
| `semantic.partial.*` | `semantic.c` | Partially stripped executable with symbols but no compiler DWARF |
| `semantic.exec.no-build-id.*` | `semantic.c` | Explicit loading when no build identity exists |
| `semantic.exec.no-sections.stripped` | derived from `semantic.exec.stripped` | Program-header-only input and new output section table |
| `semantic.pie.*` | `semantic.c` | PIE load bias and ASLR behavior |
| `semantic.{exec,pie}.extended-sections` | derived from the corresponding stripped fixture | Genuine extended section count and high section-name-table index |
| `semantic.{exec,pie}.no-section-names` | derived from the corresponding stripped fixture | Present section table with `e_shstrndx == 0` |
| `semantic.{exec,pie}.extended-programs` | derived from the corresponding stripped fixture | `PN_XNUM` count in section zero's `sh_info` |
| `libsemantic.so.*` | `shared_semantic.c` | PIC shared object without `main` |
| `semantic.shared-driver.*` | `shared_driver.c` | Runtime loading and calls into the stripped shared object |

`src/test/integration/fixture-reproducibility.sh <target>` builds this complete
set twice in isolated directories and requires byte-identical file lists and
contents. It records per-artifact SHA-256 values plus ELF headers, program
headers, section tables, and notes under
`build/test-results/fixture-metadata/<target>/`. CI retains that directory with
the target-lane diagnostics. The script also enforces the reviewed fixture
source inventory: the tests require no firmware or external binary input.

Each target also has `semantic.exec.no-build-id.{reference,stripped}` built
with `--build-id=none`. Its Forge sidecar must remain free of a build-ID claim
and load through the documented explicit `symbol-file` workflow.

Each target also has `semantic.exec.no-sections.stripped`, an executable whose
ELF section-header table has been removed (`e_shoff`, `e_shnum`, and
`e_shstrndx` are zero). This models firmware and BusyBox-style inputs that are
loadable from program headers alone. The Forge sidecar writer must create a
fresh section table and section-name string table for this case; an absent
input section table is not an error.

The extended-section fixtures are generated separately after the regular
source build:

```bash
./gradlew extendedSectionNumberingSmoke -PfixtureTarget=x86_64
src/test/integration/extended-sections-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64
```

The generator appends enough inactive section headers to require real extended
numbering and puts a copied section-name table at a high index. It preserves
the original section indexes, load segments, code, and build identity. A shared
nonempty padding name avoids quadratic unnamed-section handling in Ghidra.
The integration harness imports and executes the modified input itself,
validates the emitted sidecar with GNU/LLVM/libdwarf tools, and runs the full
native/QEMU GDB semantic oracle for both ET_EXEC and PIE. Diagnostics and
artifacts are retained under `build/test-results/extended-sections-export/`.
These few-megabyte fixtures test large section counts. Other layout and size
cases have separate harnesses:

```bash
java src/test/integration/ElfLayoutFixtures.java build/fixtures x86_64 mips32be
src/test/integration/elf-layout-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64 mips32be
src/test/integration/large-elf-sidecar.sh
src/test/integration/large-headless-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2
```

The layout harness exports unnamed-section and extended-program-header inputs
through Ghidra, checks target identity/build ID and actual-input static GDB
lookup, and runs the existing runtime semantic oracle. Linux/QEMU cannot
execute the extended-program fixture used here: that case explicitly uses
the unchanged ordinary fixture for runtime checks after proving the original
load image is equivalent. It does not claim native execution of `PN_XNUM`.
Known GNU input-reader diagnostics are allowed only for the exact fixture
condition; generated sidecar validators remain strict. ARM QEMU vDSO warnings
need corroboration from the independent compiler-DWARF runtime oracle.

The two large-file harnesses create disposable source-built inputs over 2 GiB.
The container oracle uses a 64 MiB Java heap and compiler DWARF; the headless
test runs real Ghidra analysis/export and the full GDB semantic oracle, then
repeats a fresh import to check byte-identical artifacts. Both retain compact
logs/hashes and remove their multi-gigabyte scratch files. These checks bound
source-file buffering, not generated DWARF or Ghidra's analysis memory.

The Makefile requires the corresponding GNU cross-compilers and binutils.
Runtime integration for non-host targets additionally requires QEMU user-mode
and a matching multi-architecture or cross GDB. Cross-compilation or headless
Ghidra import by itself is not a complete architecture-support test.

Focused harnesses build additional fixtures independently of the Makefile:

- `bitfield-values-export.sh` uses `bitfield-values.c` on each target. Compiler
  and Forge DWARF must both read initialized `{a=5,b=17}` values from four-byte
  and packed one-byte structures. The applied Ghidra types use four-byte bases
  with one-byte component storage, exercising the big-endian offset calculation
  as well as mutually exclusive member-location attributes. Checking `ptype`
  alone would not catch the previous incorrect values.
- `nonzero-load-offset-export.sh` uses `nonzero_load_offset.c`, its startup
  assembly, and linker script for a static x86-64 executable whose first load
  segment has file offset `0x1000` and virtual address `0x401000`. Normal and
  explicitly rebased Ghidra imports must retain exact function/global addresses,
  usable source stepping, runtime values, and deterministic repeats.
- `function-entry-export.sh` uses `function_entry_ranges.c` and its assembly
  for x86-64 ET_EXEC/PIE functions with executable bytes below their entries.
  One body is split around a trap-filled gap and one is contiguous. Assembler
  labels independently establish exact entries/body bounds; fully stripped
  inputs ensure compiler symbols/DWARF cannot mask the Forge oracle. Baseline,
  explicit Ghidra rebase and repeat runs check exact named breakpoints, all
  body bytes and gaps, source, stable arguments, global values and stepping.

- `register-prefix-export.sh` uses `register_prefix.c` for x86-64/AArch64
  ET_EXEC/PIE incoming parameters. Compiler references preserve value 19 after
  an explicit partial/alias register overwrite; Forge now retains the proven
  direct saved-register copy across that write. Exact
  instruction markers, source stepping, values, rebases and repeats are checked
  using fully stripped Ghidra/runtime inputs.

- `register-copy-export.sh` uses `register-copy.c` for signed 32/64-bit values
  on x86-64/AArch64. Each keep/kill function receives positive, negative and
  high-bit inputs. Exact compiler labels and raw location-list checks require
  incoming-register coverage followed by the one proved backup, then an
  unavailable tail when that backup is overwritten. The compiler retains
  entry-value recovery after the kill; Forge deliberately has no such location.
  Exec, PIE and explicit rebase cases include fresh-import repeats, unchanged
  originals, strict validators, source stepping and runtime values. See
  `docs/REGISTER-COPY-LIFETIMES.md` for the bounded proof.

- `stack-first-use-export.sh` uses `stack-first-use.c` with disjoint compiler
  scopes that reuse one stack slot, plus an ordinary zero-offset local.
  Compiler GDB measures the entry-relative slots; the preparation script
  persists explicit nonzero first-use on the stored `second` local. Forge
  must retain its signed type but report/omit the unsupported location at
  every observation, while `zero` remains `37`. Exec, PIE and rebase roles
  on x86-64/AArch64 require validators, exact reports/DIEs, source stepping,
  unchanged inputs and byte-identical pairs. A separate baseline mode must
  reproduce the old wrong `11` before `second` is in scope. This does not
  establish general stack-slot lifetimes; see `docs/STACK-FIRST-USE.md`.

- `floating-registers-export.sh` uses `fp_register_aliases.c` with `-Og` and
  fully stripped runtime/export inputs. Compiler references establish scalar
  float/double arguments across stores on x86-64/AArch64, and scalar floats on
  MIPS32 BE/LE. ARM32's CI case includes the second float in `s1`, encoded as
  the upper 32 bits of canonical `d0`; its local runtime is unavailable.
  Explicit register overwrites on x86/ARM targets require Forge values to become
  unavailable after the instruction. MIPS double pairs stay unavailable:
  the current compiler-GDB pair oracle reports zero despite exact stored
  globals, and those globals do not validate parameter locations. Each target
  runs ET_EXEC/PIE, `+0x2000000` Ghidra rebases and deterministic repeats.

After installing the current extension, exercise import and target metadata
detection for every fixture with:

```bash
src/test/integration/headless-preflight.sh "$GHIDRA_INSTALL_DIR"
```

This preflight is intentionally weaker than the future integration suite: it
does not enable native export or run validators/GDB.

With `qemu-user-static` and `gdb-multiarch` installed, validate the non-host
fixture/runtime/debugger infrastructure against the compiler-DWARF reference
files:

```bash
src/test/integration/qemu-gdb-oracle.sh
```

That harness runs AArch64, ARM32, and both MIPS byte orders, checks a function
breakpoint and arguments, performs source stepping, prints a local, and waits
for normal process exit. It is an oracle/infrastructure test, not a Forge
sidecar test; the future exporter acceptance harness will load `.dbg` instead
of the reference binary's compiler DWARF.

The qualified-function regression reuses `function-static-scopes.c` with a
conditional real global `curated_same` definition. Preparation places two
other functions under `analysis_left::nested` and `analysis_right::nested`,
renames both `curated_same`, and retains their separate owned static objects.
Run it through the actual installed exporter with:

```bash
FORGE_SCOPE_QUALIFIED=1 src/test/integration/function-static-scopes-export.sh \
    "$GHIDRA_INSTALL_DIR" x86_64 aarch64 arm32 mips32be mips32le
```

The ordinary static-scope mode is unchanged when the variable is unset. Each
mode checks non-PIE, PIE and rebased PIE against compiler addresses, GDB values,
source and stepping; qualified mode additionally checks distinct full display
names and a global function with the same short name. Every case repeats export
and compares both output files, preserves input hashes and runs GNU/LLVM/strict
validators. `FORGE_ARM32_SYSROOT` optionally selects an existing private ARM32
runtime sysroot; CI retains the installed `/usr/arm-linux-gnueabihf` default.


`path-traversal-export.py` reuses `minimal.c` for a Linux x86-64 saved-program
fixture. It checks real directory-link/`..` input/output selection, input-leaf
default names, output-link replacement, original/source alias rejection and
missing-input guidance. Exact paths/hashes, byte-identical pairs, preserved
program databases, validators and GDB values/source lookup from an unrelated
working directory are required. `--expectation baseline-reproducer` requires
the old wrong-path behavior and never counts as a passing correction. See
`docs/FILESYSTEM-PATHS.md` for host semantics and the two explicitly recorded
Ghidra index-backup files.

### Formal structure return

`formal-function-return.c` is an ordinary x86-64 SysV caller/callee fixture
returning three 64-bit fields. The dedicated `formal-function-return-export.sh`
harness preserves its original `-O1` probe flags, compares compiler and exported
return types, checks the hidden destination parameter, and verifies actual
returned memory and caller observations in GDB. The original input remains
unchanged. This is not a general aggregate-ABI claim.
