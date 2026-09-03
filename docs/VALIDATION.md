# Validation record

Local validation date: 2026-09-03
Ghidra: 12.0.3
Host: Linux x86-64
Host JVM used by Ghidra/Gradle: OpenJDK 25.0.4
Extension bytecode target: Java 21

This record distinguishes container/oracle validation from real Forge DWARF
export. Export remains explicit: installed wrappers request checksum-verified
packaged natives by default, while source-tree audit runs may supply explicit
library paths.

## Ancillary local checks

```bash
find src/test/integration -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
```

Result: PASS.

`actionlint` 1.7.12 accepted the workflow. The CI workflow also
downloads that pinned release, verifies it against the upstream checksum file,
and rejects workflow changes that fail linting. The historical Maven shaded
JAR path, committed wrapper natives, and unpacked JNA tree were removed in
favor of the Gradle extension plus CI-native release path.

```bash
src/test/integration/release-package.sh
```

Result: PASS. Two assemblies from identical inputs were byte-identical; all
platform and release manifests verified and executable wrapper permissions
were preserved. This synthetic assembly test does not substitute for the
hosted clean-install native exports.

## Hosted continuous validation

**CONFIRMED:** GitHub Actions run 33751896850 passed workflow lint, pinned
Linux and Windows libdwarf builds, the extension build, x86-64/AArch64/MIPS32
target integration, the Windows-hosted exporter, and the aggregate
`required-validation` job. Each job records exact Ghidra, libdwarf, Java,
compiler, binutils, validator, GDB, and applicable QEMU versions. Native smoke
tests run through an isolated crash-status wrapper, and diagnostic artifacts
are retained for 14 days even when a job fails.

**CONFIRMED:** GitHub Actions run 33757707307 passed all 11 jobs, including the
aggregate gate, after adding an ARM32 target job using `arm-linux-gnueabihf`,
an ARMv7 hard-float little-endian ARM-state fixture, `qemu-arm-static`, and
`gdb-multiarch`. The lane passed real Ghidra export for ET_EXEC, PIE,
shared-object, no-build-ID, and no-section-table inputs; GNU readelf, LLVM
verification, independent dwarfdump, and the runtime GDB oracles accepted the
artifacts. This evidence does not claim Thumb, big-endian ARM, or other ARM ABI
profiles.

**CONFIRMED:** after the repository became public on 2026-09-03, `main` branch
protection was enabled with strict/up-to-date status checking and
`required-validation` as its required GitHub Actions check. Force pushes and
branch deletion remain disabled.

**CONFIRMED:** GitHub Actions run 33778570507 passed all 12 jobs after the
native ABI audit and `.debug_str` implementation. Both Linux and Windows
compiled and ran the pinned-header C ABI probe, built patched libdwarf twice,
and passed functional file/export/dependency equivalence. All five target
lanes passed isolated producer smoke, real headless export, GNU/LLVM/libdwarf
structural validation, and native/QEMU GDB behavior with `.debug_str` and
`DW_FORM_strp`. The Windows host passed opaque producer-error callback
delivery, file-lock rollback, explicit-native export, and packaged-native
export.

The required workflow now also assembles the Linux/Windows native release ZIP
twice, compares it byte for byte, verifies every embedded SHA-256 manifest,
and installs that aggregate artifact for real exports on both host operating
systems without external native paths. `required-validation` cannot pass when
release assembly or either clean-install export is skipped or fails.

## Windows-hosted lane

**CONFIRMED:** `.github/workflows/ci.yml` defines a Windows lane
that builds the pinned libdwarf 2.3.2 DLL pair under MSYS2 MinGW64, checks
required exports, recursively resolves non-system runtime DLL dependencies,
and records DLL hashes, compiler identity, configure flags, and dependency
names. A second Windows job installs Ghidra 12.0.3, runs the isolated native
producer plus native-independent source/publication tests, and performs a real
headless export of the Linux x86-64 ELF fixture.

The PowerShell harness preserves the input hash, rejects staging leftovers and
CR bytes, requires the generated `.dbg.c` to match the Linux lane byte for
byte, compares ELF identity/build ID, and runs Windows GNU `readelf` plus LLVM
DWARF verification. It also holds the existing source open with Windows
`FileShare.None`, forces the second publication move to fail, and proves the
old sidecar/source pair is restored without staged or backup leftovers. GitHub
Actions runs 33751896850 and 33778570507 passed the native DLL build/audit,
real Ghidra export, cross-host source comparison, file-lock rollback, and both
Windows validators. Run 33778570507 additionally passed the pinned-header ABI
probe, clean native rebuild comparison, error callback, and `.debug_str`
checks.
Earlier runs exposed and verified fixes for batch argument
transport, Ghidra's Windows drive-path spelling, and MSYS2 tool discovery. GDB
execution of ELF artifacts remains in the Linux native/QEMU jobs; PE/PDB is out
of scope.

The Windows batch launcher transports script options as separate name/value
tokens. The exporter accepts those tokens as well as the `--name=value` form
used on Linux and normalizes Ghidra's `/C:/...` Windows executable-path form
before Java filesystem access. A real Linux headless export with the split-token
form passed; the PowerShell invocation and Windows normalization then passed on
the hosted runner.

## Extension build

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew clean addressNormalizerSmoke outputPathPolicySmoke \
    exportReportSmoke syntheticSourceSmoke typeGraphSmoke variableStorageSmoke \
    dwarfInfoRepairSmoke dwarfLineTableSmoke \
    dwarfRangeListsSmoke dwarfLocationListsSmoke artifactPairPublisherSmoke \
    packagedNativeLibrariesSmoke buildExtension
```

Result: PASS. All twelve native-independent smoke tests passed and the
installable artifact was generated under `dist/`. `unzip -t` accepted the ZIP,
and inspection confirmed that the local `.ghidra-test` directory was not
packaged.

`dwarfLineTableSmoke` covers overlapping token evidence, one source line with
addresses in discontiguous function intervals, out-of-range evidence, separate
line sequences for each interval, and order-independent serialization. A
shared instruction address deterministically selects the earliest generated
source line.

`exportReportSmoke` covers stable JSON ordering and escaping plus `SUCCESS`,
`PARTIAL`, `CANCELLED`, and `FATAL` terminal states. A real x86-64 headless
export emits `PARTIAL` with target identity, artifact hashes, libdwarf 2.3.2,
export counts, skipped-function reason codes, unavailable-location ranges, and
opaque-type diagnostics. The controlled decompiler-failure oracle reports
`functionsFailed: 1` and names `recovered_add`; its sidecar still passes GNU,
LLVM, independent libdwarf, and GDB checks. A mismatched-input preflight emits
`FATAL` and publishes neither output. Validator state is explicitly `NOT_RUN`
inside the export report because the development harness validates the final
artifact after the report is produced.

## Packaged headless wrapper

```bash
src/test/integration/headless-wrapper.sh
support/ghidra-dwarf-forge-headless \
  --ghidra-dir=/home/ziggy/ghidra_12.0.3_PUBLIC \
  --import=build/fixtures/x86_64/semantic.exec.stripped \
  --output=build/test-results/headless-wrapper/semantic.dbg
```

Result: PASS. The native-free wrapper contract covers temporary-import and
read-only existing-project arguments plus completed, partial, fatal, cancelled,
missing/multiple report, launcher-failure, and usage exit codes. Real Ghidra
returned `0` for `PARTIAL` and the wrapper converted an analyzeHeadless
zero-status script failure into exit `10` for `FATAL`. Repeated imports produced
byte-identical sidecar/source hashes; GNU readelf, LLVM verification, and
independent libdwarf validation passed. Both wrappers are included in the
extension ZIP. The PowerShell implementation parsed, launched the production
exporter, and completed its report/artifact contract on the hosted Windows run.

## Pinned libdwarf producer ABI

Using a local build of pinned libdwarf v2.3.2:

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew nativeProducerSmoke \
  -PlibdwarfPath=<audit-build>/libdwarf.so.2.3.2 \
  -PlibdwarfpPath=<audit-build>/libdwarfp.so.2.3.2 \
  -PtargetProfile=<x86_64|arm64|arm32|mips32be|mips32le>
```

Result: PASS for all five profiles in separate JVM processes. Each run
created a DWARF 5 CU and subprogram, retrieved `.debug_info`,
`.debug_abbrev`, and `.debug_str`, validated a version-2 symbolic relocation
buffer, checked target-address and string-table relocations, and finished
cleanly. Each run also deliberately passes `DW_AT_data_bit_offset` to
libdwarfp's restricted fixed-width constant helper, checks the expected
`DW_DLE_INPUT_ATTR_BAD (143)`, and safely decodes the producer error both from
an explicit error output and through the opaque callback. This specifically
guards the producer/consumer `Dwarf_Error_s` layout mismatch.

The local audit build applies
`native/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch` to the
pinned v2.3.2 source. A clean second Linux build produced functionally
equivalent library file sets, ELF identity, exports, SONAME/dependencies, and
normalized RUNPATH. The exact binary hashes differed because the compiler
embedded distinct build paths/build IDs; both sets are recorded rather than
misrepresented as byte reproducible. The pinned-header C ABI probe compiled
with warnings as errors and reported 64-bit `Dwarf_Unsigned`, `Dwarf_Signed`,
`Dwarf_Off`, and `Dwarf_Addr`, plus the expected callback/function signatures
and 24-byte relocation record layout.

## Cross-target fixtures and Ghidra

```bash
make -C src/test/fixtures all
src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
FIXTURE_SUFFIX=exec.no-sections.stripped \
  src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
FIXTURE_SUFFIX=pie.stripped \
  src/test/integration/headless-preflight.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC
```

Result: PASS for x86-64, AArch64, MIPS32 big-endian, and MIPS32 little-endian.
Ghidra selected the expected processor, byte order, address size, and pointer
size. This is import/preflight evidence, not export evidence.

## Matched sidecar container

```bash
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC \
  ./gradlew sectionlessSidecarSmoke
```

Result: PASS for all four architectures and three variants per architecture:
ordinary ET_EXEC, PIE, and ET_EXEC with no input section-header table. The
writer preserved class, byte order, type, machine, flags, note/build-ID data,
and original input hashes. It created a new `SHT_STRTAB` `.shstrtab` and
section table where none existed.

Every generated container then passed without sidecar warnings:

```bash
readelf -h <sidecar>
readelf -S <sidecar>
readelf -n <sidecar>
readelf --debug-dump=info <sidecar>
readelf --debug-dump=abbrev <sidecar>
readelf --debug-dump=decodedline <sidecar>
```

The DWARF payload in this test comes from the fixture's compiler-DWARF
reference file. The test validates packaging, byte order, and loading—not the
future Forge semantic producer.

## GDB/QEMU behavior oracle

```bash
for role in exec exec.no-build-id exec.no-sections pie; do
  FIXTURE_ROLE="$role" DEBUG_ARTIFACT_SUFFIX=forge-container.dbg \
    src/test/integration/qemu-gdb-oracle.sh
done
```

Result: PASS on x86-64 natively and on AArch64/MIPS BE/MIPS LE through QEMU.
For all 12 cases GDB:

- loaded the stripped original and external matched sidecar;
- broke at `recovered_add` at the correct runtime address;
- reported arguments `left=19` and `right=23`;
- performed a source-level step;
- printed local `sum` as 42; and
- observed normal process exit.

QEMU AArch64 exposes a system-supplied synthetic DSO that this host GDB warns
has a corrupt string-table index. The same warning occurs with the unmodified
compiler reference and is not emitted for the sidecar itself. Sidecar
`readelf` checks are warning-free.

## Real headless Forge function/source-line/type export

Using the installed extension and the same explicit pinned native pair:

```bash
for role in exec exec.no-sections pie; do
  FIXTURE_ROLE="$role" src/test/integration/headless-symbol-export.sh \
    /home/ziggy/ghidra_12.0.3_PUBLIC \
    <audit-build>/libdwarf.so.2.3.2 \
    <audit-build>/libdwarfp.so.2.3.2
  FIXTURE_ROLE="$role" src/test/integration/qemu-gdb-symbols.sh
done
```

Result: PASS for x86-64, AArch64, MIPS32 big-endian, and MIPS32
little-endian—16 real exports in this executable section. Headless Ghidra
emitted deterministic synthetic source, evidence-backed line rows, canonical
types/signatures, and recovered contiguous/discontiguous functions depending
on target/input. It
also emitted honest unavailable locals, stable register locals, SP-relative
stack location lists, and exact register composites. It preserved address gaps
with DWARF 5 range lists. For every sidecar:

- original input SHA-256 was unchanged;
- `readelf -h`, `-S`, `-n`, `--debug-dump=info`,
  `--debug-dump=abbrev`, `--debug-dump=aranges`, `--debug-dump=decodedline`,
  and `--debug-dump=loc` completed without sidecar warnings;
- LLVM 18.1.3 `llvm-dwarfdump --verify` and libdwarf 20210528
  `dwarfdump -ka -ks` passed;
- GDB listed the generated function, resolved both function and explicit
  file/line breakpoints, executed `next`, `step`, and `nexti` through useful
  mapped code, and hit the expected runtime addresses; and
- for ET_EXEC/PIE, GDB `ptype` validated the analyst-applied function
  prototype, recursive struct, aggregate/member layout, union, array, signed
  enum, typedef, function pointer, variadic signature, and no-return
  signature; and
- for ET_EXEC/PIE, GDB resolved the analyst-applied `int fixture_sink`, read
  zero before its assignment, stepped the recovered statement, and read 42;
  and
- for ET_EXEC/PIE, GDB displayed the analyst-applied locationless local as
  `analyst_local = <optimized out>` rather than reading invented storage; and
- for ET_EXEC/PIE, GDB read `analyst_register` as 31, reconstructed the
  two-register `analyst_composite` as `0x1122334455667788`, and read
  `analyst_stack` as 42 both before and during a controlled SP adjustment; and
- for ET_EXEC/PIE, GDB displays the real favorite Ghidra `packed_flags`
  structure with unsigned 3-bit and 5-bit fields; and
- for ET_EXEC/PIE, `readelf` reports `DW_AT_calling_convention: normal` on the
  explicitly curated `recovered_add` signature; and
- for ET_EXEC/PIE, a typed `external_counter` declaration has
  `DW_AT_declaration`/`DW_AT_external` but no invented location, while
  `scoped_counter` is a child of the preserved `analyst_scope` namespace and
  GDB reads its defined value as 7; and
- the inferior exited normally, natively on x86-64 and under QEMU for the
  other targets.

For ordinary ET_EXEC and PIE inputs, a test-only post-analysis script renamed
the known fixture function to `recovered_add` with `USER_DEFINED` provenance
before export. It also applies `USER_DEFINED int recovered_add(int left,
int right)`, three analyst local-storage cases, and favorite recursive fixture
types. `readelf` and GDB observe that curated state rather than only initial
loader symbols. Two fresh x86-64 headless analyses produced byte-identical
outputs after the loaded-memory global filter and P1.9
declaration/namespace milestone:

```text
3d346c6f6e02e6da80f145a05cf445e4c1b88015cc6d45b8e04b0163051512c1  semantic.exec.ghidra-forge.dbg
c743c8f3dba3b7884b4d40c76e93e1c0208302c37384ce2351d498fc98423a2d  semantic.exec.ghidra-forge.dbg.c
```

These are validation-fixture hashes, not release artifact checksums; update
them after an intentional producer-string or semantic change.

## Explicitly rebased Ghidra project

```bash
src/test/integration/rebased-program-export.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS. The harness compared fresh analyses at the ELF loader base and
at a Ghidra image base shifted by `0x2000000`. The rebased export retained
original ELF link-time PCs, ranges, global addresses, and location-list ranges;
GNU readelf, LLVM, independent libdwarf, and the complete native x86-64 GDB
source/type/variable oracle passed. The original ELF hash was unchanged.

The `.dbg` and `.dbg.c` hashes differ between the two Ghidra databases because
Ghidra rewrites address-derived `FUN_...`/`DAT_...` names and decompiler text
when its database is rebased. Those strings are preserved as current Ghidra
knowledge; executable DWARF addresses are normalized. The regression also
found and fixed an unrelated loader-artifact leak: labels in non-loaded memory
blocks such as `ElfComment` are no longer exported as runtime globals.

## Output path and stale-input recovery

```bash
src/test/integration/output-path-policy.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS. The test changes the imported program's stored executable path
to a nonexistent file, supplies the original through explicit `--input`, and
omits `--output`. The exporter verifies the supplied file against Ghidra's
imported SHA-256 and publishes the required defaults
`semantic.exec.stripped.dbg` and `semantic.exec.stripped.dbg.c` beside the
input. The real artifact passes the normal readelf/LLVM/libdwarf checks, the
input hash is unchanged, no pair-specific staging file remains, and final
input/output/source SHA-256 values are reported.

`outputPathPolicySmoke` independently covers deterministic default/explicit
naming, missing input, original-file alias rejection, nonexistent output
directories, and an injected unwritable-directory result. GUI directory
selection is implemented for a valid input whose default destination fails,
but is **PRESENT, UNVERIFIED** in an interactive Ghidra process.

## Build-ID discovery

```bash
src/test/integration/build-id-discovery.sh
```

Result: PASS. The harness installs the x86-64 sidecar temporarily at
`.build-id/8c/97fca5bc3a09a3f115eb66d515c95b16f21783.debug`, points GDB's global debug
directory at that tree, and loads only the stripped original. Without any
`symbol-file` command, GDB discovers the sidecar, lists and types
`recovered_add`, displays synthetic source, breaks with arguments 19/23, and
leaves the original hash unchanged.

As a negative control, the harness first places the PIE sidecar under the
non-PIE build-ID path. GDB reports that it has a different build ID and skips
it. All four target lanes also export a `--build-id=none` fixture, verify that
its sidecar does not invent a build ID, and pass the explicit `symbol-file`
GDB/QEMU behavior oracle.

## Shared-object export and runtime loading

```bash
FIXTURE_ROLE=shared src/test/integration/headless-symbol-export.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
src/test/integration/shared-object-gdb.sh
```

Result: PASS for native x86-64 and QEMU-backed AArch64, MIPS32 big-endian,
and MIPS32 little-endian. Each stripped `ET_DYN` input passes `readelf`, LLVM,
and independent libdwarf validation. GDB can inspect types and link-time
source rows before the library is mapped. Once the loader maps the library,
the tested manual loading sequence is:

```gdb
set auto-solib-add off
file <stripped-driver>
# Run or continue until the shared library appears in `info sharedlibrary`.
# BIAS = relocated .text start - link-time .text address.
add-symbol-file <library>.ghidra-forge.dbg -o BIAS
break recovered_add
continue
```

The automated harness derives `BIAS` from `info sharedlibrary`, verifies it is
nonzero, and checks that the relocated function and global addresses are
outside every main-executable `PT_LOAD` range. The breakpoint receives 19 and
23 on the targets whose stable parameter registers are exportable; AArch64
reports its intentionally omitted overwritten registers as optimized out. In
every lane, GDB recognizes the typed locationless external declaration and the
namespace child, reads `scoped_counter` as 7, reads `fixture_sink` as zero
before the recovered assignment and 42 after stepping it, then observes normal
process exit.

`artifactPairPublisherSmoke` also injects a failure after the staged sidecar is
installed. It verifies that an existing sidecar/source pair is restored and
that a fresh failed publication leaves neither final path behind. Production
uses the same stage-and-publish helper and supplies Ghidra cancellation as its
pre-publication callback. The smoke test injects cancellation after both
staging writers finish and verifies that the prior final pair remains intact
and no staging file survives.

## Controlled decompiler failure

```bash
src/test/integration/controlled-decompiler-failure.sh \
  /home/ziggy/ghidra_12.0.3_PUBLIC \
  <audit-build>/libdwarf.so.2.3.2 \
  <audit-build>/libdwarfp.so.2.3.2
```

Result: PASS on Linux x86-64. The headless test forces `recovered_add` through
the production per-function exception path, requires exactly one failed
decompilation and a later successful one, and verifies the diagnostic source
comment. The failed function remains an addressed, symbol-only subprogram DIE
without source/type/variable assertions. `readelf`, `llvm-dwarfdump --verify`,
`dwarfdump`, and GDB accept the result; GDB resolves the failed function but
has no line for it, while a later function retains its source line.

The exporter deliberately omits Ghidra functions marked external/import or
thunk and emits a diagnostic for each. Treating those stubs as ordinary
addressed definitions produced misleading decompiler output; external-function
declarations, linkage names, thunks, and aliases remain future work. Typed
external-data declarations are covered by the real-export matrix above. Every
integration lane asserts that the function-omission policy was exercised.

The x86-64 fixture's recovered `FUN_00401090` has real intervals
`[0x401090,0x4010ae)` and `[0x4010b0,0x4010b1)`. `readelf` reports two
`DW_RLE_start_end` entries under one subprogram `DW_AT_ranges`; GDB resolves
both addresses to `FUN_00401090` and reports no line information at the gap
address `0x4010ae`. The CU has its own merged, non-gap-covering `DW_AT_ranges`.
`.debug_aranges` is intentionally absent because it is an optional accelerator,
not required for the validated GDB lookup path.

Global extraction is deliberately narrower than “every address with a name”:
the symbol must be a primary, non-default, non-external Ghidra label with
defined listing data at the same memory address. Its type joins the canonical
graph and its definition receives a `DW_OP_addr` location. The curated
`fixture_sink` test passes on x86-64, AArch64, MIPS32 BE, and MIPS32 LE for
ET_EXEC and PIE; PIE values remain correct after runtime load-bias relocation.
The no-section-table roles continue to export only information Ghidra actually
recovers and do not require the preparation label.

PIE inputs were loaded by Ghidra at a nonzero analysis base. The exporter
normalized those addresses back to ELF link-time VAs. GDB then applied ASLR
correctly: the x86-64 breakpoint, for example, was described by DWARF at
`0x1149` and hit at a randomized `0x5555...5151` runtime address.

The no-section-table runs are the real regression for ghidra2dwarf issue 29:
headless export did not crash, the writer created the output section table,
and source generation, line tables, structural validation, and runtime source
stepping passed for all four targets. The type/signature path is also active on
these inputs (using only information Ghidra actually recovers); future variable
paths must retain the same regression.

libdwarf 2.3.2 does not generate producer `.debug_line` for DWARF 5. The Forge
path therefore writes its deterministic DWARF 5 line program in Java and uses
the audited producer for CU/subprogram DIEs. The file table includes an
explicit `.` directory: GNU `readelf` and LLVM accept an empty directory table,
but Ubuntu's older libdwarf consumer crashes while resolving source paths when
it is empty.

The producer's public `dwarf_add_AT_dataref_a` writes eight-byte section-offset
payloads in an otherwise DWARF32 ELF64 CU. Forge parses the
producer `.debug_abbrev`/`.debug_info`, removes the surplus bytes, adjusts all
CU-relative `DW_FORM_ref4` targets, and fails on unknown forms/layouts. A
native-free smoke test covers the repair; all emitted type references pass LLVM
verification.

## Independent DWARF validators

After installing Ubuntu's `llvm` and `dwarfdump` packages, every real Forge
function/source/type sidecar in the four-target by three-input-role matrix passed:

```bash
llvm-dwarfdump --verify <sidecar>
dwarfdump -ka -ks <sidecar>
```

Full transcripts are retained under
`build/test-results/headless-symbol-export/`, and the headless integration
harness runs both validators for every artifact.

`dwarfdump -ka` reports two harmless `.eh_frame` length-alignment diagnostics
for the x86-64 fixture. The matched sidecar retains those original target
sections byte-for-byte, and the same diagnostics occur on the original input;
they are not emitted from Forge DWARF sections. There are zero line-table,
abbreviation, DIE, range, or declaration-file errors.
