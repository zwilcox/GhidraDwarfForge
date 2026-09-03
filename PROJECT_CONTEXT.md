# PROJECT_CONTEXT.md — GhidraDwarfForge

This document is the durable project handoff for GhidraDwarfForge. It captures the intended product, the verified repository state, the prototype architecture, known hazards, and unresolved decisions.

- Repository: `zwilcox/GhidraDwarfForge`
- Default branch: `main`
- Handoff baseline: `7a39a186538c7aec3f7dbdc4a6e396125b5d63ea`
- Baseline commit date: 2025-06-22
- Handoff snapshot date: 2026-09-01

## 1. Evidence and status labels

This handoff distinguishes repository facts from intended behavior.

- **CONFIRMED REQUIREMENT** — established in the project discussion and intended to survive implementation changes.
- **CONFIRMED REPOSITORY FACT** — directly observed at the handoff baseline.
- **PRESENT, UNVERIFIED** — implementation exists, but no retained end-to-end evidence proves correctness.
- **PLANNED** — desired behavior or architecture not yet implemented.
- **HISTORICAL** — found in an old commit, issue, or crash log; it may not reproduce in the current code.
- **UNCERTAIN** — evidence is insufficient. Codex must investigate rather than guess.

The issue tracker is stale in places. A still-open issue does not prove the related code is absent, and code that emits a section name does not prove the issue is complete.

## 2. Executive summary

### 2.1 Product statement

**CONFIRMED REQUIREMENT:** GhidraDwarfForge takes an analyzed ELF program in Ghidra—typically a stripped executable or shared library—and exports Ghidra’s current reconstructed knowledge as:

```text
<binary>          # original target, unchanged by default
<binary>.dbg      # separate ELF artifact containing reconstructed DWARF
<binary>.dbg.c    # deterministic synthetic/decompiled C referenced by DWARF
```

The intent is to debug the original target in GDB using recovered function names, types, variables, and source-like stepping even though the original compiler’s debug information is absent.

### 2.2 Definition of done

The project is not done when it merely writes an ELF file or displays section names in `readelf -S`.

A complete supported path must demonstrate all of the following:

1. A clean checkout builds a distributable Ghidra extension.
2. The extension runs without crashing the Ghidra JVM.
3. The original executable remains byte-for-byte unchanged in default mode.
4. The generated sidecar is structurally valid ELF and DWARF 5.
5. Independent validators report no unexplained errors.
6. GDB associates or explicitly loads the sidecar at the correct addresses.
7. GDB can resolve recovered functions, list the generated source, and step through useful source mappings.
8. Types and variables are inspectable when Ghidra has defensible information.
9. Unsupported or uncertain information is omitted or diagnosed rather than fabricated.
10. Every architecture and host-platform support claim is backed by tests.

A representative target experience is:

```gdb
(gdb) info functions
(gdb) break recovered_function
(gdb) list recovered_function
(gdb) next
(gdb) step
(gdb) print recovered_variable
(gdb) ptype recovered_structure
```

## 3. Goals

### 3.1 Primary goals

**CONFIRMED REQUIREMENT:**

- Convert the current curated Ghidra program into a usable separate DWARF debug artifact.
- Export a companion decompiled C file that GDB can display as synthetic source.
- Preserve analyst work: renamed functions, symbols, signatures, types, variable names, calling conventions, and other applied knowledge.
- Enable source-like GDB workflows against stripped ELF firmware and native binaries.
- Produce standards-compliant DWARF 5 rather than a tool-specific metadata format.
- Keep the default workflow non-destructive to the original target.
- Build a self-contained Ghidra extension that bundles the required native producer libraries.
- Support GUI use first and provide a headless path after the core exporter is stable.

### 3.2 Quality goals

**CONFIRMED REQUIREMENT:**

- Deterministic output for an unchanged Ghidra program.
- Architecture-neutral extraction and serialization.
- Accurate address, range, type, and variable-location semantics.
- Graceful per-function failure isolation.
- Prompt cancellation and complete cleanup.
- Reproducible native dependencies and builds.
- Small, redistributable automated fixtures and behavior tests.
- Mandatory end-to-end integration-pipeline coverage for x86-64 and AArch64
  targets before the first supported release.
- An architecture-extensible design whose intended scope includes MIPS and
  other Ghidra-supported ELF processors; MIPS is the planned first
  32-bit/big-endian expansion and should use QEMU for integration testing when
  native hardware is unavailable.

### 3.3 Non-goals

**CONFIRMED REQUIREMENT:**

- Recovering the literal original source code.
- Claiming inferred Ghidra information came from the original compiler.
- Making the generated decompiler output recompilable.
- Inventing variable locations, types, names, or source lines to make GDB output look complete.
- Modifying the original ELF by default.
- PE/PDB or Mach-O/dSYM support before the ELF milestone is complete.
- Advanced accelerators such as `.debug_names`, compression, or indexing before core DIE, line, type, range, and location correctness.

## 4. Inspiration

### 4.1 `cesena/ghidra2dwarf`

`ghidra2dwarf` is the closest direct user-experience reference. Its README describes a Ghidra plugin that exports functions, decompiled code, and types into DWARF inside an ELF artifact, alongside a generated C file. It demonstrates GDB operations such as:

- `list <function>`
- source-line `n`
- instruction-level `ni`
- `p variable`

Repository: `https://github.com/cesena/ghidra2dwarf`

GhidraDwarfForge is not required to copy its implementation. The intended improvement is a maintainable Java/Ghidra API implementation with a carefully audited JNA/libdwarfp boundary, modern DWARF 5 semantics, deterministic source correlation, and stronger validation.

### 4.2 `ALSchwalm/dwarfexport`

`ghidra2dwarf` credits `dwarfexport` as its inspiration. `dwarfexport` is an unmaintained IDA/Hex-Rays plugin that emits a `.c` file and `.dbg` file so recovered reverse-engineering information can be used in GDB.

Its architecture notes are relevant because they explicitly call out:

- Mapping disassembler register numbers to DWARF register numbers.
- Computing register-relative stack-variable locations.
- Implementing architecture-specific location logic.

Repository: `https://github.com/ALSchwalm/dwarfexport`

The lesson for this project is not to hard-code one architecture’s frame pointer or register numbering in generic code.

A source-level comparison of both reference projects, including the exact
reviewed commits and patterns that must not be inherited, is recorded in
`docs/REFERENCE_PROJECTS.md`.

### 4.3 GDB separate-debug-file workflow

The output model is inspired by GDB’s separate-debug-file mechanism: debugging data can live outside the stripped executable while describing the same program image.

Relevant association mechanisms include:

- Matching build IDs.
- `.gnu_debuglink` plus CRC.
- Explicit GDB loading commands.

The exact association strategy for GhidraDwarfForge remains **UNCERTAIN** and is a P0 design decision. Modifying the original executable to add `.gnu_debuglink` must remain optional and explicit.

Reference: `https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html`

### 4.4 Compiler-generated DWARF as the semantic model

The conceptual model is that Ghidra acts as a reverse compiler:

- Decompiled output becomes synthetic source.
- Ghidra functions become `DW_TAG_subprogram` DIEs.
- Ghidra signatures become return/parameter type references.
- Ghidra variables become parameter/local/global DIEs with defensible locations.
- Ghidra data types become a canonical DWARF type graph.
- Decompiled token address sets become line-table rows and ranges.

The exporter must remain honest about the fact that this information is reconstructed.

### 4.5 libdwarf producer mode

The implementation is intended to use libdwarf’s producer API (`libdwarfp`) rather than hand-encoding every abbreviation and DIE form. A JNA bridge is used so the exporter can remain in Java and integrate directly with Ghidra APIs.

Upstream repository: `https://github.com/davea42/libdwarf-code`

### 4.6 Project identity

The repository tagline is:

> hammering debug sections straight into your ELF.

This is the source of the “Forge” name and captures the intended focus on generating real debugger-consumable artifacts.

## 5. Functional requirements

### 5.1 Non-destructive sidecar output

**CONFIRMED REQUIREMENT:**

- Default output directory is the original target’s directory.
- Default debug artifact name is `<original-file>.dbg`.
- Default generated source name is `<original-file>.dbg.c`.
- The original target is unchanged by default.
- Optional target mutation, such as adding `.gnu_debuglink`, requires explicit user intent and safe handling.
- The sidecar must correspond to the same target image: architecture, ELF class, endianness, ABI flags, address size, section-address semantics, image base/load bias, and build identity.
- PIE executables and shared objects require correct relocation/load-bias behavior.
- ELF inputs without a section-header table are valid and supported. A
  program-header-only image with zero `e_shoff`, `e_shnum`, and `e_shstrndx`
  must not crash export; the sidecar must construct a new section table and
  `.shstrtab` while leaving the input unchanged.

**UNCERTAIN:** what to do when `Program.getExecutablePath()` is absent, stale, remote, or read-only. This requires a designed output-selection/fallback policy.

### 5.2 Standards-compliant DWARF 5

**CONFIRMED REQUIREMENT:** The final exporter targets DWARF 5.

The complete semantic model should include, when the underlying Ghidra information exists:

- One or more `DW_TAG_compile_unit` DIEs.
- `DW_TAG_subprogram` DIEs for recovered functions.
- `DW_AT_name` and `DW_AT_linkage_name` where applicable.
- `DW_AT_low_pc`/`DW_AT_high_pc` or `DW_AT_ranges`.
- `DW_TAG_formal_parameter` and local/global variable DIEs.
- Function return types and parameter types.
- Base, pointer, reference, array, typedef, qualified, enumeration, structure, union, and subroutine types.
- Structure/union members and correct offsets.
- Namespace or class-like scope information when meaningful.
- `DW_AT_decl_file`, `DW_AT_decl_line`, and `DW_AT_stmt_list` tied to `.dbg.c`.
- A real `.debug_line` program mapping addresses to generated source lines.
- Location expressions and `.debug_loclists` where variable storage changes.
- `.debug_rnglists` for discontiguous ranges where appropriate.
- `.debug_str`, `.debug_addr`, and other support sections required by chosen forms.

`.debug_frame` is listed in the original issue tracker, but whether GhidraDwarfForge should synthesize unwind information or rely on the target’s existing unwind sections is **UNCERTAIN**. It must not be emitted inaccurately.

### 5.3 Decompiled-source correlation

**CONFIRMED REQUIREMENT:** `.dbg.c` is the synthetic source GDB displays; it is not merely a decompiler report.

It must be:

- Deterministic for an unchanged Ghidra program.
- Generated in stable function order with stable formatting.
- Produced together with an exact address-to-line model.
- Correlated using decompiler token address sets or another evidence-backed mapping.
- Able to represent a source statement associated with multiple/discontiguous instruction ranges.
- Careful not to assign executable addresses to comments, declarations, blank lines, or formatting-only lines unless intentionally modeled.

A decompilation failure for one function must not abort the export. The exporter should retain a symbol-only function DIE and write a diagnostic comment in the synthetic source according to a documented format.

### 5.4 Preserve Ghidra’s curated state

**CONFIRMED REQUIREMENT:** Export the current Ghidra database, including analyst changes.

Relevant information includes:

- Renamed functions and symbols.
- Explicitly applied function signatures.
- Return types and parameter types.
- Calling conventions.
- Parameter and local-variable names.
- Variable storage and live ranges when known.
- Structures, unions, enums, arrays, pointers, typedefs, and qualifiers.
- Global symbols and memory objects.
- Namespaces and class-like scopes when meaningful.
- Thunks, aliases, imports, and external declarations according to a defined policy.
- Discontiguous function bodies.

Analyst-defined information should take precedence over weaker decompiler inference.

### 5.5 Variable locations

**CONFIRMED REQUIREMENT:** Variable-location accuracy is a core feature, not an optional polish item.

A variable can:

- Live at a stack offset.
- Live in a register.
- Move between registers and stack locations.
- Occupy multiple pieces.
- Be live for only part of a function.
- Be optimized away or unrecoverable.

The exporter must use proper DWARF expressions and location lists where defensible. It must not assume x86-64, `RBP`, one stack model, or one representative `Varnode` for a variable’s complete lifetime.

When no reliable location is available, emit a declaration/type without a location or omit it with a diagnostic. Do not invent one.

### 5.6 Architecture-neutral behavior

**CONFIRMED REQUIREMENT:** Derive target properties from Ghidra and the original ELF.

The implementation must account for:

- Processor and ABI.
- ELF machine and architecture-specific flags.
- Pointer/address size.
- Endianness.
- Register identity and DWARF register numbering.
- Calling convention and parameter storage.
- Stack direction and frame semantics.
- Link-time addresses, Ghidra image base, and runtime load bias.

The first release validation matrix is intended to cover x86-64 and AArch64,
including non-PIE, PIE, and shared-object cases. The design is not limited to
those processors. MIPS is the planned first 32-bit/big-endian expansion, with
QEMU-backed GDB behavior tests when native hardware is unavailable.
Linux-hosted and Windows-hosted Ghidra are intended support targets.

### 5.7 Self-contained Ghidra extension

**CONFIRMED REQUIREMENT:** The finished product is an installable Ghidra extension, not a manual collection of scripts and system-wide native dependencies.

It should:

- Bundle compatible `libdwarf` and `libdwarfp` native libraries.
- Load them safely through JNA.
- Avoid requiring a system-wide libdwarf install.
- Run from Ghidra’s Script Manager or extension UI.
- Provide progress and cancellation for large binaries.
- Eventually expose an equivalent headless workflow.
- Produce useful diagnostics without terminating Ghidra.

## 6. Important decisions

### 6.1 Confirmed project decisions

- **ELF first.** Other executable/debug formats wait until the ELF path is complete.
- **DWARF 5 target.** Do not regress the product target to an older DWARF version merely because the prototype is limited.
- **Separate artifact by default.** Keep the original target unchanged.
- **Companion synthetic source.** `.dbg.c` is a first-class artifact referenced by DWARF.
- **Ghidra is the source of reconstructed truth.** Preserve analyst edits and distinguish reconstruction from original compiler facts.
- **Java/Ghidra API front end.** Extract program semantics inside Ghidra rather than parsing a text export.
- **libdwarfp producer back end.** Use a mature producer API, but audit the native boundary rigorously.
- **Validation is behavioral.** `readelf`, `llvm-dwarfdump`, `dwarfdump`, and GDB behavior determine correctness.
- **Omit rather than fabricate.** Especially for variable locations and source mappings.
- **Architecture-specific logic is isolated.** Generic code may not assume x86-64 details.
- **Ghidra 12.0.3 baseline.** Compile extension code as Java 21 bytecode; newer
  host JVMs are acceptable only when Ghidra itself accepts them and tests pass.

### 6.2 Prototype choices that are not yet durable decisions

**PRESENT, UNVERIFIED:**

- A single monolithic Ghidra script performs source export, DWARF construction, and ELF writing.
- libdwarfp is initialized with symbolic relocations.
- A custom Java `ByteBuffer` emitter writes an `ET_REL` ELF container.
- Function ranges are represented as one contiguous span from entry to max body address.
- Decompiled functions are appended directly in address order.

These choices may be replaced if tests show they cannot satisfy the requirements.

### 6.3 P0 decisions still open

- Exact pinned libdwarf tag/commit and artifact provenance scheme.
- Automatic GDB association behavior beyond the selected explicit matched
  sidecar workflow.
- Initial supported host/target matrix for the first release.
- How native libraries should coexist with Ghidra’s own JNA version.
- Output fallback/UI behavior when the executable path is unavailable or unwritable.
- Source mapping granularity and statement-selection rules.
- Confidence policy for variable locations and decompiler-only names/types.
- Licensing for the repository and bundled/generated native artifacts.

### 6.4 Selected ELF sidecar strategy

**CONFIRMED (2026-09-02):** ADR 0001 selects a matched, non-loadable ELF
sidecar derived from the original target. The sidecar retains ELF identity and
build-ID note content, clears its program-header table, and writes a fresh
section table containing reconstructed DWARF. GDB loads the original with
`file` and the sidecar with `symbol-file`; the original remains responsible for
PIE runtime mapping.

The pure-Java container writer and GDB oracle pass for x86-64, AArch64, MIPS32
big-endian, and MIPS32 little-endian across ET_EXEC, PIE, and ET_EXEC inputs
with no section-header table. The real producer now passes the same local
matrix using Ghidra-extracted contiguous functions, source lines, curated
function signatures, and canonical types. Variables/locations, discontiguous
ranges, shared objects, and packaged natives remain **PLANNED**.

## 7. Current repository state

### 7.1 Top-level layout

**CONFIRMED REPOSITORY FACT:** At baseline the root contains:

```text
.github/
.gitignore
README.md
jna-wrapper/
src/
```

There is no current Gradle wrapper, Ghidra extension module, automated test directory, release artifact, or repository license.

### 7.2 Current files of interest

```text
README.md
.github/workflows/buildLibDwarfJarWrapper.yml
jna-wrapper/pom.xml
jna-wrapper/src/main/resources/linux-x86-64/libdwarf.so*
jna-wrapper/src/main/resources/linux-x86-64/libdwarfp.so*
jna-wrapper/src/main/resources/win32-x86-64/libdwarf*.dll
jna-wrapper/src/main/resources/win32-x86-64/libdwarfp*.dll
jna-wrapper/target/...
src/DwarfConst.java
src/GhidraDwarfForgeFixed.java
src/LibDwarf.java
src/LibDwarfp.java
src/libdwarf.jar
src/temp/...
```

`src/temp/` contains unpacked/generated material, duplicate native resources/JAR contents, and a historical fatal JVM crash log. `.gitignore` is empty.

### 7.3 README

**CONFIRMED REPOSITORY FACT:** The current README contains only the project heading and the tagline “hammering debug sections straight into your ELF.” It does not document installation, supported versions, use, or validation.

### 7.4 Branches and releases

**CONFIRMED REPOSITORY FACT:**

- `main` and `debug_issue` both point to the same baseline commit.
- No releases were present at the handoff snapshot.
- No pull requests were present at the handoff snapshot.
- The GitHub API returned no retained Actions workflow runs. This does not prove the workflow was never run historically.

## 8. Current build and dependency system

### 8.1 Maven wrapper JAR

**CONFIRMED REPOSITORY FACT:** `jna-wrapper/pom.xml` defines:

- Group: `aldelaro5`
- Artifact: `libdwarf`
- Version: `1.0`
- Packaging: `jar`
- Java source/target: `1.7`
- JNA: `5.6.0`
- Maven Shade Plugin: `3.2.4`
- Shaded final name: `libdwarf`

The repository-defined packaging command is:

```bash
mvn -B -ntp -f jna-wrapper/pom.xml package -DskipTests
```

This packages JNA and native resources. It does not build a Ghidra extension, and there are no Maven tests at the baseline.

### 8.2 Native/JAR GitHub Actions workflow

**CONFIRMED REPOSITORY FACT:** `.github/workflows/buildLibDwarfJarWrapper.yml` is manual (`workflow_dispatch`) and sets:

```yaml
LIBDWARF_VERSION: main
```

That moving dependency is a reproducibility and ABI risk.

Linux job:

```bash
sudo apt-get install --no-install-recommends -y \
  build-essential zlib1g-dev libzstd-dev \
  autoconf automake libtool pkg-config patchelf

git clone --depth 1 --branch "$LIBDWARF_VERSION" \
  https://github.com/davea42/libdwarf-code libdwarf-code

sh autogen.sh
./configure --enable-shared \
  --enable-dwarfgen --disable-static --prefix="$PWD/install"
make -j"$(nproc)"
make install
```

The Linux job applies `$ORIGIN` RUNPATH to `libdwarfp.so*` and verifies it with `readelf`.

Windows job:

- Runs on `windows-latest`.
- Uses MSYS2 `MINGW64`.
- Installs the MinGW x86-64 toolchain, zlib, autotools, and pkg-config.
- Runs the same `autogen.sh`, `configure`, and `make` sequence but does not run `make install`.
- Copies versioned `libdwarf-*.dll` and `libdwarfp-*.dll` outputs.
- Verifies the producer DLL depends on the matching libdwarf DLL name.

Java job:

```bash
mvn -B -ntp -f jna-wrapper/pom.xml package -DskipTests
```

using Temurin Java 17.

Publish job:

- Downloads the native/JAR artifacts.
- Copies them into the repository.
- Commits changed binaries directly to `main` when the workflow runs on `main`.

### 8.3 Historical extension command

**HISTORICAL, UNVERIFIED:** An older README documented:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3_PUBLIC
./gradlew :DwarfForge:buildExtension && \
  cp DwarfForge/build/dist/DwarfForge.zip "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

The handoff baseline did not contain the referenced Gradle wrapper/module. The
replacement build described below supersedes this historical command.

### 8.4 Current Ghidra 12.0.3 extension scaffold

**CONFIRMED (2026-09-02):** The post-handoff tree contains a repository-owned
Gradle 9.3.1 wrapper, conventional `src/main/java` production sources,
extension metadata, and a native-free Script Manager/headless entry point.

```bash
export GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC
./gradlew clean buildExtension
```

This command produced an installable Ghidra 12.0.3 extension ZIP. The installed
extension was discovered by `analyzeHeadless`; it imported and analyzed a small
x86-64 non-PIE ELF and ran `GhidraDwarfForge.java` successfully. The script
reported the program identity, ELF format, language, pointer size, and image
base without loading libdwarfp.

This initially proved the build and safe entry-point scaffold. The later
milestones below supersede the original preflight-only limitation.

### 8.5 Pinned native ABI smoke result

**CONFIRMED (2026-09-02):** native production sources are pinned to official
libdwarf v2.3.2, commit
`af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`. The release archive SHA-256 is
`7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
The native workflow no longer tracks upstream `main` and no longer commits
rebuilt opaque binaries directly to `main`.

The new fixed-width JNA subset was audited against the pinned producer headers
and exercised in a child JVM using a local Linux build. The test initialized
the producer, created a DWARF 5 CU and subprogram, generated and retrieved
`.debug_info`/`.debug_abbrev`, validated symbolic relocation records, and
finished cleanly. It passed through the same Java path for:

- x86-64, 64-bit little-endian;
- AArch64, 64-bit little-endian; and
- MIPS, 32-bit big-endian.

This established the native ABI boundary before it was enabled in headless
Ghidra. The subsequent symbol-only integration described below now proves the
same producer path in matched sidecars. Windows native ABI coverage remains
**PLANNED**.

**CONFIRMED (2026-09-02):** the shared `semantic.c` fixture builds as stripped
non-PIE ET_EXEC inputs for x86-64, AArch64, MIPS32 big-endian, and MIPS32
little-endian. All four imported and analyzed successfully under headless
Ghidra 12.0.3. Preflight reported `x86:LE:64:default`, `AARCH64:LE:64:v8A`,
`MIPS:BE:32:default`, and `MIPS:LE:32:default`, respectively, with the expected
pointer sizes. This initially confirmed target detection; the later
symbol-only integration also exports these targets and exercises their
sidecars in GDB.

**CONFIRMED (2026-09-02):** after installing `qemu-user-static` and
`gdb-multiarch`, the AArch64 and both MIPS stripped fixtures executed normally
under QEMU. GDB connected through each emulator's remote stub using the
matching compiler-DWARF reference file, broke at `recovered_add`, observed
arguments 19 and 23, stepped source, printed local `sum` as 42, and observed
normal exit. This first proved the fixture/QEMU/GDB oracle infrastructure.
Real Forge-generated symbol sidecars now pass equivalent breakpoint tests.

**CONFIRMED (2026-09-03):** `.github/workflows/ci.yml` defines a
pinned Ghidra 12.0.3 extension build, a pinned libdwarf 2.3.2 Linux build, and
separate x86-64, AArch64, MIPS32 big-endian, and MIPS32 little-endian lanes.
Each target lane builds its fixture, checks the input hash, runs real headless
source/line export for ET_EXEC/PIE/shared/no-section inputs, validates with
`readelf`, `llvm-dwarfdump`, and `dwarfdump`, and runs native or QEMU-backed
GDB source-level behavior. GitHub Actions run 33747224613 passed every target
lane.

The same workflow now also defines a Windows-hosted x86-64 ELF lane. It builds
and audits the pinned MinGW64 DLL pair and its non-system runtime dependencies,
runs isolated producer/source/publication tests, then runs a real Ghidra 12.0.3
headless export against the Linux lane's stripped ELF. The harness requires
LF-only, byte-identical synthetic source; unchanged input; matched ELF/build
identity; and clean Windows `readelf` plus LLVM validation. GitHub Actions run
33747224613 passed the native Windows build and the Windows-hosted export lane.
ELF runtime/GDB behavior is still exercised by the Linux native/QEMU lanes;
this does not add PE/PDB support.

**CONFIRMED (2026-09-02):** the issue-29 no-section-header failure was
reproduced with source-built program-header-only fixtures. GNU objcopy cannot
add a section to these inputs. The new pure-Java writer instead creates a
fresh table and `.shstrtab`; external `readelf` checks and GDB/QEMU behavior
pass for ELF64 x86-64/AArch64 and ELF32 big/little-endian MIPS. This proves the
container is not dependent on an input section table. The final exporter must
retain this path and its atomic-output behavior.

**CONFIRMED (2026-09-02):** an x86-64 program explicitly rebased in Ghidra by
`0x2000000` exports PCs, discontiguous ranges, globals, source rows, and
location-list ranges in the original ELF link-time address domain. GNU
readelf, LLVM, independent libdwarf, and the complete native GDB behavior
oracle pass, and checked address-normalization tests cover positive/negative
deltas plus overflow. Ghidra's address-derived automatic names and decompiler
text change after a database rebase and are preserved honestly; they do not
change emitted executable addresses. This regression also excluded symbols in
non-loaded loader metadata blocks (for example `ElfComment`) from runtime
global export.

**CONFIRMED (2026-09-02):** output resolution now defaults to
`<original>.dbg`/`<original>.dbg.c`, accepts explicit `--input` and `--output`,
and validates readability, writability, existing targets, and aliasing before
decompilation/native production. A stale `Program.getExecutablePath()` test
passes by supplying the original ELF explicitly; the override must match
Ghidra's imported executable SHA-256. The real default artifact validates and
the original remains unchanged. The exporter reports all three hashes. GUI
directory fallback is **PRESENT, UNVERIFIED**; headless failures instead direct
the caller to an explicit writable output without prompting.

**CONFIRMED (2026-09-02):** the matched sidecar preserves the original build
ID and GDB automatically discovers it from the standard
`.build-id/xx/rest.debug` tree without `symbol-file`. The discovered sidecar
supports source listing, function typing, and a live `recovered_add(19, 23)`
breakpoint. A negative control places the PIE sidecar under the non-PIE build
ID path; GDB reports the identity mismatch and skips it. All four target lanes
also pass real export and explicit GDB/QEMU loading for `--build-id=none`
fixtures whose sidecars correctly make no build-ID claim. Automatic
installation into a global debug directory remains outside this slice.

**CONFIRMED (2026-09-02):** the installed extension's opt-in headless path now
extracts Ghidra functions into immutable name/address/size records and emits a
DWARF 5 CU with one subprogram DIE per contiguous function. Discontiguous
functions are skipped with explicit diagnostics rather than flattened. The
producer validates its symbolic relocation records, publishes only resolved
`.debug_info`/`.debug_abbrev`, and atomically writes the matched sidecar.

The integration harness applies a `USER_DEFINED` rename to the known fixture
function before export for ET_EXEC and PIE. The emitted DIE and GDB both use
`recovered_add`, proving the path observes curated Ghidra state. Two fresh
x86-64 headless analyses produced byte-identical symbol sidecars locally.

Local `readelf` and GDB tests pass for x86-64, AArch64, MIPS32 big-endian, and
MIPS32 little-endian ET_EXEC, PIE, and no-section-table fixtures. PIE export
normalizes Ghidra's default rebase (`0x100000` on x86-64/AArch64 and `0x10000`
on MIPS here) back to ELF link-time VAs; GDB then applies the runtime ASLR load
bias correctly. QEMU-backed breakpoints resolve in all three non-host target
lanes.

**CONFIRMED (2026-09-02):** the installed exporter now also generates a
deterministic UTF-8/LF `.dbg.c` and a structured address-to-line model in one
decompiler pass. Functions are stably ordered; the header explicitly labels
the text as synthetic decompiler output; and a per-function failure path
retains a diagnostic placeholder. Comments, blank lines, and formatting-only
lines receive no token-derived rows. Function entry addresses are
intentionally attached to their non-comment declarations, while executable
statement rows come from Ghidra decompiler token/P-code address evidence.

libdwarf 2.3.2 deliberately suppresses its producer line section for DWARF 5,
so the current path serializes the architecture-neutral DWARF 5 line program
in Java. The CU has `DW_AT_stmt_list`; subprograms have
`DW_AT_decl_file`/`DW_AT_decl_line`. The pinned public data-reference producer
also writes a pointer-sized placeholder for a DWARF32 section offset on ELF64;
the adapter parses the generated abbreviations and DIE forms, removes the four
surplus bytes, and adjusts every affected CU-relative reference. Unknown forms
or layouts fail closed. This tested workaround should be replaced when the DIE
producer is redesigned or libdwarf gains a usable DWARF 5 line path.

All 20 local target/input combinations now pass `readelf` decoded-line checks,
LLVM verification, independent `dwarfdump`, and GDB source-level behavior.
GDB lists the synthetic function, resolves both function and file/line
breakpoints, executes `next` and `step` through mapped rows, and exits normally.
The no-section-header and no-build-ID regressions pass through this source/line
path as well; shared objects use their documented load-bias flow.
Two fresh x86-64 analyses produced byte-identical `.dbg` and `.dbg.c` outputs.
Their current SHA-256 values are
`3d346c6f6e02e6da80f145a05cf445e4c1b88015cc6d45b8e04b0163051512c1`
and `c743c8f3dba3b7884b4d40c76e93e1c0208302c37384ce2351d498fc98423a2d`,
respectively. This is a **CONFIRMED local semantic milestone**.

**CONFIRMED (2026-09-02):** the installed exporter now extracts listing-level
Ghidra function signatures, with `USER_DEFINED` analyst changes taking
precedence, into a native-independent canonical type graph. Stable type keys
and references terminate recursive graphs without duplicating DIEs. The model
and emitter cover base/unspecified types, pointers/references, qualifiers,
arrays, typedefs, signed/unsigned enums, structures/unions, member offsets,
bit-field metadata, subroutine types, formal parameters, variadic markers, and
no-return flags. Unsupported/dynamic Ghidra types are retained as explicitly
diagnosed `DW_TAG_unspecified_type` nodes rather than guessed.

The integration preparation applies a realistic analyst signature and favorite
recursive fixture types. Across x86-64, AArch64, MIPS32 BE, and MIPS32 LE,
`readelf`, LLVM, and libdwarf validation pass and GDB `ptype` shows
`int recovered_add(int,int)`, a recursive list node, aligned fixture state,
union, three-element array, signed enum with `OP_INVALID = -1`, typedef, and
function pointer. PIE `ptype` also passes under ASLR. Curated variadic and
no-return functions emit `DW_TAG_unspecified_parameters` and `DW_AT_noreturn`;
GDB displays `int (int, ...)` and `void (int)` in every ET_EXEC/PIE lane.
Supported stable register, stack, and composite parameter/local storage now
has validated locations; uncertain storage remains optimized out. External
and thunk functions are deliberately omitted with diagnostics instead of
being misrepresented as addressed definitions; every integration lane
exercises this policy. Standard calling-convention and external-data
declaration attributes now pass. Distinct function linkage-name, thunk, and
alias emission remain incomplete. Windows and hosted-CI evidence remain open.

**CONFIRMED (2026-09-02):** function extraction now retains every Ghidra
`AddressSetView` interval. Contiguous subprograms keep `low_pc`/`high_pc`;
discontiguous subprograms and the CU use deterministic DWARF 5
`.debug_rnglists` with absolute `DW_RLE_start_end` entries. Line programs use
separate sequences per interval, so neither DIE ranges nor source rows cover a
gap. On x86-64, GDB associates both `[0x401090,0x4010ae)` and
`[0x4010b0,0x4010b1)` with `FUN_00401090` and reports no line at `0x4010ae`.
All 12 architecture/input roles pass `readelf`, LLVM, libdwarf, and GDB after
this change, including ELF32 big-endian and no-section-table inputs.
`.debug_aranges` is intentionally not emitted because the validated CU range
list supplies lookup coverage; it can be added later only as an accelerator.

**CONFIRMED (2026-09-02):** primary, non-default Ghidra labels backed by
defined listing data now become canonical typed `DW_TAG_variable` DIEs.
Memory definitions use audited libdwarf expression APIs to emit `DW_OP_addr`;
external/bodyless or undefined objects are not assigned guessed locations.
The integration preparation applies `USER_DEFINED int fixture_sink` at the
ELF-derived address. GDB reads 0 before the recovered assignment and 42 after
stepping it on x86-64, AArch64, MIPS32 BE, and MIPS32 LE for ET_EXEC, PIE, and
shared objects under ASLR. Typed external declarations and namespace-scoped
definitions are covered by the later confirmed P1.9 paragraph.

**CONFIRMED (2026-09-02):** a native-independent variable-storage model now
represents Ghidra stack coordinates, direct registers and register slices,
register-relative memory, absolute memory, composite pieces, changing
half-open live ranges, unavailable/optimized-away states, evidence confidence,
and omission reasons. It rejects overlapping ranges and incomplete composite
values. Target register numbers are isolated in one table whose provenance is
Ghidra 12.0.3's `x86-64.dwarf`, `AARCH64.dwarf`, and `mips.dwarf` resources.
Focused tests cover x86-64, AArch64, MIPS32 big/little endian, deterministic
ordering, and all storage kinds. Unknown register names resolve only to an
explicit `UNMAPPED_REGISTER` state; generic code never invents a numeric DWARF
register. Ghidra storage/live-range extraction and parameter/local location
emission remain **PLANNED** under P1.11.

**CONFIRMED (2026-09-02):** the exporter now snapshots Ghidra listing locals
into the canonical program model and emits each recovered local as a typed
`DW_TAG_variable` child of its subprogram. No local receives a location yet.
The integration preparation adds a `USER_DEFINED int analyst_local` with
unassigned storage; all x86-64, AArch64, MIPS32 BE, and MIPS32 LE ET_EXEC/PIE
lanes verify its DIE and GDB reports `analyst_local = <optimized out>`. The
no-section-table paths also retain the locals Ghidra actually discovers. All
12 artifacts pass `readelf`, LLVM, libdwarf, and native/QEMU GDB behavior
checks. This preserves names/types without fabricating lifetime or storage;
stack/register expressions and `.debug_loclists` remain **PLANNED**.

**CONFIRMED (2026-09-02):** a native-independent DWARF location-expression
planner now accepts only stable exact-width registers, register-relative
memory, and absolute memory. It explicitly omits raw Ghidra stack coordinates,
partial register slices, composites, and changing/partially unavailable ranges
until their frame-base, piece-order, or location-list semantics are proven.
The pinned libdwarf 2.3.2 `dwarf_add_expr_gen_a` signature was checked against
`libdwarfp.h` lines 616–622 and exercised in isolated JVMs for x86-64,
AArch64, MIPS32 big-endian, and MIPS32 little-endian producer modes. A complete
model-to-DIE x86-64 smoke sidecar emits `DW_OP_regx 5`; `readelf`,
`llvm-dwarfdump --verify`, and independent `dwarfdump` accept it, and GDB reads
the live RDI-backed test parameter as 19. This established the isolated
expression/emission milestone before the production extraction rule below.

**CONFIRMED (2026-09-02):** production extraction now considers simple direct
register parameters with explicit Ghidra storage. It maps the base register
through the isolated target table, checks both instruction result objects and
p-code outputs for overlapping writes, and rejects every function containing
a call because ABI clobbers are not otherwise proven. The curated fixture uses
explicit EDI/ESI, w0/w1, and a0/a1 parameter storage. Across ET_EXEC and PIE,
GDB reads `left=19, right=23` on x86-64 and both MIPS byte orders. AArch64's
body overwrites x0/x1; the scan reports the exact write addresses, emits no
locations, and GDB reports both parameters optimized out. All 12 current
export/validator/native-or-QEMU-GDB lanes pass. Stack variables, register
locals, call-crossing registers, pieces, and changing locations remain
**PLANNED** rather than guessed.

**CONFIRMED (2026-09-02):** production extraction now accepts exact, simple
Ghidra stack slots for parameters and locals. One `CallDepthChangeInfo` profile
per function resolves the raw incoming-stack-pointer coordinate against the
analyzed SP depth at each instruction; known intervals become target-mapped
`DW_OP_bregx` expressions and unknown intervals remain explicit gaps. A
deterministic DWARF 5 `.debug_loclists` writer emits absolute `start_end`
entries, and the DWARF32 repair path now handles its `DW_AT_location`
section offsets. This intentionally does not rely on target unwind data: an
earlier `DW_OP_call_frame_cfa`/`DW_OP_fbreg` attempt read 23 instead of 42 on
the stripped big-endian MIPS fixture because that input has no usable CFI, so
that approach was rejected. GDB reads the curated `analyst_stack` local as 42
on x86-64, AArch64, MIPS32 BE, and MIPS32 LE for both ET_EXEC and PIE. The same
four no-section-table exports also pass, and all artifacts pass `readelf`,
`llvm-dwarfdump --verify`, independent `dwarfdump`, and native/QEMU GDB checks.
Register locals, composite pieces, and semantic storage changes remain
**PLANNED**.

**CONFIRMED (2026-09-02):** exact register-backed locals whose Ghidra
`firstUseOffset` is the function entry now share the stable-register proof used
for parameters: the storage must be one exact-width mapped register, every
instruction must preserve it, and the function must contain no calls. The
fixture passes 31 in the fourth ABI input register and applies a `USER_DEFINED`
`analyst_register` local there while retaining the curated two-parameter
signature. GDB reads 31 on x86-64, AArch64, MIPS32 BE, and MIPS32 LE for
ET_EXEC and PIE. The initially considered third register was rejected after
the x86-64 body reused EDX; the overwrite scan correctly withheld its
location. All structural validators, no-section-table regressions, and
native/QEMU behavior checks still pass. Non-entry register lifetimes,
call-crossing registers, composite pieces, and semantic storage changes remain
**PLANNED**.

**CONFIRMED (2026-09-02):** P1.11 now supports exact register-only composite
storage. Ghidra 12.0.3's `VariableStorage` contract orders compound varnodes
least-significant-first on little-endian targets and most-significant-first on
big-endian targets; these are both the memory-address order required by DWARF
5 section 2.6.1.2. Each exact register slice emits `DW_OP_regx` followed by
`DW_OP_bit_piece`, making the bit size and LSB offset explicit instead of
depending on ABI-specific partial-register `DW_OP_piece` placement. The
fixture's `analyst_composite` reconstructs `0x1122334455667788` in GDB on
x86-64, AArch64, MIPS32 BE, and MIPS32 LE for ET_EXEC and PIE. Mixed memory or
stack pieces, unstable registers, incomplete widths, and uncertain lifetimes
remain locationless rather than guessed.

**CONFIRMED (2026-09-02):** the P1.11 changing-location acceptance case now
uses a balanced, architecture-specific 16-byte SP adjustment between two
fixture marker addresses after `analyst_stack` has been initialized. Ghidra's
instruction-level depth analysis produces distinct `DW_OP_bregx` intervals;
GDB reads 42 both before and during the adjustment on all four targets for
ET_EXEC and PIE. The normal/shifted expressions are respectively `rsp-4` and
`rsp+12`, `sp+28` and `sp+44`, or MIPS `r29+4` and `r29+20`. All structural
validators and the no-section-table regression pass. This completes the
evidence-backed P1.11 scope; storage that cannot be proven remains explicitly
unavailable.

**CONFIRMED (2026-09-02):** sidecar/source publication now stages both complete
files in their destination directory before either final path changes. The
sidecar producer receives the final synthetic-source filename even though it
writes to a staging path. Pair publication uses same-filesystem atomic moves,
temporarily preserves any prior pair, and rolls both paths back if the second
installation fails. Native-free filesystem tests cover successful replacement,
rollback to an old pair, and removal of a fresh partial pair after a controlled
mid-publication failure. The Ghidra entry point checks cancellation immediately
before publication and always removes its staging files. A process crash during
the two final rename operations cannot be made transactionally atomic on a
general filesystem; durable crash recovery remains **PLANNED** rather than
claimed.

**CONFIRMED (2026-09-02):** the P1 source-map/line-table boundary now has a
native-independent planning oracle. It verifies that one line sequence is
created for each real function interval, one source line can retain addresses
in discontiguous intervals, and addresses outside those intervals are omitted.
When multiple generated lines share one instruction address, the already
implemented deterministic policy selects the earliest generated line because
the line machine can expose only one current source row for that address. The
test also proves that input function/evidence ordering does not change the
serialized table. The rebuilt extension retained byte-identical x86-64
fixture outputs and the complete four-target ET_EXEC/PIE/no-section-table
validator and GDB matrix passed. This closes local P1.1, P1.3, and P1.4
acceptance; hosted execution remains tracked by P2.12.

**CONFIRMED (2026-09-02):** per-function decompilation failure isolation now
has a real headless Ghidra integration oracle. The test wraps the production
decompile operation, forces only `recovered_add` to throw, and requires every
other fixture function to decompile successfully. The generated source retains
a deterministic diagnostic comment; the failed subprogram DIE retains only
its name and real address/range (no source, type, parameter, or local claims).
GNU readelf, LLVM verification, and independent libdwarf validation accept the
artifact. GDB resolves the failed function address without line information
and resolves a later successfully decompiled function with line information.
The original target hash remains unchanged.

The production script now delegates staging and publication to one reusable
helper. A native-independent controlled-cancellation test throws after both
complete staging files have been written but before either final path changes;
it proves the prior pair is preserved and all staging files are removed. The
production callback at that exact boundary is `TaskMonitor.checkCancelled()`.
Together these close the local failure-isolation and cancellation criteria of
P1.2. A Windows-host UTF-8/LF and cross-host byte-identity check is now present
in CI, but remains unverified until that hosted lane passes.

**CONFIRMED (2026-09-02):** a real favorite Ghidra `packed_flags` structure now
exercises two unsigned bit fields through extraction, canonical modeling,
DWARF emission, independent validators, and GDB `ptype`. Little-endian x86-64,
AArch64, and MIPS emit `DW_AT_data_bit_offset` values 0 and 3; big-endian MIPS
emits 24 and 27 for the same 32-bit storage units. GDB displays the expected
3-bit and 5-bit members on all four targets. Native-independent tests retain
coverage for qualified and lvalue/rvalue-reference graph nodes. Inspection of
Ghidra 12.0.3's shipped `SoftwareModeling` classes confirms its public listing
`DataType` hierarchy has no qualifier or C++ reference datatype, so the Ghidra
extractor cannot honestly reconstruct those properties and does not invent
them. This closes the locally testable P1.6 type-graph scope.

The first bit-field run also exposed and then isolated a native error-path ABI
hazard. libdwarfp 2.3.2's producer `Dwarf_Error_s` contains only `er_errval`,
whereas libdwarf's consumer structure additionally contains an error-message
pointer and allocation metadata. Passing a producer error to consumer
`dwarf_errmsg()` read beyond the smaller structure and crashed in
`dwarfstring_string`. Forge no longer maps that unsafe call: it reads the
compatible first-field number with `dwarf_errno()` and resolves the message
with `dwarf_errmsg_by_number()`. The isolated producer smoke deliberately
requests an invalid attribute and now reports
`DW_DLE_INPUT_ATTR_BAD (143)` without a fault on all four target profiles.
`DW_AT_data_bit_offset` uses the pinned `dwarf_add_AT_any_value_uleb_a` API,
whose exact 2.3.2 signature was audited before enabling it. The crash occurred
while writing a staging file, so the original input and prior final pair were
unchanged; the generated JVM crash log was inspected and removed.

**CONFIRMED (2026-09-02):** function signatures now emit the standard
`DW_AT_calling_convention = DW_CC_normal` attribute when Ghidra reports a
recognized convention. The integration preparation explicitly applies
Ghidra's default convention to `recovered_add`; every target's `readelf` dump
observes `normal`, validators pass, and existing GDB prototypes remain correct.
Functions whose Ghidra convention is `unknown` omit the attribute. The exact
Ghidra convention string remains in the immutable model, but Forge does not
invent vendor DWARF codes for ABI distinctions the standard cannot express.
A distinct `DW_AT_linkage_name` is also omitted unless a future extractor can
prove a separate preserved linker spelling; a namespace-qualified display
name or arbitrary alias is not treated as linkage evidence. Import/thunk/alias
definitions remain diagnosed and omitted under the tested initial policy.

**CONFIRMED (2026-09-02):** source-built stripped `ET_DYN` shared libraries
now pass the same real headless exporter on x86-64, AArch64, MIPS32
big-endian, and MIPS32 little-endian. Ghidra's default shared-object analysis
bases (`0x100000` for the 64-bit targets and `0x10000` for MIPS here) are
normalized back to zero-based ELF link-time VAs. `readelf`,
`llvm-dwarfdump --verify`, and independent `dwarfdump` accept all four
sidecars. The GDB harness first loads each sidecar at link-time addresses
before the library exists, then removes it, runs to the stripped driver's
`main`, derives the runtime bias from the mapped `.text`, and reloads the
sidecar with `add-symbol-file -o`. Native x86-64 and QEMU-backed AArch64/MIPS
then hit `recovered_add`, resolve and update `fixture_sink`, and exit normally.
The observed relocated function and global addresses are explicitly checked
not to fall within any main-executable `PT_LOAD` range.

**CONFIRMED (2026-09-02):** the P1 global model now retains two additional
forms of curated Ghidra evidence. A typed `ExternalLocation` emits
`DW_AT_declaration` plus `DW_AT_external` and no location, while a defined
`analyst_scope::scoped_counter` is nested under a `DW_TAG_namespace` and
retains its exact address. Because Forge honestly marks the synthetic source
CU as C11, current GDB exposes that namespace child by its unqualified name;
structural validators confirm the namespace parentage. A separate experiment
with an evidence-backed distinct `DW_AT_linkage_name` was not retained: GDB
16.3 replaced the analyst-facing function name with the linker spelling for a
C11 CU, which broke `break recovered_add`. Linkage-name work therefore remains
open until both names can stay useful without inventing the source language.

## 9. Handoff-baseline prototype architecture

Sections 9–13 describe the historical `7a39a18` prototype unless a paragraph
explicitly says otherwise. The confirmed post-handoff implementation and test
state in Section 8 supersedes those baseline limitations.

### 9.1 Entry point

**CONFIRMED REPOSITORY FACT:** `src/GhidraDwarfForgeFixed.java` extends `GhidraScript` and expects `currentProgram`.

Its current run sequence is:

1. Reject execution when no program is loaded.
2. Export decompiled C to:

   ```java
   currentProgram.getExecutablePath() + ".dbg.c"
   ```

3. Read pointer size, endianness, processor, and a hand-mapped ABI string.
4. Construct libdwarfp flags for pointer/offset size, target endianness, and symbolic relocations.
5. Collect executable memory ranges from Ghidra.
6. Call `dwarf_producer_init(..., abi, "V5", ...)`.
7. Build one compile-unit DIE.
8. Add address ranges.
9. Add one minimal subprogram DIE for each non-external function.
10. Transform producer data to disk form.
11. Retrieve selected section bytes.
12. Hand-write an ELF sidecar to:

    ```java
    currentProgram.getExecutablePath() + ".dbg"
    ```

### 9.2 Current compile-unit DIE

**PRESENT, UNVERIFIED:** The prototype emits:

- `DW_TAG_compile_unit`
- `DW_AT_name` = `currentProgram.getName()`
- `DW_AT_producer` = `GhidraDwarfForge`
- `DW_AT_low_pc` = first executable range start
- `DW_AT_language` = hard-coded `0x0001` (`DW_LANG_C89`)

It does not currently emit `DW_AT_stmt_list`, `DW_AT_comp_dir`, a complete range description, or type roots.

### 9.3 Current subprogram DIEs

**PRESENT, UNVERIFIED:** For each non-external function, the prototype emits:

- `DW_TAG_subprogram`
- `DW_AT_name`
- `DW_AT_low_pc`
- `DW_AT_high_pc` as a size

The range is computed as:

```text
entry point .. function body maximum address + 1
```

This is incorrect for discontiguous functions because it includes holes and assumes the entry point is the minimum address.

No return type, formal parameters, locals, frame base, declaration file/line, linkage name, calling convention, inline data, or range list is emitted.

The code contains a branch intended to set `DW_AT_external`, but the caller skips all external functions first; the branch is therefore unreachable for external functions. It also conditions the flag on `!hasNoReturn`, which has no obvious semantic relation to external visibility.

### 9.4 Current generated source

**PRESENT, UNVERIFIED:** The exporter:

- Iterates functions in address order.
- Skips external functions.
- Calls the Ghidra decompiler with default options.
- Writes each successfully decompiled function’s complete C text.
- Adds two line separators after each function.
- Silently omits functions whose decompilation does not complete.
- Stops when the monitor is cancelled.

It does not create a source-line/address mapping. It does not write a deterministic diagnostic placeholder for a failed function. It does not prove that decompiler formatting is stable across Ghidra versions.

### 9.5 Current collected DWARF sections

**PRESENT, UNVERIFIED:** The prototype explicitly requests:

```text
.debug_info
.debug_abbrev
.debug_aranges
.rel.debug_info
.rel.debug_aranges
.rela.debug_info
.rela.debug_aranges
```

It does not request or emit a line table, string table by explicit policy, type/location/range-list support sections, or frame data.

### 9.6 Current ELF writer

**PRESENT, UNVERIFIED:** The prototype writes a custom `ET_REL` ELF container.

Important current behavior:

- ELF magic is written manually.
- `EI_CLASS` is always `ELFCLASS64` (`2`).
- ELF header size is always 64 bytes.
- Section-header size is always 64 bytes.
- `e_type` is always `ET_REL`.
- `e_entry` and program-header fields are zero.
- Debug sections are written as `SHT_PROGBITS`.
- Relocation sections are written as `SHT_REL` or `SHT_RELA` based on name.
- No `.symtab` or `.strtab` is emitted.
- Relocation `sh_link` is written as zero.
- `sh_info` points at the named target debug section when found.
- Section virtual addresses are zero.
- Only `.shstrtab` is added as support metadata.

The `is64` parameter affects relocation entry size, but not the ELF header/class/section-header layout. The code therefore cannot correctly emit 32-bit ELF despite setting 32-bit libdwarf flags.

The processor mapping also assumes 64-bit in several cases:

- Ghidra processor `x86` maps to `EM_X86_64`.
- `powerpc` maps to `EM_PPC64`.
- MIPS is commented as assuming a 64-bit ABI.

The current sidecar packaging and relocation model has not been proven valid in GDB.

## 10. Native/JNA boundary status

### 10.1 Why this is a P0 blocker

A JNA signature mismatch can corrupt the call frame and terminate the entire Ghidra JVM. The repository includes a historical native crash, and the current mapping differs from the inspected upstream producer header in multiple places.

### 10.2 Exact revision uncertainty

**CONFIRMED REPOSITORY FACT:** The workflow builds from moving libdwarf `main` and does not record the resolved source commit in the bundled JAR metadata.

Therefore:

- The exact source revision used for the committed `.so`/`.dll` files is **UNCERTAIN**.
- Every signature must be checked against the exact revision selected and pinned for future builds.
- The observations below are based on the inspected current upstream header and are highly likely to identify real defects, but the bundled binary must still be matched to a known revision before final correction.

### 10.3 Fixed-width type mismatch

The inspected upstream header defines:

```c
typedef unsigned long long Dwarf_Unsigned;
typedef signed   long long Dwarf_Signed;
typedef unsigned long long Dwarf_Off;
typedef unsigned long long Dwarf_Addr;
```

The current Java callback mapping uses `NativeLong` and `NativeLongByReference` for several `Dwarf_Unsigned` values.

This is unsafe across platforms because `NativeLong` follows C `long`; on 64-bit Windows, C `long` is 32-bit while `Dwarf_Unsigned` is 64-bit.

Required direction:

- `Dwarf_Unsigned` by value → Java `long`.
- `Dwarf_Unsigned *` → `LongByReference` or an explicitly 64-bit custom wrapper.
- Do not use `NativeLong` for these producer ABI fields.

### 10.4 Error handler mismatch

Inspected upstream type:

```c
typedef void (*Dwarf_Handler)(Dwarf_Error dw_error,
    Dwarf_Ptr dw_errarg);
```

Current Java mapping:

```java
void invoke(int errorNo, Pointer arg);
```

The first argument should be an opaque `Dwarf_Error`, not an integer error number.

### 10.5 Function signature mismatches

The inspected upstream producer API includes:

```c
int dwarf_transform_to_disk_form_a(
    Dwarf_P_Debug dbg,
    Dwarf_Unsigned *nbufs_out,
    Dwarf_Error *error);
```

Current Java mapping omits `nbufs_out`.

The inspected upstream producer API includes:

```c
int dwarf_add_AT_targ_address_c(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *outattr,
    Dwarf_Error *error);
```

Current Java mapping omits `outattr`.

The inspected upstream producer API includes:

```c
int dwarf_add_AT_flag_a(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Small flag,
    Dwarf_P_Attribute *outattr,
    Dwarf_Error *error);
```

Current Java mapping omits `dbg` and `outattr`.

The complete JNA interface—not only these examples—must be audited before feature work continues.

### 10.6 Callback semantics

The producer section callback has both:

- A function return value representing the created ELF section index.
- A separate `sect_name_index` output representing an ELF symbol-table index usable for relocations.

The prototype assigns the same incrementing number to both even though it emits no symbol table. This is not a valid documented relocation model.

### 10.7 Symbolic relocation handling

Upstream libdwarfp documents symbolic relocation retrieval through:

- `dwarf_get_relocation_info_count()`
- `dwarf_get_relocation_info()`

The prototype instead attempts to retrieve `.rel.*`/`.rela.*` byte buffers as if they were ordinary producer section kinds and then writes ELF relocation sections without a symbol table.

The correct strategy is **UNCERTAIN** until the exact pinned libdwarf API is inspected and a valid ELF packaging design is selected.

### 10.8 Callback lifetime

The prototype passes newly constructed Java callback objects directly into `dwarf_producer_init` and does not retain explicit strong fields for the producer lifetime.

This is a **LIKELY RISK**, not a proven current failure. JNA callbacks should be held strongly until `dwarf_producer_finish_a` completes.

## 11. Historical native crash

**HISTORICAL:** `src/temp/hs_err_pid549820.log` records a fatal JVM `SIGSEGV` on 2025-06-03:

- JRE: OpenJDK 21.0.7
- Host: Ubuntu 22.04.5, x86-64
- Problematic native frame: `libdwarfp.so`, `_dwarf_p_error+0x41`
- Native call path includes `dwarf_producer_init`
- Ghidra script thread name: `GhidraDwarfForge.java`

The stack reflects an older script/JNA proxy signature, so it does not prove the exact current source reproduces the crash. It does prove that the native boundary has historically been capable of terminating Ghidra and must be isolated and tested outside the GUI process first.

## 12. Current issue tracker

The baseline issue state is:

| Issue | State | Title | Handoff interpretation |
|---:|:---:|---|---|
| #1 | Open | Write the new ELF in the same directory as the original program. | Behavior is present in code via `getExecutablePath() + ".dbg"`, but is unverified and lacks fallback/error policy. |
| #2 | Open | Name the new ELF `{original_file}.dbg`. | Naming is present in code, unverified end-to-end. A comment says closure was deferred until all debug sections were added. |
| #3 | Open | Export decompiled code to the same directory as `{original_file}.dbg.c`. | Present in code, unverified, with no line map and weak failure handling. |
| #4 | Closed | Generate `.debug_aranges`. | Prototype calls libdwarfp arange APIs and the issue was closed in 2025; structural/GDB correctness still requires regression tests. |
| #5 | Open | Generate `.debug_info`. | Minimal section/DIE generation is present, but the requirement is far from semantically complete. |
| #6 | Open | Generate `.debug_abbrev`. | Produced indirectly by libdwarfp for current DIEs; not independently validated. |
| #7 | Open | Generate `.debug_line`. | Not implemented. |
| #8 | Open | Generate `.debug_frame`. | Not implemented; product need and source of correct unwind semantics remain uncertain. |
| #9 | Open | Generate `.debug_str`. | Not explicitly controlled or validated; string-form policy is absent. |

Do not bulk-close these issues based solely on the prototype. Reconcile each issue with test-backed acceptance criteria.

## 13. Known issues and risks

### 13.1 P0 — native safety and reproducibility

- Moving libdwarf `main` dependency.
- Exact bundled native revision not recorded.
- Multiple likely JNA ABI mismatches.
- Unsafe error-handler mapping.
- Callback lifetime not explicit.
- Historical JVM native crash.
- No isolated native ABI smoke-test process.
- Bundled JNA 5.6.0 may conflict with the version Ghidra provides; compatibility is **UNCERTAIN**.

### 13.2 P0 — no complete build/product packaging

- No current Ghidra extension Gradle project.
- No current clean-checkout extension build command.
- No installable release artifact.
- No declared Ghidra compatibility version.
- Maven builds only the resource/JNA JAR.

### 13.3 P0 — invalid or unproven ELF packaging

- Always emits ELF64.
- Several processor mappings assume 64-bit.
- Writes `ET_REL` regardless of input.
- No matching build ID.
- No `.gnu_debuglink` mode.
- No symbol table for relocation sections.
- Relocation `sh_link` is zero.
- Symbolic relocation callback semantics are not implemented correctly.
- No proven GDB loading/association workflow.
- No explicit handling of PIE, shared-library load bias, or a rebased Ghidra image.

### 13.4 P1 — incomplete DWARF semantics at the handoff baseline

- No `.debug_line`.
- No source file table or line rows.
- No type DIE graph.
- No parameters, locals, or globals.
- No variable locations or location lists.
- No discontiguous function range lists.
- No namespaces/scopes.
- No linkage names.
- No declaration file/line attributes.
- No frame-base model.
- Hard-coded `DW_LANG_C89` with no documented language policy.
- Partial handwritten constants increase drift risk.
- Most native return values and error details are not checked.

### 13.5 P1 — source-generation limitations at the handoff baseline

- No address-to-line correlation.
- Failed decompilations silently disappear.
- No deterministic diagnostic placeholders.
- No stable synthetic declaration/type preamble.
- No guarantee decompiler text is stable across Ghidra versions.
- No atomic output replacement.
- A cancellation or exception can leave `.dbg.c` without a matching `.dbg`.

### 13.6 Repository hygiene and legal risk

- `.gitignore` is empty.
- `jna-wrapper/target/` is committed.
- `src/temp/` is committed with a crash log and duplicate extracted artifacts.
- Large generated binary files are committed directly.
- No repository license is present.
- Native library license notices and source-offer/distribution obligations have not been documented in this repository.
- No dependency checksums/provenance manifest.

### 13.7 Testing/documentation gaps

- No unit tests.
- No integration fixtures.
- No GDB behavior scripts.
- No DWARF validation CI.
- No Actions runs retained at the snapshot.
- No installation/use documentation.
- No support matrix.
- No benchmark or large-firmware test.

## 14. Planned architecture

The following is a **PLANNED** separation of concerns. It is intended to replace the monolithic script incrementally; exact class/package names are not decided.

### 14.1 Layer 1 — Ghidra extraction snapshot

Create immutable/project-owned models for:

- Program identity and original ELF metadata.
- Address spaces, image base, and executable ranges.
- Functions and discontiguous bodies.
- Signatures, calling conventions, parameters, locals, and globals.
- Canonical Ghidra data types.
- Variable storage and confidence/live-range evidence.
- Decompiled functions, tokens, syntax, and address sets.

Do not let native libdwarf calls reach back into mutable Ghidra state unpredictably.

### 14.2 Layer 2 — deterministic synthetic source

Generate `.dbg.c` and a structured source map in one pass:

```text
synthetic source file
  ├── stable lines
  ├── function boundaries
  ├── declaration/type locations
  └── line → one or more address ranges
```

The source-map model should survive independently of libdwarf so it can be unit tested.

### 14.3 Layer 3 — type and variable-location model

Build:

- A canonical, cycle-safe type graph.
- A target-independent variable storage model.
- Architecture-specific register-number translators.
- DWARF expression/location-list plans with confidence/omission reasons.

### 14.4 Layer 4 — DWARF producer adapter

Use a pinned, fully audited libdwarfp JNA binding to create:

- Compile units.
- Function, parameter, variable, and type DIEs.
- Line tables.
- Range/location lists.
- Required strings/address support sections.

Keep callbacks and opaque handles strongly referenced and centrally managed. Check every return code.

### 14.5 Layer 5 — ELF packaging and association

Implement one documented, valid sidecar strategy that:

- Matches original target identity.
- Handles ELF32/ELF64 and both byte orders.
- Handles target architecture flags.
- Treats PIE/shared-object addresses correctly.
- Provides a tested GDB association/loading path.
- Supports optional build-ID and/or explicit `.gnu_debuglink` workflows.

Prefer a well-tested ELF library or metadata-copy strategy if hand-writing a container proves too error-prone. The library choice is **UNCERTAIN**.

### 14.6 Layer 6 — validation harness

Automate:

- Fixture compilation and stripping.
- Ghidra import/analysis/export in headless or test harness mode.
- `readelf` section/header/debug dumps.
- `llvm-dwarfdump --verify`.
- `dwarfdump` when available.
- Scripted GDB symbol/source/type/location checks.
- Determinism checks.
- Original-file hash checks.

### 14.7 Layer 7 — GUI/headless product surface

Provide:

- A Ghidra UI/script entry point.
- Output-directory and optional association choices.
- Progress, warnings, and a final report.
- A headless entry point using the same exporter core.
- Extension packaging and release automation.

## 15. Validation requirements

### 15.1 Structural commands

For each supported fixture:

```bash
readelf -h <binary>
readelf -S <binary>
readelf -n <binary>

readelf -h <binary>.dbg
readelf -S <binary>.dbg
readelf -n <binary>.dbg
readelf --debug-dump=info <binary>.dbg
readelf --debug-dump=abbrev <binary>.dbg
readelf --debug-dump=aranges <binary>.dbg
readelf --debug-dump=decodedline <binary>.dbg

llvm-dwarfdump --verify <binary>.dbg
dwarfdump <binary>.dbg
```

Record unavailable tools rather than claiming they passed.

### 15.2 GDB behavior

At minimum, scripted tests should verify:

1. No malformed-DWARF warning.
2. Recovered function names resolve to correct addresses.
3. Function-name breakpoints resolve.
4. `list` displays the generated `.dbg.c` content.
5. `next`/`step` move through sensible source rows.
6. Available parameters/locals can be inspected.
7. Recovered structures/enums can be inspected with `ptype`/`print`.
8. PIE/shared-object loading does not shift symbols incorrectly.
9. Unavailable variable locations are reported honestly rather than reading unrelated storage.

### 15.3 Determinism and safety

- Hash the original target before/after default export; hashes must match.
- Repeat export without changing the Ghidra program.
- `.dbg.c` should be byte-identical.
- `.dbg` should be byte-identical when feasible; otherwise semantic equivalence must be explained and tested.
- Cancellation must leave no final partial artifacts.
- One decompiler failure must not prevent other functions from exporting.
- Native smoke tests must run in a separate process before equivalent calls are accepted inside Ghidra.

## 16. Intended test matrix

The initial serious matrix should include:

| Dimension | Cases |
|---|---|
| Target architecture | x86-64; AArch64; MIPS32 big-endian expansion |
| ELF role | non-PIE `ET_EXEC`; PIE; `ET_DYN` shared object |
| Symbol state | stripped; partially stripped |
| Ghidra host | Linux; Windows |
| Function bodies | contiguous; discontiguous |
| Variables | stack; register; changing storage; unavailable/optimized-away |
| Types | base; pointer; array; enum; typedef; structure; recursive structure; function pointer |
| Failure behavior | one failed decompilation; cancellation; unwritable default output |
| Address behavior | zero/non-zero image base; rebased program; runtime load bias |

MIPS32 big-endian is the planned first combined ELF32/big-endian case. It may
follow the initial x86-64/AArch64 release milestone, but generic code must
remain capable of describing it.

**CONFIRMED REQUIREMENT (2026-09-02):** CI must contain separate end-to-end
x86-64 and AArch64 target lanes. Each lane must exercise source-built fixture
creation, headless Ghidra import/analysis/export, structural DWARF validation,
and scripted GDB behavior. AArch64 may run on a native ARM64 worker or through
a documented cross-toolchain/emulation environment, but cross-compilation by
itself is insufficient.

**CONFIRMED REQUIREMENT (2026-09-02):** the product must not be limited to x86
and ARM. MIPS is explicitly in scope. Add a QEMU-backed MIPS end-to-end lane
when the fixture/export path exists; it becomes a required check before a MIPS
support claim. Cross-target producer tests alone are useful ABI coverage but
are not a substitute for Ghidra/exporter/validator/GDB behavior tests.

**CONFIRMED (2026-09-03):** P2.10 now emits one schema-versioned deterministic
JSON report per requested export. `SUCCESS`, `PARTIAL`, `CANCELLED`, and `FATAL`
are distinct; completed reports include target class/byte order, paths and
SHA-256 hashes, semantic counts, named failed/skipped functions, omitted
location ranges and reasons, opaque constructs, sorted diagnostics, validator
status, and the verified libdwarf revision. Native-independent tests cover all
four statuses and JSON escaping/order. Real headless success, controlled
decompiler failure, and mismatched-input fatal paths pass locally without
partial publication. The exporter records validator status as `NOT_RUN`
because the development harness runs validators only after publication.

**CONFIRMED (2026-09-03):** P2.11 now has packaged Bash and PowerShell wrappers
for stable headless invocation. Both temporary import and read-only/no-analysis
existing-project modes call the production Ghidra script; existing projects are
never saved or deleted. The wrapper treats `SUCCESS` and honest `PARTIAL` as a
completed exit 0, maps `FATAL` to 10 and `CANCELLED` to 11, reserves 12 for a
launcher or report-contract failure, and uses 64 for bad arguments. A fake
launcher contract test covers argument and exit handling. Real Linux Ghidra
partial and fatal paths, deterministic rerun, and structural validators pass.
The PowerShell path uses separate option-name/value tokens because the Windows
Ghidra batch-launch path does not preserve `--name=value`; the production script
accepts both forms. Ghidra's Windows ELF import path form (`/C:/...`) is
normalized to the native drive-path form before Java filesystem access. The
PowerShell path passed the hosted Windows lane in Actions run 33747224613.

**CONFIRMED (2026-09-03):** the continuous-validation workflow now has a
dedicated `actionlint` 1.7.12 job. CI downloads the pinned Linux executable and
upstream checksum list, verifies the archive before extraction, and lints all
repository workflows. Cross-target fixture jobs install their matching target
libc development headers in addition to each compiler and binutils package.
The Windows validator steps resolve MinGW binaries from `setup-msys2`'s
`msys2-location` output instead of assuming the installation is under `C:\`.

## 17. Open questions

Codex should not silently answer these through implementation choices. Investigate, document, and obtain user direction when the answer materially changes compatibility or scope.

1. **RESOLVED — Ghidra baseline:** Ghidra 12.0.3 is the first supported version.
2. **RESOLVED — Java baseline:** Extension sources compile as Java 21 bytecode,
   as required by Ghidra 12.0.3. The historical Java 7 Maven wrapper target is
   not the production extension baseline.
3. **RESOLVED — libdwarf revision:** libdwarf v2.3.2, source commit
   `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`, is pinned with the official
   archive SHA-256.
4. **Native provenance:** Should release builds compile native libraries in CI, consume checksummed upstream artifacts, or both?
5. **JNA ownership:** Should the extension use Ghidra’s bundled JNA or a shaded private copy? Classloader/native-loader conflicts must be tested.
6. **ELF packaging:** What precise separate-debug container does GDB accept most reliably across non-PIE, PIE, and shared objects?
7. **Association:** Is explicit `symbol-file`/`add-symbol-file` sufficient for the first milestone, or is automatic build-ID association required immediately?
8. **Build ID:** Should the sidecar copy the target build ID, and how should targets without a build ID be handled?
9. **Optional debuglink:** Should the extension offer a safe “attach `.gnu_debuglink`” mode, and what backup/CRC behavior is required?
10. **Output path:** What UI/headless option should replace the default path when `Program.getExecutablePath()` is unavailable or unwritable?
11. **Synthetic source language:** Should the CU language remain C89, use a newer C language code, or use another convention to reflect decompiler output?
12. **Line granularity:** Should rows map statements, expressions, p-code operations, or selected decompiler token groups?
13. **RESOLVED for the current line granularity — overlapping mappings:** one
    instruction address emits one row for the earliest generated source line.
    Revisit this if statement/expression granularity changes.
14. **Type precedence:** What exact ordering applies among analyst-applied signature types, listing types, high-function types, and decompiler guesses?
15. **Variable confidence:** What evidence threshold permits emitting `DW_AT_location` versus name/type only?
16. **Extern/import policy:** Should imported functions receive declarations only, symbol DIEs, PLT/thunk DIEs, or a combination?
17. **Inlining:** Is reconstructed inline information a later goal, or explicitly out of scope?
18. **`.debug_frame`:** Is generating synthetic unwind information required, or should the exporter preserve/rely on target `.eh_frame`/`.debug_frame` information?
19. **ELF implementation library:** Continue a hand-written emitter, use Ghidra ELF classes, use another Java ELF library, or derive metadata through an external tool? Licensing and portability matter.
20. **Distribution license:** Which license should cover the repository, and what notices/source obligations apply to bundled libdwarf/JNA binaries?
21. **Release format:** Ghidra extension ZIP only, or extension ZIP plus standalone/headless tools and native provenance manifest?
22. **PARTIALLY RESOLVED — initial support promise:** x86-64 and AArch64 target
    integration lanes are first-release blockers. MIPS is explicitly in the
    product scope and requires a QEMU/native behavior lane before support is
    advertised. The precise Linux/Windows host release matrix remains to be
    finalized.

## 18. Immediate strategic direction

The safest next move is not to add more DWARF features to the monolithic prototype. The immediate sequence should be:

1. Restore a reproducible extension build and select compatibility baselines.
2. Pin libdwarf and repair the complete JNA ABI in an isolated smoke test.
3. Establish small ELF fixtures and automated validators.
4. Decide and prove the sidecar ELF/GDB-loading model.
5. Deliver one narrow, fully validated x86-64 non-PIE symbol-only milestone.
6. Add deterministic source/line mapping.
7. Add types and variable locations with architecture-neutral models.
8. Expand to PIE/shared objects, AArch64, Windows host, and a QEMU-backed
   MIPS32 big-endian case; keep additional architectures table-driven.

The prioritized, testable work breakdown is in `TODO.md`.
