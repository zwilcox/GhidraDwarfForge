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

**HISTORICAL assessment, with bounded follow-ups now accepted:**
`docs/TARGET-PROFILES.md` records the five tested
ELF/ABI profiles and separates machine/class acceptance from actual storage
behavior. An audit of the earlier code, retained fixture metadata and
Ghidra 12.0.3 register aliases found that ABI classification is incomplete
and larger base-register aliases can hide otherwise mapped scalar FP storage.
The scalar-alias correction and definite ELF/Ghidra identity guard now pass
combined run `40068401197`; the final acceptance record below states their
exact scope. ABI classification and additional storage/profile cases remain
partial; the old audit is not a new blanket architecture support claim.

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

**CONFIRMED locally (2026-10-23):** the original x86-64 build-ID test checked
successful lookup but did not reject GDB warnings. Automatic separate-file
association warned about allocated relocation sections because the writer
renamed and zeroed them. Allocated REL/RELA headers now become inert
`SHT_NOBITS` entries retaining their original names/addresses/sizes/offsets/
alignment and only `SHF_ALLOC`; link/info/entry-size fields are cleared.
Nonallocated relocation retirement is unchanged.

The stricter association harness checks ET_EXEC and PIE on every target lane,
including full DWARF symbol identity, the exact debug artifact/source file,
function address, type/source lookup, and build-ID mismatch rejection.
Debuglink tests modify only private fixture copies with target `objcopy`;
CRC rejection uses inputs and sidecars with no build ID so another discovery
method cannot mask failure. All four locally available targets pass, alongside
the existing six-role native/QEMU matrix. The optional product attachment mode
remains unimplemented, and hosted verification of this expansion is pending.

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
alias emission remain incomplete. Later P2.12 hosted runs confirm this same
semantic path on Linux and Windows where applicable; release packaging remains
separate.

**CONFIRMED (2026-09-02):** function extraction now retains every Ghidra
`AddressSetView` interval. Contiguous subprograms keep `low_pc`/`high_pc`;
discontiguous subprograms and the CU use deterministic DWARF 5
`.debug_rnglists` with absolute `DW_RLE_start_end` entries. Line programs use
separate sequences per interval, so neither DIE ranges nor source rows cover a
gap. On x86-64, GDB associates both `[0x401090,0x4010ae)` and
`[0x4010b0,0x4010b1)` with `FUN_00401090` and reports no line at `0x4010ae`.
All 12 architecture/input roles pass `readelf`, LLVM, libdwarf, and GDB after
this change, including ELF32 big-endian and no-section-table inputs.
**HISTORICAL:** `.debug_aranges` was intentionally not emitted for this tested
lookup path. The later direct global-address formatting regression and exact
code-index decision supersede that absence policy; see `docs/ADDRESS-INDEX.md`.

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

**CONFIRMED (2026-09-03):** the `ET_DYN` fixture now builds from the dedicated
`shared_semantic.c` translation unit rather than reusing the executable
fixture. It retains the exporter-facing functions, globals, stack markers,
and semantic type declarations while intentionally defining no `main`; the
Makefile rejects a shared-library reference ELF that defines one. GitHub
Actions PR run 33787801175 passed the complete 12-job matrix, including real
exporter/GDB behavior on x86-64, AArch64, ARM32, and both MIPS byte orders.

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

**CONFIRMED locally (2026-10-23):** defined, primary typed memory labels whose
immediate Ghidra parent is a `Function` now retain that owner instead of being
flattened into CU globals. The model stores the owner's normalized ELF entry
address; DWARF places each variable under that function with its existing
absolute-address location encoding. An owner omitted from the export produces
a diagnostic and the private object is omitted, rather than promoted to global
scope. The structured report adds `counts.functionStaticVariables` while
retaining the meanings of its existing local/global counts. Namespace globals
and external-data declarations retain their previous behavior.

The dedicated compiler/real-export oracle covers two functions with the same
private spelling plus a global of that spelling, exact runtime addresses and
values, non-PIE/PIE, an explicit Ghidra rebase, deterministic reruns and input
preservation. This is a bounded P3.3 slice: datatype categories, decompiler
braces, lexical lifetimes, class scopes and aliases supply no new inferred
facts. Distinct linkage names are unchanged. A MIPS PIE `next`/unwind warning
also reproduces using the untouched compiler ELF as the separate symbol file;
the harness corroborates the precise warning independently and does not claim
general unwind correctness. See `docs/VALIDATION.md` for commands and limits.

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
| Target architecture | x86-64; AArch64; ARM32; MIPS32 big/little endian |
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

**CONFIRMED (2026-09-03):** P2.12 now retains exact tool and source provenance,
isolates native smoke tests with explicit signal/exit-status diagnostics,
uploads build logs and integration transcripts on failure, and gates the
workflow through one aggregate `required-validation` job. GitHub Actions run
33751896850 passed workflow lint, Linux/Windows native builds, the extension,
the four existing target lanes, the Windows-hosted real exporter, the explicit
Windows `FileShare.None` publication-rollback test, and the aggregate job.
The initial branch-protection attempt returned HTTP 403 while the repository
was private on the free plan. After the user made the repository public on
2026-09-03, `main` branch protection was enabled with strict/up-to-date
checking and `required-validation` as the required GitHub Actions status.
Force pushes and branch deletion remain disabled. This resolves the final
P2.12 administrative criterion.

**CONFIRMED (2026-09-03):** ARM32/AArch32 is now an active target profile. The
initial profile is ARMv7 hard-float, little-endian ARM state, built with
`arm-linux-gnueabihf` and executed through `qemu-arm-static` plus
`gdb-multiarch`. The target derives ELF32/EM_ARM identity, uses an isolated
Ghidra-12.0.3-derived ARM DWARF register map, and runs the same producer and
real exporter path as every other target. GitHub Actions run 33757707307 passed
all 11 jobs, including the aggregate validation gate. Its ARM32 lane passed
ET_EXEC, PIE, shared-object, no-build-ID, and no-section-table export; GNU
readelf, LLVM, independent libdwarf/dwarfdump, source/type/global tests,
load-bias checks, and changing stack-location behavior all passed. ARM32
register locations are emitted only when the per-role overwrite scan supports
them: `r1` is available in the executable/PIE fixture, while overwritten
`r0`, `r3`, composite pieces, and shared-object `r1` remain honestly
locationless. Thumb, big-endian ARM, and other ARM ABI profiles remain
**PLANNED** rather than implied by this result.

### 16.20 Release packaging and repository cleanup

**CONFIRMED (2026-09-03):** release version `0.1.0-alpha.1` establishes a
Semantic Versioning source in `VERSION`. The production packaging path is now
the pinned native builds in `.github/workflows/ci.yml` followed by
`support/assemble-release.sh`; the historical Maven shaded JAR workflow is no
longer a production or repository path. Committed `jna-wrapper/`, `src/temp/`,
and `src/libdwarf.jar` artifacts were removed. Ghidra's bundled JNA remains the
Java/native bridge.

The assembler adds the Linux x86-64 and Windows x86-64 builds to Ghidra's
`os/<platform>` extension layout. It writes an exact native-pair descriptor,
per-platform hashes, build provenance, a root release manifest, and a
whole-bundle checksum manifest; all ZIP timestamps and entry ordering are
normalized. CI assembles twice and requires byte identity. Installed wrappers
select packaged natives by default, while explicit library pairs remain a
developer override. The exporter checks the packaged file set and hashes
before loading native code.

The required pipeline installs only the aggregate bundle and runs real
packaged-native exports on fresh Linux and Windows Ghidra installations. This
is the evidence boundary for the initial Linux/Windows x86-64 host claim.
Target coverage remains the separately documented ELF matrix. Licensing,
third-party notices, and publication of an official GitHub Release are
explicitly deferred by the user; CI output is a validated pre-release artifact
until those items are resumed.

### 16.21 Native ABI audit, string forms, and unwind policy

**CONFIRMED (2026-09-03):** the production JNA surface is now
inventoried in `docs/LIBDWARF-ABI.md` and checked during both native builds by
a C probe compiled against the exact pinned libdwarf 2.3.2 headers. The probe
checks every enabled function signature, fixed-width typedef, and relocation
record layout. The Java producer smoke additionally verifies opaque error
callback delivery and readable messages. The obsolete top-level prototype
sources, which retained known unsafe JNA mappings, were removed; their history
remains available at the handoff baseline.

Both native jobs build the pinned source twice and require matching file
sets, exported symbols, target identity, SONAME/dependencies, and normalized
RUNPATH semantics. Binary hashes are recorded for diagnosis but are not
required to match because compiler build paths and build IDs can differ.
GitHub Actions run 33778570507 passed both hosted gates.

The exporter requests `DW_FORM_strp` before DIE construction and requires
`.debug_str`. Pinned libdwarf retains strings of at most four bytes including
NUL as inline `DW_FORM_string`; longer strings use deterministic
`DW_FORM_strp` offsets. A repository-owned patch widens libdwarf's private
AArch64 producer relocation-type field because the upstream byte field
truncates `R_AARCH64_ABS32`/`R_AARCH64_ABS64` and otherwise silently prevents
valid string-table production. GitHub Actions run 33778570507 passed the
producer and real exporter/validator/GDB matrix for x86-64, AArch64, ARM32,
and both MIPS32 byte orders, plus the Windows-hosted exporter.

**RESOLVED — `.debug_frame`:** ADR-0002 rejects synthetic call-frame
information for the current ELF milestone. GDB keeps the original ELF loaded
and uses its existing unwind metadata. Ghidra stack-frame summaries do not
provide sufficient instruction-range CFA and saved-register evidence, so
invented CFI could corrupt backtraces and variable evaluation.

**CONFIRMED REQUIREMENT (2026-09-03):** the user selected the MIT License for
GhidraDwarfForge. The repository license covers project-authored work; it does
not relicense Ghidra, JNA, libdwarf/libdwarfp, or other dependencies.

**CONFIRMED (2026-09-03):** the user chose to retain bundled native libraries
and provide their required notices and corresponding-source availability.
Hosted run `33798706990` assembled a native-inclusive release containing the
exact checksummed libdwarf 2.3.2 source archive, the applied repository patch,
LGPL/copyright notices, and reconstruction instructions. It also contains the
installed license files and exact MSYS2 package versions for the Windows zlib
1.3.2-2 and Zstandard 1.5.7-2 runtime DLLs. Independent artifact inspection
passed the nested compliance manifests, whole-release manifest, and pinned
source/patch digest checks. Ghidra 12.0.3 and its JNA 5.14.0 remain documented
host-provided dependencies, not redistributed payloads.

### 16.22 Release-hardening coverage

**CONFIRMED (2026-09-03, GitHub Actions run 33824105805):** the isolated
producer smoke can repeat a
complete init/DIE/transform/relocation/finish lifetime in one JVM. The Linux
path samples post-warmup RSS and rejects growth above 32 MiB over 64 lifetimes;
the Windows path repeats the same native lifecycle without claiming a
platform RSS measurement. A companion smoke resolves and loads the exact
checksummed native pair from an installed extension. Local Linux runs passed
64 explicit-native lifetimes after rebuilding the patched source; the package
resolver also selected the expected pair from a prior installed artifact. The
strengthened test initially exposed shared upstream `.debug_str` state in that
prior native: identical lifetimes grew
from 95 to 190 bytes and onward. The bundled source patch now allocates the
string-section descriptors per producer and releases their buffers at finish;
the rebuilt local producer emitted identical 95-byte output for all 64
lifetimes. Hosted Linux and Windows passed 64 explicit-native lifetimes and
loaded the checksummed native pair from the clean installed release artifact.

**CONFIRMED (2026-09-03, GitHub Actions run 33824105805):** every target
fixture now includes a
partially stripped, symbol-retaining variant. A source-inventory and
reproducibility harness builds each target twice, requires byte-identical file
sets, and records artifact hashes plus ELF header/program-header/section/note
metadata. Local x86-64, AArch64, and both MIPS32 byte-order rebuilds passed;
the hosted x86-64, AArch64, ARM32, MIPS32 big-endian, and MIPS32 little-endian
lanes all passed rebuild, real partial-input export, structural validation, and
native/QEMU GDB behavior checks.

**CONFIRMED (2026-09-03, GitHub Actions run 33824105805):** target selection is
table-driven and
fails closed for unvalidated class/byte-order combinations. A source guard
confines architecture identifiers and register spellings to the audited target
description/register-map boundary. The matched sidecar writer neutralizes all
inherited relocation-section headers after producer relocations are resolved,
and regression tests reject published `SHT_REL`/`SHT_RELA` sections. The real
export harness at that historical checkpoint required `.debug_aranges` to
remain absent and used CU/subprogram `DW_AT_ranges` as the lookup authority.
The later exact code-index change preserves those authoritative ranges while
replacing the absence assertion with a decoded coverage check.

### 16.23 Alpha release resumption

**CONFIRMED (2026-10-22):** the user resumed release work and authorized the
proposed fresh full CI validation and publication of `0.1.0-alpha.1`. This
supersedes the publication deferral recorded in Section 16.20. The repository
and remote `main` both identify commit
`f4a01992deb5b2e65736c573cc3e6d2cbe59ce75`.

The clean local extension build and thirteen native-independent smoke tests
passed. Fresh GitHub Actions run `39892474892` produced the native-inclusive
release candidate; independent ZIP, nested manifest, source/patch digest,
version, and wrapper-permission checks passed. Its SHA-256 is
`27ad36e575ad410df475d2ec45c0fac03287dab19515fcbe39ffc6dd69bfc502`.
All twelve jobs passed, including the five architecture lanes, Windows-hosted
export, and the aggregate `required-validation` gate. The verified bundle and
checksum file were published as
[v0.1.0-alpha.1](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.1)
on 2026-10-22 America/Chicago (2026-10-23 UTC), with the public tag pointing to
the tested commit. Architecture scope and alpha limitations remain as
documented in the release notes; publication does not imply completion of
unrelated scope gaps.

### 16.24 Post-alpha input and GUI validation

**CONFIRMED (2026-10-22):** testing the published alpha on `/usr/bin/true`
exposed a stale `.gnu_debugaltlink` warning in GDB. The development writer now
replaces, rather than merges, the original debug view: matching `.debug_*`
sections receive new uncompressed payloads, while unmatched DWARF, GNU
compressed DWARF, indexes, debug links, and mini-debug data are retired under
`.forge.stale` names. Duplicate matching section names leave only one active
replacement. Original bytes and target identity are retained; the executable
is never changed. ADR 0001 records this policy.

All four width/byte-order combinations pass the native-independent writer
test. Real x86-64 compiler-DWARF inputs (plain, SHF_COMPRESSED zlib, GNU zlib,
and a genuine `.gdb_index`) pass headless export, structural validators, and
GDB against the debugless runtime fixture. Each resulting sidecar contains one
Forge CU. Importing compiler types can create equal names in distinct Ghidra
categories; the enum oracle now also uses the unique `OP_INVALID` enumerator
to select the curated type. General type-name disambiguation remains a scope
limitation, not a reason to discard valid types.

Two unmodified distro PIEs, `/usr/bin/true` and `/usr/bin/basename`, pass
independent double imports with byte-identical sidecar/source output, unchanged
input hashes, validators, and warning-free GDB entry/application breakpoints,
source listing, stepping, and normal exit. These tests use naturally recovered
analysis with no fixture renames. This is narrow real-world evidence, not a
claim that arbitrary firmware is validated.

**CONFIRMED:** actual Linux GUI output-directory selection and cancellation
pass in a non-headless Ghidra 12.0.3 JVM under a private Xvfb display. The test
runs the production script and real Swing chooser, writes to the selected
directory when the input directory is read-only, and publishes nothing after
cancellation. Hash preservation, validators, and GDB source stepping pass.
At that checkpoint, Script Manager navigation and Windows GUI behavior were
untested; Section 16.32 records the later hosted component evidence.
The three new integration harnesses are wired into the x86-64 CI lane; hosted
run `39896787460` passed all twelve jobs for implementation commit `3cdc3f8`,
including these three tests, the five target lanes, Windows-hosted export,
and the aggregate gate. Detailed evidence is recorded in `VALIDATION.md`.
These changes do not alter the already published alpha artifact.

### 16.25 Correctness review of the published alpha

**CONFIRMED (2026-10-23):** all six review findings against `f4a0199`
are valid. Explicit wrapper logs could truncate the input before export;
nonzero first-load file offsets shifted exported addresses; bit fields used
conflicting location attributes and, on big-endian targets, the wrong storage
width; inherited `.gdb_index` could hide replacement symbols; and source
lookup depended on GDB's working directory. The index fix is already in the
post-alpha development branch described above, not in the published alpha.

The current development fixes reject log aliases before launching Ghidra,
including symlink/hardlink aliases; translate against the minimum PT_LOAD
virtual address used by Ghidra; emit exclusively `DW_AT_data_bit_offset` for
bit fields using their actual component storage width; and record the absolute
artifact directory in the source line table. An explicit log in existing-project
mode now requires the original ELF argument because the wrapper cannot safely
infer that path before opening the project. Private temporary logs remain the
default. Absolute source paths make lookup independent of debugger CWD;
moving the artifact pair still requires GDB source-path remapping. Byte
determinism is assessed at the same output destination.

**CONFIRMED locally:** real Ghidra/GDB reproductions fail before these fixes
and pass afterward for nonzero load offsets, x86-64/MIPS32 BE bit-field values,
and source lookup from an unrelated directory. The bit-field oracle also passes
on AArch64 and MIPS32 LE. Bash and portable PowerShell collision tests reject
the operation before launch and preserve protected hashes. Tests and evidence
are recorded in `docs/VALIDATION.md`.

**CONFIRMED:** hosted run `40041110549` passed all twelve jobs for implementation
commit `cd906de`, including the new ARM32 bit-field values, native Windows
wrapper safety (without skipped cases), all five architecture lanes, and
Windows-hosted export. The first run exposed a known QEMU synthetic-vDSO
warning in the ARM32 compiler oracle; its narrow handling now matches AArch64
and still requires the same warning in the independent compiler oracle before
accepting it for Forge. No value assertions were relaxed. The published
`0.1.0-alpha.1` bundle has not changed and still contains the reviewed defects.

### 16.26 Current handoff and remaining-work audit

**CONFIRMED:** the documentation-only head `b313e32` subsequently passed all
twelve jobs in run `40042631047`. PRs #16/#17 are still unmerged. The original
eight-step prototype bring-up instructions at the end of `TODO.md` were stale;
they have been replaced with a current sequence and an evidence-based backlog.
Existing build/native ABI/source/type/location/CI machinery must not be
reimplemented merely because older snapshot prose describes it as absent.

**HISTORICAL at that audit:** remaining core work included ELF layout/size robustness, distinct
function/linkage identity, richer scopes/declarations, functions whose body
starts below their entry point, and more precise variable lifetimes/storage
migration. The current stable-register and SP-relative location profile is
validated; it does not establish arbitrary value migration or scope/liveness.
Additional target profiles require explicit, finite acceptance cases. At that
audit, native Windows GUI and Script Manager journeys were **PRESENT,
UNVERIFIED**; Section 16.32 records the subsequent component passes and
remaining combined-head reproducibility gate.

**HISTORICAL:** extended-section-number emission was parked on
`work/elf-table-robustness` at `f2884e6`. Its build/smoke checks passed, but a
large-output shell-pipeline failure stopped the integration harness before GDB;
it has no complete hosted validation and is outside PRs #16/#17. That checkpoint
does not complete missing section-name tables, extended program-header counts,
or large-file/resource handling.

Optional debuglink remains unimplemented. Inlining remains an **UNCERTAIN**
evidence investigation, and performance work must begin with benchmarks and
explicitly selected improvements. The accepted no-synthetic-CFI decision is
already complete. No optional item was marked implemented by this audit.

### 16.27 ELF robustness continuation

**CONFIRMED:** the user selected P0.9 on 2026-10-23. Work is isolated on
`work/elf-robustness-completion`, based on PR #17, retaining the old checkpoint
and the earlier correctness fixes. Ghidra 12.0.3/Java 21 and pinned libdwarf
2.3.2 remain the baseline; no JNA/native ABI changes were needed.

**CONFIRMED locally:** the reader/writer now uses bounded metadata buffers and
file channels for original bytes. Extended section and program counts,
unnamed section tables, high file offsets and metadata limits have ELF32/64 ×
both-byte-order regressions. Partial `PT_NOTE` coverage preserves build ID
without duplicate note records. Physical symlink traversal and input/output
alias rejection are tested. Cancellation during copy and before publication
preserves prior outputs and removes staging files.

The >2 GiB compiler oracle passes with a 64 MiB Java heap. Real >2 GiB
Ghidra export, validators, GDB values/source stepping, input hashes and
byte-identical fresh-import repeats also pass. Import wrappers explicitly
select `ElfLoader`: automatic format detection exhausted Ghidra's heap inside
an unrelated SOM probe before ELF import. These tests bound source-file I/O,
not the memory required for arbitrarily large recovered program models.

The stronger extended-program fixture found an additional silent address
error: Ghidra searches only its first 20 headers for an initial base, then
records the base actually used to map ELF addresses. With all load headers
later, recomputing a minimum load VA produced a false delta. Production now
uses the loader's recorded original base, matching Ghidra's own DWARF importer;
missing/invalid metadata fails explicitly. Real MIPS `main` changed from the
incorrect `0x800874` to `0x400874`; the ordinary nonzero-offset/rebased fixture
still passes. ADR 0001 and `docs/VALIDATION.md` record limits and evidence.

**CONFIRMED:** final strengthened-layout runtime/rebase checks pass locally
on x86-64, AArch64 and both MIPS byte orders. Real mid-copy cancellation reports
`CANCELLED` while preserving both prior artifacts. Implementation `3e47589` in
[PR #18](https://github.com/zwilcox/GhidraDwarfForge/pull/18) passes all twelve
jobs in [run 40047390539](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40047390539),
including ARM32 and Windows-hosted export. ARM32 artifact inspection independently
confirms the late-header, rebase, value, source, validator and hash assertions.
P0.9 is complete within ADR 0001's documented bounds. Integration is tracked
by PRs #16/#17/#18; the published alpha is unchanged. Native Linux/QEMU cannot directly execute the
large-program-table fixture; its exact-input static checks and runtime checks
against the proven-equivalent ordinary load image are explicitly distinguished.

### 16.28 PR approval authority clarification

**CONFIRMED (2026-10-23):** the user reminded the agent that PR approval was
already delegated. The authenticated `zwilcox` account has admin/merge access.
`main` enforces an up-to-date `required-validation` check, including for admins,
and does not require a separate approving review. GitHub's own-author approval
restriction does not prevent normal integration after review and passing CI.

The previous handoff wording combined routine merges with new release
publication and caused an unnecessary stop. Routine reviewed PR integration
now proceeds under the standing authorization without another confirmation.
Independent review found no outstanding findings or review threads in the
three-PR stack. PR #16 was merged at `5f8d07a`; subsequent PRs are retargeted
and validated against the updated `main` in order. Use GitHub for live merge
and CI state. No protection rule was weakened, no admin bypass was used, and
this integration does not replace the published alpha artifact.

### 16.29 Incoming-register parameter lifetimes

**CONFIRMED locally (2026-10-23):** an incoming parameter can retain its exact
register location before that register is overwritten. The new proof accepts
only one ordinary contiguous body beginning at the function entry, complete
decoded instruction coverage, linear fall-through and a final actual return.
It rejects branches, calls, opaque p-code, delay slots, flow overrides, secondary
incoming flows and decoding gaps. Register writes are checked against both
named output registers and raw p-code byte ranges, including partial aliases.

The value remains valid at the first writing instruction, before execution,
and is unavailable from its fall-through address onward. No later move or
restoration is inferred. Existing name/type information and analyst storage
precedence remain intact. Locals, composites and other rejected storage retain
the conservative path; the existing location-list representation supplies the
available prefix and honest unavailable remainder without new native calls.

Real compiler-DWARF and production Ghidra/GDB tests pass on x86-64 and AArch64
for normal/PIE/rebased inputs, including partial-register writes, exact boundary
values, unavailable later values, deterministic artifacts and preserved inputs.
The feature is a bounded entry-lifetime improvement, not general storage
migration. See `docs/VALIDATION.md`; its hosted gate remains pending.

### 16.30 Corrective alpha.2 preparation

**CONFIRMED integration:** PRs #16/#17/#18 are merged through their enforced,
up-to-date checks; `main` is `1f2a46b`. The final ELF robustness PR head passed
all twelve jobs in run `40051501201`. The versioned candidate includes the
separately reviewed `32d2303` automatic-association correction and strengthened
build-ID/debuglink tests. Its combined tree passes nineteen native-independent
smokes, `buildExtension` and `release-package.sh`; exact versioned hosted
validation and publication remain **PLANNED**.

**CONFIRMED (2026-10-23):** `VERSION` is now `0.1.0-alpha.2` in the isolated
corrective-release branch based on `b089802`. The release notes at
`docs/releases/0.1.0-alpha.2.md` describe all six alpha.1 correctness fixes,
P0.9 ELF layout/resource/cancellation changes, and the tested host/target
profiles. They explicitly retain the direct-`PN_XNUM` runtime restriction,
metadata limits, conservative location policy and remaining feature work.
Later feature branches are excluded from this candidate.

Source inspection of the pinned Script Manager confirms that its ordinary Run
action supplies no script arguments. The existing no-argument production
script performs preflight only. Release notes therefore direct alpha.2 users
to the tested headless wrappers and distinguish the programmatically invoked
GUI fallback test from a full Script Manager export journey; later launcher
work remains outside this corrective candidate.

The Ghidra-generated `extension.properties` still uses `version=12.0.3` for
host compatibility. The packaged `VERSION` and assembly-derived
`RELEASE-MANIFEST.txt` identify alpha.2. No native library was rebuilt for the
local preparation check: existing hosted native files and corresponding-source
materials were verified against their recorded manifests before reuse.

**CONFIRMED locally:** clean `buildExtension`, `release-package.sh`, two
byte-identical native-inclusive assemblies, all release/platform/source/runtime
manifests, version metadata, ZIP integrity/timestamps and executable wrapper
permissions pass. The assembled Linux native pair passes
`packagedNativeProducerSmoke` for 20 producer lifetimes with deterministic
output. Logs and the local rehearsal ZIP are under
`/home/ziggy/GhidraDwarfForge-worktrees/corrective-alpha2/build/release-preparation/`.
The shared Ghidra installation was not changed.

**PLANNED:** integrate the versioned candidate after the reviewed correction
stack and run the full required matrix on the exact release commit. Publish
only that validated CI package with its commit, run and checksum recorded.
Local assembly is a packaging rehearsal, not final hosted release validation.
No alpha.2 tag or release was created during preparation; alpha.1 and its
assets remain unchanged.

### 16.31 Source/sidecar publication timestamps

**CONFIRMED:** main run `40053041949` failed the AArch64 rebased extended-program
layout's static GDB check with a source-freshness warning. GDB 15.1 compares the
source mtime with its compilation unit's loaded debug objfile, which is the
Forge `.dbg`, rather than necessarily the original executable. Pair publication
previously wrote the artifact first and source second, exposing a seconds-boundary
race even for an unchanged program. The retained failed Forge pair reproduces
that comparison independently of the original ELF's timestamp.

Publication now raises the staged sidecar mtime to the staged source mtime only
when needed, before any final target backup/replacement. It compares full
`FileTime` values, never lowers an existing newer sidecar timestamp, and keeps
callback/cancellation order unchanged. Original executable bytes and timestamps
are untouched. Rollback restores the previous pair and its timestamps. A later
source edit still warns in GDB; no warning filter was added. Deterministic unit,
source-built GDB/runtime, and retained AArch64 Forge-artifact checks pass locally.
See `docs/VALIDATION.md`; the next exact versioned CI remains required.

### 16.32 Installed Script Manager export journey

**CONFIRMED locally:** Ghidra 12.0.3's Script Manager Run action creates and
executes a script without supplying arguments. Running the existing
`GhidraDwarfForge.java` therefore correctly performs native-free preflight,
but did not provide the documented ordinary GUI export journey.
`ExportGhidraDwarfForge.java` is now an explicit DWARF-category launcher that
delegates to that same production script with `--packaged-natives`. It leaves
the native-free contract and headless wrappers unchanged. Release assembly
requires both installed scripts.

`gui-script-manager.sh` creates a real Ghidra front end and Script Manager
plugin in a private installation. It discovers the installed script sources,
double-clicks their table entries, checks Console output, and selects/cancels
the production output chooser with real mouse events under Xvfb. Linux run
`run.5CZSfnND` passes input preservation, exact output pair/no cancellation
outputs, GNU/LLVM/libdwarf validation, and GDB source lookup/stepping/normal
exit. The native-free preflight is also executed through Script Manager.
See `docs/VALIDATION.md` for reproduction and diagnostic scope.

**CONFIRMED:** run `40054563515` at `83b74a6` passed all twelve jobs, including
the Linux Script Manager/validator/GDB journey and native Windows desktop/ACL
probe plus full Script Manager selection/cancellation. The Windows journey
uses packaged natives, real ACL denial, paths with spaces, original hashes,
Console reports and GNU/LLVM validation. Independent `dwarfdump` was unavailable
and Linux ELF runtime GDB was explicitly not run on Windows. These are actual
component results, not evidence that every subsequent combined head passes.
The GUI changes remain separate from the corrective alpha.2 release scope.

The first hosted Linux Script Manager run `40053779323` exposed a harness
focus race: the selected component was showing but covered by other windows,
and no script executed. The driver now waits for native window focus followed
by table focus, then clicks the actual visible Name cell using fresh bounds.
Failure Console/window/screenshot diagnostics are retained. Controlled overlap
reproduction and full local run `run.B4Zeob4d` pass. No timeout or CI gate was relaxed.

Attempt 2 of combined run `40055880742` exposed a second harness issue on
Windows: after successful selection/export, the cancellation case failed its
table-keyboard-focus assertion before the preflight double-click. The retained
desktop shows the intended selected row in the foreground Script Manager,
with keyboard focus in its filter. Pinned Ghidra 12.0.3 deliberately requests
that filter focus in `GhidraScriptComponentProvider.componentActivated()`.
The test now requires a foreground window and the selected visible Name cell,
then verifies one delivered real mouse double-click on that exact filename.
It does not require table keyboard focus before a mouse action. A controlled
filter-focus regression runs on both host lanes; the full Linux journey
`run.syAI9N4O` passes with validators/GDB. The new exact-head native Windows and
complete combined gates remain pending; no production script or launch retry
was introduced.

Run `40062946718` at `cec4b5b` exposed a third harness observation error on
Linux. The real double-click had entered Ghidra's modal "Compiling Script
Directory" action, but an appended component mouse listener had not yet run.
The nested Swing event loop let `Robot.waitForIdle()` return before that late
observer, causing a false missed-click assertion. A controlled modal-dialog
case reproduces the exact failure with the previous helper. The observer now
uses the Toolkit event listener before component dispatch, filters the exact
table/left double-click/Name cell, and is always removed afterward. It neither
consumes the event nor invokes the script. Both host harnesses run the new
control. Full local Java 21 journey `run.O3SsqvwH`, using that run's verified
release package, passes select/cancel, GNU/LLVM, strict libdwarf checking with
three exactly corroborated inherited frame diagnostics, and GDB. Hosted
validation of this correction, including native Windows, remains required.

Run `40064976588` at `a977a93` passed both click controls but exposed a separate
Linux display problem: Java reported the floating Script Manager at `(0,0)`
while the native desktop placed it at `(298,253)`. The coordinate click reached
the category tree. A standalone pack/position/show probe reproduces incorrect
Java versus `xwininfo` coordinates under bare Xvfb (2 of 100 final comparison
cases); the same probe with Openbox matches all 100. The Linux harness now owns
Openbox, a private configuration/menu and Xvfb, verifies WM readiness, and runs
an independent 100-window geometry check before the genuine Ghidra journey.
Full Java 21 run `run.KPdcV6p3` passes geometry, both chooser outcomes,
GNU/LLVM/strict-libdwarf and GDB; its Openbox log is empty. Process cleanup,
mouse dispatch and production oracles remain intact. Windows code is unchanged
and the new full hosted gate remains required.

The combined-production follow-up `run.yI7ooUik` passed native geometry and
delivered the real double-click, but did not launch the preflight script.
Buffered diagnostic reproduction `run.3HcGrt32` identifies a separate harness
readiness race: Ghidra's pending table-filter timer clears selection after the
second mouse press; the second click reaches `runScript()` with no selected
`ResourceFile`, and selection restoration runs afterward. The harness now
observes completion of the pinned ScriptList refresh, category-tree work and
filter timer, table-filter timer and sorting, drains queued selection repair,
then selects the final row and performs one ordinary double-click. It does
not flush or modify those production updates. A real Ghidra table/filter
control verifies the former selected/visible predicate accepts pending work,
then verifies filtering and selection repair finish before the single action.
Full Java 21 combined-product run `run.LFXUdxrq` passes all three controls,
100 geometry cases, select/cancel, GNU/LLVM/strict-libdwarf and GDB, using
production JAR SHA-256 `d6e94336652ddc2cc3a14f9bc2971f58d1ca7cb1dcbd980fb713bd058779470e`.
These shared harness changes still require renewed Linux and native Windows
hosted validation; earlier component runs remain historical evidence.

### 16.33 Shared-object QEMU debugger endpoint isolation

**CONFIRMED:** combined GUI run `40055880742`, MIPS32LE job `120759663719`,
failed before debugger attachment because TCP port `40514` was already in use.
The old shared-object harness derived this port from its PID. The failure is
an observed test-infrastructure collision, not evidence of an exporter defect.

The shared-object harness now launches QEMU with a unique short UNIX socket in
a mode-0700 directory, supported by the tested QEMU 8.2.2 and GDB. Bounded
child/listener readiness does not consume the debugger connection. Startup
failure, timeout and caller failure retain diagnostics and clean up the owned
child/socket. No GDB execution or diagnostic is retried or waived. Real
MIPS32LE shared-object debugging passes while its exact old TCP port is held
open; native QEMU/GDB startup and failure-cleanup controls also pass locally.
The two controls are wired into CI; exact-head hosted validation is pending.
Other QEMU scripts still using TCP are a separate, evidence-driven follow-up.
See `docs/VALIDATION.md` for commands and retained evidence.

Attempt 2 of GUI run `40058560162` failed this startup control before GUI
testing: the x86-64 lane did not install `qemu-user-static`, so
`/usr/bin/qemu-x86_64-static` was missing. The cross-target lanes already
installed it. The x86-64 toolchain step now declares the same dependency.
The native Windows dependency mirror retry succeeded, but its GUI job was
skipped after the x86-64 failure. This run supplies no new GUI product result;
the corrected complete hosted gate remains pending.

### 16.34 Native patch checkout and provenance consistency

**CONFIRMED:** prepublication audit of candidate run `40055176326` found that
Windows `BUILD-METADATA.txt` recorded patch hash `733405d03e2fd34f7bba971e6bbfe534d72ee9b3c1856879a7652f4eff17bc2a`,
while the release manifest and bundled patch used the pinned
`b98561b3e63b76546bd2f18d81d53e188b56deb637b5e145205b3b6eedadf696`.
The former is exactly the CRLF checkout of the latter. Applying each with GNU
patch to independent copies of the pinned source produced identical source
trees; the CRLF application explicitly stripped trailing CRs. This explains the
metadata discrepancy, without asserting that the original records matched.

Git attributes now force LF for native patches. CI checks the pinned hash before
all four primary/comparison patch applications. Assembly rejects a noncanonical
bundled patch and missing, malformed, duplicate or inconsistent platform patch
hash records before replacing the release output. Canonical hashes in escaped
Windows/CRLF metadata remain accepted. The native version, patch contents and
Java/native API are unchanged. Assembly explicitly accepts the unbundled Gradle
base and rejects native/compliance directories already in that base, preventing
stale base metadata or binaries from filling gaps in new native inputs.
Checkout-conversion and package regressions pass
locally; exact native Windows and complete candidate CI remain required before
publication. See `docs/VALIDATION.md` for retained evidence.

### ARM32 static-scope fixture unwind correction

**CONFIRMED:** semantic run `40057031192` at `8e3fd27` failed only the ARM32
target's static-scope fixture precondition: it required a DWARF FDE, but the
stripped compiler output has native `.ARM.exidx`/`.ARM.extab` rules and only
an `.eh_frame` terminator. It stopped before Ghidra export or the later
floating-register tests. This is a target-specific harness assumption, not
an observed exporter failure.

The ARM precondition now verifies independent `readelf` decoding and usable
native-index coverage for both owner functions and main; other targets keep
the FDE requirement. Actual absent/truncated/cantunwind/Refuse-to-unwind ELF
copies are rejected without changing supplied originals. ARM32 exec, PIE and
rebased PIE now pass the unchanged compiler/Forge GDB scope/value/source/return
oracles, GNU/LLVM checks, input hashes and repeated-export comparison
locally using an isolated GCC 13.3/sysroot and exact hosted semantic package.
The old distro checker returned zero despite four summary errors; independent
review caught the false clean claim. Rechecking these exact three artifacts
with pinned consumer 2.3.2 produces completed zero-error summaries. The
separate strict-validator investigation covers the broader matrix.
The evidence establishes unwind availability plus successful return behavior,
not which GDB unwinder was selected. No producer/runtime implementation or
warning allowance changed. See `docs/VALIDATION.md`; corrected hosted ARM
validation remains pending.

The subsequently reached ARM scalar-FP cases now pass exact stable float and
double values across exec/PIE/rebase/repeat, including `s1`'s upper `d0` slice.
The clobbered parameter stays unavailable: actual `bx lr` p-code includes
opaque `setISAMode`, which deliberately fails the existing whole-body prefix
proof. Preparation verifies this evidence; report and GDB checks require the
explicit omission. x86/AArch64 positive prefix tests are unchanged. Pinned
2.3.2 reports zero errors for all six ARM FP samples. No ARM mode-switching
return prefix support is claimed.

### 16.35 Independent-validator reporting gap

**CONFIRMED:** PR #19 merged as `680ecd6` after candidate run `40057428382`
passed all twelve jobs and its native-inclusive package passed independent
provenance/source/producer checks. Alpha.2 was still unpublished at that checkpoint. A subsequent
review of a new ARM static-scope test exposed a broader existing harness gap:
libdwarf `dwarfdump -ka -ks` exits zero while printing nonzero check summaries.
The shell tests did not enforce those summary counts.

The five corrective-run target artifacts were downloaded and checked against
GitHub's artifact digests. The audit inspected 201 dwarfdump/LLVM result logs
and found nonzero libdwarf summaries in 25 x86-64, 14 AArch64, and four logs
in each ARM32/MIPS32 lane. These are log counts, including repeated cases, not
counts of distinct defects. The older checker mishandles DWARF 5 ranges and
unnamed sections. The validation executable is now built separately from the
pinned libdwarf 2.3.2 source, with a checksum-pinned correction to its line
sequence check: sequence boundaries are not function boundaries. The shipped
native libraries and their patch/provenance contract are unchanged.

**CONFIRMED locally:** the strict runner enforces full numeric summaries and
completion, exit status and empty stderr. It accepts an inherited frame-length
diagnostic only when the original ELF produces the exact same diagnostic and
has identical target metadata and `.eh_frame` address, size and bytes. Raw
diagnostics remain visible. Malformed reports, input/log aliases, corrupted
line programs and corrupted range relationships have rejecting controls.
The checker artifact includes its source, patch, build instructions, manifests
and GPL/LGPL notices; it is excluded from release-native inputs.

A fresh five-target matrix passed 25 non-sectionless export/validator/GDB
cases. The five sectionless cases exposed missing image-bound evidence:
their sidecars contain allocated identity notes but no load extents, causing
the checker to mistake note addresses for the image limits. Independent ARM32
and MIPS32 inspection found all emitted location intervals inside the original
executable segments and their owning functions. The selected correction adds
inert sectionless-only load extent metadata derived from original `PT_LOAD`
headers; see ADR 0001. **CONFIRMED locally:** the corrected writer passes
ELF32/64 in both byte orders, five real sectionless exports with zero checker
errors, exact load/interval metadata checks, rejecting corruption controls,
GDB runtime checks and byte-identical repeats. All 19 strict-baseline CI Java
smoke tasks, the extension build, packaging/wrapper checks and the greater-than-2-GiB
and source-timestamp integrations also pass. The local build uses JDK 25 with
Java 21 bytecode; the installed Java 21 directory contains a JRE without
`javac`. Hosted Java 21 and the complete corrected matrix remain
**PRESENT, UNVERIFIED**. Do not publish based only on the earlier green gates,
including main run `40058691020`.
See TODO Section 0.2 and `docs/VALIDATION.md`.

PR #22's first hosted run `40061424810` passed the native builds, extension,
release package and ARM32/MIPS32 target lanes, but failed x86-64 and AArch64
at original-file frame corroboration for `PN_XNUM` fixtures. The standalone
consumer rejects section zero's nonzero `sh_info` even when it encodes the
valid extended program-header count. The sidecars themselves pass LLVM and
have only their exactly inherited frame messages. A separate validation-only
reader correction passes 16 local positives, 60 malformed-header controls,
exact retained-original corroboration and fresh x86-64/AArch64 ELF-layout
export/validator/GDB suites. No additional diagnostic exception or shipped
native-library change is selected. Windows-hosted checks were skipped
and the aggregate gate failed. The exact `bf7f2b1` package precheck passed
source/manifests/native provenance and 20 isolated Java 21 producer lifetimes,
but this is not a release approval. The checker completion gate additionally
rejects missing zero-count categories, demonstrated by fifteen new controls
and 52 unchanged retained real reports.

### Definite ELF/Ghidra target agreement (2026-10-24)

**CONFIRMED locally:** the strict baseline `bf7f2b1`, rebuilt and installed in
an isolated Ghidra copy, still exported an ELF64 x86 target deliberately imported
as AArch64 and an ELF32 MIPS little-endian target imported as ARM. Both shared
pointer width/byte order with their forced language; both produced `PARTIAL`
sidecars accepted by LLVM. A structural checker cannot establish that Ghidra
decoded the original processor correctly.

The isolated target table now records the processor names from pinned Ghidra
12.0.3 ELF opinions/language definitions. A small Program adapter compares
processor, data-pointer width and byte order before image-base handling,
function extraction, decompilation or native production. Mismatch diagnostics
identify both ELF and Program metadata, including language/compiler IDs.
The guard reads metadata only. It neither changes the Program nor rejects a
compiler specification or language variant merely because it is nondefault.
ISA/register width is not substituted for data-pointer width; broader ABI and
ELF-flag agreement remains separate work.

All five supported metadata profiles, same-width processor contradictions,
width/endian contradictions and nondefault-choice controls pass. Real forced
imports reject with both absent and existing output pairs, preserving original
and prior-pair hashes/mtimes and leaving no output temporaries. Correct five-
profile ET_EXEC exports pass GNU/LLVM/strict-libdwarf and native/QEMU GDB checks.
The full hosted matrix and native Windows execution of the new metadata smoke
remain **PRESENT, UNVERIFIED**. See the target-agreement section of
`docs/VALIDATION.md`; this follow-up is separate from corrective alpha.2.

The normal merge of strict `99845c7` into target-agreement `736d164` adds
only the reviewed validation corrections and their documentation. Target-guard
production and test code are unchanged. Workflow and changed-script syntax
checks pass; prior smoke/runtime suites were not repeated. Hosted validation
of this separate follow-up remains pending.

### P3.4 bounded inline-evidence investigation (2026-10-23)

**CONFIRMED:** ADR 0003 records the completed investigation and the conditions
for implementing inline-instance export. The installed Ghidra 12.0.3 source
and help distinguish the function-level decompiler inline flag from compiler
inline instances. The DWARF importer can retain inline children as locals of
the containing function and preserve source rows/optional comments; this is
not evidence that all inline information is discarded. Its inline processing
also flattens the body's disjoint ranges for comments/child handling.

The reproducible `src/test/research/inline/run.sh` probe builds its own GCC
optimized-inline fixture, validates its compiler DWARF and demonstrates an
actual GDB inline frame with argument 4/local 11. A real Ghidra import retains
two `IMPORTED` inline locals, 20 source rows and two comments; a debug-stripped
counterpart loses those compiler identities. Independently marking an ordinary
callee inline removes its high-pcode call while its real machine call remains.
Original hashes match. Exact source hashes and observations are committed at
`docs/research/inline-evidence-12.0.3.txt`; full logs are retained under the
isolated inline worktree's `build/test-results/inline-evidence/run.tB61GBSm/`.

The probe's Ghidra importer reports three unrecoverable `DW_OP_reg5`
expressions for other optimized locals; this limitation is recorded, not
suppressed. This is research evidence, not a Forge inline-export validation or
a new architecture support claim. No production exporter code changes.
Inline DIE emission remains deferred pending an explicit provenance-bearing
instance model and the compiler/analyst-evidence GDB checks in ADR 0003.

### Performance scaling baseline (P3.5)

**CONFIRMED locally (2026-10-23):** a standalone benchmark harness now builds
synthetic named-function ELF workloads, measures import separately from saved
project export, and retains commands/tool versions/module hashes/metrics.
Three repeated fresh-JVM exports of 100, 1,000 and 10,000 generated functions
have medians of 2.52, 3.27 and 10.62 seconds on the recorded host. All artifacts
pass GNU/LLVM, full GDB DWARF symbol/address/source checks, runtime
entry/stepping/exit, original hashes and byte-identical reruns. Their historical
exit-zero libdwarf checks did not enforce numeric summaries; those pass labels
are withdrawn pending the strict evidence recorded below.
Independent review strengthened the oracle so inherited minimal ELF symbols
cannot mask missing function DIEs, and timeout cleanup kills descendants even
when the wrapper exits first. The adversarial cleanup probe passes.

The harness changes no production code and excludes validators from timing.
Its whole-process measurements include JVM startup and do not identify which
export phase dominates. **PLANNED:** representative complex-binary and phase
profiling before choosing an optimization; P3.5 remains partially complete.
See `docs/PERFORMANCE.md` for commands, retained evidence and limits.

### Optional debuglink transaction design and re-export evidence

**CONFIRMED:** bounded Linux probes of GNU 2.42 `objcopy` on disposable
source-built x86-64/AArch64/MIPS32 big/little-endian copies preserve program
headers/load bytes for standard exec/PIE inputs and encode the correct
target-endian debuglink CRC. The tested tools reject no-section-header and
unnamed-section inputs; their PN_XNUM rewrites change `e_phoff` and fail the
proposed strict preservation check. These attachment-backend limitations do
not narrow ordinary export support. `objcopy` accepts a non-ELF debug file,
so successful invocation/CRC alone cannot establish target identity.

**PLANNED:** the product operation in `docs/ADR-0004-DEBUGLINK-ATTACHMENT.md`
requires an explicit post-export choice, independently verified identity,
exclusive original backup, supported host metadata, atomic replacement and
tested rollback. Preflight includes receipt, temporary receipt and log paths
before any write. Refresh exports directly to a new final pair basename,
retains the old pair/receipt, and creates a separate backup of the prior
attached image. Rollback must restore that image's still-valid debug
association, not merely a runnable pristine binary. The old byte-identical
re-export experiment does not validate changed-CRC refresh or this transaction.
A configured staged `objcopy` is the first proposed backend;
the non-loadable sidecar writer must not be reused as an executable writer.
Neither a product attachment command nor native Windows attachment validation
was added. P2.8 remains incomplete.

The existing imported-executable SHA guard stays strict after attachment.
Re-export the current curated Program using explicit `--input=<original-backup>`
and `--output=<fresh-final-sidecar>` for refresh; do not silently update its
imported identity.
The private saved-Program experiment retains an analyst name and proves
backup-based, same-path, byte-identical re-export. Fresh-generation export,
changed-CRC refresh and rollback remain design acceptance, not measured results.
Genuine curation changes require an explicit CRC refresh independently
of the separate type-ordering issue below.
The historical research scripts' bare `dwarfdump` checks did not enforce
complete summaries and are not current libdwarf acceptance evidence. These
design refinements add no product operation or new runtime validation.

**HISTORICAL, resolved bounded determinism finding:** Ghidra 12.0.3's generic
`DefaultDataType` inherits a new process-local universal ID. The research
baseline sorted that key with persistent type IDs, so a newly imported versus
reopened saved Program could produce different type DIE ordering. Settled-
analysis, identical-option/output-path probes showed unchanged normalized
type/function/global/location/body models and byte-identical source; repeated
reopened exports were byte-identical. This was not evidence of target corruption
or changed DWARF semantics. Reproduction and evidence remain in
`docs/research/DEBUGLINK-EVIDENCE.md`.

Semantic commit `3070e95` resolves that finding with a stable fallback key only
for the exact generic `DefaultDataType` class. All other persisted/analyst type
identity rules remain unchanged. The initial/save/two-fresh-reopen regression
compares raw models and actual DWARF/source bytes and passes hosted semantic run
`40063017269`. The fix is included in this combined tree, but not in corrective
alpha.2. See "Stable generic undefined identity across save/reopen" below.

### Semantic and strict-validator integration checkpoints

**CONFIRMED locally:** the normal merge of strict-validator `bf7f2b1` into
semantic `0b754078` retains the function-entry/static-scope, register-prefix,
scalar-FP, saved-program identity and ARM fixture corrections. Five semantic
integration scripts and both isolated semantic producer checks now use the
strict helper with their exact original ELF; the existing LLVM and GDB
oracles remain in place. All 23 semantic Java smoke tasks, extension build,
workflow/architecture checks, package regression and strict-parser controls
pass. Rechecking one retained artifact from each of the five semantic suites
passes with only exactly corroborated inherited frame diagnostics; this is
a validator replay, not a fresh merged export/runtime matrix. No complete
cross-target rerun was performed locally for this merge. Hosted verification
of the combined source remains **PRESENT, UNVERIFIED**.

The subsequent normal merge of strict `99845c7` into semantic `cc8dd8b`
adds complete-category enforcement and the validation-only extended-program
reader correction without changing semantic production sources. Workflow and
changed-script syntax checks pass; the previously passing Java/runtime suites
were not repeated for this validation-only merge. The combined hosted matrix
remains pending.

## 17. Open questions

Codex should not silently answer these through implementation choices. Investigate, document, and obtain user direction when the answer materially changes compatibility or scope.

1. **RESOLVED — Ghidra baseline:** Ghidra 12.0.3 is the first supported version.
2. **RESOLVED — Java baseline:** Extension sources compile as Java 21 bytecode,
   as required by Ghidra 12.0.3. The historical Java 7 Maven wrapper target is
   not the production extension baseline.
3. **RESOLVED — libdwarf revision:** libdwarf v2.3.2, source commit
   `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`, is pinned with the official
   archive SHA-256.
4. **RESOLVED — Native provenance:** release builds compile pinned libdwarf in
   CI from the checksummed official source archive and package only those
   reviewed job artifacts.
5. **RESOLVED — JNA ownership:** the extension uses Ghidra's bundled JNA. The
   obsolete shaded private copy and unpacked JAR tree were removed.
6. **RESOLVED for the current ELF profile — packaging:** matched non-loadable
   sidecars are specified in ADR-0001 and validated for executable, PIE and
   shared-object inputs. Remaining layout/size cases are tracked under P0.9.
7. **RESOLVED for the current milestone — association:** explicit loading is
   supported; standard build-ID discovery is also validated. Automatic
   installation into a debugger's build-ID directory remains a separate convenience.
8. **RESOLVED — build ID:** preserve an existing identity; do not invent one
   when absent. Both cases have integration tests under P2.9.
9. **Optional debuglink:** Should the extension offer a safe “attach `.gnu_debuglink`” mode, and what backup/CRC behavior is required?
10. **RESOLVED for the implemented path policy — output path:** explicit
    input/output overrides, imported-input hash verification, headless failure
    and GUI directory selection are implemented. Remaining GUI journeys are
    tracked under P2.7.
11. **RESOLVED for current output — synthetic source language:** the producer
    emits `DW_LANG_C11`. Richer scope/linkage work must preserve honest source
    language and analyst-facing GDB lookup.
12. **RESOLVED for current line mapping — granularity:** decompiler token/line
    address evidence supplies deterministic executable rows; no addresses are
    assigned merely to fill formatting or declaration lines.
13. **RESOLVED for the current line granularity — overlapping mappings:** one
    instruction address emits one row for the earliest generated source line.
    Revisit this if statement/expression granularity changes.
14. **RESOLVED for current extraction — type precedence:** current listing and
    signature data supply exported types, including analyst edits. Any future
    high-function evidence must preserve that precedence; it is not currently
    a substitute source of unproven variable lifetimes.
15. **RESOLVED for the conservative location profile:** exact stable registers,
    proven stack-depth intervals and supported register composites may receive
    locations; uncertain storage remains locationless with diagnostics. Broader
    live-range evidence and migration are tracked under P1.11a.
16. **RESOLVED for the initial extern/import policy:** external-data declarations
    may omit locations; imported functions/thunks are diagnosed and skipped.
    Expanded declaration/linkage handling remains under P1.7/P3.3.
17. **RESOLVED for the current exporter — inline evidence:** ADR 0003 completes
    the bounded Ghidra 12.0.3 investigation. Inline DIE emission remains
    deferred until explicit instance/origin/range evidence and behavioral
    acceptance exist; it is not inferred from the decompiler inline flag.
18. **RESOLVED — `.debug_frame`:** the current ELF milestone relies on unwind
    information in the original target and does not synthesize unsupported
    CFI. See `docs/ADR-0002-DEBUG-FRAME.md`.
19. **RESOLVED for current packaging — ELF implementation:** repository-owned
    Java reader/writer follows ADR-0001 without a runtime `objcopy` dependency.
    P0.9 may revise buffering/layout handling without changing the identity and
    original-preservation requirements.
20. **RESOLVED — distribution license:** GhidraDwarfForge uses MIT. Required
    notices and exact corresponding source for bundled libdwarf plus the
    Windows runtime notices are included and verified under P0.3. Ghidra/JNA
    are host-provided and are not redistributed.
21. **RESOLVED — Release format:** one versioned Ghidra extension ZIP includes
    the headless wrappers, Linux/Windows natives, and provenance/checksum
    manifests.
22. **RESOLVED — initial support promise:** Linux x86-64 and Windows x86-64 are
    the initial Ghidra host platforms. x86-64 and AArch64 target
    integration lanes are first-release blockers. MIPS is explicitly in the
    product scope and requires a QEMU/native behavior lane before support is
    advertised broadly; the validated ARM32 and MIPS profiles remain narrower
    claims documented in the release notes.

## 17.1 Function entries above their lowest body address

**CONFIRMED locally (2026-10-23):** extraction accepts an entry in any real
body range rather than dropping functions with earlier instructions. The
canonical body remains sorted and retains every gap. Such functions emit
`DW_AT_entry_pc` plus a range list whose first interval starts at that entry;
an interval containing the entry is split there when necessary, with exactly
the same covered bytes. Contiguous bodies with interior entries use that same
representation. Existing ordinary low/high-PC output remains unchanged.

This representation is deliberate: local GDB 15.1 ignores `DW_AT_entry_pc`
and takes the entry from the first range. DWARF 5 sections 2.17.3 and 2.18
permit unordered nonoverlapping range intervals and an explicit entry address.
An attribute-only attempt passed validators but resolved GDB names and
breakpoints to the wrong lower address. The final representation passes real
named-breakpoint, all-body-byte, excluded-gap, source, value and stepping checks
for x86-64 ET_EXEC/PIE, including explicit rebases and deterministic repeats.
Only the already-audited target-address producer call is used; no JNA signatures
were added. The added hosted gate is **PRESENT, UNVERIFIED** until CI passes.
Commands, limitations and evidence are recorded in `docs/VALIDATION.md`.

## 17.2 Combined semantic review (2026-10-23)

The below-entry range, function-owned static and incoming-register lifetime
changes are combined separately from the corrective alpha2 release. Their
new hosted gates remain **PRESENT, UNVERIFIED** until the combined pipeline
passes; individual local results do not substitute for that gate.

Review preserved the established symbol-only decompilation-failure contract:
an owned static is omitted when its owner fails decompilation. One shared
selection policy controls emitted DIEs, native address-relocation validation,
omission diagnostics and exported-static counts. Successfully decompiled owners
retain their curated statics. The controlled failure fixture now includes both
owners and verifies that only the successful owner's object survives.

The register proof also treats p-code `STORE` to the register address space
as a possible clobber, including indirect offsets. Pinned Ghidra 12.0.3
documents this opcode's destination space in its first input; it has no output
varnode and therefore requires a separate check. Malformed stores fail closed;
ordinary stores to memory retain their existing behavior. This shared check
protects stable locations as well as bounded incoming-register prefixes.

## 18. Immediate strategic direction

**CONFIRMED:** the previous prototype bring-up sequence is complete for the
documented profiles. The project has an extension build, pinned/audited natives,
real source/type/location export and a passing Linux/Windows integration matrix.

1. Preserve the working tree and inspect current PR/CI/release state.
2. Integrate the subsequent reviewed semantic/GUI/target/performance work under
   the standing authorization and enforced current-base checks. Alpha.2 is
   published from `2f88c4a`; preserve both public alpha tags and their assets.
3. Preserve completed P0.9's layout/resource bounds and regression matrix;
   implementation `3e47589` is validated by all twelve hosted jobs. Do not
   redo the parked checkpoint or treat direct PN_XNUM execution as supported.
4. Implement focused identity/scope/entry-point cases and evidence-backed
   lifetime/storage migration with compiler-oracle and GDB tests.
5. Extend selected target/GUI coverage; give optional debuglink, inlining and
   performance items explicit scoped outcomes without inventing recovered facts.
6. Preserve the complete supported-profile validation matrix and update current
   handoff status as each acceptance gate is actually met.

The bounded backlog and next-session sequence are in `TODO.md` Sections 1.1
and 4. Historical prototype observations elsewhere in this file remain useful
history, not instructions to redo completed implementation.

### P3.5 measured line-table address index (2026-10-23)

**CONFIRMED locally:** an actual 10,000-function saved-project export profile
identified repeated source-address scans in `Dwarf5LineTable.plan` (131/516 Java
execution samples). The resulting bounded change builds a sorted global
address-to-earliest-line map once and takes half-open submaps for each original
body range. Range/sequence order, overlapping bodies and earliest-row policy
are unchanged; focused boundary assertions and the existing width/endian tests
pass. No native signature or decompilation behavior changes.

Five alternating baseline/indexed pairs reduce median whole-process export
time from 10.86 to 9.18 seconds on this local workload, with every sidecar/source
pair byte-identical. GNU/LLVM, all 10,000 full DWARF symbols, runtime GDB,
input/historical-artifact hashes and the saved-project file manifest pass.
The old libdwarf report contains 11,833 errors despite exit zero, so its clean
validation claim is withdrawn. The earlier indexed build passed nineteen
smoke tasks and the four-profile ET_EXEC/PIE/shared GDB matrix; those historical
runs predate strict libdwarf summary enforcement. `docs/PERFORMANCE.md` records the complete
samples, hashes, methodology and limits. This does not establish a speed or
memory bound for arbitrary firmware or another host.

The benchmark/inline/target-profile research branch was normally merged into
`work/line-table-index` at `5bc72f1`, retaining its history and additive evidence.
The only runtime change remains the small line-table index. Larger application/
firmware profiling and hosted validation remain **PLANNED**; timing thresholds,
caching, parallel decompilation and compression are not introduced.

### Line-index integration and complete diagnostic evidence (2026-10-23)

**CONFIRMED locally:** normal integration of strict `99845c7` into the isolated
line-index branch preserves the measured planner without changes. The merged
line/source/range smokes and extension build pass. New ARM32 ARMv7 hard-float
exec/PIE/shared exports pass GNU/LLVM/strict checks and QEMU/GDB runtime oracles;
all three strict summaries are zero, and a fresh exec repeat is byte-identical.
A ten-function/two-export rehearsal proves the migrated benchmark harness.

Strict replay correctly rejected the retained 10,000-function artifact when
the original and sidecar each reported 10,002 inherited frame errors but the
consumer printed only 49 messages. The performance branch adds a third pinned
validation-only patch with capacity 65,536, checked heap retrieval and
all-or-nothing buffer allocation. Allocation failure, over-capacity and
incomplete evidence fail explicitly; prior buffers/messages/counters survive
failed resizing. Shipped producer/consumer libraries and public APIs are
unchanged. Exact Counter equality still precedes the helper's set-membership
optimization; missing or duplicated messages cannot pass on counts alone.

The retained result now passes full GNU/LLVM/strict/GDB replay with all 10,002
messages matched to unchanged original frame bytes, identity and same-version
diagnostics; no other errors remain. All ten recorded output hashes and the
saved-project manifest are unchanged. No timed 10,000-function export was
rerun, and historical timing remains baseline evidence rather than a new
merged measurement. `docs/PERFORMANCE.md` and `support/validation/README.md`
record limits, failure controls and retained paths. The complete combined
hosted matrix and representative complex workloads remain **PLANNED**.

### Standalone checker configuration packaging (2026-10-24)

PR #24 run `40064815083` exposed a hidden host dependency in the validation
bundle: native Linux had no `dwarfdump.conf`, so the consumer suppressed frame
checks after printing an error and exiting zero. Strict validation correctly
failed the first capacity positive. Local distro config had masked this.
The digest-verified failure remains in `build/hosted-capacity-review/`.

The bounded correction includes the unchanged pinned upstream configuration,
a relocatable explicit-path launcher and hashes for both launcher and real
ELF. Configuration absence/corruption or override fails closed; no ABI policy,
shipped native patch, validator exception or test threshold changes. Relocation
and negative controls join the full capacity/allocation regression. This is a
performance-branch validation-packaging follow-up; corrected hosted CI remains
required and the separate corrective release is unchanged.

The configured bundle passes local relocation/configuration controls, the
full 50/65,536/65,537 diagnostic boundary and allocation/resize-failure suite,
strict parser/line/range/extended-program rejection tests, and exact 10,002-message
retained-benchmark corroboration. Source/manifest checks and independent review
pass. `docs/VALIDATION.md` records exact bundle hashes and result directories;
no Ghidra/benchmark export was repeated for this validation-only packaging fix.

### Scalar FP logical-register selection (2026-10-23)

**CONFIRMED locally:** the follow-on `fp-register-aliases` branch selects the
first audited covering register on the actual Ghidra parent chain, with a
relative least-significant-bit offset. Wider unmapped physical bases no longer
force omission of defensible scalar aliases. Stable and entry-prefix proofs
still reject writes through the full physical base, including partial aliases
and register-space STORE. Scalar upper slices use the existing audited
`DW_OP_bit_piece` producer path; no native signature changed.

x86-64/AArch64 scalar float/double parameters and both MIPS32 O32 scalar floats
pass real exporter/GDB values through RAM stores, PIE and explicit rebases.
MIPS paired doubles remain unavailable. The independent compiler oracle also
reports zero pair values on the tested QEMU8.2.2/GDB15.1 transport even though
executed double stores and exit are correct; those memory checks are not a
positive double-parameter location claim. The exact evidence and likely QEMU
register-width cause are recorded in `docs/VALIDATION.md`.

ARM's mapping now uses canonical AADWARF32 D registers and scalar bit slices.
The real-language alias smoke and isolated native upper-slice validators pass;
ARM runtime values remain **PRESENT, UNVERIFIED** until hosted CI, because the
local cross-compiler/sysroot is absent. The new CI fixture exercises both
floats, including `s1` as the upper 32 bits of `d0`, plus doubles and explicit
clobber unavailability. This bounded scalar work does not add vector, aggregate,
calling-convention, migration or new CPU/ABI claims, and remains separate from
the corrective alpha2 release.

### Combined semantic features after corrective alpha.2 (2026-10-23)

**CONFIRMED locally:** `work/semantic-todo-completion` retains normal merge
history for scalar FP aliases (`493983d`, from `1f52431`) and corrective
sidecar identity/publication fixes (`4a4ce38`, through `ddad598`). The only
conflict was additive context prose, and both histories were retained. The
writer and publisher match the reviewed corrective branch exactly; the other
production paths match the independently tested FP/semantic branch.

The actual combined extension was installed only into the worktree's private
Ghidra copy. All 22 native-independent checks/build, timestamp regression,
24 scalar-FP cases, the existing four-profile six-role real export/validator/GDB
matrix, strict build-ID/debuglink association and ARM isolated upper-slice
producer/validators pass. Evidence and precise limits are in the new combined
section of `docs/VALIDATION.md` and `build/combined-final-review/`.

All feature and corrective CI gates remain present. Hosted combined validation,
including new ARM static/FP runtime behavior, remains **PRESENT, UNVERIFIED**
until the final commit passes its required matrix. This branch prepares the
subsequent semantic PR; it does not add features to the corrective alpha.2
release. No remote action, release or shared installation change occurred in
this local integration.

### Stable generic undefined identity across save/reopen (2026-10-23)

**CONFIRMED locally:** Ghidra 12.0.3's `DefaultDataType` singleton inherits a
new per-process `UniversalID` from `DataTypeImpl`, unlike the normal `BuiltIn`
null-ID policy. Sorting by that transient ID changed type DIE order between a
settled initial export and a fresh read-only reopen even when the normalized
model and synthetic source were unchanged. This was a byte-determinism defect,
not a demonstrated target-address or debugger-value defect.

Only the exact `DefaultDataType` class now bypasses that transient ID and uses
the existing class/path/length fallback key. All other UID and collision rules
remain unchanged, including analyst/imported types named `undefined`. Real
Ghidra identity controls and a saved-program integration regression cover that
boundary. The latter compares complete raw extraction models independently of
DWARF serialization, as well as actual `.dbg`/`.dbg.c` bytes across three fresh
processes, validators and GDB types, addresses, values and source stepping.
The baseline reproduces the byte difference; the fixed artifact passes. Exact
commands/evidence and the bounded claim are recorded in `docs/VALIDATION.md`.

This follow-up is based on the semantic branch `8e3fd27` and remains separate
from corrective alpha.2. It does not canonicalize unrelated persisted types,
promise equal output from independent imports, or change native APIs.

### Semantic hosted acceptance and main integration (2026-10-24)

**CONFIRMED:** semantic PR #20 head
`b14e8109ca95358bacba6b0d11223a913d32db80` passed all twelve jobs in
[run 40063017269](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40063017269),
completed `2026-10-24T04:57:49Z`: workflow lint, Linux/Windows native builds,
extension build, release packaging, all five Linux-hosted target lanes,
Windows-hosted export and the aggregate gate. No job failed or was skipped.
Earlier pending-hosted descriptions of these semantic features are historical;
`docs/VALIDATION.md` records the exact job IDs and conditional-step scope.

Function-owned statics and scalar FP pass their bounded all-five-target
oracles, including ARM32 EHABI coverage, returns and scalar upper slices.
Incoming-register prefixes pass x86-64/AArch64; advanced true-entry GDB and
saved-program byte determinism pass x86-64. Entry producer/structural checks
pass all five targets. P1.8 is complete within that documented acceptance;
P1.11a, richer scopes and target-profile expansion remain partial. MIPS paired
doubles and ARM opaque-return prefix locations remain unavailable. No broad
vector/ABI, migration, call-crossing, Windows runtime-GDB or new Script Manager
claim follows from this run.

The normal merge of main `2f88c4a` changes no source/test/workflow/package tree:
that main tree equals the strict `99845c7` parent already in this branch. The
integration updates only current status/evidence documentation and preserves
both histories. The new PR head requires current-base hosted CI before normal
integration. Corrective alpha.2 publication status is unchanged; the semantic
branch remains a subsequent feature change and contains neither the separate
GUI journey nor target-language agreement/performance work.

### Corrective alpha.2 official publication (2026-10-24)

**CONFIRMED:** [v0.1.0-alpha.2](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.2)
was published at `2026-10-24T05:15:20Z` (`00:15:20` America/Chicago), from exact
main commit `2f88c4a1a7dd90dfedbd8d578b27242dfb8a73b7`. PR #22's corrected
head passed all twelve jobs in run `40062747733` before normal merge; the
exact-main `push` run `40064204515` also passed all twelve jobs. The final
release audit then enforced that event/head/job set, compared the packaged
source and metadata against the commit, verified all nested manifests and both
native provenance records, and passed 20 Linux packaged-producer lifetimes on
Java 21 using the downloaded production JAR.

The native-inclusive release ZIP SHA-256 is
`0ae14cf8f4760703d4778d5b414fd14b9c8a68414edc89dcf8cb58a21669ade6`.
Draft and published ZIP/checksum assets were downloaded and compared with the
audited bytes. The public tag resolves to the exact tested commit. Alpha.1's
tag, release identity and asset digests remain unchanged; alpha.1 remains
affected by the previously recorded correctness findings.

This closes the corrective release and strict-validator gates within the
published target/host profiles. Earlier failed runs and missed-summary findings
remain historical evidence, not retroactively clean validation. Exact inherited
frame diagnostics remain visible and require matching original bytes/identity
and same-tool diagnostics; no new generic exception was introduced.

The tag and its packaged documents remain the immutable prepublication
snapshot. This later handoff update does not retag or replace them. Semantic
features in this branch, the separate Script Manager journey, target-language
agreement and measured line-table optimization are subsequent work and are
excluded from alpha.2. Their own current-base/combined acceptance gates remain.
See `docs/VALIDATION.md`, "Corrective alpha.2 official publication", for exact
CI, final-audit and downloaded-asset evidence.

### Reviewed TODO integration scope (2026-10-24)

This combined tree now retains the separately reviewed semantic, Script Manager,
target-language agreement, line-table/performance and inline/debuglink research
histories. The component evidence above remains attributed to its exact tested
head; it does not by itself establish that the new combined head passes. The
separate combined gate and observed normal merge are recorded immediately below.
The published alpha.2 tag and assets remain unchanged and exclude these
subsequent features. The optional debuglink operation and inline DIE emission
remain unimplemented under their recorded design/evidence conditions.

### Reviewed TODO integration accepted (2026-10-24)

**CONFIRMED:** PR #25 head
`961265543762e96fa6e9a80a9b06210b5d9397e9` passed
[run 40068401197](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40068401197)
(`pull_request`, attempt 1). All twelve expected jobs succeeded, with none
failed or skipped; the aggregate completed at `2026-10-24T06:22:06Z`. The job
set comprises workflow lint, both native builds, extension build, release
packaging, five target lanes, Windows host and the required aggregate gate.
Conditional steps keep their documented target/host scope.

The independent package precheck verified artifact `12550562112`, exact
31 production Java sources plus two scripts, nested manifests/native
provenance, 135 Java 21 classfiles and 20 packaged Linux producer lifetimes.
Package SHA-256:
`a1ea4069dce1ea66aee8ecb59751b690a069bada19dea348306e0c9243aa412f`.
This is an accepted integration artifact, not a new published release.

Actual Script Manager discovery/preflight/export, Console reporting and both
chooser outcomes pass on Linux and native Windows. Linux additionally passes
the managed-display 100-window geometry control, strict independent libdwarf
checks and runtime GDB; Windows passes the shared filter/modal/readiness
controls, real ACL denial and available native GNU/LLVM checks. Independent
libdwarf is unavailable and Linux-ELF runtime GDB is not run on Windows. The
earlier failed GUI attempts remain recorded; only the final corrected run is
accepted. `docs/VALIDATION.md` records the digest-verified GUI artifacts and
the exact conditional semantic/target/performance coverage.

PR #25 merged normally at `2026-10-24T06:23:24Z` as
`befce2c5aa621d7c72a1803a3bbcfd566db6d31b`; its tree equals the tested head.
Component PRs #20/#21/#23/#24 are observed merged. The distinct main-push run
`40070016394` was still running at this checkpoint and is not claimed passed.
The local final API evidence is retained in the `reviewed-todo-integration`
worktree at `build/review-preparation/final-{run,jobs}.json`.

This supersedes earlier pending-hosted/integration descriptions for these
bounded changes. P1.8's tested entry/range acceptance is complete; richer
function/class/lexical scopes, P1.11a lifetimes and target-profile expansion
remain partial. External-function declaration research is not an implemented
feature here. MIPS paired doubles and ARM opaque-return prefixes remain
unavailable. Inline emission and optional debuglink attachment/refresh/rollback
remain unimplemented. Performance CI supplies acceptance, not new timing data
or a general speed/memory guarantee. Published alpha.2 stays immutable at
`2f88c4a`, excluding these features; no version, tag or release assets changed.

### Qualified analyst function display names (2026-10-24)

**CONFIRMED locally:** the next bounded function-identity slice retains actual
plain Ghidra namespace paths separately from lexical function names. Only the
CU-owned subprogram's display name becomes qualified; source declaration-line,
signature and location matching retain lexical name/address keys. The C11 CU,
global naming, native ABI and failed-decompilation policy remain unchanged.
Class/other unsupported parent chains retain prior lexical behavior with a
diagnostic. Distinct path/name identities that flatten to one display are
rejected before ELF parsing/native loading, preserving existing file preflight.

The old installed exporter loses qualified identity in the real fixture; GDB
cannot resolve the scoped name. The implementation passes 15 local real-export
cases across x86-64, AArch64, ARM32 and both MIPS orders (exec, PIE and explicit
Ghidra rebase), with compiler address/value oracles, source/type/stepping,
separate owned statics, a same-named real global function, original hashes,
byte-identical repeats and GNU/LLVM/strict validation. The original x86 static
cases and focused real-Ghidra/model smokes also pass. Exact hosted acceptance
remains pending; local results are not attributed to the preceding merged CI.

The tested GDB 15.1 does not provide the required function lookup from ordinary
namespace DIEs under C11, and ignores the compiler's external-function
declaration prototype. Qualified CU-level names are an explicit analyst-display
policy, not reconstruction of C++ scopes or linkage. External declarations and
full class/lexical/alias semantics remain planned. `docs/FUNCTION-NAMING.md`
records quoting, tradeoffs, the research evidence and the unchanged debugger
baseline. Published alpha.2 is unaffected. Detailed commands, package identity,
failure history and passing directories are in `docs/VALIDATION.md`.

### Opaque instruction effects and register locations (2026-10-24)

**CONFIRMED:** Ghidra 12.0.3 decodes AArch64 `svc` as falling through with an
outputless `CALLOTHER`. Its user-operation contract permits effects beyond
explicit outputs, so an absence of register writes does not prove stability.
The old exporter emitted a whole-function x0 parameter location; runtime GDB
showed the process ID after `getpid`, although the compiler's saved parameter
and stored result remained `-19`.

**CONFIRMED locally:** whole-function register extraction now rejects opaque
effects with `UNKNOWN_LIFETIME`, preserving names/types without a location.
This applies to scalar/composite parameters and locals without target-specific
syscall assumptions or new native calls. Existing call/write diagnostic
precedence remains intact. An ordinary unconditional terminal return is a
pre-instruction boundary exception for `CALLOTHER` only when raw flow, full-width RETURN,
absence of override/delay slots/fallthrough and p-code control flow prove that
this invocation ends; this preserves tested ARM `BX LR` scalar locations and
does not claim user-operation purity. `UNIMPLEMENTED` always rejects the proof.
Prefix/migration coverage is unchanged.

Actual AArch64 exec/PIE/rebased-PIE exports, structural validators and GDB pass;
four PCs show typed unavailable parameters, raw x0 changes, the global becomes
`-19`, and execution exits normally. Fresh imports reproduce both output files
byte-for-byte. Existing 12 x86/AArch64 prefix and six ARM scalar exports pass.
Local headless runs use JDK 25; the final isolated native-free old/fixed smoke
comparison runs on Java 21. Hosted Java 21 gates are added but remain pending. Published alpha.2
is unchanged; the new guard is not included in that release.

**CONFIRMED separate issue:** direct GDB `p/a` on the global's address warns
about the address map and symtab in both old and fixed artifacts. CU address
coverage needs its own investigation/regression. The parameter omission avoids
the automatic formatting trigger, not the underlying warning. No exception
was added to strict diagnostics; failed baseline runs remain failed.

**CONFIRMED naming acceptance:** exact PR #26 head `d5f2521` passed all twelve
jobs in `40071594248`; digest-verified artifacts prove all 15 qualified-name
cases, both GUI hosts and the native Windows smoke. Normal merge `89c07ce`
preserves the tested tree. Post-merge main run `40073445177` is a separate,
still-pending gate. Earlier PR #25 main-push run `40070016394` also passed all
twelve jobs. These later observations supersede the historical pending notes
above; neither published alpha includes these features.

### Exact code-address lookup (2026-10-24)

**CONFIRMED locally, hosted gate pending:** a separate `.debug_aranges` fix
resolves the demonstrated global-address formatting warning without changing
function/CU ranges or variable locations. Exact GDB 15.1 source explains the
mismatch: its fallback quick index includes global data addresses outside the
expanded code symtab. A code-only index avoids that fallback; a CU range list
alone does not set the relevant GDB flag. The table indexes the exact union of
exported function body intervals, never globals or gaps. Both existing DIE
coverage and runtime relocation behavior remain authoritative.

`docs/ADDRESS-INDEX.md` records the standards-backed decision, single-CU header
offset, version-2/DWARF32 encoding, both widths/orders, full ELF32 range splitting
and explicit limitations. No native declarations or producer calls changed.
The old absence assertion is replaced with an independent raw-table/LLVM-DIE
coverage check and malformed-index controls, with no warning suppression.

All 15 qualified-static cases pass on x86-64, AArch64, ARM32 and both MIPS orders,
including exec/PIE/rebase, address and typed-pointer formatting, values, stepping,
validators, original hashes and byte-identical repeats. Three AArch64 SVC roles,
six x86 backward-entry/gap exports and generic x86/MIPS32-BE sectionless export
and runtime checks also pass. Failed baseline pointers and the first harness
variable-name error remain recorded separately. Exact hosted acceptance is still
required; neither published alpha contains this fix.

**CONFIRMED opaque-guard acceptance:** exact PR #27 head
`e7a289cd3443c277ee5617076fede8b75703f83b` passed all twelve jobs in
`40073884397`. Independent artifact reviews verify the real AArch64 regression,
both GUI hosts and the eight native Windows smoke checks. Normal merge
`ce0c3a4a71c2e5f9414ccd9a36878617c827818c` at `2026-10-24T07:51:07Z` retains
the tested tree. Exact-main push `40075761646` remains pending. The preceding
naming merge's main push `40073445177` also passed all twelve jobs. These later
observations supersede the earlier opaque/naming pending checkpoints without
attributing their results to the new address-index implementation.

### Address-index hosted acceptance and next bounded lifetime work (2026-10-24)

**CONFIRMED:** exact PR #28 head `a5f79109f5cb345dff789938f2b41741967f47ad`
passed all twelve jobs in `40076025207` (attempt 1, none skipped). Independent
reviews verified all five target artifacts, including 30 core/index roles,
all five sectionless inputs, 30 ordinary/qualified pointer cases, six advanced
entry cases and three opaque-effect cases. Exact strict diagnostics, original
hashes and applicable deterministic repeats pass. Actual Linux and native
Windows GUI journeys pass, including all nine native Windows smoke checks.
The exact package/source/native-provenance audit and actual Java 21 smoke and
20-lifetime native tests pass; the package SHA-256 is
`a6edcb42cee25a81b598ad01703b34445394ccb0a829827b6172773a7d6459f3`.

Normal merge `b4d786947ab49902c2fa86da73ba7e03c043f05d` at
`2026-10-24T08:23:21Z` preserves the tested tree. The separate main-push run
`40077843290` remains pending. PR #27's preceding main-push run `40075761646`
also passed all twelve jobs and independently reviewed host artifacts. These
observations supersede the corresponding historical pending checkpoints.
No published version, tag or asset changed.

**CONFIRMED locally; hosted gate pending:** the next P1.11a slice tracks one proven direct register
copy of an incoming parameter. It keeps the existing complete straight-line
eligibility gate, exact low-slice/width checks and ordered p-code proof, and
does not follow memory, calls, arbitrary chains or lost values. The new fixture
uses both widths, signed/high-bit values and explicit backup destruction; a
raw location-list oracle compares exact intervals with compiler labels.
The final reviewed production commit `5ba6f39` passes actual Java 21 focused
checks and private packaged run `run.V0gUehki`: six roles, twelve exports and
72 compiler/Forge calls per mode, with exact raw location intervals, signed
values, backup-kill omissions, strict validators, preserved inputs and
byte-identical pairs. Independent review also closes physical alias, offcut
entry, fallthrough provenance and unknown-store proof gaps. The complete
hosted gate remains required. The policy and evidence boundaries are in
`docs/REGISTER-COPY-LIFETIMES.md`.

### Unsupported stack-local starts (2026-10-24)

**CONFIRMED:** Ghidra 12.0.3 rejects nonzero stack first-use during ordinary
construction/insertion, but its public stored-variable setter persists it.
Its decompiler stack-symbol mapping ignores that field and supplies no
complete lifetime end. The old Forge output nevertheless located such a
local throughout the body; in a real shared-slot fixture, the later variable
showed the earlier object's `11` before becoming `22` in its own scope.
Uninitialized compiler variables are a separate case and are not treated as
proof of incorrect locations.

**CONFIRMED locally; hosted gate pending:** the bounded fix preserves the
curated name/type/offset but omits any nonzero stack-local first-use location
with `UNKNOWN_LIFETIME` and an explicit diagnostic. It does not clip a guessed
interval, change zero-offset/parameter behavior or claim general slot-reuse
support. Actual Ghidra five-profile extraction and Java 21 tests pass,
including saved/reopened metadata and guard-absent negative controls.
Final packaged run `run.zHNit33c` passes twelve exports across x86-64/AArch64
exec/PIE/rebase roles; old-exporter run `run.R6pJS512` reproduces the wrong
value in all six roles. The fixed variable is typed but unavailable at all
four observations, while the zero-offset local stays correct. Structural
checks, exact reports, input hashes and byte-identical repeats pass. Hosted
acceptance is still required. Policy and pinned API evidence are in
`docs/STACK-FIRST-USE.md`; detailed commands are in `docs/VALIDATION.md`.

**CONFIRMED prior acceptance:** PR #28's exact-main run `40077843290` passed
all twelve jobs; independent Linux and native Windows GUI artifact reviews
also pass. This supersedes its earlier pending-main checkpoint. Neither
published alpha nor its tag/assets changed.

### Register-copy hosted acceptance (2026-10-24)

**CONFIRMED:** exact PR #29 head `698e9398c382923b50274516f26e928c1d4fc738`
passed all twelve jobs in `40079317009`, attempt 1, with none skipped. The
independent source/gate/package audit and targeted x86-64/AArch64 runtime,
ARM32 floating and both-host GUI artifact reviews are clear. All five target
lanes pass; MIPS evidence for this PR is its CI conclusions, not an additional
manual artifact review. Native Windows also passes all ten focused smokes.
The exact package SHA-256 is
`e147f60544a0a16cd801444000ff94109e916066e4c7a9bdd9fde37bc4a9f46e`.
Actual Java 21 smokes, production origins and 20 native producer lifetimes pass.

Normal merge `25f9830f64899a1b3ed9f45e60c3b7404f0fc67c` at
`2026-10-24T09:16:38Z` preserves the tested tree. Its separate main-push gate
is still pending. This supersedes earlier pending-hosted register-copy notes;
it does not attribute acceptance to the later stack guard. No release changed.

### Actual filesystem paths and publication preflight (2026-10-24)

**CONFIRMED:** the old output policy lexically reduced `symlink/..` before
opening a file. A Linux compiler fixture reproduces both a wrong-input hash
rejection and an independently misdirected output. Separate public-publisher
controls reproduce cross-stage cleanup deleting a newly published source and
a directory destination being moved before a cleanup failure. The script's
ordinary path policy already rejected directory destinations; that finding
is specific to the public API, not a new default-export regression.

**CONFIRMED locally; hosted gate pending:** production commits `a0b75fb` and
`821808a` resolve existing parents with host filesystem semantics while keeping
literal file leaves, check all stage/final aliases before mutation, reject
stage symlinks and unsupported final objects, and preserve dangling-leaf
rollback. Input-link default naming and unrelated output-link referents remain
intact. Standalone exporter/source/native paths share the policy; report
formatting does not introduce filesystem I/O. Missing-input-parent guidance
keeps `--input` and avoids unrelated `--output` advice.

Final package run `run.ua6ucr7i` passes eight real saved-program exports and
three rejection cases, with exact paths/reports, source lookup from another
working directory, typed values/stepping, validators, immutable inputs and
identical repeats. Every program database/live index/property is unchanged;
only two explicitly recorded Ghidra index backup paths may rotate. Actual
Java 21 focused checks and an isolated direct-native raw-path probe pass.
The final JAR is `14c6fb2e4a89a98888570873e27790761ea3785c543dc1fc6fa4f43dd19f47f3`.
Independent code and runtime review is clear. Full hosted/native Windows gates
remain pending. `docs/FILESYSTEM-PATHS.md` defines the scope; this is not an
attachment transaction or a new crash/concurrency guarantee. Releases stay
unchanged.

### Stack-first-use hosted acceptance (2026-10-24)

**CONFIRMED:** PR #30 head `fb2fa406908822fe4ced131da843ad5dc31df1b7` passes
all twelve jobs in exact pull-request run `40081385807`, attempt 1, none
skipped. Package/source/native-provenance and Java 21/lifetime audits pass.
Digest-verified artifacts independently prove the six x86-64/AArch64 stack
roles/twelve exports, related location regressions, both actual GUI journeys
and all eleven native Windows focused smokes. The five target job conclusions
pass; MIPS artifacts were not separately reviewed for this PR. Strict reports
have zero unexplained diagnostics and preserve their exact inherited errors.

Normal merge `74a7466a6ff03f44b143bad0e764d65c1e11d521` at
`2026-10-24T09:47:17Z` retains the tested tree. Its separate main-push gate is
pending. PR #29's earlier main-push `40081314935` now passes all twelve jobs
and both GUI artifact reviews. This supersedes those historical pending notes,
without attributing acceptance to the later path correction. Releases remain
unchanged; P1.11a is still partial.

### Windows ambiguous file-leaf follow-up (2026-10-24)

**UNCERTAIN on the native runner:** review of pinned OpenJDK and Windows naming
rules identified absent final spellings such as `out` and `out.` that can name
the same entry after a Win32 creation. Existing-identity checks cannot establish
that relationship while both paths are absent. PR #31's first candidate `50e0a4`
remains intermediate evidence and must not be merged on its checks alone.

**CONFIRMED locally; native gate pending:** the Windows profile now rejects
trailing-dot/space file leaves without trimming them; Unix legal dotted names
remain distinct. The native Windows smoke must first prove the actual short-path
alias, then prove both publication APIs and both target orders reject before
callbacks, timestamps, staging or cleanup. Unexpected native behavior fails;
there is no capability skip or speculative 8.3 restriction. The five focused
checks/build and actual Java 21 tests pass on Linux. New JAR SHA-256 is
`125d6753d0f16e97af04c2c99d5d70ee1740f671d580ffda24c90bd2b4b1447b`;
production script/native ABI are unchanged. Exact new-head hosted package,
Windows alias evidence and the complete gate remain required.

### Standalone timestamp harness dependency (2026-10-24)

**CONFIRMED:** intermediate run `40083416513` failed its x86 timestamp check
because that harness compiled `ArtifactPairPublisher` directly without its new
`FileSystemPaths` dependency. This was a compilation failure, not passing
runtime evidence. The standalone source list now includes the helper. Local
`run.n90Mvxpa` passes GNU/LLVM, strict libdwarf with two exactly corroborated
inherited frame diagnostics and zero unexplained errors, and GDB freshness,
typed-value/stepping and later-edit controls. Original bytes and timestamps
remain unchanged. Candidate `ffe6c81` has the same omission and is also
intermediate only; a new exact-head full gate and package review are required.

### Windows short-parent test oracle correction (2026-10-24)

**CONFIRMED:** candidate `e465e07`, run `40085186824`, passes all five target
lanes, including the corrected timestamp check and eight real path exports with
three rejection cases. Exact package and Linux GUI/runtime reviews pass. Its
Windows focused job fails before the new alias probe: `OutputPathPolicySmoke`
expects the raw `RUNNER~1` temporary-parent spelling, while the intended policy
returns the actual `runneradmin` parent. This is a stale test expectation.

The test now retains the raw request, independently resolves its existing
directory, and requires exact expected filenames below that directory plus
input file identity. Actual Java 21 and configured Linux checks pass. Production
bytes are unchanged; native Windows acceptance and the full updated-head gate
remain pending. No skipped Windows alias/GUI test is counted as passed.

### Read-only digest foundation (2026-10-24)

**CONFIRMED locally; hosted gate pending:** the next bounded P2.8 slice centralizes the two existing
SHA loops in a native-free `FileDigests` helper and computes GNU debuglink CRC32
plus the actual byte count in the same bounded-memory pass. Its optional
cancellation API owns and closes the stream; existing callers retain their
previous cancellation behavior. Results describe observed bytes, not stable
snapshots or file identity. No report parser, ELF matching or executable
attachment is added. The Windows JDK's null `fileKey` cannot establish identity.
`docs/FILE-DIGESTS.md` records the API limits and independent acceptance tests;
P2.8's backup/receipt/refresh/recovery transaction remains planned.

Six focused checks pass both through Gradle and on actual Java 21 against the
packaged JAR. Nine fresh x86-64/AArch64/MIPS32 big-endian exports pass GNU/LLVM,
strict libdwarf and GDB, with all inherited frame errors explicitly corroborated.
Installed-JAR SHA/CRC/counts match Python and target GNU debuglink payloads in
all nine cases. A 2,147,614,787-byte sparse input passes twice under a 64 MiB
Java 21 heap, also matching GNU SHA-256; the owned large file is removed.
Eight saved-program packaged exports and three rejection cases additionally
pass path/report/hash/original-database preservation and byte-identical repeats.
No native Windows or full hosted acceptance is inferred from these local tests.

### Bounded ELF build-ID observation foundation (2026-10-24)

**CONFIRMED locally; hosted gate pending:** `ElfBuildId` reads typed note
sections/segments independently of names and compares observed values without
asserting file identity or attachment eligibility. It handles both widths and
byte orders, compatible duplicate views, sectionless/nameless metadata and
explicit absence; malformed/ambiguous data fails. GNU 2.42 source and tool
probes establish four/eight-byte layouts and padding. Review found the separate
IA-64/OpenVMS header format could otherwise be misread as absent; an isolated
format table now rejects its nonempty notes. Ordinary export is unchanged.

Source review and actual Java 21 focused checks pass, including bounded reads,
extended tables, late/high-offset notes, limits, cancellation and source-change
controls. The installed helper agrees with GNU on existing validated x86-64,
AArch64 and MIPS32 big-endian pairs and owned renamed/unnamed/sectionless,
duplicate/conflict/decoy/malformed variants. Initial nameless dynamic-original
oracle runs exposed GNU readelf's name-based `.dynamic` lookup diagnostic; the
quiet nameless positive uses the real non-loadable sidecar instead, retaining
the failed attempts. Native Windows/full hosted acceptance remains pending.
See `docs/ELF-BUILD-ID-OBSERVATIONS.md`; P2.8's transaction is still planned.

### Filesystem-path hosted acceptance (2026-10-24)

**CONFIRMED:** PR #31 head `3632f2b581e3080e92567b0e00479c4f38b00cdb`
passes all twelve jobs in hosted run `40087258846`. Independent package and
Linux/native Windows artifact reviews are clear. Linux repeats eight saved-
program exports and three rejection cases, timestamp handling and its real
GUI journey. Windows Java 21 passes twelve focused checks, actual short-parent
resolution, real trailing-dot alias rejection through both publisher APIs in
both target orders, and its GUI journey. Original files and program databases
remain preserved within the documented two-backup-file exception. Cross-target
lanes pass CI; their artifact archives were not separately reviewed for this PR.

Normal merge `00aaba161c5663556302c10da658ddab88b96d92` preserves the tested
tree. Its separate main-push run `40089265777` is pending at this checkpoint.
PR #30's earlier main-push `40083338151` now passes all twelve jobs and both
GUI artifact reviews. These observations supersede the corresponding earlier
pending notes, including the failed intermediate PR #31 candidates. Published
alpha.2 is unchanged; this does not complete the P2.8 attachment transaction.

### Combined read-only foundations, local acceptance (2026-10-24)

**CONFIRMED locally; exact hosted gate pending:** the digest and build-ID
foundations form one reviewed change. The combined JAR `04398abf...` passes
seventeen fresh exports: executable/PIE/no-build-ID cases on x86-64, AArch64 and
MIPS32 big-endian, plus four saved-program path cases repeated twice. Three
path rejection controls, GNU/LLVM/strict validators, native/QEMU GDB behavior,
unchanged inputs and deterministic path repeats pass. Both installed helper
oracles rerun against the fresh pairs; the digest oracle again verifies an
input above 2 GiB under an actual Java 21 64 MiB heap. Independent final audit
`build/build-id-review/combined-runtime-audit.json` is clear. The existing
association harness also passes with its documented narrower runtime scope.

The earlier component results remain attributed to their respective packages.
Merge `409c029` incorporates accepted PR #31 without production source changes;
the corrected parent oracle also passes on actual Java 21 against the combined
JAR. Final package/source matching and the complete hosted matrix, including
native Windows and both GUI hosts, remain required. Read-only observations do
not establish snapshot/file identity or attachment eligibility. No report
reader, attachment operation, native binding or release change is introduced.

### Current-shape report claims, local acceptance (2026-10-24)

**CONFIRMED locally; hosted gate pending:** production `3d1c62c` adds a bounded
read-only `ExportReportClaims` reader. It opens only its supplied JSON report,
preserves exporting-host path/hash spelling and returns immutable reported
values. Inventories are validated and discarded. Successful parsing retains
`NOT_RUN`; it does not attest artifact identity, ELF compatibility, validation
or eligibility for attachment. The ordinary report writer/exporter is unchanged.

The current schema-one shape requires `functionStaticVariables`. Historical
reports omitted that field without a schema increment; they receive an explicit
unsupported-shape rejection, not a guessed default. Field presence cannot prove
which historical count semantics or exporter revision produced the report.
Valid cancelled/fatal shapes receive a distinct no-completed-claims exception.

Ghidra's provided Gson 2.9 remains the grammar/decoding dependency. A bounded
schema-specific lexical guard handles the strictness and allocation gaps found
in the earlier source/research audit; no private Gson or generic replacement
parser is added. Four focused checks pass on actual Java 21 with a 64 MiB heap,
including 429 malformed controls and the default resource boundaries. Independent
source/test review is clear. The installed reader oracle passes on nine retained
reports from the previously audited combined exporter; this is not fresh
ordinary-export execution. The first adapter attempt lost Unicode on ASCII
stdout; explicit UTF-8/Base64 transport fixes the oracle without a reader change.
Final package matching and native Windows/full hosted acceptance remain required.

Separately, PR #31's main-push `40089265777` now passes all twelve jobs and both
independent GUI artifact reviews, superseding its earlier pending-main record.
The digest/build-ID PR #32 gate remains pending at this checkpoint. Published
alpha.2 and P2.8's attachment transaction remain unchanged.
