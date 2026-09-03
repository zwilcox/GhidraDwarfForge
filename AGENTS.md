# AGENTS.md — GhidraDwarfForge

This file contains durable operating instructions for Codex and other coding agents working in this repository.

- Repository: `zwilcox/GhidraDwarfForge`
- Default branch: `main`
- Handoff baseline: commit `7a39a186538c7aec3f7dbdc4a6e396125b5d63ea`
- Baseline commit date: 2025-06-22
- Handoff snapshot date: 2026-09-01

## 1. Mission

GhidraDwarfForge turns the current knowledge in an analyzed Ghidra program into a standards-compliant DWARF sidecar and a companion decompiled C source file so the original ELF can be debugged in GDB with recovered function names, types, variables, and source-like stepping.

The intended default outputs are:

```text
<binary>          # original executable, unchanged
<binary>.dbg      # separate ELF debug artifact
<binary>.dbg.c    # deterministic synthetic source referenced by DWARF
```

The definition of success is not “a file was written.” Success means independent DWARF validators accept the artifact and GDB provides useful, correctly addressed source-level debugging of the original program.

## 2. Status vocabulary

Use these labels whenever documenting incomplete or uncertain work:

- **CONFIRMED** — explicitly required by the user or directly observed in the repository.
- **PRESENT, UNVERIFIED** — code exists, but no passing end-to-end test proves it works.
- **PLANNED** — intended architecture or behavior that is not implemented.
- **HISTORICAL** — observed in old code, logs, commits, or documentation; it may no longer describe the current implementation.
- **UNCERTAIN** — evidence is insufficient. Do not silently turn an uncertain item into a fact.

When the code, issue tracker, and these documents disagree, do not guess. Record the conflict, inspect the relevant history/tests, and update the documentation when the conflict is resolved.

## 3. Source-of-truth order

Use this precedence order:

1. The user’s newest explicit instruction.
2. This `AGENTS.md` file.
3. `PROJECT_CONTEXT.md` for project intent and historical/current context.
4. `TODO.md` for current prioritization and acceptance criteria.
5. Executable tests and validators.
6. Current implementation behavior.
7. GitHub issues and old README/build notes, which are known to be stale in places.

Never weaken a confirmed product requirement merely because the prototype does less.

## 4. Non-negotiable product constraints

### 4.1 Preserve the original executable

- Do not rewrite, relink, strip, or patch the original target by default.
- Creating or updating `.gnu_debuglink` is an optional, explicit operation because it modifies the target.
- Any destructive or target-modifying mode must require an explicit user choice and must retain a safe original copy.

### 4.2 Output names and location

- Default sidecar name: `<original-file>.dbg`.
- Default synthetic source name: `<original-file>.dbg.c`.
- Default output directory: the directory containing the original executable.
- The current behavior assumes `Program.getExecutablePath()` still exists and is writable. Fallback behavior for missing/read-only paths is **UNCERTAIN** and must be designed rather than guessed.

### 4.3 DWARF and ELF scope

- Target DWARF version: **DWARF 5**.
- Initial object format: **ELF**.
- PE/PDB and Mach-O/dSYM are non-goals until the ELF milestone is complete.
- The sidecar must describe the same target image: ELF class, byte order, machine, ABI flags, section addresses, image base/load bias, and build identity must be handled correctly.
- PIE executables and shared objects must not be treated as fixed-address non-PIE binaries.

### 4.4 Preserve Ghidra’s recovered knowledge

Export the current curated Ghidra program, including analyst changes, not merely initial auto-analysis:

- Function and symbol names.
- User-defined and recovered signatures.
- Calling conventions.
- Parameters and local variables.
- Global variables and memory objects.
- Structures, unions, enumerations, arrays, pointers, typedefs, and qualifiers.
- Namespaces or class-like scopes where Ghidra has meaningful information.
- Discontiguous function bodies and address ranges.

Prefer explicit analyst-defined information over weaker decompiler guesses.

### 4.5 Be honest about recovered information

- The generated `.dbg.c` is synthetic decompiler output, not recovered original source.
- Never label inferred names/types/locations as original compiler facts.
- Never fabricate a variable location, type, source line, or address mapping merely to make GDB output look complete.
- If a defensible variable location is unavailable, emit its name/type without `DW_AT_location`, or omit the variable with a diagnostic according to the documented policy.

### 4.6 Architecture neutrality

- Do not hard-code x86-64 register numbers, `RBP`, stack direction, calling convention, pointer width, endianness, or relocation type in generic code.
- Derive processor, ABI, registers, storage, address size, endianness, and image-base behavior from Ghidra and the original ELF.
- Keep architecture-specific mappings isolated, table-driven, documented, and tested.
- The prototype’s multi-architecture switch statements are not proof of multi-architecture support.
- The design is not limited to x86 and ARM. MIPS, including 32-bit and
  big-endian variants, is an explicit target; additional Ghidra-supported ELF
  processors should be addable through isolated target descriptions rather
  than generic-code changes.
- Never claim support for an architecture until its emitted artifact passes
  structural validators and applicable GDB behavior tests on native hardware
  or a documented emulator.

### 4.7 Deterministic source correlation

- Generate `.dbg.c` deterministically for an unchanged Ghidra program.
- Use stable ordering, stable formatting, and stable synthetic identifiers.
- Build the generated source and its address-to-line map as one operation.
- Use address sets attached to decompiler tokens or another evidence-backed mapping; do not assign every line only the function entry address.
- Support one source line mapping to multiple address ranges and discontiguous instructions.
- Do not attach executable addresses to comments, blank lines, synthetic declarations, or formatting-only lines unless intentionally modeled and tested.

### 4.8 Failure isolation and cancellation

- One decompilation failure must not abort the entire export.
- Emit a symbol-only function DIE and a diagnostic source comment when source generation fails for one function.
- Honor Ghidra cancellation promptly.
- Ensure native producer resources, decompiler interfaces, streams, and temporary files are released on success, failure, and cancellation.
- Never leave a partially written file under the final output name. Write to a temporary file and atomically replace on successful completion.

### 4.9 Validation is mandatory

A change that alters emitted ELF, DWARF, source mapping, types, or locations is not complete until it passes appropriate structural validators and GDB behavior tests. See Section 10.

## 5. Repository orientation at the handoff baseline

The current repository is a prototype, not a complete Ghidra extension.

- `src/GhidraDwarfForgeFixed.java` — monolithic Ghidra script; exports decompiled C, builds minimal DIEs through libdwarfp, and hand-writes a minimal ELF container.
- `src/LibDwarfp.java` — partial JNA producer mapping. Treat it as unsafe until every signature is checked against a pinned libdwarf header.
- `src/LibDwarf.java` — small consumer mapping; currently not integrated into an automated validation path.
- `src/DwarfConst.java` — partial, handwritten constants.
- `src/libdwarf.jar` — shaded JAR containing JNA/resources; exact bundled libdwarf source revision is not recorded.
- `jna-wrapper/pom.xml` — Maven packaging for JNA plus bundled native resources; it is not a Ghidra extension build.
- `.github/workflows/buildLibDwarfJarWrapper.yml` — manual workflow that builds Linux/Windows libdwarf producer libraries and a shaded JAR, then may commit binaries to `main`.
- `src/temp/` and `jna-wrapper/target/` — generated/unpacked artifacts currently committed, including a historical JVM native-crash log.
- `.gitignore` — empty at the baseline.
- No current Gradle wrapper, Ghidra extension module, automated tests, release, or repository license is present.

Read `PROJECT_CONTEXT.md` before modifying the prototype.

## 6. Required workflow for every coding task

Use four spaces for indentation in source, scripts, and build files. Do not use
literal tab characters except where the file format requires them, such as
Makefile recipe lines.

1. Run `git status --short` and inspect existing changes. Do not discard user work.
2. Read `AGENTS.md`, `PROJECT_CONTEXT.md`, and the relevant section of `TODO.md`.
3. State the exact acceptance criteria being addressed in the commit/PR description.
4. Inspect the original ELF and Ghidra APIs instead of assuming target properties.
5. For native/JNA work, identify the exact pinned libdwarf revision and verify signatures against its headers before writing Java code.
6. Make the smallest coherent change that can be independently tested.
7. Add or update fixtures/tests with the implementation.
8. Run the relevant build, structural validation, and GDB behavior tests.
9. Record commands and outcomes. Do not report a test as passed if it was skipped or unavailable.
10. Update `PROJECT_CONTEXT.md` when an important decision is made, and update `TODO.md` when status or priority changes.

Do not use `git reset --hard`, force-push, delete branches, rewrite history, or remove user data unless the user explicitly directs it.

## 7. Native/JNA rules

Native ABI mistakes can terminate the entire Ghidra JVM. Native stability is a P0 release blocker.

### 7.1 Pin before mapping

- Replace the workflow’s moving `LIBDWARF_VERSION: main` with an exact release tag or commit SHA before relying on ABI details.
- Record the exact revision and build options in generated artifacts or release metadata.
- Verify the shipped `.so`/`.dll` exports and dependency names as part of CI.

### 7.2 Use fixed-width mappings

Against the inspected upstream libdwarf header snapshot, `Dwarf_Unsigned`, `Dwarf_Signed`, `Dwarf_Off`, and `Dwarf_Addr` are 64-bit `long long` types on both Linux and Windows.

- Map by value to Java `long`.
- Map `Dwarf_Unsigned *` to `LongByReference` or an explicitly 64-bit custom type.
- Do **not** use `NativeLong`/`NativeLongByReference` for `Dwarf_Unsigned`; `NativeLong` is 32-bit on 64-bit Windows.
- Model `Dwarf_Error` as an opaque pointer type.
- Model `Dwarf_Handler` as `void handler(Dwarf_Error, Dwarf_Ptr)`, not as `void handler(int, Pointer)`.

These points must be rechecked against the exact pinned revision before implementation because the bundled binary’s source revision is currently **UNCERTAIN**.

### 7.3 Known producer signatures requiring correction/verification

The baseline mapping differs from the inspected upstream header in at least these places:

```c
int dwarf_transform_to_disk_form_a(
    Dwarf_P_Debug dbg,
    Dwarf_Unsigned *nbufs_out,
    Dwarf_Error *error);

int dwarf_add_AT_targ_address_c(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *outattr,
    Dwarf_Error *error);

int dwarf_add_AT_flag_a(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Small flag,
    Dwarf_P_Attribute *outattr,
    Dwarf_Error *error);
```

Do not add new producer calls until all existing declarations are audited.

### 7.4 Callback lifetime and semantics

- Keep strong Java references to callbacks for the entire native producer lifetime.
- The section-creation callback’s return value and `sect_name_index` output have different meanings. Do not set both to an arbitrary incrementing value.
- With symbolic relocations, implement the documented `dwarf_get_relocation_info_count()` / `dwarf_get_relocation_info()` flow or deliberately select a no-relocation strategy. Do not invent ELF relocation records.
- Check every `DW_DLV_OK`, `DW_DLV_NO_ENTRY`, and `DW_DLV_ERROR` result.
- Convert `Dwarf_Error` to a useful message before deallocation.

### 7.5 Isolate crash-prone tests

- First exercise new JNA mappings in a small standalone smoke-test process, not in the interactive Ghidra JVM.
- A segmentation fault, access violation, corrupted callback, or unexplained native error is a failed test even if an output file was created.

## 8. DWARF implementation rules

### 8.1 Minimum semantic structure

The planned complete output includes, as applicable:

- `DW_TAG_compile_unit`.
- `DW_TAG_subprogram` for recovered functions.
- `DW_AT_name`, `DW_AT_linkage_name`, `DW_AT_low_pc`/`DW_AT_high_pc` or `DW_AT_ranges`.
- `DW_TAG_formal_parameter`, local/global variable DIEs, and return types.
- Base, pointer, reference, array, typedef, qualified, enumeration, structure, union, and subroutine types.
- Structure/union members and correct offsets.
- `DW_AT_decl_file`, `DW_AT_decl_line`, and `DW_AT_stmt_list` tied to `.dbg.c`.
- `.debug_line` with address-accurate rows.
- `.debug_rnglists` for discontiguous ranges when appropriate.
- `.debug_loclists` for variables whose storage changes over a function.
- `.debug_str`, `.debug_addr`, and other support sections when required by the chosen forms.

Do not add `.debug_names`, compression, or other accelerators before the core DIE, line, type, range, and location data validates.

### 8.2 Address and range handling

- Retain `Address`/`AddressSetView` objects through extraction; convert to integer offsets only at a clearly defined serialization boundary.
- Treat function bodies as sets of ranges, not `[entry, max-address]` spans.
- Distinguish link-time virtual addresses, file offsets, Ghidra image-base addresses, and runtime relocated addresses.
- Document whether emitted addresses are absolute, section-relative, or relocation-backed.
- Test non-zero image bases, PIE, shared objects, and rebased Ghidra programs.

### 8.3 Type identity

- Maintain a type cache so repeated Ghidra types reference one canonical DIE rather than recursively duplicating cycles.
- Preserve signedness, byte size, qualifiers, array bounds, member offsets, enum values, and function prototypes.
- Detect recursive/self-referential types safely.
- Preserve analyst-applied data types over decompiler-only guesses.

### 8.4 Variable locations

- Use Ghidra variable storage and live ranges when defensible.
- Support stack, register, register-relative, piecewise, and changing locations.
- Do not assume one representative `Varnode` describes the entire variable lifetime.
- Omit uncertain locations rather than emitting a wrong expression.
- Keep architecture register-number mappings separate from Ghidra’s internal register identifiers.

## 9. ELF sidecar rules

- Do not hard-code `ELFCLASS64`, 64-bit ELF headers, or 64-bit section headers.
- Copy or derive `EI_CLASS`, `EI_DATA`, `e_machine`, `e_flags`, OS ABI, build ID, and section-address semantics from the original ELF.
- A relocation section must have a valid target (`sh_info`) and symbol table (`sh_link`) and use the correct target relocation encoding. The baseline emitter has no symbol table; do not preserve invalid placeholder relocations.
- The selected packaging strategy is a matched, non-loadable separate-debug
  ELF derived from the original target. It preserves target identity and
  build-ID notes, has no program-header table, and contains a newly written
  section table with Forge DWARF. See `docs/ADR-0001-ELF-SIDECAR.md`.
- Automatic discovery through matching build ID should be supported when possible.
- Optional `.gnu_debuglink` attachment must remain explicit because it changes the original executable.
- Inputs with no ELF section-header table are supported. Treat `e_shoff == 0`,
  `e_shnum == 0`, and `e_shstrndx == 0` as a valid program-header-only ELF,
  not an indexing error. The sidecar writer must create a new section table
  and `.shstrtab` without changing the original target.
- Maintain a 32-bit big-endian MIPS no-section-header regression fixture
  modeled on `cesena/ghidra2dwarf` issue 29. It must run/import/export without
  crashing, validate structurally, and leave no partial final artifact on
  failure.

The explicit first-milestone GDB workflow is `file <original>` followed by
`set auto-solib-add off` and `symbol-file <original>.dbg`. Automatic build-ID
discovery remains planned.

## 10. Build, run, and validation commands

### 10.1 Native and release packaging

The historical Maven shaded-JAR path and committed native/unpacked artifacts
were removed. `.github/workflows/ci.yml` is the sole production native build;
it compiles the pinned source once per host platform and passes those artifacts
to `support/assemble-release.sh`. Release bundles use Ghidra's standard
`os/<platform>` layout and include per-platform plus whole-release SHA-256
manifests. Do not reintroduce committed native binaries or a private JNA copy.

The native configuration is:

```bash
sh autogen.sh
./configure --enable-shared --enable-dwarfgen --disable-static --prefix="$PWD/install"
make -j"$(nproc)"
make install                 # Linux job; Windows job stops after make
```

Linux additionally sets `$ORIGIN` RUNPATH on `libdwarfp.so*` with `patchelf`.
Windows builds under MSYS2 `MINGW64`. See `docs/RELEASE.md` for the versioning,
assembly, host support, and install contract.

### 10.2 Full Ghidra extension build

**CONFIRMED:** the first supported baseline is Ghidra 12.0.3. Its extension
build compiles Java 21-compatible bytecode. The repository-owned wrapper uses
Gradle 9.3.1, matching the wrapper shipped by the selected Ghidra installation.

Build with:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC
./gradlew clean buildExtension
```

The ZIP is written to `dist/`. On 2026-09-02 this command built successfully,
the ZIP was installed into Ghidra 12.0.3, and its native-free preflight script
ran successfully through `analyzeHeadless` on an x86-64 `ET_EXEC` fixture.
Native DWARF production remains disabled until the isolated ABI smoke test
passes.

### 10.4 Required structural validation

For every generated test artifact, run the tools available on the platform and record any unavailable tool:

```bash
readelf -h <binary>.dbg
readelf -S <binary>.dbg
readelf --debug-dump=info <binary>.dbg
readelf --debug-dump=abbrev <binary>.dbg
readelf --debug-dump=aranges <binary>.dbg
readelf --debug-dump=decodedline <binary>.dbg
llvm-dwarfdump --verify <binary>.dbg
dwarfdump <binary>.dbg
```

Also compare target identity/address metadata with the original:

```bash
readelf -h <binary>
readelf -S <binary>
readelf -n <binary>
readelf -n <binary>.dbg
```

A validator warning is not automatically harmless. Explain it or fix it.

### 10.5 Required GDB behavior validation

Use a reproducible GDB script for each fixture. At minimum prove:

```gdb
info functions
break <recovered-function>
list <recovered-function>
ptype <recovered-type>
print <available-variable>
next
step
```

The initial sidecar-loading sequence is `file <original>`,
`set auto-solib-add off`, then `symbol-file <original>.dbg`; it is encoded in
the GDB oracle harness. Automatic discovery is later work.

## 11. Test matrix

The first serious support matrix is:

- x86-64 ET_EXEC, non-PIE.
- x86-64 PIE.
- x86-64 ET_DYN shared object.
- AArch64 ET_EXEC, non-PIE.
- AArch64 PIE or shared object.
- ARM32/AArch32 little-endian ARMv7 hard-float ET_EXEC, PIE, and shared object,
  initially under QEMU when native hardware is unavailable.
- MIPS ELF32 big-endian ET_EXEC, initially under QEMU when native hardware is
  unavailable.
- At least one MIPS PIE or shared-object case before claiming broad MIPS
  support.
- Linux-hosted Ghidra.
- Windows-hosted Ghidra.
- Stripped and partially stripped inputs.
- Functions with contiguous and discontiguous bodies.
- Parameters/locals in registers, on stack, and changing storage.
- Recursive structures, arrays, enums, typedefs, and function pointers.
- A function that fails decompilation without aborting the export.
- A cancelled export that leaves no final partial files.

MIPS is the planned first 32-bit/big-endian validation target. It may follow
the initial x86-64/AArch64 release lanes, but the implementation must not
exclude it in the meantime.

Use small, redistributable source-built fixtures. Do not commit proprietary firmware or confidential binaries.

### 11.1 Mandatory cross-architecture pipeline

- The integration pipeline must have end-to-end target lanes for both x86-64
  and AArch64 before the first supported release.
- Each lane must build its fixture, import/analyze it with headless Ghidra, run
  the real exporter, validate the emitted ELF/DWARF, and execute the applicable
  scripted GDB behavior checks.
- The AArch64 lane may use a native ARM64 runner or a documented cross-compile
  plus emulation setup. Merely cross-compiling or structurally inspecting an
  AArch64 fixture does not satisfy the integration requirement.
- Both lanes must use the same production exporter path and retain useful
  diagnostics/artifacts when a job fails.
- The ARM32/AArch32 lane uses the same production exporter path with an
  `arm-linux-gnueabihf` fixture toolchain and QEMU/GDB runtime checks. The
  initial validated profile does not imply Thumb or big-endian ARM support.
- Add a QEMU-backed MIPS lane as soon as the fixture/export path is available.
  It must perform exporter and GDB behavior checks, not merely cross-compile a
  MIPS binary. This lane becomes required before MIPS is advertised as
  supported.
- x86-32 remains a later target case. ARM32/AArch32 is an active end-to-end
  target following the user's 2026-09-03 reprioritization.

## 12. Completion rules

A feature is complete only when all applicable conditions hold:

- The implementation is buildable from a clean checkout.
- Native code does not crash the JVM.
- Unit/integration tests pass.
- DWARF validators pass without unexplained errors.
- GDB behavior matches the acceptance criteria.
- The original target remains byte-for-byte unchanged in default mode.
- Deterministic reruns produce identical `.dbg.c` and semantically identical, preferably byte-identical, `.dbg` output.
- Linux/Windows and architecture claims are backed by tests, not switch statements.
- The mandatory x86-64 and AArch64 pipeline lanes pass end to end.
- Documentation and `TODO.md` are updated.

Do not close an issue merely because a section name appears in `readelf -S`. Close it only when the section is structurally and behaviorally correct for its required use.
