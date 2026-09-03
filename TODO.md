# TODO.md — GhidraDwarfForge

This file is the prioritized execution plan for the repository state captured at commit `7a39a186538c7aec3f7dbdc4a6e396125b5d63ea`.

Status vocabulary:

- `[ ]` — not complete.
- `[~]` — implementation is present or work has started, but acceptance criteria are not met.
- `[x]` — complete and backed by recorded tests.
- **BLOCKED** — cannot be completed safely until the named dependency/decision is resolved.
- **UNCERTAIN** — scope or design requires investigation; do not guess.

## 0. Global completion criteria

No project-level milestone is complete unless all applicable conditions hold:

- [ ] Builds from a clean checkout using documented commands.
- [ ] Uses a pinned Ghidra compatibility baseline.
- [ ] Uses a pinned, provenance-recorded libdwarf revision.
- [ ] Does not crash or corrupt the Ghidra JVM.
- [ ] Preserves the original target byte-for-byte in default mode.
- [ ] Produces deterministic `.dbg.c` for an unchanged Ghidra program.
- [ ] Produces structurally valid ELF and DWARF accepted by independent validators.
- [ ] Passes scripted GDB behavior checks, not only `readelf -S`.
- [ ] Is honest about unavailable types, variables, locations, and source mappings.
- [ ] Has tests for every claimed architecture/host combination.
- [ ] Runs mandatory end-to-end integration lanes for x86-64 and AArch64
  targets in the pipeline.
- [ ] Keeps target handling extensible beyond x86/ARM and adds a QEMU-backed
  MIPS behavior lane before claiming MIPS support.
- [ ] Updates `PROJECT_CONTEXT.md`, this file, and user-facing documentation when decisions or support claims change.

## 1. Milestone ordering

Do not bypass this dependency order:

```text
M0: reproducible build and repository hygiene
  ↓
M1: pinned libdwarf + ABI-safe producer smoke test
  ↓
M2: valid minimal ELF/DWARF sidecar + explicit GDB loading
  ↓
M3: deterministic synthetic source + .debug_line
  ↓
M4: type graph + signatures
  ↓
M5: variables + accurate locations
  ↓
M6: PIE/shared objects + mandatory AArch64 pipeline lane + Windows host
  ↓
M7: headless/release productization
```

Feature work that calls new libdwarfp functions is blocked until M1.

---

# P0 — Safety, reproducibility, and a buildable product

## P0.1 Restore a clean, reproducible Ghidra extension build

**Status:** `[x]` — build, installation, packaged native selection, and hosted
clean-install validation are enforced by the release pipeline.
**Blocks:** all release milestones.

### Work

- [x] Select and document Ghidra 12.0.3 as the first supported version.
- [x] Compile Java 21-compatible bytecode as required by Ghidra 12.0.3.
- [x] Create the normal Ghidra extension Gradle layout.
- [x] Add a Gradle 9.3.1 wrapper to the repository.
- [x] Add native-free production Java under a conventional package/source tree.
- [x] Package required JAR/native resources into the extension ZIP.
- [x] Add extension metadata and installation documentation.
- [x] Ensure the extension build does not depend on files already present under
  `src/`, `src/temp/`, or `jna-wrapper/target/`.

### Known historical command

An old README contained:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3_PUBLIC
./gradlew :DwarfForge:buildExtension && \
  cp DwarfForge/build/dist/DwarfForge.zip "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

This command is **HISTORICAL, UNVERIFIED** and cannot be treated as current until the missing build structure is restored or replaced.

### Completion criteria

- [x] `./gradlew clean buildExtension` succeeds with `GHIDRA_INSTALL_DIR` set.
- [x] The generated extension ZIP installs in Ghidra 12.0.3.
- [x] Ghidra loads the native-free extension without classloader/native-loader errors.
- [x] The entry point runs on a trivial x86-64 ELF through `analyzeHeadless`.
- [x] Ghidra 12.0.3 and Java 21 bytecode are documented.
- [x] CI workflow builds the extension successfully on a hosted runner.
- [x] No build output is required to be committed for the build to succeed.

## P0.2 Clean generated artifacts and establish repository hygiene

**Status:** `[x]` — generated/shaded artifacts were removed; the pinned CI
native build and deterministic release assembler are the source of truth.
**Dependency:** coordinate with P0.1 so required resources are not accidentally removed.

### Work

- [x] Add a real `.gitignore` covering Gradle, Maven, IDE, temporary,
  native-build, crash-dump, and generated test output.
- [x] Remove committed `jna-wrapper/target/` and the obsolete Maven wrapper tree.
- [x] Remove committed `src/temp/` extracted/generated content after preserving
  its historical role in `PROJECT_CONTEXT.md`.
- [x] Remove the obsolete `src/libdwarf.jar`; production uses Ghidra's JNA and
  CI-built pinned native libraries.
- [x] Avoid duplicate copies of the same native library under generated directories.
- [x] Add reproducible artifact/provenance manifests rather than relying on
  opaque committed binaries.

### Completion criteria

- [x] `git status --short` remains clean after a normal build/test run.
- [x] Clean checkout plus documented tools reproduces all required generated files.
- [x] No crash logs, cores, temporary JNA extraction files, or unpacked JAR contents are tracked.
- [x] Native/JAR artifacts have one documented source of truth.
- [x] Removal does not break extension packaging.

## P0.3 Add repository and dependency licensing

**Status:** `[x]` — the project is MIT licensed. The hosted native-inclusive
bundle carries the third-party inventory, upstream notices, exact LGPL
corresponding source, local patch, reconstruction instructions, and enforced
checksums.

### Work

- [x] Add the project’s chosen MIT `LICENSE`.
- [x] Record licenses for Ghidra APIs, JNA, libdwarf/libdwarfp, and current
  Windows native dependencies.
- [x] Include required notices in the extension/release bundle.
- [x] Document how corresponding source and build scripts for bundled LGPL
  components are made available.
- [x] Ensure the chosen packaging approach includes the technically reviewed
  dependency-distribution materials and replacement mechanism.

### Completion criteria

- [x] Repository has an explicit project license.
- [x] Release artifact contains all required notices.
- [x] Third-party dependency versions and licenses are documented.
- [x] Bundled native distribution obligations have been technically reviewed
  and enforced by release assembly and hosted CI.

## P0.4 Pin libdwarf and record native provenance

**Status:** `[x]` — pinned source, checksums, native provenance, and
Linux/Windows functional-rebuild comparison gates pass in hosted CI run
33778570507.
**Blocks:** P0.5 and all producer feature work.

### Work

- [x] Replace workflow `LIBDWARF_VERSION: main` with an exact release tag or commit SHA.
- [x] Record the resolved commit, configure flags, compiler/toolchain versions, target triple, checksums, and dependent DLL/SO names.
- [x] Fetch the pinned, checksummed official source archive at build time.
- [x] Make Linux and Windows native builds functionally reproducible.
- [x] Add exported-symbol and dependency checks.
- [x] Do not automatically commit opaque rebuilt binaries directly to `main` without review; choose a safer release/update flow.

Current configure flags that must be preserved or deliberately changed:

```bash
sh autogen.sh
./configure --enable-shared \
  --enable-dwarfgen --disable-static --prefix="$PWD/install"
make -j"$(nproc)"
```

Linux currently also runs:

```bash
make install
```

and patches `libdwarfp.so*` RUNPATH to `$ORIGIN`.

### Completion criteria

- [x] No production build references moving upstream `main`.
- [x] A provenance file identifies libdwarf v2.3.2, source commit
  `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`, and the official archive hash.
- [x] Linux x86-64 native build succeeds and dependency/RUNPATH checks pass.
- [x] Windows x86-64 native build succeeds and DLL dependency checks pass.
- [x] SHA-256 checksums are recorded for release natives.
- [x] Rebuilding the same revision with the documented environment produces
  functionally equivalent artifacts on Linux and Windows.
- [x] CI fails when expected symbols or dependency names are missing.

## P0.5 Audit and repair the complete JNA ABI

**Status:** `[x]` — the complete production producer/consumer surface is
audited against pinned headers; the C ABI probe and expanded Java smoke pass
on Linux and Windows in hosted CI run 33778570507.
**Dependency:** P0.4.

### Work

Audit every production declaration against the exact pinned headers. The
superseded top-level prototype bindings were removed so their known unsafe
declarations cannot be compiled, packaged, or mistaken for supported APIs.

Known high-risk mismatches observed against the inspected upstream header include:

1. `Dwarf_Unsigned`/`Dwarf_Addr` are 64-bit `unsigned long long`, but the callback uses `NativeLong`/`NativeLongByReference`.
2. `Dwarf_Handler` should receive opaque `Dwarf_Error`, not an `int`.
3. `dwarf_transform_to_disk_form_a` is missing `Dwarf_Unsigned *nbufs_out`.
4. `dwarf_add_AT_targ_address_c` is missing `Dwarf_P_Attribute *outattr`.
5. `dwarf_add_AT_flag_a` is missing `Dwarf_P_Debug` and `Dwarf_P_Attribute *outattr`.
6. Section callback return value and `sect_name_index` have different semantics.

Additional required work:

- [x] Add opaque JNA types for every handle used by the audited subset.
- [x] Use fixed-width Java mappings in the new production subset.
- [x] Verify signedness and pointer indirection.
- [x] Verify calling convention on Windows.
- [x] Keep strong references to callbacks for the producer lifetime.
- [x] Check every enabled-subset return status and decode producer
  `Dwarf_Error` through its compatible error number; document and verify
  producer-owned error cleanup through producer finish.
- [x] Add a native ABI probe that checks C signatures, widths, structure size,
  and offsets against the pinned headers.

### Completion criteria

- [x] Every function in the new enabled subset has a reference to the pinned
  header declaration.
- [x] A mapping test proves 64-bit `Dwarf_Unsigned` behavior on Linux and
  Windows.
- [x] Error callbacks receive valid opaque error objects and produce readable
  messages on Linux and Windows.
- [x] No known wrong-arity declaration remains in the production binding.
- [x] Callback objects remain reachable until producer finish in the smoke path.
- [x] A standalone smoke test initializes the producer, creates a CU/DIE,
  transforms it, retrieves sections/relocations, and finishes cleanly.
- [x] The expanded smoke test passes under Linux and Windows processes without
  JVM crash/access violation.
- [x] Equivalent calls have passed the standalone test before the production
  exporter path uses them.

## P0.6 Create an isolated native producer smoke-test executable

**Status:** `[~]` — explicit-native isolated JVM coverage passes for every
target profile and packaged-native resolution plus bounded repetition coverage
is **PRESENT, UNVERIFIED** on hosted Linux/Windows. The repetition test exposed
and now guards a patched upstream cross-export string-table state leak.
**Dependency:** P0.4 and P0.5.

### Work

Create a small Java command-line test that does not depend on Ghidra and that:

1. `[~]` Loads explicit pinned native libraries and the checksummed native pair
   from an installed extension; hosted confirmation of the packaged path remains.
2. `[x]` Calls `dwarf_producer_init`.
3. `[x]` Creates a compile-unit DIE and one subprogram DIE.
4. `[x]` Transforms to disk form.
5. `[x]` Retrieves all generated section buffers.
6. `[x]` Retrieves and checks symbolic relocation data using the pinned API.
7. `[x]` Finishes/deallocates cleanly on the passing path.
8. `[x]` Writes native revision, platform, target mode, and SHA-256 diagnostics.

Run it in a separate process so a native fault produces a test failure rather than killing the test orchestrator or Ghidra.

### Completion criteria

- [x] Exit code is zero on supported Linux/Windows hosts.
- [x] A crash or signal is surfaced as a failed test.
- [~] A 64-lifetime process test samples Linux RSS and enforces a bounded-growth
  threshold; hosted Linux/Windows confirmation remains.
- [x] Section callback indices and relocation data are internally consistent.
- [x] Test output records the pinned libdwarf revision and native checksum.

## P0.7 Add source-built ELF fixtures and a test harness

**Status:** `[~]` — a redistributable semantic source builds ET_EXEC, PIE,
shared-object, partially stripped, and program-header-only variants for all
five target profiles. Reproducibility/metadata capture and the real partial
export role are **PRESENT, UNVERIFIED** across the hosted matrix.
**Blocks:** meaningful validation of all exporter work.

### Work

Create small redistributable C/C++ fixtures covering:

- [x] One global and one static function.
- [x] Source constructs for parameters and locals; storage cases remain to be
  asserted after analysis/export.
- [x] Struct, union, enum, array, typedef, qualifier, recursive pointer type, and function pointer.
- [x] Contiguous and intentionally discontiguous/partitioned function ranges.
- [x] Non-PIE `ET_EXEC`.
- [x] Source-built PIE reference/stripped fixtures with real headless symbol
  export and runtime assertions.
- [x] Shared object built from a dedicated source without `main`.
- [x] x86-64, AArch64, MIPS32 big-endian, and MIPS32 little-endian builds from
  the same semantic fixture source.
- [~] Stripped and partially stripped variants; hosted confirmation of the new
  partial role remains.
- [x] Program-header-only variants with no ELF section-header table.
- [x] A fixture/function that the decompiler cannot complete or a controlled mock failure.

Retain original compiler DWARF in a reference build for expected addresses/types, then create stripped inputs for Ghidra. Do not claim Ghidra should reproduce every compiler detail exactly; use reference data to detect gross address/type errors.

### Completion criteria

- [x] Current non-PIE fixtures build through one documented command.
- [~] Stripped, partially stripped, and reference variants are rebuilt twice
  and compared byte for byte; hosted confirmation remains.
- [~] Original, stripped, and partially stripped hashes plus ELF metadata are
  recorded as CI diagnostics; hosted confirmation remains.
- [x] Test harness imports/analyzes/exports every current fixture using Ghidra
  12.0.3 and validates the resulting symbol sidecar.
- [x] No proprietary firmware is needed for CI.
- [x] Each fixture documents what behavior it exercises.

### No-section-header regression

`cesena/ghidra2dwarf` issue 29 demonstrates an ELF32 big-endian MIPS input with
`e_shoff=0`, `e_shentsize=0`, `e_shnum=0`, and `e_shstrndx=0` crashing an
exporter that indexes the absent section-name table. GhidraDwarfForge must:

- treat this as a valid program-header-only input;
- derive target identity/load information from the ELF/program headers;
- create a fresh output section table and `.shstrtab`;
- pass the normal validators and GDB behavior tests; and
- never crash Ghidra or publish a partial `.dbg`/`.dbg.c` pair.

**Current evidence:** the real headless function/source exporter completes without a
crash for all five no-section-table fixtures, creates a fresh section table
and correctly typed `SHT_STRTAB` `.shstrtab`, and leaves every input hash
unchanged. `.dbg.c`, DWARF 5 line tables, all structural validators, and
native/QEMU GDB source-level behavior pass. Future type/variable paths must
retain this regression before the full product requirement is complete.

## P0.8 Decide and document the ELF sidecar/association strategy

**Status:** `[x]` — matched non-loadable sidecar selected and proven across
ELF32/ELF64, both byte orders, ET_EXEC/PIE, and no-section-table inputs.
**Blocks:** P0.9 and all GDB acceptance tests.

### Questions to resolve

- Should the output be a debug-only ELF derived from the original ELF’s identity/section metadata?
- Should it be an `ET_REL` object loaded explicitly with `add-symbol-file`/`symbol-file`?
- Which approach works correctly for non-PIE, PIE, and shared objects?
- How are build IDs handled?
- Is automatic discovery required in the first milestone or is explicit loading acceptable?
- Which ELF implementation should be used: a tested library, Ghidra ELF classes, or a corrected custom emitter?

### Required experiment

For at least one x86-64 non-PIE fixture, construct candidate sidecars and prove:

- GDB associates or loads the file.
- Function addresses resolve exactly.
- No invalid relocation/symbol-table assumptions remain.
- `readelf` and DWARF validators accept the artifact.

### Completion criteria

- [x] A short architecture decision record documents the selected format and alternatives rejected.
- [x] Exact GDB loading/association commands are documented.
- [x] Build-ID and `.gnu_debuglink` behavior are specified.
- [x] Original-file modification remains optional.
- [x] The chosen design is proven for PIE and ELF32/ELF64; shared-object load
  timing remains a P2 behavior test.
- [x] Test harness encodes the selected behavior.

## P0.9 Replace or correct the ELF writer for the minimal path

**Status:** `[~]` — the pure-Java matched sidecar writer passes both
compiler-oracle and real Forge symbol tests, including no-section-table inputs;
existing-DWARF policy, large files, and complete DWARF sections remain.
**Dependency:** P0.8.

### Work

Remove these prototype assumptions from the supported path:

- Always `ELFCLASS64`.
- Always 64-byte ELF/section headers.
- Always `ET_REL` regardless of the selected design.
- `x86` always means `EM_X86_64`.
- Relocation sections with `sh_link = 0` and no symbol table.
- Arbitrary section callback/symbol indices.
- Zero section addresses when the chosen GDB model requires matched addresses.

Implement:

- ELF32/ELF64-aware headers.
- Correct byte order.
- Correct machine and architecture flags.
- Correct section types, alignment, links, and info fields.
- Build identity/association metadata selected in P0.8.
- Correct atomic file writing.

### Completion criteria

- [x] Compiler-DWARF container oracle passes `readelf -h -S -n` and GDB for
  x86-64, AArch64, and MIPS32 big/little endian across ET_EXEC, PIE, and
  no-section-table variants.
- [x] Minimal x86-64 non-PIE sidecar passes `readelf -h -S -n`.
- [x] Producer symbolic relocations are validated and resolved values are
  emitted without an incomplete debug relocation section.
- [x] No unresolved `SHT_REL`/`SHT_RELA` section is emitted; inherited
  relocation headers are neutralized because producer relocations are resolved
  before publication.
- [x] GDB loads the sidecar using the documented path.
- [x] Function symbols/DIE addresses match the original executable for the
  current contiguous-function fixture coverage.
- [x] Original target hash is unchanged.
- [x] Invalid/unsupported target combinations fail before output is published.

## P0.10 Deliver the first validated symbol-only milestone

**Status:** `[x]` — the Linux x86-64 symbol-only milestone passes all local and
hosted validators and GDB behavior tests.
**Dependencies:** P0.1, P0.4–P0.9.

### Scope

Narrow first target:

```text
Host: Linux
Target: x86-64 ELF, non-PIE ET_EXEC
DWARF: one CU + named subprogram DIEs + valid ranges/aranges as needed
Source stepping/types/variables: not yet required
Loading: exact strategy selected in P0.8
```

### Completion criteria

- [x] Exporter runs from installed Ghidra extension.
- [x] Sidecar output name is `<binary>.dbg` by default.
- [x] Sidecar is written atomically beside the binary or to an explicitly selected output path.
- [x] `llvm-dwarfdump --verify` passes.
- [x] `readelf --debug-dump=info` shows valid CU/subprogram DIEs.
- [x] GDB `info functions` includes expected recovered names.
- [x] GDB `break <function>` resolves to the correct link-time/runtime address.
- [x] Discontiguous functions are rejected with a diagnostic; they are never flattened silently.
- [x] Automated test records all commands/results.

---

# P1 — Deterministic synthetic source and line debugging

## P1.1 Refactor extraction away from the monolithic script

**Status:** `[x]` locally — Ghidra extraction, immutable project-owned models,
synthetic-source generation, native DWARF production, and ELF packaging are
separate. Native-independent model smokes and the full local GDB matrix pass;
hosted integration remains tracked by P2.12.
**Dependency:** P0 minimal path should remain working throughout refactor.

### Work

Create project-owned immutable models for:

- Program/ELF identity.
- Address spaces and image base.
- Functions and address ranges.
- Symbols/signatures/variables/types.
- Decompiled source tokens and address sets.
- Diagnostics and confidence/omission reasons.

Separate Ghidra extraction, source generation, DWARF production, ELF packaging, and validation reporting.

### Completion criteria

- [x] Unit tests can construct exporter models without opening Ghidra.
- [x] Native producer code does not query mutable Ghidra objects during serialization.
- [x] Existing P0 GDB tests continue to pass.
- [x] No single class owns decompilation, DIE construction, and ELF writing.

## P1.2 Generate deterministic `.dbg.c`

**Status:** `[x]` — deterministic production source, controlled function
failure/cancellation, staged pair publication, and Linux/Windows cross-host
byte identity pass in hosted CI.

### Work

- Define stable function ordering.
- Define stable newlines/encoding.
- Add a deterministic header explaining that source is reconstructed.
- Define stable synthetic declarations and identifiers.
- Record function start/end line numbers.
- Isolate one function’s decompiler failure.
- Write a deterministic diagnostic placeholder for failed functions.
- Avoid leaving a final `.dbg.c` unless its matching `.dbg` succeeds.
- Write to temporary files and atomically rename the pair after complete success.

### Completion criteria

- [x] Repeated export produces byte-identical `.dbg.c` for unchanged input/Ghidra version.
- [x] Function ordering, UTF-8, LF formatting, and honesty header are enforced.
- [x] One controlled decompiler failure does not suppress other functions.
- [x] Failed function still has a symbol-only DIE and source diagnostic.
- [x] Cancellation leaves neither final artifact partially updated.
- [x] UTF-8/newline behavior is tested on Linux and Windows.

## P1.3 Build a structured address-to-source map

**Status:** `[x]` locally — Ghidra line/token evidence is represented
independently of native production. Focused overlap/discontiguous-range tests
and the 12-case local exporter/validator/GDB matrix pass; hosted integration
remains tracked by P2.12.

### Work

- Extract address sets from decompiler tokens or another validated Ghidra source.
- Use `ghidra2dwarf` and `dwarfexport` token/expression mapping approaches as
  references, while preserving all defensible ranges instead of collapsing a
  line to one minimum address.
- Associate source statements/lines with one or more address ranges.
- Preserve discontiguous mappings.
- [x] Resolve overlapping token address sets deterministically to the earliest
  generated source line for the shared instruction address.
- Do not assign addresses to comments, blank lines, type declarations, or formatting-only lines.
- Preserve mapping evidence/confidence for diagnostics.

### Completion criteria

- [x] Source map is independently constructible/testable without native code.
- [x] Every emitted executable source row has at least one defensible address.
- [x] Comments, blanks, and formatting-only lines have no accidental token row.
- [x] Multiple addresses per line are supported.
- [x] Mapping is deterministic.
- [x] Tests cover overlapping/discontiguous token address sets.

## P1.4 Emit a valid DWARF 5 `.debug_line`

**Status:** `[x]` locally — valid DWARF 5 line programs, including independent
sequences for discontiguous function ranges, pass all local targets/input
roles; hosted integration remains tracked by P2.12.
**Corresponds to:** issue #7.

### Work

- Add pinned libdwarfp line-table bindings, or another documented DWARF-producing path.
- Emit a source file table containing `<binary>.dbg.c`.
- Set CU `DW_AT_stmt_list`.
- Emit address/line rows from P1.3.
- End sequences correctly for each function/range as required.
- Add `DW_AT_decl_file` and `DW_AT_decl_line` to functions.
- Validate DWARF 5 line-table forms and support sections.

### Completion criteria

- [x] `readelf --debug-dump=decodedline <binary>.dbg` shows expected rows.
- [x] `llvm-dwarfdump --verify` passes.
- [x] GDB `list <function>` displays the generated function body.
- [x] GDB source breakpoint by file/line resolves to expected addresses.
- [x] GDB `next` advances through sensible source rows.
- [x] Discontiguous function ranges do not merge into unrelated code.
- [x] No rows point at synthetic comments/blank lines.

## P1.5 Complete source-level GDB milestone

**Status:** `[x]` locally for the required x86-64 non-PIE fixture; hosted CI
remains tracked by P2.12.
**Dependencies:** P1.2–P1.4.

### Completion criteria

For x86-64 non-PIE fixture:

- [x] `list <function>` displays `.dbg.c`.
- [x] `break <function>` resolves correctly.
- [x] `break <file>:<line>` resolves correctly for mapped lines.
- [x] `next`/`step` behavior is documented and sensible.
- [x] `ni` continues to operate normally alongside source stepping.
- [x] GDB reports no malformed line-table/DWARF warnings.
- [x] Automated test stores a transcript or machine-checkable assertions.

---

# P1 — Types, signatures, variables, and ranges

## P1.6 Implement a canonical, cycle-safe type graph

**Status:** `[x]` locally — native-independent qualifier/reference modeling and
emission pass focused tests; real Ghidra extraction and DIE emission pass local
x86-64/AArch64/MIPS BE/MIPS LE validators and `ptype`, including endian-aware
bit fields. Ghidra 12.0.3's public listing `DataType` model has no qualifier or
C++ reference datatype to extract, so those are not fabricated.

### Work

Support and cache, at minimum:

- Base types with byte size and encoding.
- Void/unspecified type policy.
- Pointers and references where applicable.
- `const`, `volatile`, and other qualifiers available from Ghidra.
- Arrays and bounds.
- Typedefs.
- Enumerations and values.
- Structures/unions and member offsets.
- Recursive/self-referential types.
- Subroutine/function types and function pointers.

Define precedence among analyst-applied listing/signature types and decompiler guesses.

### Completion criteria

- [x] Repeated references share canonical DIEs.
- [x] Recursive types terminate without stack overflow/duplicate explosion.
- [x] Signedness, size, member offset, array bound, and enum values validate.
- [x] `ptype` in GDB matches expected fixture shape.
- [x] Unsupported types produce a documented fallback/diagnostic.
- [x] Type output is deterministic.

## P1.7 Emit complete function signatures

**Status:** `[~]` — return/parameter DIEs, names,
prototype/no-return/variadic flags, a user-defined signature, and
standards-backed `DW_CC_normal` pass locally. Unrepresentable vendor ABI
distinctions retain their model string without invented DWARF codes. External
functions and thunks are diagnosed and omitted under the tested initial
policy. Distinct linkage-name emission remains because GDB must retain the
analyst-facing breakpoint name.

### Work

- Add function return-type references.
- Add `DW_TAG_formal_parameter` DIEs.
- Preserve parameter names.
- Preserve variadic signatures when known.
- [x] Preserve calling-convention information where DWARF/GDB can use it:
  recognized conventional subroutines emit `DW_CC_normal`; unknown convention
  state and unproven vendor codes remain absent.
- [~] Add linkage names where meaningful. A distinct imported-name experiment
  was rejected because GDB 16.3 used `DW_AT_linkage_name` instead of the
  analyst-facing `DW_AT_name` in the honest C11 CU, breaking
  `break recovered_add`.
- [x] Distinguish definitions, declarations, imports, thunks, and aliases under
  a documented initial policy: only real definitions emit; imports/thunks are
  diagnosed and omitted until declaration/linkage modeling exists.

### Completion criteria

- [x] GDB displays expected function prototypes.
- [x] `ptype <function>` or equivalent output reflects return/parameter types.
- [x] Analyst-applied signature overrides are preserved.
- [x] Variadic and no-return cases are represented correctly or diagnosed.
- [x] External/import policy has tests (imports/thunks are diagnosed and
  omitted until declaration/linkage emission exists).

## P1.8 Represent discontiguous program/function ranges correctly

**Status:** `[x]` — Ghidra address sets, deterministic DWARF 5 range lists,
split line sequences, validators, and GDB gap behavior pass locally.

### Work

- Retain `AddressSetView` ranges during extraction.
- Replace `[entry, max+1)` spans with explicit range sets.
- Emit `DW_AT_ranges`/`.debug_rnglists` where needed.
- Ensure CU ranges describe all relevant executable code without accidental gaps.
- Decide whether `.debug_aranges` is retained and how CU offsets are supplied.

### Completion criteria

- [x] A discontiguous function fixture has no false coverage over the gap.
- [x] GDB associates both real ranges with one function.
- [x] `llvm-dwarfdump --verify` passes.
- [x] `readelf --debug-dump=ranges` or equivalent shows expected entries.
- [x] `.debug_aranges` is deliberately not emitted; CU `DW_AT_ranges` provides
  the tested lookup coverage without an optional accelerator.

## P1.9 Export global variables

**Status:** `[x]` — primary non-default labels backed by defined memory data
emit typed `DW_TAG_variable` DIEs and tested `DW_OP_addr` locations across
ET_EXEC, PIE, and shared objects in all five hosted target lanes. A real typed
Ghidra external declaration emits without a fabricated location, and a
curated namespace is retained as `DW_TAG_namespace` parentage.

### Work

- Export named global/static data objects with type references.
- [x] Distinguish declarations from definitions.
- Handle absolute/address expressions and PIE/shared relocation semantics.
- [x] Preserve Ghidra namespace scope when meaningful. Library/class/function
  scopes remain out of this initial namespace-only policy.

### Completion criteria

- [x] GDB resolves and prints fixture globals at correct addresses.
- [x] Types and sizes match expected fixture data.
- [x] PIE and shared-object behavior pass under ASLR.
- [x] No memory object is exported with a guessed address.

## P1.10 Build an architecture-neutral variable storage model

**Status:** `[x]` — native-independent storage/live-range types and isolated
Ghidra 12.0.3 x86-64, AArch64, and MIPS register maps pass focused tests.
Production register and stack extraction plus DWARF emission are implemented
under P1.11; composite pieces and additional storage classes remain there.
**Blocks:** P1.11.

### Work

Represent, independently of DWARF encoding:

- Stack locations.
- Register locations.
- Register-relative locations.
- Pieces/composite storage.
- Changing locations over live ranges.
- Unavailable/optimized-away locations.
- Confidence and omission reason.

Map Ghidra registers to target DWARF register numbers using isolated architecture tables/adapters.

### Completion criteria

- [x] No generic code hard-codes `RBP` or x86 DWARF register numbers.
- [x] Storage model unit tests cover stack/register/piece/changing/unavailable cases.
- [x] Register mappings are tied to target architecture and tested.
- [x] Unknown storage cannot silently become a numeric DWARF expression.

## P1.11 Emit parameters/locals with accurate locations

**Status:** `[x]` — parameters and recovered locals have canonical name/type
DIEs. A curated locationless local is proven in all ET_EXEC/PIE lanes and GDB
reports it optimized out. A native-independent planner and audited libdwarf
producer path now emit exact-width stable register/register-relative locations.
Production extraction admits explicit Ghidra register parameters only after an
instruction/p-code scan proves the register is never written and the function
contains no calls. GDB reads 19/23 on x86-64 and both MIPS byte orders;
AArch64's overwritten input registers are honestly omitted, while ARM32
retains only `r1` in executable/PIE roles. Exact Ghidra stack slots
are translated with instruction-level stack-pointer depths and emitted through
DWARF 5 `.debug_loclists`; GDB reads the curated local as 42 on x86-64,
AArch64, ARM32, and both MIPS byte orders for ET_EXEC and PIE. Exact entry-live
register locals use the same whole-function overwrite/call-clobber proof;
GDB reads the curated register local as 31 on x86-64, AArch64, and both MIPS
profiles for ET_EXEC and PIE; ARM32's `r3` is overwritten and omitted. Exact
register composites preserve Ghidra's endian-aware varnode order and emit
explicit `DW_OP_bit_piece` sequences; GDB reconstructs the curated 64-bit value
on the same four profiles, while ARM32's overwritten piece remains
locationless. A controlled stack-depth change proves the stack local resolves
as 42 in two different location-list ranges on all five targets. Unsupported
or uncertain storage remains locationless with a diagnostic.
**Dependency:** P1.10.

### Work

- Emit parameters and local variables with type references.
- Emit simple `DW_AT_location` expressions when storage is stable.
- Emit `.debug_loclists` when storage changes over address ranges.
- Add `DW_AT_frame_base` only when a defensible model exists.
- Handle piecewise storage when supported.
- Omit location while retaining name/type when evidence is insufficient.

### Completion criteria

- [x] GDB prints a stack parameter/local correctly at a breakpoint.
- [x] GDB prints production Ghidra register parameters correctly on x86-64 and
  both MIPS byte orders; overwritten AArch64 input registers are omitted.
- [x] A changing-location fixture resolves correctly in each tested live range.
- [x] Unavailable variable produces an honest unavailable/optimized-out result rather than an incorrect value.
- [x] `llvm-dwarfdump --verify` passes for every production stable-register and
  stack-location-list lane.
- [x] x86-64 register-number mapping has explicit tests.

## P1.12 Complete semantic GDB milestone

**Status:** `[x]` locally for the required x86-64 non-PIE fixture; hosted CI
remains tracked by P2.12.
**Dependencies:** P1.6–P1.11.

### Completion criteria

For the initial x86-64 non-PIE fixture:

- [x] `info functions` shows recovered names.
- [x] `list` shows synthetic source.
- [x] `ptype` shows expected struct/enum/typedef/function-pointer shapes.
- [x] `print` reads supported globals, parameters, and locals correctly.
- [x] Unsupported variable locations are honest.
- [x] Discontiguous ranges are correct.
- [x] All structural validators pass.
- [x] Default export leaves original target unchanged.

---

# P2 — Address relocation, architecture, and host portability

## P2.1 Implement and validate PIE address/load-bias behavior

**Status:** `[x]` locally — symbol addresses are normalized from Ghidra's image
base to ELF link-time VAs. Runtime breakpoints, source/type behavior, globals,
stable registers, and stack location lists pass under ASLR. A Ghidra project
rebased by `0x2000000` produces link-time DWARF that passes validators and the
full x86-64 GDB behavior oracle; checked conversion tests cover both rebase
directions and overflow.
**Dependency:** P0.8/P0.9 address model.

### Work

- Distinguish Ghidra image-base addresses, ELF link-time virtual addresses, and runtime relocated addresses.
- Determine how GDB applies load bias for the selected sidecar format.
- [x] Handle a Ghidra program that has been rebased.
- [x] Add a PIE fixture and runtime GDB test.

### Completion criteria

- [x] Symbol breakpoints resolve at correct runtime addresses under ASLR.
- [x] Source rows, types, and current supported variables remain aligned after
  relocation.
- [x] Rebased Ghidra input is normalized to original ELF link-time addresses.
- [x] Address conversions are unit tested, including checked overflow.

## P2.2 Support shared objects

**Status:** `[x]` — real stripped `ET_DYN` libraries export through headless
Ghidra and pass hosted structural plus runtime GDB validation on x86-64,
AArch64, ARM32, and MIPS32 big/little endian.

### Work

- [x] Add `ET_DYN` shared-library fixtures.
- [x] Build the library from a dedicated source that does not define `main`.
- [x] Test loading before and after the library is mapped.
- [x] Verify exported function/global addresses and load bias.
- [x] Document exact GDB commands for shared-library sidecars.

### Completion criteria

- [x] GDB loads link-time symbols before mapping and reloads them with the
  observed runtime load bias after mapping.
- [x] The recovered function breakpoint and global address/value resolve after
  load.
- [x] The runtime function address is checked against the main executable.
- [x] The shared-library ELF has no defined `main` symbol.
- [x] Structural and behavior tests pass in all five hosted target lanes.

## P2.3 Add AArch64 target support

**Status:** `[~]` — the symbol/source-line/type/signature milestone passes in
hosted CI for ET_EXEC, PIE, shared objects, and no-section inputs. Stack-local
locations pass; overwritten input registers are honestly omitted. Additional
storage cases and release support remain.

### Work

- Add AArch64 ELF fixtures.
- Verify `e_machine`, ABI flags, endianness, pointer/address size.
- Implement/test AArch64 DWARF register mapping.
- Validate parameter/local locations under AAPCS64.
- Test non-PIE first, then PIE/shared object.

### Completion criteria

- [x] Symbol/source-line milestone passes for AArch64 non-PIE and PIE.
- [~] Type/signature and stack-local milestones pass; additional variable
  storage classes remain.
- [x] AArch64 PIE/shared cases pass in hosted CI; packaged release evidence
  remains.
- [~] A repository guard confines architecture identifiers/register spellings
  to target-description boundaries; hosted confirmation remains.

## P2.3a Add MIPS target support

**Status:** `[~]` — hosted real headless symbol export, structural validation,
and QEMU/GDB runtime breakpoints pass for MIPS32 big/little endian ET_EXEC,
PIE, shared-object, and no-section-table inputs; `ptype`, stable register
parameters, and stack locals pass, while additional variable storage and
packaged release evidence remain.

### Work

- Add source-built MIPS ELF32 big-endian fixtures from the shared semantic
  fixture source.
- Derive MIPS ABI, ELF flags, endianness, address size, and relocation choices
  from the original ELF rather than processor-name guesses.
- Isolate and test MIPS DWARF register mappings for the selected ABI.
- Add a documented QEMU user-mode or system-mode test environment with a
  matching cross-GDB/toolchain.
- Run the real headless exporter, structural validators, and scripted GDB
  behavior checks under that environment.
- Add PIE/shared-object coverage before claiming broad MIPS support.

### Completion criteria

- [x] Producer ABI smoke test emits 32-bit big-endian MIPS DWARF buffers with
  correctly sized symbolic target relocations.
- [x] Headless Ghidra imports and exports the source-built MIPS fixtures.
- [x] QEMU plus `gdb-multiarch` executes both MIPS byte orders and proves the
  compiler-DWARF oracle breakpoint/arguments/source-step/local-value workflow.
- [x] `readelf`, `llvm-dwarfdump --verify`, independent `dwarfdump`, and GDB
  source/type behavior checks pass for the current artifacts.
- [x] QEMU runtime addresses/load bias agree with emitted DWARF for non-PIE,
  PIE, and shared objects.
- [~] A repository guard confines MIPS-specific code to target descriptions and
  register maps; hosted confirmation remains.

## P2.3b Add ARM32/AArch32 target support

**Status:** `[~]` — the ARMv7 hard-float, little-endian ARM-state profile passes
the hosted producer, real headless exporter, structural-validator, and
QEMU/GDB behavior matrix for ET_EXEC, PIE, shared objects, no-build-ID inputs,
and program-header-only inputs. Thumb, big-endian ARM, and additional ABI or
storage profiles are not claimed.

### Work

- Add a source-built `arm-linux-gnueabihf` fixture using the shared semantic
  source.
- Derive ELF32 target identity and isolate the ARM DWARF register map.
- Exercise the same production exporter path used by the other target lanes.
- Validate source/type/global behavior, PIE/shared load bias, stack location
  lists, and honest omission of overwritten registers under QEMU/GDB.

### Completion criteria

- [x] The isolated producer emits 32-bit little-endian ARM DWARF buffers.
- [x] Ghidra imports and exports ARM32 ET_EXEC, PIE, shared-object,
  no-build-ID, and no-section-table fixtures.
- [x] `readelf`, `llvm-dwarfdump --verify`, and independent `dwarfdump`
  accept every current ARM32 Forge artifact.
- [x] QEMU plus `gdb-multiarch` proves function/source/type/global behavior,
  PIE/shared load bias, and the changing stack location.
- [x] ARM register mappings are isolated and covered by native-independent
  storage tests.
- [ ] Thumb, big-endian ARM, and additional ARM ABI/storage profiles are
  separately modeled and validated before any broader support claim.

## P2.4 Validate Windows-hosted Ghidra

**Status:** `[x]` — the Windows CI lane builds and audits pinned MinGW DLLs,
runs isolated native/publisher/source smoke tests, performs real Ghidra 12.0.3
headless exports with explicit and packaged natives, and validates source bytes
plus ELF/DWARF. GitHub Actions run 33778570507 passed the complete lane,
including explicit Windows file-lock contention and rollback.
**Dependencies:** pinned Windows natives and corrected JNA ABI.

### Work

- [x] Install/test selected Ghidra baseline on Windows.
- [x] Verify JNA finds both the explicitly supplied and packaged
  `libdwarf`/`libdwarfp` DLL pairs.
- [x] Audit and bundle non-system MinGW runtime dependencies.
- [x] Output paths, atomic replacement, UTF-8/LF, and explicit Windows
  file-lock contention rollback pass.
- [x] Run a real ELF target export with Windows `readelf` and LLVM validation;
  executable GDB behavior remains in the Linux native/QEMU lanes.

### Completion criteria

- [x] Extension loads and exports without access violation.
- [x] Native CI artifacts include documented non-system runtime dependencies.
- [x] Generated source and artifact semantics match the Linux reference.
- [x] Windows-hosted export passes structural validators; executable ELF/GDB
  behavior passes in the supported Linux lanes.
- [x] Host validation is included in CI.

## P2.5 Add ELF32 support

**Status:** `[~]` — ELF32 container, DWARF, line mapping, locations, validators,
and GDB source/type behavior pass for ARM32 and MIPS32 big/little endian. A
table-driven target-profile regression is **PRESENT, UNVERIFIED** in hosted CI.

### Work

- Implement ELF32 headers/section headers and target metadata.
- Add at least one 32-bit fixture.
- Verify 32-bit DWARF address size independently of DWARF offset size.
- Add 32-bit architecture register mapping and locations for the selected target.

### Completion criteria

- [x] No ELF64 header/layout code is used for the 32-bit artifact.
- [x] Validators and GDB pass for the selected 32-bit targets.
- [x] Current 32-bit pointer/address and DWARF32 offset combination is tested.

## P2.6 Add big-endian support

**Status:** `[~]` — MIPS32 big-endian container, DWARF 5 line/type/location
serialization, validators, and QEMU/GDB pass. Fail-closed rejection for
unsupported big-endian target profiles is **PRESENT, UNVERIFIED** in hosted CI.

### Work

- Select a practical big-endian test architecture/toolchain.
- Verify target ELF metadata, DWARF byte order, and libdwarfp flags.
- Test all integer/section serialization paths.

### Completion criteria

- [x] Big-endian fixture artifact passes validators.
- [x] GDB resolves expected symbols/source mappings under QEMU.
- [~] Unsupported big-endian targets fail explicitly rather than producing
  little-endian output; hosted confirmation remains.

---

# P2 — Product behavior and integration

## P2.7 Add output selection, fallback, and atomic pair commit

**Status:** `[~]` — deterministic default and explicit paths, stale-path input
override with imported-file hash verification, preflight collision/write
checks, staged pair rollback, and final hashes pass locally. GUI fallback is
implemented but remains unverified in an interactive Ghidra process.

### Work

- [x] Default to the executable directory when valid/writable.
- [x] Detect missing, stale, or unwritable `Program.getExecutablePath()`;
  inaccessible remote paths follow the same explicit-input/output failure
  policy rather than receiving guessed behavior.
- [~] Offer/select an output directory in GUI mode; code is present but the
  interactive chooser has not been exercised manually.
- [x] Accept explicit input/output paths in headless mode.
- [x] Write `.dbg` and `.dbg.c` to temporary files.
- [x] Commit the pair atomically as far as the host filesystem permits.
- [x] Report final paths and SHA-256 hashes.

### Completion criteria

- [x] Default path behavior satisfies issues #1–#3 for a normal local file.
- [x] Unwritable-path policy fails before writing; GUI prompting remains
  PRESENT, UNVERIFIED.
- [x] Headless path is deterministic and non-interactive.
- [x] Cancellation/failure leaves no mismatched final pair.

## P2.8 Add optional `.gnu_debuglink` attachment

**Status:** `[ ]` — optional feature; exact scope **UNCERTAIN**.

### Work

- Keep default export non-mutating.
- Add an explicit user option to attach `.gnu_debuglink` only after sidecar success.
- Compute/store the required CRC correctly.
- Back up or atomically replace the modified target.
- Verify automatic GDB discovery.

### Completion criteria

- [ ] Option is disabled by default.
- [ ] User receives an explicit warning that the target will change.
- [ ] Original backup/rollback policy is documented and tested.
- [ ] GDB automatically discovers the sidecar.
- [ ] CRC mismatch test fails as expected.
- [ ] Default-mode original hash test remains unchanged.

## P2.9 Add build-ID association where applicable

**Status:** `[x]` locally — matched sidecars preserve the original build ID and GDB
automatic discovery plus mismatched-image rejection pass locally using the
standard `.build-id/xx/rest.debug` layout. Sidecars for inputs without build
IDs retain that absence and pass the explicit GDB loading workflow on all four
targets.

### Work

- [x] Copy the original build ID into the matched sidecar.
- [x] Handle and test binaries without build IDs without inventing identity.
- [x] Test standard `.build-id` directory lookup.

### Completion criteria

- [x] Build-ID behavior is documented.
- [x] GDB discovery works in the selected layout.
- [x] A sidecar with another fixture's build ID is rejected by GDB.

## P2.10 Add exporter diagnostics/reporting

**Status:** `[x]` locally — schema-versioned deterministic JSON reports distinguish
success, partial semantic coverage, cancellation, and fatal failure. Real headless
success, controlled decompiler failure, and fatal preflight paths pass locally;
the Windows-hosted assertions remain PRESENT, UNVERIFIED under P2.12.

### Work

Produce a structured final report with:

- [x] Target identity and architecture.
- [x] Output paths/hashes.
- [x] Counts of functions/types/variables exported.
- [x] Counts and names of failed/skipped functions.
- [x] Omitted variable locations and reasons.
- [x] Unsupported constructs.
- [x] Validator/test status; the exporter honestly records `NOT_RUN`, while
  development harnesses run and retain validator results after publication.
- [x] Native/libdwarf revision.

### Completion criteria

- [x] User can distinguish success, partial semantic coverage, cancellation, and
  fatal failure.
- [x] Diagnostics are deterministic and machine-readable JSON.
- [x] Native errors include libdwarf messages without unsafe pointer use.
- [x] No unsupported feature is silently presented as supported.

---

# P2 — Headless, CI, and releases

## P2.11 Add a headless exporter entry point

**Status:** `[x]` locally — packaged Bash and PowerShell wrappers drive the same
production exporter in temporary-import or read-only existing-project mode.
The Bash contract, real Ghidra completion/fatal behavior, deterministic rerun,
and validators pass locally; the PowerShell wrapper remains PRESENT, UNVERIFIED
until P2.12 runs on a Windows host.
**Dependency:** exporter core separated from GUI/script state.

### Work

- [x] Expose the same core exporter through Ghidra headless analysis.
- [x] Define stable command-line arguments for project/program/output/options.
- [x] Return meaningful exit codes.
- [x] Avoid GUI prompts.
- [x] Support CI fixtures.

### Completion criteria

- [x] Headless command invokes the same production script/core as GUI mode.
- [x] Output is deterministic.
- [x] Failure/cancellation exit codes are documented.
- [x] CI can run the current source/type/signature milestone end-to-end without
  interactive Ghidra.

## P2.12 Add continuous validation

**Status:** `[x]` — Linux target lanes run for x86-64, AArch64, ARM32, MIPS32
big-endian, and MIPS32 little-endian, plus a Windows-hosted x86-64 ELF export
lane. They build pinned libdwarf, run the real headless exporter for
ET_EXEC/PIE/shared/no-section inputs as applicable, preserve input hashes,
validate with GNU/LLVM/libdwarf tools, and execute GDB/`ptype` natively or
through QEMU. GitHub Actions run 33751896850 passed the complete P2.12
diagnostic/Windows matrix; run 33757707307 added ARM32 and passed all 11 jobs,
including the aggregate `required-validation` gate. Enforcing that gate as a
strict, up-to-date merge requirement on `main` is now enabled through GitHub
branch protection for the public repository.

### Work

CI should include separate jobs for:

- GitHub Actions workflow linting with a pinned, checksum-verified `actionlint`.
- Java/unit tests.
- Native ABI smoke tests.
- Extension build.
- Fixture build/import/export.
- ELF/DWARF validators.
- GDB behavior scripts.
- Determinism/original-hash checks.
- Linux host initially; Windows host once stable.
- An x86-64 end-to-end target lane.
- An AArch64 end-to-end target lane using a dedicated runner or a documented
  cross-compile/emulation environment.
- An ARM32/AArch32 end-to-end target lane using a documented ARMv7
  cross-compile/emulation environment.
- A QEMU-backed MIPS target lane once the MIPS fixture/export path exists.

Every supported target lane must build fixtures, import/analyze/export through
headless Ghidra, run ELF/DWARF validators, and execute applicable scripted GDB
behavior checks. Cross-compilation without exporter and GDB execution is not
an integration pass.

### Completion criteria

- [x] Pull requests cannot merge with failing structural/GDB tests for
  supported paths; strict branch protection requires `required-validation`.
- [x] x86-64 and AArch64 have separate passing hosted end-to-end jobs.
- [x] Both jobs exercise the same production exporter entry point.
- [x] The AArch64 job proves runtime address behavior under a native runner or
  documented emulation setup.
- [x] MIPS is not advertised as release-supported; its hosted QEMU lanes perform
  headless export, validation, and GDB behavior checks.
- [x] Test logs expose exact Ghidra/libdwarf/tool versions.
- [x] Native crashes are clearly reported as failures.
- [x] Artifacts/transcripts are retained for failed runs.

## P2.13 Produce installable releases

**Status:** `[~]` — deterministic CI artifacts, packaged Linux/Windows natives,
clean-install exports, checksums, operating documentation, third-party
notices, corresponding-source packaging, and hosted verification are
implemented. Official GitHub Release publication remains separate.

### Work

- [x] Define semantic versioning/release policy.
- [x] Build Ghidra extension ZIPs reproducibly.
- [x] Include native checksums, provenance, third-party notices, and exact
  corresponding source.
- [x] Publish support matrix and known limitations.
- [x] Add installation, run, GDB loading, and troubleshooting instructions.

### Completion criteria

- [x] Release artifact can be installed without compiling libdwarf locally.
- [x] Clean Linux and Windows CI environments export a documented fixture.
- [x] Release documentation identifies supported Ghidra/Java/host/target combinations.
- [x] Checksums and provenance are included in the artifact.
- [x] No generated build directory is required from the source tree.

---

# P3 — Later features after the core is correct

## P3.1 Investigate `.debug_frame`

**Status:** `[x]` — ADR-0002 concludes that the current exporter must rely on
the original ELF's unwind metadata and must not synthesize unsupported CFI.
**Corresponds to:** issue #8.

### Questions

- Does the original target already contain sufficient `.eh_frame`/unwind information?
- Can Ghidra provide reliable CFI data?
- Would synthetic frame information improve variable evaluation or risk corrupt unwinding?

### Completion criteria

- [x] Written decision explains why `.debug_frame` is not required for the
  current ELF milestone.
- [x] No synthetic CFI is emitted without an evidence-backed generation model.
- [ ] If implemented, unwind tests across call stacks pass on every supported architecture.

## P3.2 Improve string/form policy

**Status:** `[x]` — deterministic `DW_FORM_strp`/`.debug_str` output passes the
full hosted target/Windows structural and behavior matrix. Issue #9 was closed
after merge and post-merge validation.
**Corresponds to:** issue #9.

### Work

- Decide when to use inline `DW_FORM_string`, `.debug_str`/`DW_FORM_strp`, and DWARF 5 indexed forms.
- Favor correctness and validator compatibility before size optimization.

### Completion criteria

- [x] Form policy is documented and deterministic.
- [x] `.debug_str` is emitted when selected and all offsets validate.
- [x] Issue #9 was closed only after structural tests passed.

## P3.3 Add richer scopes and declarations

**Status:** `[ ]`.

Potential features:

- Lexical blocks.
- Namespaces/classes.
- Thunks/aliases with specification/origin relationships.
- Static locals.
- Artificial variables.
- Declaration-only DIEs.

Do not begin until the type/location core is stable.

## P3.4 Investigate reconstructed inlining

**Status:** `[ ]` — **UNCERTAIN**.

Do not emit `DW_TAG_inlined_subroutine` based on weak guesses. Establish whether Ghidra provides defensible inline-call reconstruction and whether GDB behavior improves.

## P3.5 Add optional size/performance features

**Status:** `[ ]`.

Potential features only after correctness:

- `.debug_names` or GDB index generation.
- DWARF section compression.
- String/address indexing.
- Incremental/cached export.
- Parallel decompilation with bounded resource use.
- Large-firmware memory/performance profiling.

### Completion criteria

- [ ] No optimization changes semantic output.
- [ ] Determinism and validators remain passing.
- [ ] Benchmark demonstrates a measured benefit.

---

# 2. Issue reconciliation checklist

Use the following acceptance gates before updating the original GitHub issues:

## Issue #1 — output directory

- [x] Production export defaults next to `Program.getExecutablePath()`.
- [x] Missing/stale/unwritable paths fail before publication or use an explicit
  headless input/output path; the GUI chooser is present but separately tracked
  as an interactive verification item under P2.7.
- [x] Atomic pair behavior is tested on Linux and Windows.
- [x] GUI and headless path behavior is documented.

## Issue #2 — `.dbg` naming

- [x] Production export uses `<executablePath>.dbg`.
- [x] Naming is tested across Linux and Windows paths.
- [x] The named sidecar passes structural validators and GDB behavior tests.

## Issue #3 — `.dbg.c` naming

- [x] Production export uses `<executablePath>.dbg.c`.
- [x] Deterministic source, controlled decompiler failure, cancellation, and
  pair-publication rollback pass integration tests.
- [x] `.debug_line` references the exact final name.

## Issue #4 — `.debug_aranges`

- [x] Issue is historically closed and prototype calls arange generation.
- [x] The redesigned exporter deliberately omits this optional accelerator;
  regression tests require its absence and verify CU/subprogram
  `DW_AT_ranges` address correctness instead.

Do not reopen/close solely from this checklist; use project/user direction.

## Issue #5 — `.debug_info`

- [x] Production CU/subprogram DIEs exist.
- [x] Current supported functions/types/variables/ranges validate across the
  hosted target matrix.
- [x] GDB behavior passes for every claimed target profile.

## Issue #6 — `.debug_abbrev`

- [x] libdwarfp produces abbreviations for the production DIE set.
- [x] Current full DIE-set abbreviations validate across the hosted matrix.
- [x] No stale or invalid form combination is accepted by the validators.

## Issue #7 — `.debug_line`

- [x] Structured source map for contiguous functions.
- [x] Valid DWARF 5 line table for the current supported path.
- [x] GDB `list`/`next` acceptance.

## Issue #8 — `.debug_frame`

- [x] ADR-0002 records the requirement/design investigation.
- [x] Synthetic CFI is deferred unless reliable instruction-range unwind
  evidence and cross-architecture behavior tests become available.

## Issue #9 — `.debug_str`

- [x] String/form policy is documented and deterministic.
- [x] Section/offset validation passes across the hosted matrix.

---

# 3. Required command checklist for each generated fixture

The exact commands may be wrapped by the test harness, but equivalent checks must run.

```bash
sha256sum <binary>

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

sha256sum <binary>
```

Unavailable tools must be reported as unavailable; they must not be marked passed.

GDB script, once P0.8 selects the loading strategy, must assert at least:

```gdb
set pagination off
info functions
break <recovered-function>
list <recovered-function>
ptype <recovered-type>
print <supported-variable>
next
step
quit
```

Add target-specific load/run commands and machine-checkable expectations for addresses, source lines, types, and values.

---

# 4. The next Codex session should start here

Unless the user changes priorities, begin with this bounded sequence:

1. Inspect `git status`, all three handoff files, current source, workflow, and historical crash log.
2. Propose/select the exact Ghidra and Java baseline; do not silently choose one if compatibility consequences are material.
3. Pin a specific libdwarf revision and capture its headers.
4. Generate or manually audit a fixed-width JNA binding in a standalone module.
5. Build the isolated producer smoke test.
6. Prove producer init/create/transform/get-sections/finish on Linux before invoking corrected bindings inside Ghidra.
7. Add the first tiny x86-64 non-PIE fixture and validator harness.
8. Produce an ELF packaging experiment/decision record before adding `.debug_line`, types, or variables.

The first valuable checkpoint is a safe, reproducible, validator-clean symbol-only sidecar—not a broad but unverified feature set.
