# GhidraDwarfForge

Hammering debug sections straight into your ELF.

GhidraDwarfForge is being rebuilt as a Ghidra 12.0.3 extension that exports
recovered program knowledge to a separate DWARF debug artifact and deterministic
synthetic C source. The original executable remains unchanged by default.

## Current status

The installable extension now exports deterministic synthetic C and DWARF 5
functions, source rows, canonical recursive types, signatures, globals,
namespaces, discontiguous ranges, and evidence-backed variable locations.
Hosted end-to-end validation passes on x86-64, AArch64, ARM32, and MIPS32
big/little endian for non-PIE executables, PIE, shared objects, and inputs
without section headers. Native/QEMU GDB tests cover source stepping, types,
globals, stable registers, changing stack locations, composites, and honest
unavailable variables. Explicitly rebased Ghidra projects normalize back to
ELF link-time addresses.

Export remains an explicit operation. Installable CI bundles include verified
Linux x86-64 and Windows x86-64 native libraries; the packaged headless
wrappers select them automatically. The Windows-hosted ELF lane passes native,
publication/file-lock, real-export, and structural validation tests; ELF/GDB
execution remains in Linux native/QEMU lanes. PE/PDB is out of scope. Imports
and thunks are diagnosed and omitted, and distinct linkage-name emission
remains unresolved.

## Build

Ghidra 12.0.3 requires Java 21-compatible bytecode and Gradle 8.5 or newer.
Set the installation path and use the repository wrapper:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC
./gradlew clean buildExtension
```

The extension ZIP is written to `dist/`.

CI additionally assembles the versioned Linux/Windows bundle documented in
[`docs/RELEASE.md`](docs/RELEASE.md). That bundle installs without compiling
libdwarf locally. Official release publication and licensing work are deferred.

## Headless entry point

The extension packages Bash and PowerShell headless wrappers under `support/`.
For a fresh temporary import on Linux:

```bash
support/ghidra-dwarf-forge-headless \
    --ghidra-dir=/path/to/ghidra_12.0.3_PUBLIC \
    --import=/path/to/program.elf \
    --output=/path/to/program.elf.dbg
```

To export curated analysis without modifying the Ghidra project, select an
existing project and program:

```bash
support/ghidra-dwarf-forge-headless \
    --ghidra-dir=/path/to/ghidra_12.0.3_PUBLIC \
    --project-dir=/path/to/projects --project-name=Firmware \
    --program=/folder/program
```

The PowerShell equivalent is `support/ghidra-dwarf-forge-headless.ps1` with
`-GhidraDirectory`, `-Import`, `-ProjectDirectory`, `-ProjectName`, `-Program`,
`-Input`, `-Output`, and `-Log` parameters. `-Libdwarf` and `-Libdwarfp` are
optional paired overrides for development builds.

Exit `0` means the export completed as either `SUCCESS` or `PARTIAL`; inspect
the schema-versioned JSON report for semantic omissions. Exit `10` means
`FATAL`, `11` means `CANCELLED`, `12` means Ghidra failed or omitted a valid
report, and `64` means invalid wrapper arguments. Existing-project mode always
uses `-readOnly -noanalysis` and never deletes or saves the project.

The underlying `GhidraDwarfForge.java` script remains available from Ghidra's
Script Manager or directly through `analyzeHeadless`. With no arguments it
reports target metadata without loading native code. Its opt-in export accepts:

```text
--libdwarf=/absolute/path/libdwarf.so.2.3.2
--libdwarfp=/absolute/path/libdwarfp.so.2.3.2
--packaged-natives
--input=/optional/path/to/original-when-Ghidra-path-is-stale
--output=/optional/path/to/binary.dbg
```

Choose either `--packaged-natives` or the two explicit native paths. The
installed wrappers pass `--packaged-natives` by default and verify the bundled
file set and SHA-256 manifest before the exporter loads it.

With no `--output`, the exporter writes `<original>.dbg` and
`<original>.dbg.c` beside the original ELF. Headless mode fails with a clear
instruction when that location is unavailable; an opt-in GUI invocation offers
a directory chooser. An explicit `--input` must match the executable SHA-256
recorded at Ghidra import. The original executable is never modified by this
workflow.

For automatic GDB association without modifying the executable, a sidecar may
be installed under the standard `.build-id/xx/rest.debug` tree for its copied
build ID. Local integration proves discovery and rejects a sidecar carrying a
different image's build ID. The exporter does not yet install this layout
automatically. Inputs without build IDs make no identity claim and remain
supported through explicit `symbol-file` loading.

## Required integration matrix

The first supported release requires end-to-end pipeline lanes for x86-64 and
AArch64 targets. Both lanes must run headless Ghidra export, independent
ELF/DWARF validation, and scripted GDB behavior checks. The AArch64 lane may use
a native ARM64 worker or documented emulation; cross-compilation alone does not
count as an integration pass.

The architecture is intentionally broader than those first release gates.
ARM32/AArch32 now has a hosted end-to-end ARMv7 hard-float, little-endian
ARM-state lane. MIPS is explicitly in scope as the first ELF32/big-endian
target. Architecture-specific ABI and register mappings remain isolated and
table-driven so additional Ghidra-supported ELF processors can follow. Thumb,
big-endian ARM, and other ARM ABI profiles are not yet claimed.

CI has Linux lanes for x86-64, AArch64, ARM32, and both MIPS byte orders, plus
a Windows-hosted x86-64 ELF export lane. Linux runs real headless export,
independent DWARF validators, input-hash preservation, deterministic reruns,
and native/QEMU GDB behavior for non-PIE, PIE, shared, and no-section-header
inputs. The complete P2.12 matrix and ARM32 target lane passed on GitHub-hosted
runners on 2026-09-03.

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the exact local commands,
validator results, and scope boundaries.
