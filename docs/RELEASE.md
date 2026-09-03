# Release policy and installation

## Versioning

GhidraDwarfForge uses Semantic Versioning. `VERSION` is the single source for
the project version. Before 1.0, a minor-version change may change the exporter
or report contract, while a patch changes behavior compatibly. Pre-release
identifiers mark artifacts that are not yet a stable release.

The installable archive is named:

```text
GhidraDwarfForge-<version>-ghidra-12.0.3.zip
```

Ghidra compatibility remains recorded separately in `extension.properties`.
The initial host packages are Linux x86-64 and Windows x86-64. The required
target release lanes are x86-64 and AArch64 ELF; ARM32 and MIPS32 big/little
endian have additional hosted validation but remain narrower, explicitly
documented target profiles rather than blanket architecture claims. PE/PDB,
Mach-O/dSYM, macOS hosts, Windows on ARM, Thumb, and big-endian ARM are not
supported by this release line.

## Reproducible assembly and provenance

CI builds libdwarf/libdwarfp v2.3.2 from the pinned upstream archive for Linux
and Windows. It then combines those artifacts with the Ghidra extension base
ZIP using `support/assemble-release.sh`. Assembly normalizes ZIP timestamps and
ordering, runs twice, and requires byte-identical results.

Every platform directory contains:

- `BUILD-METADATA.txt` with source, toolchain, dependency, and build details;
- `NATIVE-PAIR.properties` identifying the exact consumer and producer;
- `SHA256SUMS` covering every packaged native and metadata file.

The extension root contains `RELEASE-MANIFEST.txt` and
`RELEASE-SHA256SUMS`. The exporter verifies the selected platform manifest and
every packaged file before native code is loaded. CI also checks all manifests
after assembly.

The release root also contains `THIRD_PARTY_NOTICES.md`. The
`third_party/libdwarf/` directory contains the complete LGPL 2.1 text,
upstream copyright/copying notices, the exact checksummed libdwarf 2.3.2 source
archive, and the patch applied by CI. `third_party/CORRESPONDING_SOURCE.md`
records the exact reconstruction commands and modified-library override path.
Windows zlib and Zstandard package versions and license files are retained
under `third_party/windows-runtime/`. All of these files are covered by
`RELEASE-SHA256SUMS`; their nested manifests are also verified during
assembly. Ghidra and JNA are documented host dependencies and are not bundled
by this release.

Publication of an official GitHub Release remains a separate release-manager
operation. CI output is a validated release candidate until it is published.

## Install

1. Install Ghidra 12.0.3 with a Java 21-compatible runtime.
2. Extract the release ZIP into `<ghidra>/Ghidra/Extensions` so the resulting
   directory is `<ghidra>/Ghidra/Extensions/GhidraDwarfForge`.
3. Restart Ghidra if it was open.

No local libdwarf compiler or separate native download is required. On Linux:

```bash
<ghidra>/Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless \
    --ghidra-dir=<ghidra> \
    --import=/path/to/program.elf
```

On Windows PowerShell:

```powershell
& <ghidra>\Ghidra\Extensions\GhidraDwarfForge\support\ghidra-dwarf-forge-headless.ps1 `
    -GhidraDirectory <ghidra> `
    -Import C:\path\to\program.elf
```

The original ELF is never modified. The default outputs are
`<program>.dbg` and `<program>.dbg.c`. Explicit `--libdwarf`/`--libdwarfp`
or `-Libdwarf`/`-Libdwarfp` pairs remain available for developer audit builds.

Load the result in GDB with:

```gdb
file /path/to/program.elf
set auto-solib-add off
symbol-file /path/to/program.elf.dbg
```

## Troubleshooting

- A packaged-native checksum or file-set failure means the installation is
  incomplete or modified. Re-extract a verified release ZIP.
- An unsupported-host error means the installed archive has no native pair for
  that Ghidra host. Cross-target ELF output does not change the host library
  requirement.
- Exit `10` is a reported fatal export, `11` is cancellation, `12` is a Ghidra
  or report-contract failure, and `64` is wrapper usage error.
- Inspect the JSON report and preserve the headless `--log`/`-Log` transcript
  when reporting a problem.
