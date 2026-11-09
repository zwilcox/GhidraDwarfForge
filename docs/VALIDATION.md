# Validation guide

Validate the installed exporter and its debugger behavior, not only whether an
output file was created. The original ELF and saved Ghidra knowledge must remain
unchanged, and unsupported values must remain unavailable.

## Baseline and authoritative commands

The supported build baseline is Ghidra 12.0.3 with Java 21-compatible bytecode.
The Gradle wrapper and native dependency pins are recorded in the repository.
See [release assembly and installation](RELEASE.md), the
[native ABI audit](LIBDWARF-ABI.md), and the
[tested target profiles](TARGET-PROFILES.md).

The [required workflow](../.github/workflows/ci.yml) is the authoritative list of
commands, target variants and dependencies. Use its exact fixture options when
reproducing a lane; a default invocation of one harness does not reproduce the
whole matrix. Native build provenance lives in
[native/libdwarf/PROVENANCE.md](../native/libdwarf/PROVENANCE.md), and independent
checker pins and patches live in
[support/validation](../support/validation/README.md).

A local extension build uses:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC
./gradlew --no-daemon buildExtension
```

The base extension ZIP appears in `dist/`. Follow the release guide to assemble
and install the native-inclusive package used by integration tests. Building
Java alone does not validate the native producer or packaged exporter. Follow
local workspace/resource limits when running builds and tests.

## Structural validation

For each emitted sidecar, retain the commands, exit statuses and full validator
output. Replace the example paths below with the original and generated files.

```bash
readelf -h /path/to/program
readelf -S /path/to/program
readelf -n /path/to/program
readelf -h /path/to/program.dbg
readelf -S /path/to/program.dbg
readelf -n /path/to/program.dbg
readelf --debug-dump=info /path/to/program.dbg
readelf --debug-dump=abbrev /path/to/program.dbg
readelf --debug-dump=aranges /path/to/program.dbg
readelf --debug-dump=decodedline /path/to/program.dbg
llvm-dwarfdump --verify /path/to/program.dbg
python3 src/test/integration/check-dwarfdump.py \
    /path/to/program.dbg /path/to/evidence/dwarfdump.txt \
    --tool "$DWARFDUMP" --original /path/to/program
```

`DWARFDUMP` must name the independently built checker selected by the workflow,
not an arbitrary executable with the same name. Compare ELF class, byte order,
machine, ABI flags, build identity and address metadata with the original.
The [sidecar design](ADR-0001-ELF-SIDECAR.md) explains which original metadata is
preserved and which debug/index sections are replaced.

A warning or zero exit status is not automatically acceptable. The checker
harness permits inherited compiler-frame diagnostics only when independently
corroborated against the original artifact. Retain the complete raw checker
report separately from wrapper output; the workflow's retained-report checks
reject missing, overwritten, truncated or mismatched evidence.

## Debugger behavior

The explicit GDB loading workflow is:

```gdb
file /path/to/program
set auto-solib-add off
symbol-file /path/to/program.dbg
info functions
break recovered_function
run
list recovered_function
ptype recovered_type
print available_variable
next
step
```

Substitute fixture names and use the appropriate native or QEMU runtime. PIE and
shared objects require the measured load mapping; use the
[GDB companion](GDB-LOADER.md) and workflow-selected loader harnesses rather than
assuming a fixed runtime address. [Build-ID installation](BUILD-ID-INSTALLATION.md)
and [debuglink attachment](ATTACHMENT-HELPER.md) are explicit optional workflows.

Compare compiler and Forge observations at meaningful instruction boundaries.
Check both correct available values and required unavailable gaps, source lookup
from another working directory, discontiguous ranges, rebased analysis and
unchanged original hashes. [Debugger consumer notes](DEBUGGER-CONSUMERS.md)
distinguish GDB and LLDB coverage and limitations.

## Required integration coverage

The workflow builds native libraries on Linux and Windows, audits their ABI,
assembles reproducible packages and runs the actual installed exporter. Target
lanes include x86-64, AArch64, ARM32 and both MIPS32 byte orders; each advertised
additional ABI/profile requires its own evidence. Windows-host export does not
establish a Windows target ABI or native Windows execution of ELF fixtures.

Feature-specific acceptance maps retain requirements, test names and limits:

- [Function signatures and aliases](P17-ACCEPTANCE.md)
- [Target ABI profiles](TARGET-ABI-ACCEPTANCE.md)
- [Variable lifetimes and scopes](LIFETIME-SCOPE-ACCEPTANCE.md)
- [Unwind information](UNWIND-ACCEPTANCE.md)
- [Multi-file synthetic source](MULTIFILE-ACCEPTANCE.md)
- [Coverage scorecards](COVERAGE-ACCEPTANCE.md)
- [GDB loading](GDB-LOADER-ACCEPTANCE.md),
  [debuglink attachment](DEBUGLINK-ATTACHMENT-ACCEPTANCE.md), and
  [build-ID installation](BUILD-ID-ACCEPTANCE.md)
- [Performance](PERFORMANCE-ACCEPTANCE.md)

Run applicable failure, cancellation, rollback, malformed-input, stale-input
and deterministic-repeat controls alongside positive fixtures. A native crash,
unexplained diagnostic, missing required lane or skipped assertion is not a pass.
The protected `required-validation` check must pass on the revision being merged.

## Retained evidence

Retain concise reports, source/tool/package hashes and CI links. Keep large
fixtures and raw artifacts only within the agreed workspace/evidence budgets.
Target artifacts named `target-preflight-<target>` contain
`target-preflight.tar.gz` inside the GitHub artifact ZIP. Extract on Linux: some
intentional fixture names are invalid Windows filenames. Preserve member paths,
hidden generation directories and links; archives alone do not prove filesystem
ACLs, extended attributes or runtime identity.

Current [evidence receipts](evidence/) and feature acceptance documents establish
specific tested revisions and scopes. They are not blanket proof for later code.
