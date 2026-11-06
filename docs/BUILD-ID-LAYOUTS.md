# Build-ID installation: shared and sectionless inputs

Tracking: #109. **CONFIRMED locally:** production Linux installation is validated
for shared objects and sectionless ET_EXEC on x86-64, AArch64, ARM32, MIPS32
big-endian and MIPS32 little-endian. The receipt is
[build-id-layouts.json](evidence/build-id-layouts.json). This does not complete
Windows, LLDB/perf or hosted/protected acceptance.

## Shared-library automatic discovery

Each target imports/analyzes a newly source-built stripped library, exports it
through the packaged production exporter, and installs it with the public
command and fresh validators. GDB starts with only its selected debug-root,
original driver and ordinary shared-library loading enabled. No symbol-file or
add-symbol-file command is used.

Empty and removed debug-root controls lack full Forge DWARF. With the registered
sidecar present, the oracle checks its exact objfile identity, retained source,
relocated function address, recovered prototype/structure, arguments 19 and 23,
source stepping and global value 42, followed by normal process exit. Old exported
sidecars and sources are absent during every consumer session. The native x86-64
case and four QEMU cases use the same production installer and oracle.

## Sectionless consumer limitation and explicit fallback

All five sectionless inputs have independently checked zero section-table offset,
section count and section-name index. They retain their original build ID. Ten
fresh compiler controls compare otherwise matching sectioned and sectionless
originals: GDB 15.1 discovers the matching compiler-generated DWARF only for the
sectioned original. The Forge installation shows the same behavior.

The harness does not relabel this absence as automatic discovery. An explicit
`--sectionless-discovery-limit` test option requires those compiler controls and
runs the automatic absence and explicit fallback as separate sessions. Without
that option, the automatic discovery assertion still fails. The fallback loads
the installed sidecar with `symbol-file`, then verifies its exact source and
compiler-reference function address, a named breakpoint, source stepping and
normal exit. Ghidra names may be its generated `FUN_<address>` or an actually
recovered `main`; neither possibility relaxes the exact address/sidecar/source
checks.

For the tested fixed-address ET_EXEC inputs:

```gdb
file /path/to/original
set auto-solib-add off
symbol-file /chosen/debug-root/.build-id/xx/rest.debug
```

Use the `registration` path returned by installation. The command now reports
`UNAVAILABLE_IN_TESTED_GDB_FOR_SECTIONLESS_ELF` on sectionless install/update and
explains explicit loading. Retained source stays valid after the former export
directory disappears. Installation never adds section headers to the original.
Sectionless PIE/shared runtime relocation is not established by these ET_EXEC
checks; use the documented Forge loader and a verified runtime load bias for
relocated images rather than assuming fixed addresses.

## Validation and diagnostics

Ten fresh producer exports and all ten final installed artifacts pass their
structural validators. The final package passes 35 layout runtime sessions,
ten static compiler-discovery controls, and the existing command suite's 27
checks/ten additional GDB sessions. Original and selected export bytes remain
unchanged. Package/source hashes and a verified raw archive bind the evidence.
Every exporter class/resource is byte-identical between the export package and
final package; only the standalone helper's consumer diagnostic changed.

ARM32 and AArch64 QEMU emit a system-supplied DSO string-table-index warning even
with an empty debug root and no Forge symbols. The oracle retains that independent
baseline and requires the same exact warning in positive/removed sessions; it
rejects other diagnostics. This is not a Forge DWARF validator warning.

The workflow now builds independent fixture copies, performs fresh headless
exports and invokes these tests on every target lane. Its hosted result remains
**PRESENT, UNVERIFIED** until the updated required gate passes.
