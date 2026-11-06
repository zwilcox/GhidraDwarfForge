# LLDB shared libraries and sectionless executables (#110)

**CONFIRMED locally; hosted integration PRESENT, UNVERIFIED.** The source-built
x86-64 and AArch64 fixtures use the same production sidecars consumed by GDB.
This checkpoint adds shared-library runtime loading, rebased shared-library
analysis, and explicit symbol loading for non-PIE sectionless executables.
It does not complete the hosted #110 gate or implement #109 installation.

## Shared-library identity and relocation

`shared-object-lldb.py` launches the original stripped driver and stops at main
after the library is mapped. The library initially has no compilation units;
only then does the harness explicitly add its compiler reference or Forge
sidecar. The LLDB module's selected symbol-file path and UUID must match the
requested artifact and independently read original build ID. The debugger's
function file address must agree with the compiler's ELF symbol table.

Each session requires a nonzero runtime load bias. Named function breakpoints,
address breakpoints at the two stack markers, globals, and source steps must
use the relocated library addresses. Compiler and Forge observations agree on
parameters 19/23, the global's 0-to-42 transition, and stack value 42 before and
after a 16-byte SP change. The Forge register local stays 31 and the unassigned
analyst local remains unavailable. The recursive `list_node` type retains its
pointer relationship. The program must exit normally.

Compiler sources use their deliberate prefix map. Forge gets no source map;
its observed source file must be the exact emitted absolute companion path
while the debugger runs from another directory. The compiler breakpoint skips
the prologue because its stack-parameter descriptions do not contain valid
values at the first instruction. Forge's parameter-entry check instead stops
at the exact function entry. The initial transport-only probe retained those
invalid compiler entry values; it is not used as semantic acceptance evidence.

The same checks pass after Ghidra analysis is rebased by `0x400000`. This is
an analysis-coordinate change, not a runtime slide: emitted addresses are still
normalized to the original ELF, and LLDB independently applies the library's
actual runtime load bias. Baseline and rebased export repeats are byte-identical.

## Sectionless consumer behavior and explicit workflow

`sectionless-lldb.py` verifies that the original is little-endian ELF64 ET_EXEC,
has no section-header table, and retains its program headers. It finds the
reference function entry from the compiler symbol table and its instruction
bytes from an executable `PT_LOAD`. No section-header lookup is used for the
original's code. The x86-64 fixture uses recovered_add; the AArch64 fixture uses
main because Ghidra does not separately recover the tiny recovered_add in that
sectionless input. The Forge names are the actual recovered `FUN_...` names.

**CONFIRMED LLDB 18.1.3 limitation:** directly attaching debug symbols to these
sectionless executables resolves function/source lookup but fails to hit the
named runtime breakpoint. This reproduces with compiler DWARF and Forge DWARF.
Explicitly loading the original module with slide zero did not correct the
compiler case. These failed probes are retained, rather than counted as passes.

The validated workflow adds the debug artifact as a separate symbol module,
stops the process before continuing into the target, and explicitly loads that
symbol module at slide zero. For the selected **non-PIE ET_EXEC** fixtures:

```text
target create /absolute/original
target modules add /absolute/original.dbg
breakpoint set --name FUN_00401136 --skip-prologue false
process launch --stop-at-entry
target modules load --file /absolute/original.dbg --slide 0
continue
```

The function name above is illustrative; use the actual recovered function.
For the AArch64 remote lane, `gdb-remote` supplies the initial stop in place of
`process launch`. Zero slide is not a general recipe for PIE or shared objects.
The executable remains the original sectionless file; the debug module supplies
symbols only. Runtime bytes at the breakpoint must match the original ELF,
the observed frame must select the requested symbol module, source stepping
must change both PC and line, and normal exit and all protected hashes are
required. No target or section table is rewritten to make LLDB accept it.

This is explicit loading, not automatic discovery. The direct-attachment failure
can be reproduced with the test harness's `--loading attached --mode compiler`.
The normal test path uses the validated separate-module workflow.

## Validation and remaining scope

The [evidence receipt](evidence/lldb-elf-layouts.json) binds the installed package,
commands, exact fixtures, raw GNU/LLVM/pinned strict results, GDB transcripts,
LLDB observations and failed experiments. Both targets pass baseline/rebased
shared-library and sectionless tests. All six original/sidecar generations have
byte-identical repeats and unchanged inputs. The six existing GDB sessions
pass as well. Strict inherited-frame diagnostics are individually corroborated
against their original ELF, not ignored.

The CI lanes run these same LLDB harnesses after normal shared and sectionless
exports and again after rebased shared exports. This checkpoint validates
LLDB 18.1.3 on native Linux x86-64 and the recorded QEMU AArch64 transport;
other debuggers/targets/transports are not inferred from it. Sliced-storage
consumer limitations, discovery controls, the final #110 support contract and
hosted/protected integration remain open. #112 integration still precedes full
#110 acceptance, followed by #109.

```bash
python3 src/test/integration/shared-object-lldb.py build/fixtures \
    build/test-results/lldb-shared --target aarch64 --lldb lldb-18
python3 src/test/integration/sectionless-lldb.py build/fixtures \
    build/test-results/lldb-sectionless --target aarch64 --lldb lldb-18
```
