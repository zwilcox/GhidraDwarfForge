# ARM/Thumb instruction-mode evidence

**CONFIRMED local limitation:** the accepted exporter can recover a Thumb
function and produce validator-clean DWARF while GDB disassembles it as ARM
before execution. The existing supported ARMv7 hard-float profile is ARM state;
this investigation does not expand that claim.

## Reproduction

The owned mixed-mode ELF32 little-endian ET_EXEC fixture has an ARM caller and
a Thumb function, compiled separately with GCC 13.3 using `-marm` and `-mthumb`.
Both use ARMv7-A, VFPv3-D16 hard float, DWARF 5, `-O0`, frame pointers and unwind
tables. The caller invokes the function directly with 12 and 7, then through
a volatile function pointer with 19 and 3. The expected global values are 19
and 22; the process exits successfully.

The compiler reference retains its symbols and DWARF. The actual Ghidra input
is a separate `--strip-all` copy with no build ID. A preparation script renames
already decoded functions and applies types; it does not create functions,
disassemble bytes or set instruction context. Ghidra 12.0.3 observes `TMode=1`
for all 19 instructions in the Thumb function. Its code entry is `0x104f0`;
the compiler's ELF function symbol and function pointer have value `0x104f1`.

Using accepted exporter JAR `d983a2989178cdc8503b90d92dbcf1bbddd1251fed5b7805ab6e2a31f5a5e395`:

- Independent LLVM 18.1.3 and strict libdwarf 2.3.2 validation passes with no
  unexplained diagnostics.
- GDB 15.1 with QEMU 8.2.2 passes separate named and exact-entry breakpoint
  sessions, direct and indirect calls, source stepping, values and normal exit.
- Before execution, compiler-reference disassembly shows 19 Thumb
  instructions. Selecting the Forge sidecar shows 11 ARM words instead,
  including undefined instructions. Neither session forces the instruction mode.
- Re-exporting the saved Ghidra program produces identical sidecar and source
  bytes. Input and installed-exporter bytes remain unchanged.

This headless experiment ran on Java 25.0.4.1; it is not a new Java 21 runtime
check. The export reports remain `PARTIAL`, with embedded validation `NOT_RUN`.
The independent validator results above are separate evidence. Three parameter
locations are omitted as `UNASSIGNED`; opaque `undefined` and `undefined4`
types remain represented conservatively.

The successful runtime sessions do not repair or negate the static failure:
the running target's CPSR can supply instruction state. Curated parameters
whose storage remains unassigned are emitted without fabricated locations.

## Consumer and ABI findings

The inspected source package is Ubuntu `gdb 15.1-1ubuntu1~24.04.1`, matching the
installed debugger. Its ARM selector uses ELF mapping symbols and the Thumb
flag on ELF-derived minimal symbols before consulting a running target's CPSR.
The DWARF line interpreter skips `DW_LNS_set_isa`; emitting that opcode alone
would not fix this debugger. An odd DWARF `low_pc` does not create the ELF
minimal-symbol flag. DWARF code addresses and ELF function-pointer tags must
remain separate concepts.

The pinned [Arm ELF ABI](https://github.com/ARM-software/abi-aa/blob/17f2cc8ee6645c1709088f4e0cb4438ce75a14ff/aaelf32/aaelf32.rst)
defines odd values for Thumb `STT_FUNC` symbols. Its `$a`, `$t` and `$d`
mapping symbols describe section intervals through the next mapping symbol or
section end. A guessed mapping marker can therefore misclassify an unknown gap
or neighboring function. The [Arm DWARF ABI](https://github.com/ARM-software/abi-aa/blob/17f2cc8ee6645c1709088f4e0cb4438ce75a14ff/aadwarf32/aadwarf32.rst)
defines line ISA values independently of consumer support.

## Bounded correction

**CONFIRMED owned-copy experiment:** one added `STT_FUNC` entry with the odd
symbol value and exact positive size of 44 bytes repairs all 19 Thumb
instructions without changing existing DWARF or code bytes. A second fixture
places a ten-instruction ARM function immediately after the Thumb body in the
same `.text` section. It still disassembles correctly at the exact Thumb upper
bound and the following instruction. The inspected GDB rejects a positive-sized
minimal symbol outside its range; a zero-size symbol can extend farther.

Compiler, original Forge and corrected-copy sessions all pass a breakpoint set
from a stopped ARM caller under QEMU. The original failure demonstrated here
is static disassembly, not a QEMU breakpoint failure or a native breakpoint
encoding result. GDB's `&function` expression is even in the compiler and Forge
controls, while the stored typed function pointer is odd; these observations
must not be conflated.

**CONFIRMED in hosted run `40138005382`:** the production correction adds synthetic
local ELF function symbols only when an input without a static symbol table
has defensible Thumb evidence. Extraction requires an entry-first contiguous
body, fully known homogeneous instruction context, exact instruction-byte
coverage and positive size. It checks the context saved with Ghidra's decoded
instruction prototype as well as the current per-byte context. The prototype
store does not retain original validity masks. Ordinary Ghidra memory writes
reject existing instructions; clearing them before a patch removes the coverage
required by this check. The byte digest describes current instruction bytes,
not an immutable decoding snapshot.

The isolated ARM planner requires ET_EXEC, the original file bytes to match that
digest, one unambiguous executable section, and no named defined dynamic symbol.
GDB 15.1 suppresses ordinary dynamic symbols whenever a static symbol table
exists, so even a nonoverlapping function or data definition prevents synthesis.
Undefined imports remain supported. Anonymous dynamic code extents also receive
conservative overlap checks.
It preserves existing static symbol tables, diagnoses unsupported or conflicting
cases, and omits mode cues for sectionless inputs. Ordinary sectionless export
continues through its existing path. Synthetic local names are
`__forge_arm_mode_<address>`; their binding describes the generated sidecar
metadata, not original linkage. DWARF keeps the curated function names and
unchanged code addresses. Generic ELF serialization handles the new table and
extended section-index records without interpreting ARM mode bits.

Only selections with a known Thumb entry enable this additional extraction.
This avoids new instruction scanning or diagnostics for ordinary ARM-only
exports; it does not claim to detect every possible mixed-mode body. Relocatable
objects, PIE and shared objects are excluded from this supplemental cue planner.
Their existing DWARF export path remains available.

The initial focused planner/serializer suite passes 132 checks on actual Java 21 with
a 64 MiB heap. The Ghidra extraction suite passes 38 checks on actual Java 21;
its Gradle execution also passes. GNU readelf independently accepts the emitted
ordinary, extended and mixed section-index symbol tables. Existing inherited
debug metadata, extended section numbering, ELF reader and cancellation checks
pass, and the extension builds. The first extraction test had an incorrect
expected guard order; a four-byte Thumb control now reaches the intended stored
context mismatch, with the failed run retained.

The installed production exporter passes the mixed-mode ET_EXEC harness with
synthetic `LOCAL` symbols. Two exports of the same saved program have identical
sidecar, source and report bytes. GNU, LLVM and strict libdwarf checks pass with
no unexplained diagnostics. Four compiler/Forge GDB sessions cover static
disassembly, the same-section ARM boundary, direct and indirect calls, source
stepping, typed global values and an exact-entry breakpoint from a stopped ARM
caller. The unchanged accepted exporter fails the same static-disassembly
assertion after passing its independent validators, providing the regression's
negative control. PR #44 subsequently passes its exact hosted gate and independent
reviews; the distinct main-push gate is tracked separately in `docs/VALIDATION.md`.

No broader Thumb support is accepted yet. PIE,
rebasing, shared objects, mixed state within one function, literal pools and
sectionless Thumb inputs require separate evidence.

### Shared-object regression found by the hosted gate

**CONFIRMED:** the second PR #44 run (`40136340620`, head `5c4f14c`)
exposes a regression in the existing ARM shared-object oracle. Adding a partial
static symbol table for startup-function modes suppresses the shared library's
ordinary dynamic minimal symbols in GDB 15.1. A named breakpoint then also selects
the driver's PLT trampoline, where source stepping fails. Avoiding only dynamic
code overlaps is insufficient.

An owned local export reproduces the failure. A diagnostic copy changes only
the new 40-byte SHT_SYMTAB section-header row to SHT_NULL; every payload byte,
including DWARF and the dynamic symbol table, remains identical. The same driver
and unchanged GDB script then pass. GDB's minimal-symbol dump confirms that the
global `recovered_add` definition returns. This copy is a causal experiment,
not a production artifact. The inspected distro GDB 15.1 source explains the
behavior in `elfread.c`'s stripped/static-table precedence and `linespec.c`'s
PLT filtering.

The correction restricts synthesis to ET_EXEC and rejects all named defined
dynamic rows, including data and absolute symbols outside the selected code.
PIE/shared mode support requires a separately validated design. The corrected
package passes 231 planner checks on actual Java 21, the original Thumb harness,
an owned export-dynamic variant and the unchanged shared-library oracle. Its
exact local evidence and subsequent hosted acceptance are recorded in
`docs/VALIDATION.md`; earlier positive
Thumb evidence does not establish this correction's acceptance.

## Retained local evidence

Evidence is under the ignored directory
`GhidraDwarfForge-worktrees/attachment-replacement-primitives/build/thumb-mode-research/`.
The selected run is `run.ks4iiune`; `compiler-static.stdout` and
`forge-static.stdout` retain the disassembly contrast. `first-comparison.json`
binds the initial exports, repeated output and runtime results. The exact
debugger source and package provenance are in `gdb-source-review/`. The
same-section boundary fixture is `canary.r8del6uo`. Independent reviews
`gui-initial-comparison-review.json` and `gui-cue-review.json` bind the original
failure, appended cue layouts, validators, runtime results and preserved inputs.

An initial test-runner argument error added a literal `+` executable argument
to GDB. Its failed setup evidence is retained separately from the corrected
sessions. The known QEMU vDSO warning is also retained. An initial attempt to
add a symbol with GNU objcopy to the non-loadable sidecar failed with a program
header/load-segment error; it did not create a candidate. None of these failures
is counted as a passing correction.
