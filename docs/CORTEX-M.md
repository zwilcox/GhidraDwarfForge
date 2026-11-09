# Cortex-M debugging profile — issue #120

**CONFIRMED local curated runtime; full profile acceptance pending.** The
compiler reference and a fresh stripped/curated Ghidra import pass the selected
QEMU/GDB checks. Production exports preserve eight functions and eleven globals;
GNU, LLVM and pinned libdwarf validators report no errors. Repeated sidecar/source
bytes match, and firmware, all saved-project files and installed-package hashes
remain unchanged. Explicit profile checks and eight rejection/cancellation
controls also pass locally. Required CI integration and independent runtime
mutation controls remain outstanding. See the initial [runtime receipt](evidence/cortex-m-runtime.json)
and the subsequent [profile and failure receipt](evidence/cortex-m-profile.json).
Implementation follows the completed
[call-site work, PR190](https://github.com/zwilcox/GhidraDwarfForge/pull/190).

## Selected baseline

- Cortex-M3, ARMv7-M, little-endian, Thumb-only, no FPU or TrustZone.
- QEMU 8.2.2 `lm3s6965evb`: 256 KiB flash at zero and 64 KiB SRAM at
  `0x20000000`. Initial MSP is `0x20010000`; the fixture's PSP starts at
  `0x2000f000`.
- GNU Arm Embedded GCC 13.2.1 (`13.2.rel1`), base AAPCS, freestanding,
  `-mcpu=cortex-m3 -mthumb -mfloat-abi=soft`; binutils 2.42 and GDB 15.1.
- Ghidra 12.0.3, `ARM:LE:32:Cortex` / `default`, Java 21.
  The curated import verifies Thumb context at every decoded function
  instruction. Production exports and the debugger checks below pass locally;
  incompatible ELF attributes and ARM-state contexts are rejected by the explicit profile.

## Explicit profile selection

Use `--target-profile=cortex-m3` in the export script or Linux headless wrapper
(`-TargetProfile cortex-m3` in PowerShell). Ordinary ARM exports retain their
existing behavior. The selected profile requires ELF32 little-endian ET_EXEC,
System V EABI5 base PCS, explicit v7/M build attributes and Thumb permission.
It rejects declared ARM-state use, other cores, FPU/SIMD/DSP and other unsupported
extensions, ambiguous/missing attributes and a mismatched Ghidra language/compiler.
Every existing function entry and decoded instruction must have an even code
address and known Thumb context. It does not alter addresses or repair context.

These checks validate metadata and existing analysis, not every possible opcode
or the hardware connected to GDB. They do not establish board configuration,
whole-program instruction coverage, TrustZone support or exception unwinding.
Software floating-point arithmetic is not treated as hardware FPU use. Attribute
semantics follow [Arm addenda32](https://github.com/ARM-software/abi-aa/blob/2025Q1/addenda32/addenda32.rst).
The initial profile deliberately requires attributes; sectionless ELF can still
use the ordinary exporter, without claiming this validated profile.

The local tests cover 95 ELF/profile checks and actual Ghidra language/context
controls, including a decoded ARM instruction outside any function. Existing
ARM call-policy tests still pass all 3,880 checks after sharing the bounded
attribute parser. Packaged tests reject contradictory function context and
cancel during profile observation, native DWARF production and ELF writing,
each with absent outputs and an existing pair. No partial files replace the
pair; a successful retry produces identical bytes. All saved-project files and
the original firmware remain unchanged.

## Compiler-reference checkpoint

The source-built fixture has an actual vector table at flash address zero,
separate RAM `.data` with a flash load address, `.bss`, and distinct thread
stacks. Reset copies initialized data and clears a debugger-seeded BSS value.
GDB verifies the initial SP/PC/xPSR, pre-execution Thumb disassembly, the odd
function-pointer value, named and address breakpoints, `next`/`step`, an integer
parameter, a stack local, and initialized/uninitialized globals.

Two SVC exceptions exercise thread execution on MSP and PSP. The oracle
independently checks the hardware frame, return PC/xPSR, EXC_RETURN values
`0xfffffff9`/`0xfffffffd`, handler use of MSP, and successful return to thread
mode. GDB's compiler-reference backtraces contain the signal-frame transition
and the respective thread function. This does not establish Forge exception
unwinding, arbitrary interrupts, nested exceptions or floating-point contexts.

The curated Forge run also passes reset, offline Thumb disassembly, typed
function pointers, synthetic-source `next`/`step`, globals and the stack local.
It exposes the proven input register until overwritten, then correctly reports
the parameter unavailable. The handler's overwritten `number` argument is also
unavailable. Both SVC runs verify stack selection, hardware frames and return.
**Forge's exception backtrace currently stops at the handler:** one frame versus
four with compiler DWARF. The oracle checks every reported frame against the
compiler reference and does not invent the missing frames.

Expected exporter diagnostics retain one decompiler `undefined4` type as
opaque and omit overwritten parameter-register ranges. Call-site metadata is
outside the validated Cortex-M ABI, and debugger-injected calls through the
function-pointer type remain disabled because its calling convention is
unresolved. The tests execute the firmware's own indirect calls; they do not
claim GDB-injected calls. These are explicit limits, not validator failures.

Run with the compiler toolchain on `PATH`:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 src/test/integration/cortex-m-reference.py \
    --results "$PWD/.forge-work/scratch/cortex-m-reference"
```

The harness retains versioned commands, ELF attributes/disassembly, LLVM
verification, input/source hashes and GDB observations. QEMU's board-init
warnings about an unconnected Ethernet peripheral and a zero-period timer are
recorded; the fixture uses neither peripheral. The harness terminates its own
non-exiting emulator after the final breakpoint.

To validate the installed exporter, pass the resulting reference directory:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 src/test/integration/cortex-m-export.py REFERENCE_DIRECTORY \
    --ghidra "$GHIDRA_INSTALL_DIR"
```

The export harness opens the saved program through a genuinely read-only
project view and invokes the installed production script. Ghidra's ordinary
headless `-readOnly` process mode still opens the project container writable
and rotates backup files; the strict preservation check rejected that path.
The harness uses fresh temporary Ghidra settings within each run. Reproducible
package timestamps otherwise allowed an older compiled script cache to survive
a local package replacement. The temporary settings are removed on exit.

## Remaining acceptance

The first uncurated import did not discover the SVC handler path or typed
globals. Fixture curation explicitly supplies source-known function extents,
signatures and global types. ELF Thumb/data mapping symbols exclude literal
pools from bodies; unvisited mapped Thumb padding is decoded explicitly.
Production export does not perform these fixture-only repairs.

1. Carry the passing explicit profile checks and incompatible ARM-state/extension
   rejection tests into required CI; review their documented limits.
2. Preserve the passing stripped/curated production export and debugger
   coverage in the required hosted lane. Add negative runtime controls.
3. Independently check vectors, flash load addresses, RAM addresses, code/data
   distinctions, even instruction addresses and tagged function pointers.
4. Preserve the passing bounded exception scenario and the documented handler
   unwind limit without claiming compiler-CFI equivalence.
5. Keep this ELF harness independent of raw input. Issue #119 is still open;
   add its raw counterpart when explicit raw-firmware export is available.
6. Add a required system-QEMU CI lane using the passing failure/cancellation,
   structural, deterministic and preservation checks. Preserve the existing
   ARM-state matrix.
