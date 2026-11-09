# Cortex-M debugging profile — issue #120

**CONFIRMED local curated runtime; full profile acceptance pending.** The
compiler reference and a fresh stripped/curated Ghidra import pass the selected
QEMU/GDB checks. Production exports preserve eight functions and eleven globals;
GNU, LLVM and pinned libdwarf validators report no errors. Repeated sidecar/source
bytes match, and firmware, all saved-project files and installed-package hashes
remain unchanged. Profile rejection, failure/cancellation controls and required
CI integration remain outstanding. See the [local receipt](evidence/cortex-m-runtime.json).
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
  incompatible-profile rejection still needs validation.

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

## Remaining acceptance

The first uncurated import did not discover the SVC handler path or typed
globals. Fixture curation explicitly supplies source-known function extents,
signatures and global types. ELF Thumb/data mapping symbols exclude literal
pools from bodies; unvisited mapped Thumb padding is decoded explicitly.
Production export does not perform these fixture-only repairs.

1. Validate the original ELF attributes and Ghidra context against the selected
   profile; reject incompatible ARM-state and unsupported extensions.
2. Preserve the passing stripped/curated production export and debugger
   coverage in the required hosted lane. Add negative runtime controls.
3. Independently check vectors, flash load addresses, RAM addresses, code/data
   distinctions, even instruction addresses and tagged function pointers.
4. Preserve the passing bounded exception scenario and the documented handler
   unwind limit without claiming compiler-CFI equivalence.
5. Keep this ELF harness independent of raw input. Issue #119 is still open;
   add its raw counterpart when explicit raw-firmware export is available.
6. Add failure/cancellation controls and a required system-QEMU CI lane using
   the passing structural, deterministic and preservation checks. Preserve the
   existing ARM-state matrix.
