# Cortex-M debugging profile — issue #120

**CONFIRMED compiler reference and uncurated export structure; Forge debugger
behavior unverified.** The standalone firmware ELF runs under system QEMU and
passes the GDB checks below. A fresh stripped import using the selected Ghidra
language exports five automatically discovered functions without a native crash;
GNU, LLVM and pinned libdwarf validators report no errors. The untouched input
hash is preserved. This does not establish a supported Forge target profile.
Implementation follows the completed
[call-site work, PR190](https://github.com/zwilcox/GhidraDwarfForge/pull/190).

## Selected baseline

- Cortex-M3, ARMv7-M, little-endian, Thumb-only, no FPU or TrustZone.
- QEMU 8.2.2 `lm3s6965evb`: 256 KiB flash at zero and 64 KiB SRAM at
  `0x20000000`. Initial MSP is `0x20010000`; the fixture's PSP starts at
  `0x2000f000`.
- GNU Arm Embedded GCC 13.2.1 (`13.2.rel1`), base AAPCS, freestanding,
  `-mcpu=cortex-m3 -mthumb -mfloat-abi=soft`; binutils 2.42 and GDB 15.1.
- Ghidra 12.0.3, intended `ARM:LE:32:Cortex` / `default`, Java 21.
  Actual imported context, language agreement and exporter behavior remain
  to be verified. Generic ARM support alone is insufficient evidence.

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

## Remaining acceptance

The first uncurated import did not discover the SVC handler path or typed
globals. Fixture curation must explicitly supply those known functions, types
and vector entries, then verify the actual saved program and exported artifact.
The initial discovery artifact is structural evidence only.

1. Validate the original ELF attributes and Ghidra context against the selected
   profile; reject incompatible ARM-state and unsupported extensions.
2. Import the stripped ELF, curate meaningful functions/types/storage, export
   through the production package, and repeat the debugger checks with Forge
   symbols and synthetic source. Omit uncertain variable locations.
3. Independently check vectors, flash load addresses, RAM addresses, code/data
   distinctions, even instruction addresses and tagged function pointers.
4. Repeat the bounded exception scenario using Forge output and document actual
   handler/stack/unwind limitations without claiming compiler-CFI equivalence.
5. Keep this ELF harness independent of raw input. Issue #119 is still open;
   add its raw counterpart when explicit raw-firmware export is available.
6. Add GNU/pinned validators, deterministic repeated Forge export,
   original/saved-program preservation, failure/cancellation controls and a
   required system-QEMU CI lane. Preserve the existing ARM-state matrix.
