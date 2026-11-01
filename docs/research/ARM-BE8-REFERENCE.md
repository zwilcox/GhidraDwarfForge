# ARM BE8 independent reference

**CONFIRMED reference; exporter support remains PLANNED.** The private GCC 13
ARM hard-float toolchain already used for ARM32 fixtures can build a freestanding
BE8 executable without a big-endian libc. No system packages were installed.
The complete #70 requirements remain unchanged.

Evidence is retained under `build/arm-abi-completion/be8-reference` in the
`work/arm-abi-completion` worktree. `probe.c` defines a volatile unsigned global
`0x11223344` and a non-inlined unsigned function returning its argument plus
that global. `start.S` calls it with 7, checks `0x1122334b`, then performs the
Linux ARM exit syscall. Both files are small source-built research inputs.

The command uses the existing private compiler wrapper:

```bash
"$ARM32_CC" -mbig-endian -march=armv7-a -marm -mfpu=vfpv3-d16 \
    -mfloat-abi=hard -O0 -g3 -gdwarf-5 -fno-pic -fno-pie \
    -nostdlib -nostartfiles -static -no-pie -Wl,--be8 \
    -Wl,--build-id=none -Wl,-e,_start start.S probe.c -o be8.reference
qemu-armeb-static be8.reference
```

Observed ELF identity is ELF32, big-endian data, ARM ET_EXEC,
`e_flags=0x05800400` (EABI5, hard float, BE8). Compilation produced no stderr;
plain QEMU execution produced no output and exited zero. The compiler/GDB
oracle records automatic big-endian data selection, correct function instruction
decoding, typed argument 7, typed global `0x11223344`, actual global memory bytes
`11 22 33 44`, raw return register `0x1122334b` and normal exit. Automatic typed
return display was not proved. The only stderr line is the existing QEMU
synthetic-vDSO BFD warning; it is recorded, not silently discarded.

After stripping all symbols, Ghidra 12.0.3 automatically selected
`ARM:LEBE:32:v8LEInstruction:default` and imported/analyzed successfully. A
read-only production export then failed explicitly before writing final output:
`ARM big-endian producer mode has not been audited`. The original hash remained
unchanged. No native producer call or Forge runtime success is claimed.

Next work must audit the producer/target endianness distinction and actual
Ghidra storage before enabling an isolated BE8 profile. The successful scalar
reference does not establish VFP transfers, aggregate/piece ordering, Thumb,
BE32, PIE/shared loading, or any broad ARM big-endian support. Those required
cases must use source-known runtime values and independent validators, with
versioned fixtures and harnesses before acceptance. The existing reference
scripts, source files, logs and hashes are recorded in `reference-receipt.json`.

## Isolated producer endian audit

**CONFIRMED native-only experiment; production support remains PLANNED:** the
pinned producer's `arm` ISA accepts four-byte target addresses and big-endian
DWARF data. The header declares `DW_DLC_TARGET_BIGENDIAN = 0x08000000`;
`dwarf_pro_init.c` selects byte-swapping independently of the ISA relocation
name. The existing audited JNA declarations were reused without new calls or
signature changes. An ignored copy of `DwarfProducerSmoke` changes only the
ARM32 test profile's little-endian boolean to false, leaving production target
selection and its explicit rejection unchanged.

Using the actual v2 package's Linux native pair and Java 21, all 32 producer
lifetimes pass initialization, DIE creation, transformation, section collection,
relocation-record checks, intentional error callbacks and finish. Section
fingerprints are deterministic; stderr is empty and resident growth is
8,060,928 bytes against the existing 33,554,432-byte bound. The consumer and
producer SHA-256 values are respectively
`613d86accc88ea0fe369b7d6ade0d4fe605a451a7675b0c2453f21b328de81b7` and
`fa82f4524de69634c7301fa5bdd53327aa89040da92c1d086271df51119531ad`.

The source delta, original source hash, compiled class hashes and raw transcripts
are retained in the `arm-mixed-modes` worktree under
`build/arm-mixed-modes/be8-producer-reference/result.json`. This does not emit
an accepted BE8 sidecar or prove variable/return ABI correctness. The next step
remains matched-ELF validation and exact Ghidra data/instruction-endian agreement,
followed by source-known storage/return/call behavior and the required layouts.

## Symbol-only packaging and debugger experiment

**CONFIRMED isolated experiment; production support remains PLANNED:** a
standalone producer copy emits a symbol-only DIE for the actual compiler-known
`be8_probe` at `0x100b8`, with its exact 52-byte extent. The smoke fixture's
synthetic formal parameter is removed; no unproven variable lifetime, type,
source line or return ABI is emitted. The matched writer preserves ELF32
big-endian identity and `e_flags=0x05800400`, with no program-header table.
GNU, LLVM and strict libdwarf accept the artifact with zero reported errors.

Compiler and experimental symbols resolve the same function entry and decode
all thirteen instructions identically. Two independent QEMU/GDB executions
check each instruction PC, raw instruction bytes, ARM state and source-known
register values, the big-endian global bytes `11 22 33 44`, expected return
`0x1122334b` and normal process exit. All 26 observations agree; original bytes
are unchanged. Only the exact compiler-corroborated QEMU vDSO warning remains.
The initial disassembly endpoint included the first inaccessible byte past the
function; both failing transcripts are retained, and the corrected exclusive
extent checks all thirteen instructions without extending the function.

The complete experiment sources, binaries, native/validator/debugger transcripts
and hashes are in the `arm-mixed-modes` worktree's
`build/arm-mixed-modes/be8-symbol-experiment/result.json`. This is an isolated
native/packaging experiment, not the production Ghidra exporter. Production BE8
remains explicitly rejected. Next work is an isolated target/ELF/language
agreement model and real curated types/storage/runtime, including return/call
classification, before advertising any supported BE8 profile.
