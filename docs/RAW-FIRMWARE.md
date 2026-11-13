# Explicit raw firmware export

**CONFIRMED locally:** the production exporter creates synthetic debug containers
from saved raw-firmware programs. Two Cortex-M3 runtime layouts, including a
two-input flash/RAM case, pass structural and QEMU/GDB checks. Issue #119 remains
open pending final review and the required hosted regression
gate. Ghidra 12.0.3 and Java 21 remain the baseline; native producer signatures
and the pinned libdwarf revision are unchanged.

## Target and address contract

**CONFIRMED implementation:** `FirmwareTarget` records the selected architecture,
ABI, address width, pointer width, byte order, instruction mode, Ghidra language
and compiler specification, ELF machine and flags. The first implementation
profile is `cortex-m3`: ARMv7-M, base AAPCS32, little endian, Thumb-only,
`ARM:LE:32:Cortex/default`. Registry membership is not a supported-release claim.
New profiles require their own agreement checks and runtime evidence.

Raw firmware runtime addresses are explicit map addresses. They do not derive
from file offsets or an ELF minimum load address. The map supports separate
inputs, discontiguous regions, split source spans within a region, and explicit
copies of the same original bytes to different addresses. A copy describes the
analyst's initial byte mapping; it does not assert a live alias or prove startup
copy code executed. Uninitialized storage means unknown bytes, not automatic
zero filling or inferred MMIO behavior.

Every initialized region must have complete, nonoverlapping original-file
provenance. Ghidra's `MemoryBlockSourceInfo.getFileBytesOffset()` is relative to
its `FileBytes`, so the original-file offset includes `FileBytes.getFileOffset()`.
Capture checks both stored original bytes against the selected input and current
memory bytes against those originals. A patched analysis byte is rejected with a
diagnostic; it is not silently exported as a fact about the unmodified firmware.
Names alone never establish input identity. Full current input SHA-256 and size
are retained, including when only part of an input is mapped.

The initial policy rejects overlays, bit/byte-mapped aliases, external or
nonloaded blocks, nondefault address spaces, overlapping runtime regions, and
initialized blocks without file provenance. All are explicit failures rather than
silently omitted regions. Unknown RAM may have no file spans. An input without
any mapped bytes is rejected. The existing nonnegative signed-64-bit address
model remains a limit; ELF32 regions may end exactly at `2^32`.

Capture is read-only and checks cancellation between bounded reads. It compares
input digests and the program modification number before returning. These are
optimistic consistency checks, not locks or a filesystem snapshot. Publication
must repeat consistency checks immediately before installing the generation.

## Container decision and experiment

**CONFIRMED experiment:** a newly constructed ARM ELF32 `ET_EXEC` debug container
with zero entry point, no program headers, no build-ID note, and `SHT_NOBITS`
runtime allocation sections works with GDB remote debugging of the Cortex-M3 raw
fixture. It contains DWARF, symbol/string tables and ARM attributes. The ELF
machine/flags describe the explicitly selected target; they do not identify an
original executable. Region names are synthetic `.forge.region.<index>` names.
The artifact is not used to program flash or load RAM.

The reproducible experiment is
`src/test/research/firmware-container/experiment.py`. It takes a compiler-reference
case produced by `cortex-m-reference.py`, copies **compiler** DWARF and symbols
into a new container, extracts raw bytes with `objcopy -O binary`, and boots those
raw bytes in system QEMU. This proves a consumer packaging choice, not Forge
recovery, raw Ghidra export, or a second runtime memory layout.

Local evidence on 2026-11-12:

- LLVM `--verify`: no errors; `readelf -hSWn` confirms the container and absence
  of a build-ID note.
- GDB receives only `symbol-file <synthetic.dbg>` before `target remote`.
  It never opens the compiler executable as its executable image.
- Reset vectors, Thumb instructions, breakpoints, source stepping, initialized
  data, odd-address data, BSS behavior, function pointers, parameter/local values,
  both MSP/PSP exception paths and final results pass the existing compiler oracle.
- GDB gets instruction bytes from the remote target; offline memory disassembly
  is intentionally unavailable for a container with only NOBITS allocations.
- GDB's warning that no executable was specified is expected in this explicit
  symbol-only remote workflow. QEMU's existing unconnected Ethernet warning is
  unrelated to the tested CPU/memory behavior. Neither is a DWARF validator warning.
- The original ELF runtime path also passes after adding the raw-input option
  to the shared harness. Original reference and raw input hashes are unchanged.

The production container follows this layout. A synthetic container must
never enter build-ID installation, debuglink attachment, or original-ELF identity
validation as though it were the original firmware. Its ABI metadata is declared
profile information. The experiment copies compiler attributes only as an oracle;
production must derive them from the selected profile.

## Export a saved raw program

Import and analyze the raw files in Ghidra, create the intended runtime memory
blocks, curate functions/types/storage, and save the program. The exporter reads
that map; it does not guess a map from a raw file or infer startup behavior.
For one original file, use the installed wrapper:

```bash
support/ghidra-dwarf-forge-headless \
    --ghidra-dir=/path/to/ghidra_12.0.3_PUBLIC \
    --project-dir=/path/to/projects --project-name=Firmware \
    --program=/firmware.bin --raw-firmware=cortex-m3 \
    --input=/path/to/firmware.bin
```

PowerShell exposes the same options as `-GhidraDirectory`, `-ProjectDirectory`,
`-ProjectName`, `-Program`, `-RawFirmware cortex-m3`, and `-Input`. Raw wrapper
mode requires an existing saved program and an explicit primary input. It opens
that program through `DefaultProjectData` in read-only mode from a disposable
host project, without analysis, saving, or rotating the saved project's backups.
The direct `GhidraDwarfForge.java` entry point accepts `--raw-firmware=cortex-m3`
as well, including from an interactive program with unsaved analyst edits; the
manifest records whether unsaved changes were present.

For multiple imported files, pass `--firmware-inputs=/path/to/inputs.json`
(PowerShell `-FirmwareInputs`). The strict descriptor binds indexes in
`currentProgram.getMemory().getAllFileBytes()` to original files:

```json
{
    "schema": 1,
    "inputs": [
        {"id": "flash", "fileBytesIndex": 0, "path": "firmware.bin"},
        {"id": "ram", "fileBytesIndex": 1, "path": "ram-init.bin"}
    ]
}
```

Paths are absolute or relative to the descriptor's resolved parent directory.
The primary input must be included. IDs and indexes must be unique; all mapped
original bytes must be accounted for, and unused bindings are rejected. Names
and indexes are checked against stored and current bytes, not trusted as proof
of identity. With this descriptor, wrappers require a private temporary log
(omit `--log`/`-Log`): shell logging must not truncate an additional original
before Java can validate its path. The transcript still appears on standard
output. Callers redirecting that output must choose a separate destination.

Default outputs are `<input>.dbg`, `<input>.dbg.c`, and
`<input>.dbg.firmware.json`. `--output` selects the sidecar path and its companion
paths. Existing source splitting and debug compression options remain available.
The exporter publishes the sidecar, source and manifest through the existing
recoverable generation publisher. Every original input and the selection file
is protected against output aliases, including symlinks and hard links. Outputs
inside the saved project or aliasing its files are also rejected.

The manifest records the explicit target, SHA-256 and size of each original,
Ghidra FileBytes extents, every runtime region and source span, section mapping,
and output/source hashes. Its analysis binding includes saved file ID, project
locator, pathname/version/saved modification time, program ID, observed program
modification number and unsaved-change flag. This is a saved-file identity and
observed revision, **not a database checksum**. Input and program consistency
are checked again before publication. These checks detect observed changes;
they are not locks against concurrent external writers.

## Debug container and remote loading

Production writes a fresh non-loadable ELF with zero entry, no program-header
table and no original build ID. `.forge.region.<index>` sections are NOBITS at
the declared runtime addresses, with permissions from the map. ARM attributes
come from the explicit profile, and `.forge.firmware` identifies a synthetic
container. The private byte-bearing witness used for evidence checks is deleted
after export. Original raw bytes are not embedded as loadable allocations.

Program the target separately, or boot the original raw image in system QEMU.
Connect GDB using only the synthetic symbols:

```gdb
set architecture arm
symbol-file /path/to/firmware.bin.dbg
target remote localhost:1234
break recovered_function
continue
list recovered_function
```

Do not use this debug container to program the device. Instruction and data
bytes come from the remote target. GDB may warn that no executable was specified;
this is expected for this workflow. The example does not modify flash or RAM.

Addresses are fixed runtime addresses from the current map. There is no implicit
ELF image-base delta or load bias. In coordination with #107, runtime relocation
must use explicit per-section mappings: a guessed single delta cannot represent
independently placed flash and RAM. The existing original-ELF GDB loader,
formatters, attachment preparation and optional unwind synthesis are rejected
in raw mode. Build-ID installation/debuglink discovery is not a raw-container
identity mechanism. Normal ELF export retains its existing behavior.

Memory permissions and unknown RAM do not establish MMIO read width, read-clear
side effects, or cache policy. Those semantics remain the separate #118 work.
Forge's current Cortex-M exception backtrace remains handler-only; this feature
does not claim exception unwinding beyond the existing validated profile.

## Acceptance evidence and remaining gate

Local production tests use `raw-firmware-export.py`, the installed Bash wrapper, extension and
native producer, a BinaryLoader import with explicit fixture curation, and raw
QEMU boot. They compare against the source-built compiler ELF as an oracle;
they do not copy its DWARF into the production output.

- Flash starts at zero in both cases. RAM starts at `0x20000000` or `0x20001000`;
  the second case also uses a distinct RAM initialization input file.
- Eight exact function ranges/Thumb symbol values, all expected globals, line
  addresses and literal-pool exclusion pass the independent artifact oracle.
- GDB proves breakpoints, source stepping, Thumb function pointers, odd-address
  data, parameter/local values, reset/BSS behavior and both MSP/PSP exception paths.
- LLVM, GNU readelf and libdwarf inspect the actual generated artifacts.
- Repeated exports are byte-identical; original inputs, saved project files and
  installed package files retain their hashes.
- Cancellation in map capture, carrier creation, native production, ELF writing
  and manifest creation preserves absent/existing generations. Retry succeeds.
  Patched bytes, overlays, mapped aliases, unbacked initialized blocks, stale
  input selections and original-input hard-link collisions are rejected.
- The existing installed ELF export/runtime regression also passes locally.

The Cortex-M suite runs both raw layouts alongside its existing ELF tests. The
model, strict input parser and actual Ghidra provenance checks run in both host
smoke lists. Firmware ABI metadata lives in the audited target profile; the
generic container writer does not encode architecture attributes.

The Windows host receives a small, hash-bound compiler/raw reference capsule,
imports it with the same fixture curation, and invokes the installed PowerShell
wrapper twice. It checks all 21 two-input failure controls and preservation, then
transports the exact outputs to Linux. The consumer verifies hashes, reruns
structural/address checks, and uses QEMU/GDB with explicit source-directory
substitution. A local Linux producer/consumer rehearsal passes, including source
lookup after transport. **PRESENT, UNVERIFIED:** actual Windows production and
the full changed-head hosted architecture/host gate until passing evidence is
recorded. No general raw-architecture claim follows
from a Cortex-M3 result; additional profiles require their own ABI and runtime
proof.
