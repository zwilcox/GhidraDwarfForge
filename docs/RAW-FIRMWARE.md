# Explicit raw firmware export

**PRESENT, UNVERIFIED:** the raw target and memory-map capture components exist.
They are not connected to the production export entry point. Issue #119 remains
open. Ghidra 12.0.3 and Java 21 remain the baseline; no native producer ABI changes
are needed for the map-capture work.

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

The production container should follow this layout. A synthetic container must
never enter build-ID installation, debuglink attachment, or original-ELF identity
validation as though it were the original firmware. Its ABI metadata is declared
profile information. The experiment copies compiler attributes only as an oracle;
production must derive them from the selected profile.

## Remaining production work

**PLANNED:** expose explicit raw-mode and target/map selection, bind actual Ghidra
FileBytes to user-selected original inputs, and emit recovered DWARF through the
production native path. Generic code must not guess an ELF image base, load bias,
calling convention or original build identity from a raw file.

**PLANNED:** publish `<input>.dbg`, `<input>.dbg.c` and a firmware manifest as one
recoverable generation. The manifest must contain the target descriptor, original
input hashes/sizes, every runtime region and source span, saved-program identity
and analysis-state binding, map provenance, and output hashes. The exact portable
saved-analysis binding still needs API audit; a filename alone is insufficient.
Do not claim a database checksum from a modification counter. All input paths and
the descriptor must be protected from output aliases, including companion files.

**PLANNED:** record fixed runtime addresses and reject implicit relocation. Any
runtime adjustment must use #107's explicit section/mapping contract; no single
guessed base delta may relocate independent flash and RAM regions. Preserve
instruction-mode evidence and defensible variable storage. Do not infer hardware
read widths, read-clear behavior, or cache policy from memory permissions.

**PLANNED acceptance:** installed headless export of source-built raw firmware,
two distinct runtime layouts, compiler/Forge structural and GDB oracles, invalid
map/target controls, deterministic outputs, saved-project and original-input
preservation, atomic publication, cancellation/failure recovery, and existing ELF
Linux/Windows and cross-architecture regression gates. The current structural map
tests at two base addresses are not the required second QEMU runtime layout.
