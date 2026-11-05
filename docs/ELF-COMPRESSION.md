# Optional ELF debug-section compression

**CONFIRMED locally; hosted acceptance pending:** the development exporter can
store newly generated DWARF sections using gABI zlib compression. The default
remains uncompressed. This is the bounded production candidate selected by
[#74](https://github.com/zwilcox/GhidraDwarfForge/issues/74); it does not complete
that issue or publish a release. See `PERFORMANCE-WORKPLAN.md` for the measured
private-copy experiments, other candidates and remaining Windows measurements.

## Invocation

Add `--compress-debug-sections=zlib` to the packaged Bash headless wrapper or
underlying export script. Use `-CompressDebugSections zlib` with the packaged
PowerShell wrapper. Both accept `none` explicitly; unsupported codecs fail
argument validation. Script Manager provides
`ExportCompressedGhidraDwarfForge.java` as an explicit shortcut.

The standard `<binary>.dbg` and `<binary>.dbg.c` naming, original preservation,
curated analysis, report schema and consumer loading workflow remain unchanged.
Compression affects section storage only. It does not recover additional
variables, alter their lifetimes, synthesize unwinding or change source lines.

## Representation and resource contract

Each generated `.debug_*` section is compressed independently with Java's
existing zlib implementation. The exporter retains the uncompressed section
when its compression header plus payload would not be strictly smaller.
Sections may therefore mix compressed and plain storage. No legacy `.zdebug_*`
names, accelerators, native ABI changes or external compressor are introduced.

The [gABI compression header](https://gabi.xinuos.com/v42/elf/03-sheader.html)
uses the target ELF class and byte order: 12 bytes for ELF32, 24 bytes for ELF64,
type `ELFCOMPRESS_ZLIB`, reserved ELF64 word zero, original size and original
alignment one. Compressed sections have `SHF_COMPRESSED`, alignment 4/8 and no
allocation flag. All DWARF offsets address decompressed data. Original ELF
identity and the matched copied prefix retain their existing contract.

Input/output deflate calls use 32-KiB chunks with cancellation checks. The
deflater is released in `finally`, including fallback and cancellation. Work
stops when compression cannot beat the original size. The producer still holds
the original DWARF, and compression adds retained compressed payloads and bounded
temporary buffers; this is not a peak-memory reduction claim. Exact compressed
bytes are tested for repeated runs with the same runtime. Different JDK/zlib
versions are not promised to produce identical compressed bytes, but must
preserve the decompressed DWARF.

## Local evidence (2026-11-05)

Ghidra 12.0.3, actual Java 21.0.12.1 and the packaged pinned libdwarf 2.3.2
producer were used. `docs/evidence/compression-local-20261105.json` records the
package and artifact hashes, runtime/script observations and retained results.

- Eight container layouts cover ELF32/ELF64, both byte orders, and named versus
  sectionless originals. They verify headers, flags, alignment, exact inflate,
  tiny/empty/incompressible fallback, default bytes and deterministic output.
  Cancellation in every layout preserves the prior artifact and original.
- Twenty-five real cases cover x86-64, AArch64, ARM32 and both MIPS32 byte orders,
  each with ET_EXEC, PIE, shared object, sectionless and rebased-PIE fixtures.
  Each case exports plain, zlib and repeated zlib artifacts: 75 exports total.
  Decompressed sections and synthetic source are byte-identical; compressed
  reruns are byte-identical. GNU/LLVM/pinned strict validation and the applicable
  GDB function/type/variable/source/stepping checks pass. Existing inherited
  frame exceptions remain corroborated against original bytes; the documented
  QEMU ARM synthetic-vDSO warning also occurs with plain artifacts.
- Production cancellation occurs inside compression after the exporter has
  entered pair publication. The prior sidecar/source and input survive, no
  temporary files remain, and a subsequent actual export and validators pass.
- The real Linux Script Manager compression shortcut, output chooser selection
  and cancellation, console, read-only attachment preview and preparation pass.
  Both produced pairs pass validators and GDB. A separate unchanged-artifact
  consumer replay also passes; its Windows execution remains pending.
- Bash wrapper controls pass. Native Windows wrapper/container/GUI tests and
  Linux GDB replay of the Windows-produced compressed artifact are wired into
  CI but are **PRESENT, UNVERIFIED** until their exact-head jobs pass.

Retained initial failures include the missing ARM compiler in PATH (resolved
using the existing private ARM toolchain), an address-index
oracle that had not decoded compressed sections, an ARM repeat test's shared
TCP-port collision, GUI test compilation/environment mistakes, and a consumer
oracle that incorrectly required a global rather than static recovered function.
The address oracle now decodes bounded zlib data with header/stream checks.
QEMU symbol tests use the existing private UNIX-socket helper, with startup and
exit checks; all four emulated profiles have passing socket replays. The original
failed directories are retained and are not labeled passing runs.

## Remaining acceptance

Native Windows packaged execution and consumer replay, the complete required
CI gate, review and normal integration remain open. Measure the production
compression option on the pinned SQLite/U-Boot saved projects before completing
the optimization's performance decision. The private-copy size reductions are
motivation, not measurements of the new Java implementation. Full #74 also
requires final host measurements and explicit caching/parallelism decisions.
