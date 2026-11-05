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
  consumer replay also passes. Windows execution and consumer review at
  `995e0df` are recorded below; the corrected full gate remains pending.
- Bash wrapper controls pass. Native Windows wrapper/container/GUI tests and
  Linux GDB replay of the Windows-produced compressed artifact pass at
  `995e0df`; this does not substitute for the full corrected exact-head gate.

Retained initial failures include the missing ARM compiler in PATH (resolved
using the existing private ARM toolchain), an address-index
oracle that had not decoded compressed sections, an ARM repeat test's shared
TCP-port collision, GUI test compilation/environment mistakes, and a consumer
oracle that incorrectly required a global rather than static recovered function.
The address oracle now decodes bounded zlib data with header/stream checks.
QEMU symbol tests use the existing private UNIX-socket helper, with startup and
exit checks; all four emulated profiles have passing socket replays. The original
failed directories are retained and are not labeled passing runs.

The first hosted compression run `41978631212` stops at the new Windows wrapper
assertion: the fake batch launcher records all arguments on one line, while the
new assertion expected a separate line per argument. The check now matches a
complete optionally quoted argument within that line, and the explicit-none
check rejects the option anywhere in the capture. Native Windows acceptance
requires the corrected run; the failed assertion is not a passing wrapper test.

## Remaining acceptance

The complete required CI gate, final review and normal integration remain open.
Production Linux compression measurements now pass for both pinned workloads,
and the scoped Windows packaged GUI/consumer checks pass. Full #74 also requires
the broader Windows workload measurements and final caching/parallelism
decisions. Private-copy and production sizes/timings are separate populations.

## Production workload and Windows checkpoints

### Reproduce the Linux production comparison

Use a private Ghidra 12.0.3 installation containing the assembled candidate
release, its complete manifests and Java 21 configuration. Set `JAVA_HOME` to
the complete Java 21 JDK and `DWARFDUMP` to the pinned CI checker built with
compression support. Keep the installed module, saved programs and harness
files unchanged until measurement finishes. The commands below run sequentially;
`<...-case>` denotes the passing result directory printed by the preceding
workload harness, not an arbitrary saved Ghidra project.

```bash
python3 src/test/performance/sqlite-benchmark.py "$GHIDRA_INSTALL_DIR" --repeats 2
python3 src/test/integration/compression-workload.py \
    "<sqlite-case>" "$GHIDRA_INSTALL_DIR" --workload sqlite
python3 src/test/performance/build-uboot.py
python3 src/test/performance/uboot-benchmark.py \
    "$GHIDRA_INSTALL_DIR" "<uboot-build-case>" --repeats 2
python3 src/test/integration/compression-workload.py \
    "<uboot-benchmark-case>" "$GHIDRA_INSTALL_DIR" --workload uboot
```

The comparison defaults to five alternating pairs and adds two separate JFR
exports. It copies the accepted saved project, checks corpus provenance and
release manifests, verifies the running Java/script identity, compares every
decompressed section and source hash, and validates each freshly published
profile pair before another export can change source timestamps. Retain the
entire printed result directory, including negative runs and command logs.

### Observed checkpoints

**CONFIRMED production SQLite measurement:**
`compression-workload/sqlite.7bvmu704` uses the same installed exporter,
copied saved program and output path for five alternating plain/zlib pairs,
followed by two separate JFR exports. All twelve exports retain identical
decompressed DWARF and source, repeatable per-mode sidecar bytes, unchanged
protected inputs and unchanged program database files. Both published modes
pass GNU/LLVM/pinned strict checks and GDB function/type/source/global-value,
next/step, checkpoint-return and normal-exit checks.

| Measurement | Plain | Production zlib |
| --- | ---: | ---: |
| Sidecar bytes | 5,638,224 | 1,951,304 |
| Median fresh-process export, seconds | 34.76 | 35.06 |
| Maximum observed RSS, KiB | 1,194,748 | 1,191,844 |

The sidecar is 65.39% smaller. Paired zlib-minus-plain elapsed differences are
`+0.54, +0.13, +0.38, -0.13, +0.09` seconds. This supports an opt-in size
benefit, not a general speed or memory improvement. Separate JFR runs observe
0.0123/0.0696 seconds in plain/zlib ELF packaging; their inclusive export times
are not part of the unprofiled timing population. Warm caches and host load
remain uncontrolled.
Exact samples, CPU/RSS measurements, phase observations, artifact hashes and
validator-log hashes are retained in
`docs/evidence/compression-sqlite-production-20261105.json`.

**CONFIRMED production U-Boot measurement:**
`compression-workload/uboot.74ha_hcl` passes the same five-pair/two-profile
protocol, all twelve per-mode deterministic and cross-mode equivalent exports,
unchanged protected inputs and saved-program bytes, both modes' strict/GNU/LLVM
checks and compiler/Forge GDB. The recovered report retains all 6,375 functions,
6,374 successful decompilations and the known one-function 60-second timeout;
that timeout remains included in timings. This Linux sandbox workload does not
establish bare-metal firmware support.

| Measurement | Plain | Production zlib |
| --- | ---: | ---: |
| Sidecar bytes | 17,029,480 | 6,792,336 |
| Median fresh-process export, seconds | 114.80 | 115.35 |
| Median descendant CPU, seconds | 134.86 | 133.76 |
| Maximum observed RSS, KiB | 1,297,588 | 1,151,252 |

The sidecar is 60.11% smaller. Paired zlib-minus-plain elapsed differences are
`+0.67, -0.06, +4.04, +0.75, -0.11` seconds; retain the larger third-pair cost
rather than dropping it as an outlier. Separate JFR packaging observations are
0.0169/0.1480 seconds. The lower sampled CPU/RSS does not establish a resource
improvement: compression retains additional payloads, and fresh-JVM behavior
and host load vary. Complete samples, phase observations, unchanged report
counts, artifact hashes and validator-log hashes are in
`docs/evidence/compression-uboot-production-20261105.json`.

**CONFIRMED scoped Windows acceptance:** run `41979031365` at `995e0df` passes
native Windows controls, the compressed Script Manager selection/cancellation
journey and Linux GDB consumption of that unchanged Windows artifact. Review
verifies both API archive digests, 139 protected host-file hashes, matching
original/sidecar/source copies, compressed-section headers and hashes,
GNU/LLVM/pinned strict results and the raw GDB transcript. Its parameters remain
optimized out; this check establishes function/type/source/stepping behavior,
not additional variable coverage. Source lookup after host transfer uses an
explicit source directory. Three inherited frame diagnostics are corroborated
against original bytes; no uncorroborated errors remain.
The scoped review and API archive digests are recorded in
`docs/evidence/compression-windows-41979031365.json`.

That run's full CI gate fails because the independent large-ELF smoke script's
manual `javac` source list omitted the new compression enum. Commit `05953e9`
adds that dependency, and its exact compiler invocation passes on Java 21.
The complete local standalone regression also passes at
`large-elf-sidecar/run.IiO3Kxgi`: a 2,147,487,745-byte original and
2,147,491,256-byte sidecar under a 64-MiB Java heap, deterministic copies,
GNU/LLVM/pinned strict validators and GDB values/source/normal exit. Its two
inherited frame diagnostics are corroborated against the original. The large
files are removed by the harness after validation; retained log hashes are in
`docs/evidence/compression-large-elf-20261105.json`. This is a standalone
container oracle, not a Ghidra analysis-memory claim.
The corrected full hosted gate remains pending. These checkpoints supersede
the earlier local-only/pending-component wording above without claiming final
#74 acceptance or integration.
