# Relocating source references in a matched sidecar

**CONFIRMED locally; full hosted acceptance pending:** `SyntheticSourceSidecar` prepares and writes
an unpublished ELF stage for build-ID installation. It consumes a stable current
Forge sidecar and the eventual retained-source directory. It does not install a
file, verify an original/report pair, copy permissions, synchronize a directory,
or authorize replacement of any existing artifact. Those obligations belong to
the installation transaction described in ADR-0006.

The writer requires a non-loadable ELF with exactly one ordinary or gABI zlib
`.debug_info`, `.debug_abbrev`, `.debug_str` and `.debug_line`. Source sections
must have the current Forge attributes. Both ELF classes and byte orders use
the input's metadata. Stored and decoded sections are each limited to 64 MiB;
these per-section bounds do not promise a 64 MiB aggregate heap. Decoding rejects
unsupported compression, bad reserved fields, declared-size mismatches, trailing
streams and malformed data. Decompression and compression check cancellation
between bounded operations and release their native Java zlib resources.

The existing pure DWARF transformer changes only the compilation-directory
reference and line-header directory. The ELF writer copies the input through
bounded file-backed operations, appends changed payloads in stable order with
the original alignment, and patches only their section offset/size fields.
Compression status and uncompressed alignment are preserved, even when a newly
compressed payload would not save space. Every unrelated section record and
payload stays byte-identical, including symbols, ranges, locations, frame data
and build-ID notes. An unchanged directory gives a byte-identical output without
appending new payloads. A second installation using another directory can retain
old unreferenced payload bytes; this deliberate append strategy avoids altering
unrelated file content.

Active relocations targeting source sections are refused. A source-section
header patch must not overlap the ELF header or any active section payload.
The writer checks ELF32 output bounds before writing. It accepts only an empty
private staging channel; it never truncates a caller-selected file. Cancellation
or I/O failure may leave a partial **unpublished stage**, which its owner must
remove or quarantine. `writeStage` makes no final-name atomicity or durability
claim. Stable owned input snapshots, hash binding, host metadata and publication
remain mandatory at the transaction layer.

The integration oracle independently decodes the changed sections, compares
them with the pure transformer, and compares the complete original ELF prefix,
allowing differences only in those offset/size fields. GNU, LLVM and pinned
strict validation run before fresh GDB/LLDB/perf checks with the former source
absent. Malformed-container, nonempty-stage, deterministic-repeat, idempotence
and every cooperative cancellation-boundary controls operate on actual producer
artifacts. The floating-register pipeline exercises both plain and zlib exports.

The [local receipt](evidence/build-id-source-container.json) binds a native-inclusive
package and all 212 production source files. Sixty fresh producer exports include
exec/PIE, rebasing and deterministic repeats across x86-64, AArch64, ARM32 and both
MIPS32 byte orders, in plain and zlib form. Eighty pinned strict reports pass,
retaining only independently corroborated original frame diagnostics. Twenty
relocated outputs pass GDB with the old source absent; eight x86-64/AArch64 cases
also pass LLDB and offline perf lookup. Container checks cover 130 refusals and
13,741 cancellation boundaries; the underlying section transformer additionally
passes 420 refusal checks and 10,216 cancellation boundaries. The raw archive is
verified member by member. No additional ELF64 big-endian or Windows-hosted
relocation claim follows from this local five-target matrix.

`Plan.requireMatches` also provides a bounded read-only comparison against the
complete expected artifact. The derived validation binding uses this proof
before checking the artifact, without changing the original export report; see
`DERIVED-ARTIFACT-VALIDATION.md` for its distinct evidence schema and tests.

This component does not complete issue #109 or establish the installer's
ownership, update, removal, interruption-recovery or consumer-setup contract.
