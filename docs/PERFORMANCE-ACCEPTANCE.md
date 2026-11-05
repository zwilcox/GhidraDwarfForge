# Performance and optional optimization acceptance (#74)

**CONFIRMED implementation acceptance, 2026-11-05:** measurement PR159 merged
as `762dbbd55d3f5859b23ac4c54abea16acdfd79a2`; compression PR160 merged as
`5d81e4f217c93222a89f9ca490906116c7337f54`. Both merge trees exactly match their
tested PR heads. This record reconciles final documentation; issue closure
follows normal protected integration of this record. It does not publish a
release or complete #108 or any later goal item.

## Requirement mapping

| Issue acceptance requirement | Observed implementation and evidence |
| --- | --- |
| Redistributable representative application/firmware and host workloads | Source-built SQLite 3.46.1 and U-Boot 2025.01 sandbox, pinned archives/configuration, compiler commands, source licenses and hashes. Linux and native Windows exporter hosts use these ELF workloads. [Workplan](PERFORMANCE-WORKPLAN.md), [local workload evidence](evidence/performance-local-20261104.json), [Windows evidence](evidence/performance-windows-workloads-41989520582.json). |
| Repeated wall/CPU/peak-memory measurements with separated costs | Alternating baseline/candidate runs, separate imports, validation and JFR profiles; production compression comparisons use five pairs plus two profiles per workload. Linux GNU-time RSS and Windows Job Object commitment remain separate metrics. Samples, versions, boundaries and failures remain in the linked receipts and workplan. |
| Profile-driven decisions, including negative/inconclusive results | Export-phase events distinguish decompilation/source, extraction, native production and publication. Windows mixed paired differences and U-Boot's timeout remain reported. No universal speed or memory improvement is established. [Windows controls](evidence/performance-windows-controls-20261105.json), [candidate experiments](evidence/performance-candidates-local-20261105.json). |
| Explicit decision for every listed candidate | Implement opt-in zlib. Defer zstd, built-in GDB indexes, string/address indexing, incremental caching and bounded parallel decompilation with explicit conditions for revisiting. Reject the tested GDB-generated `.debug_names` route because LLVM verification fails. The [workplan](PERFORMANCE-WORKPLAN.md) records benefit/resource/invalidation tradeoffs; deferral is not implementation. |
| Selected optimization equivalence, debugger behavior, cancellation and resource bounds | Production class/endian-aware gABI zlib, deterministic fallback for incompressible/tiny sections, cancellation checkpoints and deflater cleanup. Eight container layouts; five targets × five roles × three exports; GNU/LLVM/pinned strict checks; GDB; production cancellation/retry; unchanged original/source/decompressed-DWARF bytes. [Compression contract](ELF-COMPRESSION.md), [local cases](evidence/compression-local-20261105.json), [large-ELF regression](evidence/compression-large-elf-20261105.json), [combined hosted review](evidence/compression-integrated-42010699187.json). |
| Exact datasets, tools, statistics, artifacts and limits documented | [PERFORMANCE.md](PERFORMANCE.md), [workplan](PERFORMANCE-WORKPLAN.md), [compression](ELF-COMPRESSION.md), this record, PROJECT_CONTEXT and TODO distinguish accepted current work from historical failures/pending checkpoints. Exact production samples are in the [SQLite](evidence/compression-sqlite-production-20261105.json) and [U-Boot](evidence/compression-uboot-production-20261105.json) receipts. |

## Integration and independent artifact inspection

Measurement head `3276396594d880171f006a07fa0ca668acf1ebc0` passes complete CI
[41989520429](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41989520429)
and all five performance workflow jobs in
[41989520582](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41989520582).
See [measurement integration review](evidence/performance-integration-41989520429.json).

Combined compression head `6281660250d42d228f23ed276a8cc0e43235fcc6` passes all
15 jobs, including enforced `required-validation`, in
[42010699187](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42010699187).
The GitHub test checkout `e9ba712ea6c65362b8def03533504f3ddc8be464`, PR head and
main merge all have tree `06be92112fb949c91eda7c766c75d0bfc709f73a`.
Protection required an up-to-date check, enforced administrators and allowed
normal merge history; neither merge used an admin bypass. Separate main-push
runs are not claimed as completed by these exact-PR acceptance records.

Current raw inspection revalidates 558 x86-64, 393 AArch64, 594 ARM32 and 328
reports in each MIPS32 lane. Deliberate negatives and validator self-tests are
excluded. All 75 compression exports retain report-bound hashes, original/private
inputs, deterministic compressed bytes and equivalent decompressed DWARF/source.
Each lane binds 37 shared fixture files, five separate source captures, and eight
positive/negative association transcripts. Eighteen ARM preparation receipts are
traced to completed alias runtime tests, rather than counted as runtime evidence
on their own. Specialized ABI checks do not imply arbitrary ABI support.

Package inspection covers 325 whole-release entries and nested manifests,
507 Java21 classes, native files and 33 packaged scripts. Linux GUI inspection
covers three journeys and six bound export pairs. Windows host/consumer inspection
binds four CLI/GUI generations, 885 protected-file hashes, four CRC controls and
the compressed GUI artifact's 139-file subset. This is agent source/raw-artifact
review, not a second-human approval. GitHub artifact IDs/digests, job IDs and
review-receipt hashes are retained in the
[combined evidence](evidence/compression-integrated-42010699187.json).

## Measured benefit and limits

| Production comparison | Plain sidecar | Zlib sidecar | Reduction | Median fresh-process export, plain / zlib |
| --- | ---: | ---: | ---: | ---: |
| SQLite | 5,638,224 bytes | 1,951,304 bytes | 65.39% | 34.76s / 35.06s |
| U-Boot sandbox | 17,029,480 bytes | 6,792,336 bytes | 60.11% | 114.80s / 115.35s |

These are the recorded Linux production populations, separate from private-copy
codec experiments, historical line-planner results and native Windows workload
observations. CI correctness does not create another timing sample. Compression
adds buffers and is not a claim of memory reduction. Bounded deflate calls,
cancellation and output-size fallback do not establish a universal peak-memory
cap for arbitrary programs.

U-Boot sandbox executes a representative firmware codebase as a Linux ELF; it
is not physical bare-metal firmware validation. Its known decompilation timeout
and unavailable recovery remain visible. The large workloads test selected
source/type/value/stepping behavior, not complete recovery of every variable.
LLDB compatibility remains a separate goal item.

The earlier Windows workload run failed compiler-source lookup; its timings
remain a separate historical population. Corrected hosted consumption proves
hash-bound source relocation and positive/negative controls. The retained
Windows measurement subset independently verifies 717 of 719 protected files;
two private installation settings files were observed unchanged by the job but
are unavailable for independent artifact replay.

The earlier MIPS compression run failed because the test harness replaced shared
report-bound fixtures. Private compression inputs and explicit preservation checks
fix that interference without weakening the attachment gate. Two final x86
baseline-file timestamps change during a later successful ordinary re-export;
unchanged content and actual CI step order explain those changes. Compression-local
metadata snapshots remain identical. Historical failures are retained in the
workplan and [fixture-isolation record](evidence/compression-fixture-isolation-20261105.json).
