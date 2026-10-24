# Export performance measurements

**CONFIRMED:** the initial Linux x86-64 scaling harness measures import/analysis
separately from repeated exports of the same saved Ghidra program. It changes
no production exporter behavior. Run it with a native-inclusive installation:

```bash
python3 src/test/performance/export-benchmark.py /path/to/ghidra \
    --counts 100 1000 10000 --repeats 3
```

The harness requires GCC, GNU `time`, `nm`, `readelf`, LLVM `llvm-dwarfdump`,
libdwarf `dwarfdump`, and Python-enabled `gdb-multiarch`. It retains generated
C, binaries, saved projects, commands, transcripts, tool versions, installed
module hashes, JSON metrics and validation evidence under
`build/test-results/export-benchmark/run.*`, including after failure. All
targets are generated in that private results directory. Timeout/interruption
cleanup terminates the launched process group, including children that ignore
SIGTERM after their wrapper has exited.

Each workload contains the requested number of small, distinct, non-inlined
functions plus compiler startup code. A function-pointer table invokes every
function. GCC builds a non-PIE ELF without compiler DWARF; ELF symbols remain so
Ghidra can preserve the fixture names. No analyst preparation script is used.
This is a synthetic function-count experiment, not a representative firmware
corpus or a test of recovered source signatures and parameter locations.

Every sample launches a new headless JVM. The export measurement includes JVM
startup, loading the saved project, decompilation, model extraction, native
production and publication. Structural validators and GDB run outside the
timed interval. GNU time's maximum resident set is a process-family high-water
measurement, not the sum of concurrent JVM/decompiler memory. Filesystem caches,
JIT behavior and other host work can affect these small sample sets; the
harness does not claim cold-cache or isolated-machine measurements.

Validation requires unchanged original hashes, byte-identical repeated
sidecar/source files, GNU/LLVM/libdwarf checks, and a full GDB DWARF function
symbol with synthetic-source association and the original address for every
generated function. An inherited minimal ELF symbol alone cannot satisfy that
check. GDB also lists source, stops at the first function, checks the initial
global value, steps and runs to normal exit. Broader signature, variable-value,
architecture and PIE acceptance remains in the existing semantic integration
matrix.

## Initial observations

**CONFIRMED locally (2026-10-23):** Ghidra 12.0.3, the ELF robustness exporter
from `3e47589` (unchanged runtime code through `b089802`), GCC 13.3, GDB 15.1,
and OpenJDK 25.0.4.1 on an Intel Core i9-14900KF Linux host produced these results.
Each export median contains three independent JVM processes:

| Generated functions | Original ELF bytes | Sidecar bytes | Import seconds | Median export seconds | Largest export RSS, KiB |
|---:|---:|---:|---:|---:|---:|
| 100 | 19,792 | 37,008 | 3.76 | 2.52 | 411,676 |
| 1,000 | 106,744 | 215,760 | 4.39 | 3.27 | 386,992 |
| 10,000 | 972,976 | 2,021,632 | 9.33 | 10.62 | 879,656 |

The 100/1,000-function measurements are retained in `run.9aufhyv_`; the
10,000-function measurements are in `run.3ufsbv4n` in the isolated
`export-benchmarks` worktree. A 10-function harness rehearsal is in
`run.p9fpg5et`. All four workloads pass the strengthened full-symbol oracle in
their `validation-full-symbols` directories. Export status is `PARTIAL` for
the retained startup thunks/opaque recovered types; no function decompilation
failed. These diagnostics remain visible in the JSON reports.

The initial parser attempt in `run.optdmt4c` failed because Ghidra appends a
logging suffix to the JSON report. It is not a passing benchmark. The parser
now accepts only the complete JSON document followed by the known Ghidra
suffix or whitespace. The cleanup adversarial probe at `cleanup-probe` proves
that a descendant ignoring SIGTERM stops after timeout. Its first observation
checked immediately after asynchronous SIGKILL and was too early; the passing
recheck waits up to five seconds for the descendant to disappear or become a
non-running zombie.

At that initial checkpoint no speed or size optimization was claimed. The
process totals alone did not identify a hot path. Representative complex
application/firmware workloads and further profiling remain **PLANNED**;
P3.5 is partially complete. The following targeted experiment supplies new
evidence for one bounded implementation change.

## Indexing source addresses for line-table planning

**CONFIRMED locally (2026-10-23):** a JFR recording of an actual saved-project
10,000-function export placed 131 of 516 Java execution samples in
`Dwarf5LineTable.plan`. This was one instrumented run of the `3e47589` runtime,
retained at `export-benchmarks/build/test-results/export-benchmark/profile.0mby2d5r/`.
Samples identify a candidate hot path; they do not measure exact phase wall
time or demonstrate a speedup. That method scanned every source address again
for each function-body range.

The change builds one sorted address-to-earliest-line map, then selects each
range's half-open submap. Earliest-line selection commutes with filtering by
address, so overlapping bodies still receive their own rows, starts remain
inclusive, ends remain exclusive, and sequence/row ordering is unchanged.
The extra index holds at most one entry per unique source address. With `A`
address associations, `U` unique addresses, `R` body ranges and `E` emitted rows,
planning replaces the repeated `R * A` scan with roughly
`A log U + R log U + E` work. This does not change decompilation, native calls,
or the line-program encoding.

Five baseline/indexed pairs alternated on the same saved 10,000-function
project and unchanged input. The baseline was `ddad598`; the indexed build
changed only this production method, plus its smoke assertions. Both packages
used the same verified native files. Before every timed sample the package
was freshly extracted into the same private Ghidra copy and its manifest
checked. The same wrapper, environment, working directory and new fixed output
path were used for all ten processes. Existing project mode is read-only with
analysis disabled. No historical benchmark output was overwritten.

Host: Intel Core i9-14900KF, Linux x86-64, Ghidra 12.0.3,
OpenJDK 25.0.4.1, GDB 15.1. Package installation, structural validation and GDB
are outside timing; JVM startup and decompilation are included. The host was
not a cold-cache or formally isolated benchmark environment.

| Pair | Baseline seconds | Indexed seconds | Saved seconds | Baseline max RSS, KiB | Indexed max RSS, KiB |
|---:|---:|---:|---:|---:|---:|
| 1 | 10.86 | 9.04 | 1.82 | 764,076 | 581,708 |
| 2 | 10.40 | 9.18 | 1.22 | 729,660 | 633,464 |
| 3 | 10.34 | 9.55 | 0.79 | 860,412 | 800,136 |
| 4 | 10.98 | 9.17 | 1.81 | 837,344 | 677,576 |
| 5 | 11.36 | 9.27 | 2.09 | 834,720 | 665,172 |

Median whole-process wall time decreased from **10.86 to 9.18 seconds (15.5%)**
in this workload; each adjacent pair improved. Median GNU time maximum RSS
was 834,720 versus 665,172 KiB. That memory observation is a process-family
high-water value, not aggregate concurrent memory or a general memory-bound
guarantee. Five fixed-order pairs do not establish an effect for arbitrary
firmware, different function/source distributions or other hosts. No elapsed
time threshold is added to CI.

All ten `.dbg`/`.dbg.c` pairs are byte-identical (2,021,584/995,744 bytes).
Each export decompiled 10,008 functions without failure, including startup
functions. The original, historical source/artifacts and complete saved-project
file manifest are unchanged. GNU/LLVM/libdwarf checks and full DWARF
symbol/type/source/address checks for all 10,000 named functions pass, together
with the native GDB source/stepping/runtime oracle. This preserves the existing
`PARTIAL` startup/opaque-type diagnostics rather than suppressing them.

Retained evidence is `line-table-index/build/line-profile/paired.8k_6dt_w/`:
`environment.json`, all command/metric/transcript files, per-install manifests,
`samples.json`, `summary.json` and `validation/`. The exact local driver is
`build/line-profile/paired-benchmark.py`; it reuses the tracked
`src/test/performance/export-benchmark.py` runner/validator. The packages are
`build/line-profile/{baseline,indexed}.zip`. Relevant SHA-256 values are:

```text
baseline JAR  eeba82ac7112cf33f745170d751242a43c8fc2cb36c11b51eac89ca3bb467a10
indexed JAR   d277b63da8890501f563736e7bbf9e9124377c0dd77725145222097f1b4e5803
sidecar       f06dc5d65f409bddbe1d6347935661afb21247417ef7b933f5bfb44dffc1aea6
source        7cdc2754bc7c8a9ae970c3e9640aa736b016ee92cbc4c9cddf4c7d8922fdd0a4
```

To repeat the comparison, first produce baseline/indexed native-inclusive
packages and a saved project using the harness above. Alternate fresh package
installs in a disposable Ghidra copy, outside the timed region. Use one new
fixed output path and the same command for each sample:

```bash
/usr/bin/time -o sample.metrics.json \
    -f '{"elapsedSeconds":%e,"userSeconds":%U,"systemSeconds":%S,"maximumResidentKiB":%M}' \
    "$private_ghidra/Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless" \
    --ghidra-dir="$private_ghidra" --project-dir="$saved_project" \
    --project-name=Benchmark --program=benchmark --input="$original" \
    --output="$fixed_output"
```

Retain each pair's hashes and compare both artifacts against the first sample;
check the input and saved project before/after. Run the existing harness's
`validate` helper against the final byte-identical result. Broader line/source
and target behavior remains covered by the semantic matrix documented in
`VALIDATION.md`, not inferred from this synthetic timing fixture.
