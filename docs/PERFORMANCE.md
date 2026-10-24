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

**PLANNED:** profile individual export phases and add representative complex
application/firmware workloads before selecting caching, parallel decompilation,
compression or indexing. These process totals do not identify which phase
dominates or establish that any proposed optimization would help. No speed or
size optimization is claimed, and P3.5 remains partially complete.
