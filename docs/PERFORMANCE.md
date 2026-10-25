# Export performance measurements

## Representative SQLite workload

**CONFIRMED locally (2026-10-25):** a source-built SQLite 3.46.1 workload
provides the first complex application measurement, separately from the
synthetic scaling experiment below. It uses the pinned
[amalgamation release](https://www.sqlite.org/releaselog/3_46_1.html), checks
the archive SHA-256, published source SHA3-256 and source ID, and retains
downloaded sources only in ignored build results. SQLite's deliverable is
[public domain](https://www.sqlite.org/copyright.html). The small repository
fixture opens an in-memory database, inserts 100 rows, queries their count
and sum, and verifies 100/5050 before normal exit.

```bash
DWARFDUMP=/path/to/validation/dwarfdump \
    python3 src/test/performance/sqlite-benchmark.py /path/to/ghidra \
    --repeats 3 --profile
```

This requires the tools listed below plus `curl` and a JFR-capable JDK.
The fixture is Linux x86-64 non-PIE, GCC `-O2 -g0`, `SQLITE_THREADSAFE=0`,
with ELF names retained and no compiler DWARF. No analyst curation is used.
The runtime was Ghidra 12.0.3 with the formal-return correction from
`e588d607`, JAR SHA-256
`a7bb363ef5eb1944b917f43f4c8e93a960de2144ae77f9e6381a3134183ef180`.
The headless launcher actually used OpenJDK 25.0.4.1; caller `JAVA_HOME`
does not establish the launched JVM version.

| Measurement | Observation |
|---|---:|
| Import/analysis | 23.55 seconds |
| Three fresh-JVM exports | 33.64 / 33.93 / 34.06 seconds |
| Median export | 33.93 seconds |
| Largest export process-family RSS | 900,900 KiB |
| Decompiled / failed functions | 1,539 / 0 |
| Original / sidecar / synthetic C bytes | 1,096,304 / 5,610,928 / 4,159,464 |

These are observations of one workload and host, not a speedup comparison.
All three timed exports and a separate profiled export produced identical
sidecar/source hashes. The original ELF is unchanged. LLVM reports no errors;
strict libdwarf validation corroborates all 828 inherited frame findings
against the original and reports zero unexplained errors. GDB finds full DWARF
symbols at the independently observed addresses for four selected functions,
lists synthetic source, checks the raw count/sum globals, executes `next` and
`step`, and observes normal exit. Export status remains `PARTIAL` with the
omission diagnostics retained.

**CONFIRMED limitation:** these basic GDB checks do not establish complete
signature recovery. GDB displays `benchmark_checkpoint` as `void(void)`:
the listing has a DEFAULT `undefined` return, while a separate read-only
decompiler probe recovers `int`. The exporter currently uses the listing type.
Correctly preserving recovered returns without overriding analyst types is
a separate correctness follow-up; the original unsigned C declaration must
not be claimed as recovered merely because the result is positive.

Evidence is retained in the `sqlite-performance` worktree under
`build/test-results/sqlite-benchmark/run.lxrrlupv`. The original harness reached
all measurements, validators and GDB checks, then failed its overly broad
whole-project byte assertion: Ghidra rotated only `SQLite.rep/idata/~index.bak`
and `~journal.bak` even during read-only opens. The updated postcondition
reports those exact backup paths and rejects every other changed project file.
A pure replay checks the retained before/after hashes, unchanged executable,
program data, module, original harness snapshot and fixtures; a changed
database negative control is rejected. Its `observation-review.json` SHA-256
is `45e6841da629b59cd659216d4fb6e7f93806d163081faa94ef80a18e3292fc46`.
This is not a claim that the revised full harness ran again. Original failures
and snapshots remain available. Earlier `run.q7yrttbc` failed before the JFR
export because startup logging polluted Ghidra's launcher JDK-path probe;
`-Xlog:jfr+startup=off` corrects that profiling setup.

The separately profiled export has 1,075 Java execution samples: 633 have
type/storage extraction on the stack, 265 decompiler-interface work, 64 DWARF
construction, 16 synthetic-source work and 97 other work. Full-depth stacks
place the frequent `HashMap.getNode` samples under Ghidra symbolic stack-depth
analysis. This identifies a candidate for investigation, not a measured
optimization. Another 1,241 native-method samples largely show process waits
and pipe reads. Samples are not phase wall times and do not attribute CPU in
the external C++ decompiler process. The full-depth JFR rendering and bounded
summary are in `build/sqlite-performance-review`; no export was rerun merely
to increase the rendering's stack-depth limit. Broader firmware/host workloads
and further optimization remain **PLANNED**.

**CONFIRMED:** the initial Linux x86-64 scaling harness measures import/analysis
separately from repeated exports of the same saved Ghidra program. It changes
no production exporter behavior. Run it with a native-inclusive installation:

```bash
python3 src/test/performance/export-benchmark.py /path/to/ghidra \
    --counts 100 1000 10000 --repeats 3
```

The harness requires GCC, GNU `time`, `nm`, `readelf`, LLVM `llvm-dwarfdump`,
the repository-built validation `dwarfdump`, and Python-enabled `gdb-multiarch`.
Set `DWARFDUMP` to that executable when it is not first on `PATH`. It retains generated
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
sidecar/source files, GNU/LLVM checks and strict libdwarf summaries with exact
original-frame corroboration through `check-dwarfdump.py`, and a full GDB DWARF function
symbol with synthetic-source association and the original address for every
generated function. An inherited minimal ELF symbol alone cannot satisfy that
check. GDB also lists source, stops at the first function, checks the initial
global value, steps and runs to normal exit. Broader signature, variable-value,
architecture and PIE acceptance remains in the existing semantic integration
matrix.

## Completed representative harness validation

**CONFIRMED locally (2026-10-25):** after the postcondition correction, the
complete revised SQLite harness passed fresh import, two timed exports, one
separate JFR export, validators, GDB, deterministic artifacts and exact input/
program-data preservation. Case `run.zf2690wu` uses the separately tested
scalar-return candidate JAR
`f333584802dd22ec91fcb8607035f7fadaf468077d1b631a3543604c73b26d8a`
from the `recovered-default-returns` worktree. Its summary SHA-256 is
`6a3fc5d1f683ca34ad2271d4913f32311f5e15c175a148f0d470edd2d00ec017`.
The same executable hash is retained; 1,539 functions decompile without
failures, the synthetic source remains identical to the original measurement,
and all three exports within this new run match byte for byte. Only the
reported Ghidra index/journal backups rotate; protected module/harness inputs
and program data remain unchanged. Strict validation corroborates 828 frame
findings with zero unexplained errors.

This new two-sample median is 33.965 seconds with maximum observed RSS
896,096 KiB; import is 24.08 seconds. These are a fresh harness-validation
observation of a different runtime, not replacements for the original three
samples or a controlled speed comparison. The first full-run failure remains
historical and the pure replay receipt keeps its original scope. The dedicated
return-recovery regression and separate retained-program replay establish
return-type/value behavior; this benchmark's GDB checks retain their narrower
explicit scope. The previously observed void-return gap is corrected locally
in that candidate and awaits its own hosted gate.

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
their `validation-full-symbols` directories. Their original exit-zero libdwarf
checks did not enforce numeric error summaries, so those historical runs do
not establish clean libdwarf validation. The retained paired 10,000-function
result is independently revalidated below; the earlier scaling timings are
not new measurements of the merged branch. Export status is `PARTIAL` for
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

**HISTORICAL timing evidence:** five baseline/indexed pairs alternated on the
same saved 10,000-function project and unchanged input. The baseline was `ddad598`; the indexed build
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
file manifest are unchanged. GNU/LLVM checks and full DWARF
symbol/type/source/address checks for all 10,000 named functions passed, together
with the native GDB source/stepping/runtime oracle. The old libdwarf log exited
zero but reports 11,833 errors, including 13 line-table errors; the earlier
claim of clean libdwarf validation is withdrawn. The timed measurements and
byte-equality evidence remain valid. The fresh validation below preserves the
existing `PARTIAL` startup/opaque-type diagnostics rather than suppressing them.

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

## Validation after the strict-checker merge

**CONFIRMED locally:** normal integration of strict-checker commit `99845c7`
leaves the indexed planner unchanged from `48bb8f2`; no 10,000-function timed
export was repeated. The line-table, synthetic-source and range-list smokes
and `buildExtension` pass on the merged tree. A fresh ten-function, two-export
harness rehearsal passes byte equality, strict validation and GDB in
`build/test-results/export-benchmark/run.3h1im338`. That concurrent rehearsal
is functional evidence, not a speed comparison.

The two-patch standalone checker correctly refused the retained paired
10,000-function artifact: its unchanged original and sidecar each report
10,002 inherited frame-length diagnostics, but upstream retained/printed only
49 messages. Equal counts are insufficient corroboration. A third,
checksum-pinned validation-only patch raises the bounded capacity to 65,536,
uses checked heap storage and fails explicitly on overflow or allocation
failure. The shipped producer/consumer libraries are unchanged; see
`support/validation/README.md` for the limit and failure controls.

With complete diagnostics, the retained sidecar passes GNU, LLVM, the strict
checker and the full 10,000-function GDB oracle. All **10,002** reported errors
are matched by exact same-version original diagnostics and unchanged frame
bytes/ELF identity; every other category and uncorroborated count is zero.
This is explained inherited input evidence, not an error-free original claim.
All ten recorded artifact hashes still match, and the original, historical
artifacts and saved-project manifest remain unchanged. The earlier strict
failure is retained alongside the successful replay at
`build/line-profile/merged-verification/retained-10k-complete/` and
`retained-10k-result.json`.

The merged installed exporter also passes ARM32 ARMv7 hard-float ET_EXEC, PIE
and shared-object export, GNU/LLVM/strict checks, and QEMU/GDB value, source,
stepping and normal-exit checks. All three strict reports have zero errors.
A fresh ET_EXEC import/export produces byte-identical sidecar/source files;
input hashes remain unchanged. The isolated GCC 13.3 toolchain/sysroot is
recorded in `build/line-profile/merged-verification/arm32-*.log`; no system or
user Ghidra installation was modified. Historical four-profile results are
recorded separately in `docs/VALIDATION.md`.

Final standalone-validator bundle `build/line-profile/validation-tool-final`
passes its manifest and exact bundled-source comparisons. Its executable
SHA-256 is `c6e46836af587bc34e214dd04036a3c796b87ae4afe8a0d0ec006b427b376767`.
The full capacity/allocation/static-rollback regression passes in
`build/test-results/dwarfdump-diagnostic-capacity/run.kwbald9k`; a final strict
replay retains all 10,002 messages in
`build/line-profile/merged-verification/retained-10k-final.txt`. Parser controls,
line/extended-program negative controls, release-package regression, workflow
lint and architecture-isolation checks also pass locally.

The complete merged hosted matrix was pending at this local checkpoint; its
subsequent acceptance is recorded below.
Representative complex application/firmware workloads and finer phase
profiling remain **PLANNED**; the index has no general speed or memory guarantee.

## Hosted validator configuration correction (2026-10-24)

PR #24 head `d12be10` failed the native Linux job in run `40064815083` before
the first 50-frame capacity check completed: the standalone consumer lacked
`dwarfdump.conf`, printed an error, suppressed frame access and exited zero.
The strict helper rejected that result. Local distro configuration had hidden
the bundle dependency; this is not a changed planner or benchmark result.
The original log and digest-verified artifact are retained under
`build/hosted-capacity-review/run-40064815083/`.

The follow-up packages the pinned upstream config and an explicit-path launcher,
with separate real-executable and launcher/config provenance. Its relocation,
hostile-CWD, missing/altered config and option-alias controls are described in
`support/validation/README.md`. Full capacity/allocation tests remain mandatory;
no thresholds, frame assertions or diagnostic rules are weakened. The corrected
hosted runs below close this configuration defect. The
corrective alpha.2 branch and shipped native libraries are unaffected.

## Hosted acceptance and main integration (2026-10-24)

**CONFIRMED:** component head `b0bcdb8` passed all twelve jobs in run
`40065823442`. Combined head `9612655` then passed all twelve jobs in
[run 40068401197](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/40068401197),
including native Linux configuration/capacity/allocation controls, all five
target lanes and the Windows host. PR #25 merged normally as tree-identical
`befce2c`. The separate main-push run was still pending at the documentation
checkpoint; [VALIDATION.md](VALIDATION.md#combined-hosted-acceptance-and-main-integration-2026-10-24)
records the exact source, job set and scope.

These runs establish integrated planner/tool acceptance without repeating the
timed 10,000-function experiment. The earlier local timings, byte equality and
fresh strict replay retain their original measurement boundaries; no new
hosted timing or general memory/speed claim follows. The missing-config failure
and previously incomplete diagnostic evidence remain recorded above.
Representative complex-binary workloads and further phase profiling remain
**PLANNED**. This feature is in main but excluded from published alpha.2.
