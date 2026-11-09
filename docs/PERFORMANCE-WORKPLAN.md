# Broader workload and profiling acceptance (#74)

Measurement PR159 is integrated as `762dbbd`; compression PR160 is integrated
as `5d81e4f`. Their merge trees match tested `3276396` and `6281660`, respectively.
Measurement CI `41989520429`, performance workflow `41989520582`, and all 15
combined CI jobs in `42010699187` pass. See the requirement-by-requirement
[acceptance record](PERFORMANCE-ACCEPTANCE.md) and
[combined artifact review](evidence/compression-integrated-42010699187.json).
Earlier pending checkpoints retain their historical scope. Final documentation
is reconciled here; issue closure follows protected integration of this record.


Baseline: main `6c776d7415fc5222f7e1314c0c5192454c8aced5`, Ghidra 12.0.3,
Java 21 runtime/bytecode, existing pinned libdwarf 2.3.2. No ABI change is planned.
The user-directed sequence is #74, #108, #116/#114, #112, #110, then #109.
This plan does not reduce any of those issues' acceptance criteria.

## Current Windows measurement and consumer acceptance

**CONFIRMED:** performance workflow `41989520582` at `3276396` passes all five
jobs, including 22 native Windows exports, native validators, source-relocation
controls and independent Linux compiler/Forge GDB journeys. Retained raw review
verifies 717 of 719 protected file hashes, archived program databases, exact
package/runtime/script identity, and both binary JFR recordings. The two private
installation settings files are observed unchanged by the job but unavailable
for independent artifact replay. This measurement result is combined with
production compression acceptance and the protected merges recorded above.
See [the current evidence](evidence/performance-windows-workloads-41989520582.json).

| Windows observation | SQLite baseline / candidate | U-Boot baseline / candidate |
| --- | ---: | ---: |
| Median fresh-process export, seconds | 109.522 / 110.814 | 236.894 / 238.896 |
| Median descendant CPU, seconds | 151.250 / 154.438 | 294.078 / 291.922 |
| Maximum job commitment, bytes | 1,460,269,056 / 1,376,288,768 | 1,438,969,856 / 1,290,035,200 |

Paired candidate-minus-baseline elapsed differences are
`-2.036, -5.224, +7.160, -0.614, -3.846` seconds for SQLite and
`-2.738, +3.354, +2.003, +6.915, +7.271` for U-Boot. Keep this population
separate from the previous run. Neither population proves a general speedup,
zero overhead or memory benefit. Windows commitment is not Linux RSS. Import
times are 85.260/166.275 seconds and remain outside export measurements.

Separate JFR exports observe decompilation/source at 82.276/192.919 seconds,
types/storage at 13.308/28.564, native production at 1.819/15.969 and ELF
packaging at 0.0131/0.0218 for SQLite/U-Boot. Inclusive export times are
99.108/240.744 seconds. These are elapsed observations, not pure CPU; inclusive
and child times must not be added. Independent Java 21 extraction of the binary
recordings matches the hosted phase summaries.

The corrected consumer resolves compiler source to hash-verified private copies,
proves the source path/hash in GDB, lists source, checks globals/selected values,
steps and exits normally for both compiler references and Forge artifacts.
Negative controls reject changed/missing/escaped sources and an incorrect source
archive. U-Boot remains a Linux sandbox with partial recovered knowledge and its
known decompilation timeout. No bare-metal or complete variable-coverage claim
follows from these results.

## Measurements and corpus

- **CONFIRMED retained Windows observer failure:** run `41975183135` completes
  SQLite import and its first baseline export, then stops because PowerShell
  renders the Java 21 banner with SGR color escapes. The retained
  `run.8mva_pvl/sqlite/0-baseline.log` starts with the actual 21.0.13 banner;
  import stderr has the same uncolored version. The observer now removes only
  SGR sequences. Twelve controls cover plain/colored stdout/stderr, missing,
  wrong or conflicting versions, unrelated mentions, missing/duplicate/wrong
  scripts and non-SGR escapes. Local replay verifies the retained runtime
  banner. The corrected full native measurements and consumer now pass as recorded above.
- **CONFIRMED existing corpus:** source-generated scaling fixtures and pinned
  SQLite 3.46.1. Re-run on the current packaged baseline; historical timings do
  not describe the current exporter.
- **CONFIRMED local firmware-code corpus:** U-Boot 2025.01 sandbox, archive SHA-256
  `cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f`.
  Preserve the archive URL, exact configuration, source license, compiler,
  build commands and source/binary hashes. Sandbox executes firmware code on
  Linux but excludes architecture-specific hardware code; it cannot establish
  bare-metal, Cortex-M or general firmware support. See the upstream
  [sandbox description](https://docs.u-boot-project.org/en/latest/arch/sandbox/sandbox.html).
  A successful build alone is not an accepted benchmark.
- **CONFIRMED host measurements:** representative saved-program exports run on
  Linux and Windows using the same production path and pinned ELF inputs.
  Record host-specific measurement boundaries and tool availability. Linux
  replay of Windows artifacts is a consumer check, not a Windows timing result.
- **CONFIRMED measurement protocol:** separate fixture build, import/analysis,
  fresh-JVM exports, validation and debugger costs. Measure wall time, CPU and
  peak memory. Use repeated alternating baseline/candidate pairs for changes;
  retain samples and inconclusive/negative observations. Keep profiling runs
  separate from unprofiled timing populations. Record background load and
  cache limitations rather than claiming controlled hardware.

## Internal phase observations

**CONFIRMED Linux/native Windows observations:** optional JFR `ghidradwarfforge.ExportPhase`
events measure the export operation, decompilation/source generation,
type/storage extraction, native production and ELF packaging. They are outside
the deterministic report/sidecar/source and carry normal-completion status.
Native production includes Java DIE construction, JNA calls, native producer
work and section materialization; it is not a measurement of pure native CPU.
The outer export event contains the child phases. Do not sum inclusive times.
Startup/project opening are outside that event but inside whole-process time.
Time not attributed to a child remains explicitly unattributed.

Acceptance requires real Java 21 event tests (including exception and
cancellation propagation), a real recorded headless export, independent
validator/GDB checks, deterministic profile/unprofiled artifacts, and paired
baseline/candidate runs to quantify instrumentation overhead. JFR samples
and per-process CPU measurements are complementary, not interchangeable.

Local run `build/test-results/sqlite-benchmark/run.kk3l_v4w` completes all
1,539 decompilations on actual Java 21.0.12.1. Two unprofiled exports and a
separate JFR export produce identical sidecar/source bytes. GNU/LLVM and the
pinned strict checker pass; the checker's 828 inherited frame diagnostics are
corroborated against identical original frame bytes, not suppressed wholesale.
GDB checks named DWARF functions, source lookup, raw global values, next/step
and normal exit. The report remains PARTIAL with 12,547 omitted location ranges
and 11 unsupported constructs; the benchmark does not establish complete
variable/signature recovery. Input and program database bytes remain unchanged;
only the two documented Ghidra backup metadata files rotate.

The profiled export observes 24.737s decompilation/source, 7.054s type/storage,
0.619s native production and 0.018s ELF packaging within 32.991s export time;
0.562s remains unattributed. Fresh-process unprofiled samples are 35.24/36.61s.
These are observations on this host, not a speedup claim. U-Boot preparation
overlapped part of the initial run; independent paired measurements follow
without that build load. Baseline package JAR SHA-256:
`80d57bb096febc46b8699d4205481a4c1219c7f59d9070880f72454d67e40b96`;
instrumented candidate:
`cb9e497ba45b41b73310e4b80239d1ccda2974bee73b82a1aab9f6a61f3c3763`.

Retained initial failures are not timing evidence: the first Java 21 build
attempt selected a JRE without `javac`; compilation then used the available
compiler with Java 21 production bytecode, and the standalone phase smoke was
explicitly compiled with `--release 21` and executed on Java 21. The first
private headless setup resolved the shared installation's old script and Java
25 (`run.j2k9kb86`). Giving the private installation its own Utility module and
a complete private Java 21 toolchain corrected discovery. Log checks now verify
the actual JVM version and selected packaged script, not just environment vars.

To inspect one recording (use the `jfr` executable from the selected JDK):

```bash
jfr print --json --events ghidradwarfforge.ExportPhase export.jfr > phases.json
python3 src/test/performance/jfr-phases.py phases.json phase-summary.json
```

The summarizer rejects missing, duplicate, failed, mixed-thread or overlapping
phases; it does not publish a partial recording as a complete phase breakdown.

Five alternating baseline/candidate pairs in
`build/test-results/paired-saved-exports/run.41vnf2fz` pass artifact-byte/count
equality, strict/LLVM/GNU checks, GDB return-value/source/runtime checks and
protected-file checks. All ten logs independently identify Java 21 and the
intended installed script. Baseline times are
35.75/35.01/35.08/34.84/34.73s; candidate times are
35.17/35.25/35.02/34.84/35.35s. Their medians are 35.01 and 35.17s, but the
median within-pair difference is zero and signs vary. This does not establish
a consistent timing effect or a speedup. **CONFIRMED comparison confounder:**
the hosted baseline used Java 21 compilation while this first local candidate
used Java 25 with Java 21-compatible production bytecode. Independent JAR
comparison finds 67 changed shared classes, exceeding the intended producer
change. Artifact equality and runtime checks remain valid, but these timings
cannot isolate instrumentation overhead. Rebuild both variants with the same
Java 21 compiler and repeat the comparison before drawing that conclusion.
Maximum process-family RSS
is 1,183,972 and 1,172,460KiB respectively, with no general memory claim.

Both variants have now been rebuilt with the same full Java 21.0.12.1 JDK.
The rebuilt baseline JAR exactly matches the reviewed hosted baseline above.
The candidate JAR is
`ab67c0d16aeb7738e0991c1a70b92cc7bc728a9600376363b71ba7da57f0aa17`;
all differing shared classes belong to the intentionally changed
`MinimalDwarfSidecarExporter` source. The standard release assembler accepts
the reused, hash/provenance-checked native artifacts; both complete installation
manifests pass (309/310 files). New isolated installation roles preserve the
earlier measured installations. The same-compiler timing rerun passes as recorded below.

The updated automated SQLite harness also passes `run.fml1pwam`: two fresh
exports (median 35.10s), a separate recorded export, runtime/script checks,
automatic phase-summary checks, validators and GDB. Timed validation is
0.06s LLVM, 0.19s strict, and 0.13s GDB; individual GNU views are 0.00–0.03s
at GNU time's hundredth-second resolution. A printed zero is not zero cost.
This new run supersedes manual-only phase extraction as harness evidence.

## Firmware build recipe

**CONFIRMED local build/runtime sanity and corrected exporter acceptance below:**
`build-uboot.py` verifies the pinned archive, preserves compiler reference
DWARF, strips debug data only from a new workload copy, retains the final
configuration and tool commands, and executes an echo command with the built
device tree. It does not install dependencies or touch user target files.
On Ubuntu the build dependencies include GCC/make, bison/flex/m4, swig,
Python development/setuptools support, OpenSSL development headers and
efitools; see the pinned source's `doc/build/gcc.rst` for upstream context.
The workload disables SDL and the capsule creation tool; firmware test code
and its device-tree/signature build dependencies remain present.

```bash
python3 src/test/performance/build-uboot.py --archive /path/to/u-boot-2025.01.tar.bz2
DWARFDUMP=/path/to/pinned/checker python3 src/test/performance/uboot-benchmark.py \
    /path/to/isolated/ghidra /path/to/uboot-build/run.directory \
    --repeats 3 --profile --jfr /path/to/java21/bin/jfr
```

The optional archive argument avoids downloading again; its digest is always
checked. The recipe uses a fixed build timestamp/user/host but does not claim
bit-identical compiler-reference files across different build paths/toolchains.
The benchmark binds each built artifact by digest before import, saves repeated
read-only exports, and separately validates the compiler reference and Forge
runtime behavior. U-Boot's uncurated recovered types are not assumed to equal
compiler debug types. Import/export failures and honest omissions are retained.

**CONFIRMED scoped first firmware results:** `uboot-build/run.tm7eo7ga` builds
and runs the pinned fixture. `uboot-benchmark/run.hw644d9x` imports it in 91.06s;
two exports take 115.20/116.10s. Both and a separate JFR export produce identical
sidecar/source/companion bytes. All 6,375 functions export; 6,374 decompile, with
one timeout retained for `lib_test_alist_has`. GNU/LLVM and strict validation
pass. The profile attributes 94.705s to decompilation/source (including the
timeout), 12.630s to type/storage, 5.271s to native production and 0.016s to ELF
packaging. These are local observations with the initial compiler setup.

The first complete harness run fails its compiler GDB invocation because
shell-disabled argument handling passes the quoted echo command incorrectly.
Corrected behavior replay preserves that failure and redirects only the
inferior's console output, leaving debugger diagnostics independently checked.
The next replay reveals an incorrect oracle assumption: U-Boot's `main` is a
nine-byte `endbr64; jmp sandbox_main` thunk. The existing exporter deliberately
omits uncurated imported thunks and reports `main` as THUNK; its minimal ELF
symbol must not be counted as DWARF coverage. The oracle now explicitly checks
that omission, uses the actual `sandbox_main` body for full-DWARF lookup, and
retains `main` only as an independently known relocation anchor.

`behavior-replay-2` passes compiler argc/argv values and Forge named
`do_echo` breakpoints, actual source ownership, function lookup, raw `gd`
pointer, next/step and normal exit. It also exercises the legitimate same-named
static function/data objects called `do_echo`: function breakpoints work even
though a generic expression lookup selects the data object. Full rerun of the
corrected harness with the Java 21-compiled candidate was then pending; the old
failed run is not relabeled as a fully passing harness run. The full corrected
run subsequently passes as recorded below.

## Confirmed local component acceptance

The same-compiler comparison `paired-saved-exports/run.qbzuwn7x` passes all ten
exports with identical artifact bytes/counts, actual Java 21/runtime-script
observations, independent validators/GDB and protected input/project/module
checks. Medians are 34.96s baseline and 34.98s candidate. The within-pair
candidate-minus-baseline differences are +0.23/-0.22/+0.16/+0.23/+0.21s:
four of five are slower, with a median +0.21s. Retain this small observed cost
and the raw population instead of claiming a speedup or zero overhead.
The additional 100-function five-pair comparison (`run.b7fqns55`) passes,
with medians 2.65s baseline and 2.67s candidate and mixed within-pair signs.
An isolated Java 21 probe reports FlightRecorder.isInitialized() false both
before and after an unrecorded phase hook; it does not support adding a lazy
recorder initialization guard. Neither result establishes zero overhead.
Both use Java 21.0.12.1 compilation and
runtime, with only the intended producer class family and phase utility changed.

The complete corrected `uboot-benchmark/run.1mhp4wmk` passes two exports and a
separate JFR export, byte-identical sidecar/source/companion output, GNU/LLVM/
pinned strict validation, compiler argc/argv and Forge named breakpoint/source/
step/exit checks. Its median is 115.47s, including the unchanged single
decompilation timeout. All 6,375 functions export, 6,374 decompile; the report
remains PARTIAL with 4,497 omitted location ranges and 10 unsupported constructs.
Protected corpus/module/harness bytes remain unchanged; only the documented
two Ghidra backup metadata files change.

The five same-compiler U-Boot pairs (`paired-saved-exports/run.kuxfk4nd`)
subsequently pass ten exports, artifact/report identity, compiler/Forge GDB,
strict validators and protected-file checks. Baseline/candidate medians are
115.66/114.89s; within-pair differences are -0.77/-0.21/-1.34/-0.49/-1.00s.
Maximum process-family RSS is 1,081,636/1,386,068KiB. These observations do not
establish lower memory usage or a general instrumentation speedup; SQLite's
small timing difference has the opposite sign. Both timing populations include
the unchanged U-Boot decompilation timeout, and this host was not dedicated.

The updated 100-function synthetic harness (`export-benchmark/run.thbraean`)
passes repeated deterministic exports, structural checks, runtime observations
and GDB. The real copy-cancellation control (`run.5mcAIuwz`) leaves original
and prior output generation intact. The controlled decompiler-failure harness
passes symbol-only fallback plus strict validation. The sequential local
validation queue terminates with `complete 0`. Hosted acceptance and the rest
of #74 remain pending; these tests do not cover Windows workload measurements.

## Windows measurement boundary

**CONFIRMED native Windows controls at `61e7c1d`:** `windows-measure.c` is a test-only
launcher, not part of the installed extension. It creates a suspended process,
assigns a kill-on-close Job Object before resuming it, waits for the entire job,
and records cumulative user/kernel CPU plus peak job/process memory commitment.
It uses a restricted inherited-handle list, exclusive log creation, a bounded
timeout/cleanup period and an observed 256MiB-per-stream output limit. The 10ms
membership polling is included in wall time. Launcher CPU itself is excluded.

Windows peak commitment (`peakJobCommitBytes`, `peakProcessCommitBytes`) must
not be compared as if it were Linux GNU time RSS. Microsoft documents the
[job accounting interface](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
and the continually tracked
[peak memory counters](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information).
Native controls launch a child that outlives its root, commit 64MiB while touching
one page, consume independently measured child CPU, and test timeout cleanup,
failing/missing executables, argument transport and preservation of existing logs.
Run `41971951834` passes all native controls. The first run `41971376880`
failed its incorrect exact-two-process oracle: the job reports four processes.
The corrected oracle accepts additional job support processes and retains the
independent child CPU, committed memory, marker, zero-live-member and child-death
checks. The successful descendant case records 0.21875s job CPU and 69,353,472
bytes peak job commitment; timeout terminates every job member. Raw artifact
hashes and all case outcomes are in
`docs/evidence/performance-windows-controls-20261105.json`.

**CONFIRMED native Windows workload pipeline and corrected hosted consumer:** `prepare-host-corpus.py`
builds pinned SQLite and U-Boot ELFs and retains their corresponding source.
`fetch-ci-packages.py` selects exact-commit artifacts from the sole production
CI workflow and verifies their archive digests; it does not rebuild natives.
`windows-workloads.py` imports each input once and measures five alternating
baseline/candidate pairs plus a separate JFR run, with artifact/report identity,
protected-file checks and native validators. `host-consumer.py` independently
validates the unchanged Windows artifacts and runs compiler/Forge GDB behavior
on Linux with explicit source relocation and PIE bias. Native workload and
validator jobs now pass at `cfc212c`; the missing compiler-source relocation
failure and its local correction are recorded in the current checkpoint above.

The first workload run `41973112213` passes corpus/package/control jobs and
completes its first Windows import, then fails the mandatory runtime observation:
Ghidra's Windows launcher does not print the selected JVM version by default.
The log contains no version evidence; environment variables alone are not a
replacement. The corrected workflow configures both private installations with
the selected Java 21 override and `VMARGS=-showversion`, which `LaunchSupport`
passes to the actual Ghidra JVM. It protects those configuration files during
measurement and retains the same runtime/script checks. The corrected native
workload/consumer run remains required.

## Selected implementation and explicit deferrals

- **CONFIRMED opt-in zlib production implementation integrated through PR160.**
  The earlier private-copy experiment reduced whole-sidecar size 65.62%/61.74%.
  Separate production comparisons reduce SQLite/U-Boot sidecars 65.39%/60.11%.
  Keep these populations distinct. The default remains uncompressed, using
  standard target-class/endian ELF compression headers and Java zlib without a
  new native ABI. Actual exporter tests cover deterministic/decompressed equality,
  cancellation, validators/GDB and both host paths. Combined CI `42010699187`
  passes and PR160 is merged as `5d81e4f`. See [production evidence](ELF-COMPRESSION.md). Zstd is
  deferred because it requires another production codec or external-tool contract.
- **DEFER built-in GDB indexes; reject the tested `.debug_names` route.** The
  valid GDB index adds 4.31%/1.99% to these artifacts and saves only about
  2.1/6.0ms of measured initial load, with slightly higher first-lookup times.
  Revisit when a larger or multi-CU consumer workload demonstrates sufficient
  benefit; do not weaken validators for the rejected index.
- **DEFER string/address indexing in favor of the selected compression work.**
  Additional string or exact-list deduplication has no opportunity in these
  samples. Address indexing has real size potential, but requires new address
  tables, CU bases and index forms plus their target/consumer tests. Compression
  already reduces the repeated address bytes while preserving all existing
  decompressed DWARF. This is a priority decision, not a claim that address
  indexing cannot improve performance.
- Incremental caching and bounded parallel decompilation are deferred in the
  final decision section below, based on both hosts' phase/resource results and
  the analyst-change invalidation, ordering, memory and cancellation contracts.

Any selected implementation requires semantic/byte comparisons, strict
GNU/LLVM/pinned-libdwarf validation, source/type/location and applicable GDB
behavior, unchanged originals, cancellation/failure controls, and bounded
resources. Preserve negative measurements; do not silently replace a difficult
workload with an easier one to obtain a passing result.

## Final caching and parallelism decisions

**CONFIRMED decisions for #74: defer both implementations.** The complete local
and native Windows profiles confirm that decompilation/source dominates elapsed
export time. They establish an opportunity, not the correctness or resource
cost of either optimization.

`DeterministicSourceBuilder` gathers source, token locations, resolved calls and
static-local evidence together, resets the decompiler on failure and disposes it
in `finally`. Allocation callbacks also depend on mapped callees and saved call
overrides. A function-byte hash alone cannot validate a cached result.

| Candidate | Decision and evidence needed to revisit |
| --- | --- |
| Incremental caching | **DEFER.** Repeated unchanged-project benchmarks do not measure the frequency or locality of real analyst edits. Require mutation traces and a versioned invalidation contract for program context, function bodies, namespaces, signatures/storage, canonical types, callers/callees, saved bindings and decompiler/ABI options. Cache source and location/type evidence together, account for output-directory-dependent line tables, and never cache a timeout as completed recovery. |
| Bounded parallel decompilation | **DEFER.** Both hosts show dominant decompilation, including U-Boot's known 60-second timeout, but no controlled worker-count experiment proves a net benefit within the memory budget. Require independent decompilers, a consistent program view, deterministic assembly/diagnostics, aggregate worker-memory measurement, per-function failure isolation, and cancellation that reaps every native worker. Windows commitment and Linux process-family RSS cannot stand in for aggregate parallel memory. |

Opt-in zlib compression remains the selected bounded production optimization,
implemented and measured separately in PR160, now merged as `5d81e4f`. GDB indexes, zstd and
string/address indexing retain the explicit deferrals above; the tested
`.debug_names` route remains rejected on its actual validator failure. These
decisions resolve the evaluation requirement without claiming unimplemented
speedups. Compression acceptance, complete implementation gates and normal protected
integration now pass. The corrected hosted consumer passes. Final documentation
is reconciled in the acceptance record.

## Integration gate

**CONFIRMED:** measurement PR159 and compression PR160 pass their required gates,
raw-artifact reviews and normal protected merges. The exact revision/tree and
requirement mapping are in [PERFORMANCE-ACCEPTANCE.md](PERFORMANCE-ACCEPTANCE.md).
This documentation change records final acceptance; issue closure follows its
normal protected integration. Historical failures and inconclusive measurements
remain retained, and no later goal issue or release is included.
