# Broader workload and profiling acceptance (#74)

Baseline: main `6c776d7415fc5222f7e1314c0c5192454c8aced5`, Ghidra 12.0.3,
Java 21 runtime/bytecode, existing pinned libdwarf 2.3.2. No ABI change is planned.
The user-directed sequence is #74, #108, #116/#114, #112, #110, then #109.
This plan does not reduce any of those issues' acceptance criteria.

## Measurements and corpus

- **CONFIRMED retained Windows observer failure:** run `41975183135` completes
  SQLite import and its first baseline export, then stops because PowerShell
  renders the Java 21 banner with SGR color escapes. The retained
  `run.8mva_pvl/sqlite/0-baseline.log` starts with the actual 21.0.13 banner;
  import stderr has the same uncolored version. The observer now removes only
  SGR sequences. Twelve controls cover plain/colored stdout/stderr, missing,
  wrong or conflicting versions, unrelated mentions, missing/duplicate/wrong
  scripts and non-SGR escapes. Local replay verifies the retained runtime
  banner; Windows path identity and the full measurements require a fresh run.
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
- **PLANNED host coverage:** repeat representative saved-program exports on
  Linux and Windows using the same production path and pinned ELF inputs.
  Record host-specific measurement boundaries and tool availability. Linux
  replay of Windows artifacts is a consumer check, not a Windows timing result.
- **PLANNED reproducible statistics:** separate fixture build, import/analysis,
  fresh-JVM exports, validation and debugger costs. Measure wall time, CPU and
  peak memory. Use repeated alternating baseline/candidate pairs for changes;
  retain samples and inconclusive/negative observations. Keep profiling runs
  separate from unprofiled timing populations. Record background load and
  cache limitations rather than claiming controlled hardware.

## Internal phase observations

**CONFIRMED locally on SQLite; hosted acceptance pending:** optional JFR `ghidradwarfforge.ExportPhase`
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

**PRESENT, UNVERIFIED real Windows workload pipeline:** `prepare-host-corpus.py`
builds pinned SQLite and U-Boot ELFs and retains their corresponding source.
`fetch-ci-packages.py` selects exact-commit artifacts from the sole production
CI workflow and verifies their archive digests; it does not rebuild natives.
`windows-workloads.py` imports each input once and measures five alternating
baseline/candidate pairs plus a separate JFR run, with artifact/report identity,
protected-file checks and native validators. `host-consumer.py` independently
validates the unchanged Windows artifacts and runs compiler/Forge GDB behavior
on Linux with explicit source relocation and PIE bias. No Windows workload
performance claim is accepted until these new jobs actually pass.

The first workload run `41973112213` passes corpus/package/control jobs and
completes its first Windows import, then fails the mandatory runtime observation:
Ghidra's Windows launcher does not print the selected JVM version by default.
The log contains no version evidence; environment variables alone are not a
replacement. The corrected workflow configures both private installations with
the selected Java 21 override and `VMARGS=-showversion`, which `LaunchSupport`
passes to the actual Ghidra JVM. It protects those configuration files during
measurement and retains the same runtime/script checks. The corrected native
workload/consumer run remains required.

## Optimization decisions still required

For each candidate below, document measured motivation, compatibility/resource
cost, and an explicit implement/defer/reject decision. The local experiments
below support a first selection; production implementation and full host
acceptance remain incomplete.

| Candidate | Evidence needed |
|---|---|
| `.debug_names` / GDB index | Consumer load/lookup cost and stale-index handling |
| DWARF compression | Artifact size, production cost, consumer/validator compatibility |
| String/address indexing | Actual section duplication/size and lookup/serialization cost |
| Incremental export caching | Repeated work cost and reliable invalidation for analyst changes |
| Bounded parallel decompilation | External decompiler CPU/wait cost, memory, ordering and cancellation |

### Confirmed local consumer experiments

`consumer-candidates.py` uses private copies, two deterministic generation runs,
unchanged decompressed core DWARF sections, strict/LLVM/GNU checks, runtime GDB
and five rotating fresh-GDB samples with the index cache disabled. U-Boot also
checks its compiler reference. The baseline remains untouched. The full local
evidence is `docs/evidence/performance-candidates-local-20261105.json`.

| Workload / variant | Sidecar bytes | Median load / first lookups | Whole GDB process |
|---|---:|---:|---:|
| SQLite baseline | 5,638,224 | 4.93 / 9.47ms | 0.08s |
| SQLite zlib | 1,938,296 | 7.44 / 13.58ms | 0.08s |
| SQLite zstd | 1,711,032 | 5.29 / 11.23ms | 0.07s |
| SQLite GDB index | 5,881,272 | 2.80 / 10.21ms | 0.07s |
| U-Boot baseline | 17,029,464 | 11.75 / 25.54ms | 0.10s |
| U-Boot zlib | 6,515,992 | 17.14 / 35.12ms | 0.11s |
| U-Boot zstd | 6,022,128 | 15.08 / 28.66ms | 0.10s |
| U-Boot GDB index | 17,367,904 | 5.76 / 27.27ms | 0.09s |

These are warm-cache, single-host observations; hundredth-second whole-process
resolution cannot justify fine-grained speed claims. Zlib generation takes
0.08–0.09s for SQLite and 0.16–0.18s for U-Boot. The core decompressed DWARF
bytes remain identical. No Windows compression or LLDB compatibility is claimed.

Retained failures matter to the selection:

- GNU BFD `objcopy` refuses to rewrite the matched non-loadable SQLite sidecar
  with a PHDR/LOAD diagnostic. `run.na9a9vlq` is failed, including its unnecessary
  baseline rewrite. LLVM 18.1.3 `llvm-objcopy` supports the tested copies; the
  corrected baseline is not rewritten. Do not recommend an untested GNU
  postprocessing command for these artifacts.
- The older local checker lacks zlib/zstd support; `run.pvr5w_h6` retains those
  failures. The exact-head CI checker from run `41973112217`, downloaded with
  archive digest and complete manifest verification, accepts both compressed
  variants in `run.pd7izo2k` and `run.2wrbht7k`.
- GDB-generated `.debug_names` fails LLVM verification on both workloads,
  including an unexpected `DW_FORM_udata` for `DW_IDX_parent`. No timings or
  compatibility claim are accepted for this candidate. The supported index
  generation interfaces are described in the
  [GDB manual](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Index-Files.html);
  the failure is an observed limit of the tested producer/consumer combination.

`section-inventory.py` additionally finds zero duplicate strings and zero exact
duplicate location lists in either artifact. Location-list address operands
occupy 2,473,856 bytes (SQLite) and 7,511,056 bytes (U-Boot), with 19,260 and
76,793 unique addresses. Those counts establish repetition, not the final size
or speed of an indexed implementation.

### Selected next implementation and provisional deferrals

- **Selected: opt-in zlib section compression**, integrated only after this
  measurement component is accepted. The observed private-copy whole-sidecar reduction is 65.62% and
  61.74%, with modest measured generation cost. Keep the default uncompressed;
  use the standard ELF compressed-section representation and Java's existing
  zlib implementation rather than introducing another native ABI. Require
  target class/endianness handling, cancellation, deterministic output,
  cross-architecture validators/GDB, and Linux/Windows packaged execution.
  The production candidate now passes the local correctness evidence and both
  five-pair/two-profile workloads in `ELF-COMPRESSION.md`, with 65.39%/60.11%
  smaller sidecars and slightly higher median elapsed times. The Windows GUI
  and consumer replay pass with artifact review; complete exact-head CI and
  integration remain pending. Zstd remains
  deferred because its additional measured reduction would require another
  production codec dependency or external tool contract.
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
- Incremental caching and bounded parallel decompilation still require final
  decisions after the Windows phase/resource results and an explicit review of
  analyst-change invalidation, ordering, memory bounds and cancellation.

### Caching and parallelism design review

**CONFIRMED code inspection; provisional defer recommendation:**
`GhidraSyntheticSource.decompileDetailed` creates one decompiler per export,
visits functions in address order and retains token mappings, recovered
signatures and static-local evidence together. It resets the decompiler after a
failed function and disposes it in `finally`. `GhidraAllocationDecompiler` also
reads mapped callee symbols and saved call overrides during callbacks. Therefore
a hash of one function's bytes is insufficient to validate a cached result.

| Candidate | Required contract before implementation | Present evidence and recommendation |
|---|---|---|
| Incremental caching | Versioned fingerprints of program bytes/context, function bodies, symbols/namespaces, types and their identity, signatures/storage, caller/callee overrides, persisted analyst bindings, target/ABI and decompiler options/version. Invalidate dependent callers and token/type/location evidence together. Handle output-directory-dependent line tables separately. Do not permanently cache timeouts as completed recovery. | Repeated unchanged-project exports dominate these benchmark samples by construction; this does not measure the frequency or locality of real analyst edits. No complete persistent invalidation contract is implemented. Provisionally defer until mutation-heavy traces and positive/negative invalidation fixtures justify the additional state. |
| Bounded parallel decompilation | Independent decompiler instances, a consistent analysis view, deterministic assembly and diagnostics, and explicit worker/process memory limits. Preserve allocation callbacks and per-function failure isolation. Cancel and reap every worker, including native decompilers, on cancellation or publication failure. | Decompilation dominates both local profiles, but U-Boot includes a single 60-second timeout. Overlapping other functions might hide some of that time; this is an unmeasured opportunity. Current GNU-time RSS is not aggregate worker memory. Provisionally defer until a controlled worker-count experiment measures total memory, order equivalence and cancellation under the supported heap budget. |

Neither candidate is rejected as intrinsically unsafe or unhelpful. The current
production change targets demonstrated artifact-size cost without introducing
either cache invalidation or concurrent extraction. Finalize these decisions
against the complete Windows workload/resource observations; do not turn this
design review into an implementation or a speedup claim.

Any selected implementation requires semantic/byte comparisons, strict
GNU/LLVM/pinned-libdwarf validation, source/type/location and applicable GDB
behavior, unchanged originals, cancellation/failure controls, and bounded
resources. Preserve negative measurements; do not silently replace a difficult
workload with an easier one to obtain a passing result.

## Integration gate

**PLANNED:** document datasets, versions, commands, all samples and retained
artifacts; reconcile PROJECT_CONTEXT/TODO; review the final source and package;
pass enforced exact-head CI; integrate through a normal protected merge.
Component PRs must not auto-close #74. The issue remains open until all of its
remaining requirements are implemented or explicitly resolved with evidence.

### Acceptance audit while measurements run

| Issue requirement | Evidence and remaining work |
| --- | --- |
| Pinned representative workloads | **CONFIRMED locally:** source-built SQLite 3.46.1 and U-Boot 2025.01 sandbox, with archive hashes, build configuration and compiler references. Sandbox covers firmware code on a Linux host; it does not establish bare-metal support. Shared pinned Windows corpus builds successfully. |
| Repeated wall/CPU/memory and phase measurements | **CONFIRMED locally:** five alternating same-compiler pairs for both workloads, plus separate JFR recordings; import and validation are outside export timing. **PRESENT, UNVERIFIED:** complete Windows workload measurements and Linux consumer replay. Native Windows accounting controls pass; commitment and Linux RSS remain distinct. |
| Explicit optimization choices | Zlib is selected; zstd, GDB indexes and string/address indexing have documented deferrals; the tested `.debug_names` route is rejected on validator evidence. Cache/parallel design review is present, with final decisions pending Windows observations. |
| Selected production optimization | **CONFIRMED:** 25 target cases, 75 packaged exports, identity/equivalence/determinism, validators and GDB; production cancellation/retry; Linux GUI; scoped Windows GUI and consumer review. Both production five-pair/two-profile workload comparisons pass: SQLite 65.39% smaller, U-Boot 60.11% smaller; median elapsed time is slightly higher for both. The corrected full CI gate remains pending. |
| Preservation and honest recovery | Protected input/project/module hashes and report comparisons are checked. Existing omitted locations and the U-Boot decompilation timeout remain visible; compression does not claim to recover them. |
| Documentation and integration | Local evidence and reproduction commands are recorded in `ELF-COMPRESSION.md` and its linked JSON evidence. PR159 must pass its required and performance gates plus artifact review before integration; stacked PR160 then requires retargeting and a fresh protected gate. Neither PR alone closes this issue. |
