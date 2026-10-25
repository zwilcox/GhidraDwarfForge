# Resolve stack depths only for exported stack locations

**CONFIRMED locally:** deferring unnecessary instruction-level stack analysis
preserves byte-identical artifacts in paired SQLite and 10,000-function exports.
The full five-target and both-host CI gate remains required before integration.

`GhidraTypeGraph` previously constructed a `CallDepthChangeInfo`-backed stack
profile for every selected function. The profile is only consumed when an
accepted listing variable has `StackStorage`. Register, unavailable and newly
inferred name/type-only parameters do not need it.

The extractor now creates the profile at the first parameter or local that
actually needs stack-relative location ranges, then shares it within that
function. It still uses the same profile builder and location/lifetime proofs.
Parameters with a proven register prefix do not invoke the unused stack path.
No ABI rule, stack-depth calculation, native API, location expression or source
mapping policy changes.

The pinned Ghidra 12.0.3 `CallDepthChangeInfo` implementation was inspected in
`Ghidra/Features/Base/lib/Base-src.zip`. Its selected constructor initializes
private depth/change maps and performs symbolic flow analysis; it does not need
to be run to establish register-only or explicitly unavailable locations.

## Paired measurements

Each comparison uses fresh exporter JVMs, the same copied saved program, the
same original binary and output paths, and alternating AB/BA pair order.
Every sample must produce the exact same sidecar and synthetic-source bytes.
Import, validation, package installation and GDB are outside the timed region.
GNU time's maximum RSS is a process-family high-water measurement, not aggregate
concurrent memory. These are warm-cache observations on one development host;
other host activity is uncontrolled.

Baseline JAR:
`5299b00be591544b604068e2464165c91b01eb8ee0a4c97045915f8adc180e89`.
Candidate JAR:
`4a7f2af59befdc0ef589774b483da1e5ab56da11e225febf175afa105b6a94a1`.
Both include the same recovered-return and parameter changes. These comparisons
must not be mixed with older SQLite measurements using a different exporter.

| Workload | Pairs | Baseline median | Candidate median | Observation |
| --- | --- | --- | --- | --- |
| SQLite 3.46.1, 1,539 functions | 5 | 34.76 s | 34.10 s | Small difference; overlapping samples do not establish a general improvement |
| Synthetic 10,000 functions | 5 | 9.99 s | 9.37 s | About 6% lower median on this fixture |

The synthetic run observes maximum RSS of 750,808 KiB versus 509,344 KiB.
This is not a memory guarantee for other workloads. SQLite still needs stack
profiles for many functions, so this change has limited effect on its dominant
analysis work. No broader firmware or Windows timing claim follows.

The first SQLite run `run.6s3z_8xv` completes all ten timed exports, exact byte
comparisons and validators, then fails its final clean-GDB-output check because
`step` enters libc's `printf`, whose source is absent locally. The retained
failure is not a passing full harness. A corrected same-artifact replay checks
`next` and `step` inside the exported checkpoint, captures the ordinary returned
value 5150, and exits normally with no diagnostics. The original harness bytes
are retained and matched to the pre-run hash. Measurement/replay review receipt:
`6ca2135931d3ce8ead1db3d1e5330c0cdf007574ff02c2fa787852c9e39a92b0`.

A fresh corrected full SQLite run, `run.yc13cf_m`, passes two alternating pairs,
validators, GDB and preservation checks. Its medians are 34.725 and 34.155
seconds; these validation samples do not replace the first five-pair population.
Receipt: `1b32f6ab579ed9a829a4591e5d6c4a43e0cc19ee1d42af3a82512255f1bf5b69`.
The synthetic five-pair run `run.8qosh8_g` passes in full; receipt:
`f5db9e039ea1d83fef63d8565df334c73dfa9d29e934b936207f1ca81b92b248`.
All evidence is under the `lazy-stack-profiles` worktree's ignored test results.

Both workloads pass GNU/LLVM/strict DWARF validation and GDB behavior, including
real source lookup and execution. SQLite's 828 and the synthetic fixture's
10,002 inherited frame findings are corroborated against their originals;
unexplained errors are zero. Protected original files, reference projects,
installed modules and harnesses stay unchanged. Only the copied test projects'
two explicitly reported backup metadata files may rotate.

## Storage regressions and reproduction

Real ProgramDB storage/signature checks pass, including dynamic parameter
storage (154), recovered parameters (550), recovered returns (645), formal
returns (312), first-use, register aliases/copies and composite prefixes (469).
Five focused installed-package suites pass on actual Java 21, receipt
`bf89b964fa1c30936c891bae30ceaeaed69fc6e2e8ea1e3c31fb9a2cd7a60a61`.
Local source/headless runs use Java 25.0.4.1 and are recorded separately.

`stack-first-use-export.sh` passes x86-64 and AArch64 exec, PIE and rebased PIE
in `run.zyP4DAY5`, with compiler/GDB values, unavailable nonzero-first-use gaps,
retained zero-offset stack locations, validators, determinism and input hashes.
The initial command mistakenly named nonexistent Gradle task `stackDepthSmoke`;
that failure is retained separately from the corrected successful checks.

The reusable comparison uses existing benchmark cases and copies their saved
projects before exporting:

```bash
DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 src/test/performance/paired-saved-exports.py \
    /path/to/sqlite-benchmark/run /path/to/baseline-ghidra /path/to/candidate-ghidra
DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 src/test/performance/paired-saved-exports.py \
    /path/to/export-benchmark/run/case-0-10000-functions \
    /path/to/baseline-ghidra /path/to/candidate-ghidra --synthetic-functions 10000
```

The comparator rejects changed input hashes or artifact bytes. It does not
weaken structural diagnostics or replace GDB checks with timing assertions.

The final reusable comparator also passes fresh two-pair SQLite and synthetic
runs with the same production JARs. These are final-harness validation runs,
not replacements for the five-pair measurements above:

- `run.ia8tqtro`: `26a79d342c7e69be6714caaac39f69aaa0889b994d33de5168448431793e8de8`.
- `run.czbjnqa6`: `2df5e624954dd417ceda845508b91d8b90bdbabf877e0d16ef98c5491a174732`.
