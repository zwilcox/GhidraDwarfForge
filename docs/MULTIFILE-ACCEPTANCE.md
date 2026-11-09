# Multi-file synthetic source acceptance — issue #115

**CONFIRMED implementation, hosted acceptance and protected integration.**
[PR189](https://github.com/zwilcox/GhidraDwarfForge/pull/189) merged as
`71352a398bc71e4c9bfbae8a53e98d7b16f18636` on 2026-11-08; issue #115 is closed.
The audits below cover all seven original
[issue #115](https://github.com/zwilcox/GhidraDwarfForge/issues/115) requirements,
starting with production revision `52358dbefab331beb3b96e610c50741cdc9427e4`.
The final documentation head and integration are recorded below. No release
publication is included. #117 subsequently merged; #120 has its own acceptance
gate.

The [design and historical checkpoints](MULTIFILE-SOURCE.md) explain individual
fixtures, commands and failures. Their historical lists of then-pending work are
superseded by this record's accepted integration.

## Requirement-by-requirement audit

| Original requirement | Implementation and directly inspected evidence | Hosted acceptance at d701e2b |
| --- | --- | --- |
| 1. Deterministic names, collision handling, grouping, manifest, single-file default and synthetic labels | `SourcePartitionPlan` groups whole functions and preamble by a positive line target; it does not infer original translation units. `SourceBundle` binds stable ordinal/content-hash names, index, input and logical source, part bounds and function identities. `SourceBundleStore` refuses conflicting files/aliases and preserves old complete files. Source/manifest/store/reader controls cover Unicode, duplicate names, oversized units, cancellation and collisions. Bash/PowerShell, installed Linux GUI/headless and four-target failed/empty-source evidence preserve the default and repeat bytes. | PASS: native Windows producer/store/wrapper checks, saved GUI artifacts, transported consumers and all target lanes. |
| 2. Evaluate one CU versus multiple CUs | The recorded decision retains one CU and one canonical type graph; namespaces/classes are presentation information, not evidence of original CUs. Independent LLVM decoding requires exactly one DWARF 5 CU and the ordered index/part file table. | PASS: one DWARF 5 CU and shared type graph remain the recorded design, confirmed by independent decoded comparisons. |
| 3. Preserve canonical/recursive types, scopes, ranges, declarations and locations without merging by name | Six lexical and six recursive/same-name type cases compare single/multi DIE trees, reference edges and translated coordinates. Non-presentation range/location sections remain byte-identical. GDB verifies scoped values, distinct same-name layouts, recursion, methods and globals on x86-64/AArch64 exec, PIE and rebased PIE. Thirteen mutation controls pass in each lexical/x86-64 type case; AArch64 types have twelve because their contiguous fixture lacks `DW_AT_ranges`. | PASS: twelve final x86-64/AArch64 lexical/type cases, raw artifacts and compiler-backed GDB observations. |
| 4. GDB file/function lookup, breakpoints, cross-file/discontiguous stepping, different CWD and moved output | Fifteen five-target exec/PIE/rebase source cases, ten shared/rebased-DSO cases, and two discontiguous-gap matrices exercise actual native/QEMU GDB. Loader/formatter transport tests hide the old source tree and verify quoted/Unicode paths, ownership rules and missing dependencies. Discontiguous tests distinguish mapped source steps from unmapped instruction-only gaps; no fabricated rows are accepted. | PASS: all five executable/shared-object matrices, eight discontiguous cases (96 exports/120 GDB sessions), native Windows and transported GDB/LLDB. |
| 5. Publish the entire set; cancellation, rollback, stale files and user content | Immutable complete parts and manifest precede mutable pair/companion publication; old complete generations remain. Eighty-four production cancellation/IO cases cover fresh/replacement output at seven stages with validated deterministic retry. Build-ID saved updates/recovery retain independent complete inventories. The attachment audit reproduced and fixed missing dependency checks through commit/rollback; missing previous sources refuse recovery, while damaged new sources do not prevent restoring an intact prior association. | PASS: 84 publication failure/retry cases; privileged attachment; native Windows checks; four default/multi build-ID refresh cases with sixteen recovery scenarios and 32 missing-source refusals. |
| 6. Benchmark size/time and debugger navigation, retaining regressions and inconclusive results | Redistributable 1,000/10,000-function fixtures have three measured single/multi pairs plus warmups, source/DWARF preservation and recorded size/time/RSS/navigation. Scattered listing improves in the local samples; the final hosted run regresses at 1,000 functions and improves at 10,000. All-function lookup regresses and total artifact size increases; export/RSS/load results depend on the sample and include regressions or mixed directions. The large indivisible declaration catalog remains visible. No speedup or significance threshold replaces correctness. | PASS: final 1,000/10,000-function raw benchmark audit plus Windows historical-performance producer/consumer review. Regressions and mixed directions are retained. |
| 7. Structural validators, deterministic reruns, input preservation and existing source regressions | Actual artifacts pass GNU, LLVM and pinned libdwarf checks with explicitly corroborated inherited-frame diagnostics. Repeated full inventories, original hashes, compiler controls and saved-program checks accompany target/type/source/publication/consumer cases. Latest attachment/default tests use the built production JAR and live validators. | PASS: all sixteen full-workflow jobs, including required-validation, and scoped raw artifact review. Any final documentation head must still pass the enforced gate before merge. |

The evidence scopes remain separate: controller model tests do not prove ELF or
production-host behavior; local PowerShell tests do not prove Windows; compiling
a target is not runtime validation; and a successful producer does not prove its
transported debugger consumer. The optional line target is not a hard maximum for
an indivisible function or declaration preamble. Neither cross-file atomic
visibility nor power-loss/hostile-concurrency safety is claimed.

## Evidence audit

The [machine-readable audit](evidence/multifile-acceptance-audit.json) records:

- Fourteen retained archives checked against their recorded archive hashes or,
  where the original receipt has no archive hash, every recorded member hash.
- Twenty-seven lexical/type/target acceptance records checked against their
  retained checkpoint contents. The twelve semantic comparisons have equal
  decoded single/multi snapshots, matching input/artifact hashes and the
  fixture-specific mutation counts above; raw LLVM verdicts are also inspected.
- Thirty-one independently retained result records checked against the hashes
  in publication, shared-object, discontiguous, formatter, failed-source,
  build-ID refresh and attachment receipts.
- Actual JAR entry comparison: the latest installed runtime differs from the
  earlier local exporter only in `AttachmentOperation.class`,
  `AttachmentTransaction.class` and `AttachmentTransaction$Plan.class`. The
  exporter/native/line/type entries are identical. The changed classes have
  their own latest build, controller, live-validator and GDB evidence.

This is an audit of retained test results, not a new full matrix execution.
The raw archives, logs, artifacts and audit script are retained under
`/mnt/external_drive/GhidraDwarfForge-agent-artifacts/issue115-multifile`.
No evidence archive is silently presented as a hosted result.

## Hosted acceptance at d701e2b

**CONFIRMED:** [full run 42432375106](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42432375106)
passes all sixteen jobs, including `required-validation` job `128623795323`.
The [hosted audit](evidence/multifile-hosted-acceptance.json) identifies the
actual target artifacts and hashes the scoped review receipts. It supplements
the earlier local audit; it does not relabel local evidence as hosted proof.

The release ZIP audit verifies 539 manifest files and 224 Java source files
against this head. All final target audits bind the actual packaged JAR SHA-256
`e58169211d329fb3eb82ccfd8a610a7d967e2705662b35277661624034022e39`.
This is not a byte-identity claim between local and hosted compiler output.

Raw reviews cover all 25 five-target executable/shared-object cases, twelve
x86-64/AArch64 lexical/type cases, eight discontiguous cases, 84 publication
failure/retry cases and four-target failed/empty-source cases. The source-edge
supplement rechecks raw validators, repeated inventories, file-only line
programs and GDB observations; cached source also permits repeated LLVM DIE/line
normalization on x86-64, AArch64 and MIPS little-endian. Its MIPS big-endian
supplement does not independently repeat decoding or compare other ELF sections.
The primary target and semantic audits retain their separately stated scopes.

Host/consumer review covers five PIE/zlib formatter cases, two Windows multi-file
exec/PIE exports, three saved Windows GUI split/repeat/default artifacts and
transported GDB/LLDB consumers. Four privileged Linux attachment cases retain
sixteen GDB sessions, eight missing-source refusals and eight rollback controls.
Four default/multi-file build-ID refresh cases retain 24 GDB sessions, sixteen
recovery scenarios and 32 missing-source refusals. Their forty validation records
bind 1,400 raw validator-log hashes and corroborate inherited frame diagnostics
against the original; no blanket zero-warning claim is made.

The [final hosted benchmark](evidence/multifile-hosted-benchmark.json) retains
all medians, paired ratios and sizes. At 1,000 functions all six measured paired
directions regress. At 10,000 functions scattered listing improves and
all-function lookup regresses; other directions are mixed. Artifact size grows
at both sizes. These are three-pair observations, not general speed guarantees.
See [performance details](PERFORMANCE.md#optional-multi-file-source-comparison-115).

[Performance run 42432375119](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42432375119)
also passes on this head. Twenty measured reports and two profiling reports
preserve paired semantics; artifact hashes, source-catalog differences, decoded
DWARF, validators and four compiler/Forge GDB sessions are audited. SQLite exports
1,539 functions without decompilation failures; U-Boot exports 6,375 with the
same one-function timeout in both variants. Both reports describe partial
recovery. Baseline/candidate median seconds are 78.41/80.96 and 183.82/194.82;
no speedup is claimed.

## Accepted integration

The final PR head `f4609efbca5e0c45fe199b162d0051e8bb5017d1` passed all sixteen jobs
in [run 42446082844](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42446082844),
including `required-validation`, and all five jobs in
[performance run 42446082851](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42446082851).
PR189 merged normally as `71352a398bc71e4c9bfbae8a53e98d7b16f18636`; its tree
matches the tested head. The earlier audits above retain their exact revision
and evidence scope. Their pre-merge gate requirements have been satisfied.
