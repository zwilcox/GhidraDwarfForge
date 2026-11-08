# Multi-file synthetic source acceptance — issue #115

**CONFIRMED local implementation and evidence; hosted acceptance pending.** This
record audits production revision `52358dbefab331beb3b96e610c50741cdc9427e4` against
all seven original [issue #115](https://github.com/zwilcox/GhidraDwarfForge/issues/115)
requirements. It does not close the issue or authorize a release. #117 and #120
remain subsequent work, in that order.

The [design and historical checkpoints](MULTIFILE-SOURCE.md) explain individual
fixtures, commands and failures. Their historical lists of then-pending work are
superseded by this record's current remaining gates.

## Requirement-by-requirement audit

| Original requirement | Implementation and directly inspected local evidence | Remaining acceptance |
| --- | --- | --- |
| 1. Deterministic names, collision handling, grouping, manifest, single-file default and synthetic labels | `SourcePartitionPlan` groups whole functions and preamble by a positive line target; it does not infer original translation units. `SourceBundle` binds stable ordinal/content-hash names, index, input and logical source, part bounds and function identities. `SourceBundleStore` refuses conflicting files/aliases and preserves old complete files. Source/manifest/store/reader controls cover Unicode, duplicate names, oversized units, cancellation and collisions. Bash/PowerShell, installed Linux GUI/headless and four-target failed/empty-source evidence preserve the default and repeat bytes. | Final-head hosted wrapper/GUI/store runs, including native Windows. |
| 2. Evaluate one CU versus multiple CUs | The recorded decision retains one CU and one canonical type graph; namespaces/classes are presentation information, not evidence of original CUs. Independent LLVM decoding requires exactly one DWARF 5 CU and the ordered index/part file table. | Decision is recorded; final integration still depends on the full validation gate. |
| 3. Preserve canonical/recursive types, scopes, ranges, declarations and locations without merging by name | Six lexical and six recursive/same-name type cases compare single/multi DIE trees, reference edges and translated coordinates. Non-presentation range/location sections remain byte-identical. GDB verifies scoped values, distinct same-name layouts, recursion, methods and globals on x86-64/AArch64 exec, PIE and rebased PIE. Thirteen mutation controls pass in each lexical/x86-64 type case; AArch64 types have twelve because their contiguous fixture lacks `DW_AT_ranges`. | Final-head hosted semantic/architecture lanes. |
| 4. GDB file/function lookup, breakpoints, cross-file/discontiguous stepping, different CWD and moved output | Fifteen five-target exec/PIE/rebase source cases, ten shared/rebased-DSO cases, and two discontiguous-gap matrices exercise actual native/QEMU GDB. Loader/formatter transport tests hide the old source tree and verify quoted/Unicode paths, ownership rules and missing dependencies. Discontiguous tests distinguish mapped source steps from unmapped instruction-only gaps; no fabricated rows are accepted. | Native Windows producer plus transported GDB/LLDB consumers and final-head full matrix. |
| 5. Publish the entire set; cancellation, rollback, stale files and user content | Immutable complete parts and manifest precede mutable pair/companion publication; old complete generations remain. Eighty-four production cancellation/IO cases cover fresh/replacement output at seven stages with validated deterministic retry. Build-ID saved updates/recovery retain independent complete inventories. The attachment audit reproduced and fixed missing dependency checks through commit/rollback; missing previous sources refuse recovery, while damaged new sources do not prevent restoring an intact prior association. | Privileged Linux attachment runs and native Windows publication checks on the final head. |
| 6. Benchmark size/time and debugger navigation, retaining regressions and inconclusive results | Redistributable 1,000/10,000-function fixtures have three measured single/multi pairs plus warmups, source/DWARF preservation and recorded size/time/RSS/navigation. Scattered listing improves in these samples; all-function lookup regresses, total artifact size increases, and export/RSS/load results are mixed. The large indivisible declaration catalog remains visible. No speedup or significance threshold replaces correctness. | Final-head measurement regression workflow; corrected historical Windows performance comparator must also pass. |
| 7. Structural validators, deterministic reruns, input preservation and existing source regressions | Actual artifacts pass GNU, LLVM and pinned libdwarf checks with explicitly corroborated inherited-frame diagnostics. Repeated full inventories, original hashes, compiler controls and saved-program checks accompany target/type/source/publication/consumer cases. Latest attachment/default tests use the built production JAR and live validators. | **INCOMPLETE:** final exact-head required-validation, all required Linux/Windows and target jobs, raw artifact review, and protected PR integration. |

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

## Final gates and integration

Before #115 can be closed:

1. Obtain successful `required-validation` on the actual PR head, retaining
   normal branch protection and merge history. A passing older head is only
   diagnostic evidence.
2. Inspect the final artifacts for mandatory x86-64/AArch64 and the existing
   ARM32/MIPS lanes, native Windows exports/GUI/wrappers and transported debugger
   consumers. Check that optional multi-file invocations actually ran.
3. Inspect privileged Linux attachment default/multi-file exec/PIE records,
   including the missing-dependency refusal and rollback cases. Local runs used
   the limited host and cannot satisfy this host claim.
4. Verify the corrected Windows historical-performance comparison, full workload
   validation and consumer jobs. The earlier baseline mismatch has a bounded
   comparator fix; a locally passing diagnosis is not hosted acceptance.
5. Update this record with the final run/commit/artifact evidence, integrate
   PR189 through ordinary protected merge, and then proceed to #117 and #120.

No release publication is included in this goal.
