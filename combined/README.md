# Combined Java coverage

Single-run measurement for [920b3612ae686225e5113b4a9698464dc78bd1b2](https://github.com/zwilcox/GhidraDwarfForge/commit/920b3612ae686225e5113b4a9698464dc78bd1b2); [CI run 45755488551](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45755488551).

This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.

The native-java layer includes standalone integration JVMs and measured interactive Linux GUI suites. Per-suite receipts identify the workflows and any uninstrumented child processes.

1271 measured JVM sessions; 908 production classes; 257 source files.

| Measurement | Lines | Branches |
| --- | ---: | ---: |
| [Combined Java](combined.md) | 97.3% (29,267/30,088) | 89.3% (23,302/26,106) |
| [JavaExec](javaexec.md) | 82.5% (24,831/30,088) | 79.3% (20,714/26,106) |
| [Headless Ghidra](headless.md) | 61.2% (18,401/30,088) | 46.1% (12,037/26,106) |
| [Native-Java integration](native-java.md) | 58.2% (17,523/30,088) | 37.1% (9,680/26,106) |
| [Windows Java](windows.md) | 19.6% (5,888/30,088) | 11.9% (3,095/26,106) |

## Accepted targets

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 97.3% (29,267/30,088) / target 85% | 89.3% (23,302/26,106) / target 80% |
| binaryAndLocationCorrectness | 97.5% (18,852/19,334) / target 95% | 90.0% (16,989/18,874) / target 90% |
| fileTransactionsAndValidation | 97.6% (6,674/6,836) / target 95% | 90.5% (3,912/4,324) / target 90% |

**All accepted coverage targets met: yes.**

See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.

Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.

Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.

The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.

Production JAR SHA-256: `715b5707b32190d0cb46e0c2c5725f476fc1c71c4c3048b6fdaf191baf79a383`.

## Changed executable Java

Compared with `a55a6717a66e0a943a5061cee48d0d2b5f7d6910`: MEASURED.

Lines: 94.3% (183/194); branches: 89.7% (131/146).

Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.
