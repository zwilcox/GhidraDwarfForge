# Combined Java coverage

Single-run measurement for [947348c8b14079ae0a6d5cb6fc3ba5dfb51ce200](https://github.com/zwilcox/GhidraDwarfForge/commit/947348c8b14079ae0a6d5cb6fc3ba5dfb51ce200); [CI run 46007257791](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/46007257791).

This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.

The native-java layer includes standalone integration JVMs and measured interactive Linux GUI suites. Per-suite receipts identify the workflows and any uninstrumented child processes.

1271 measured JVM sessions; 909 production classes; 258 source files.

| Measurement | Lines | Branches |
| --- | ---: | ---: |
| [Combined Java](combined.md) | 97.3% (29,290/30,116) | 89.3% (23,340/26,147) |
| [JavaExec](javaexec.md) | 82.5% (24,855/30,116) | 79.4% (20,752/26,147) |
| [Headless Ghidra](headless.md) | 61.2% (18,419/30,116) | 46.1% (12,060/26,147) |
| [Native-Java integration](native-java.md) | 58.2% (17,523/30,116) | 37.0% (9,679/26,147) |
| [Windows Java](windows.md) | 19.6% (5,889/30,116) | 11.8% (3,096/26,147) |

## Accepted targets

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 97.3% (29,290/30,116) / target 85% | 89.3% (23,340/26,147) / target 80% |
| binaryAndLocationCorrectness | 97.5% (18,875/19,360) / target 95% | 90.0% (17,027/18,915) / target 90% |
| fileTransactionsAndValidation | 97.6% (6,673/6,836) / target 95% | 90.5% (3,912/4,324) / target 90% |

**All accepted coverage targets met: yes.**

See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.

Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.

Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.

The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.

Production JAR SHA-256: `b40cde23523148306ae650da1903ed9695693239c9109324d7ca4fed1e8b645e`.

## Changed executable Java

Compared with `920b3612ae686225e5113b4a9698464dc78bd1b2`: MEASURED.

Lines: 97.7% (42/43); branches: 90.9% (40/44).

Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.
