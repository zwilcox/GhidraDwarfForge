# Combined Java coverage

Single-run measurement for [1b922641a60f13d99f2441e6eab072973e6b4f8d](https://github.com/zwilcox/GhidraDwarfForge/commit/1b922641a60f13d99f2441e6eab072973e6b4f8d); [CI run 45528494838](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45528494838).

This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.

The native-java layer includes standalone integration JVMs and measured interactive Linux GUI suites. Per-suite receipts identify the workflows and any uninstrumented child processes.

1270 measured JVM sessions; 901 production classes; 255 source files.

| Measurement | Lines | Branches |
| --- | ---: | ---: |
| [Combined Java](combined.md) | 97.3% (29,003/29,815) | 89.2% (23,123/25,924) |
| [JavaExec](javaexec.md) | 82.5% (24,583/29,815) | 79.3% (20,552/25,924) |
| [Headless Ghidra](headless.md) | 61.2% (18,245/29,815) | 46.1% (11,944/25,924) |
| [Native-Java integration](native-java.md) | 58.4% (17,407/29,815) | 37.1% (9,605/25,924) |
| [Windows Java](windows.md) | 18.9% (5,632/29,815) | 11.5% (2,991/25,924) |

## Accepted targets

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 97.3% (29,003/29,815) / target 85% | 89.2% (23,123/25,924) / target 80% |
| binaryAndLocationCorrectness | 97.5% (18,746/19,226) / target 95% | 90.0% (16,898/18,772) / target 90% |
| fileTransactionsAndValidation | 97.7% (6,522/6,677) / target 95% | 90.1% (3,831/4,250) / target 90% |

**All accepted coverage targets met: yes.**

See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.

Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.

Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.

The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.

Production JAR SHA-256: `ee02144b3e27943d5ab7f4513582d13970b8f83b5792ee70625a04039974c889`.

## Changed executable Java

Compared with `d15d021f7cdc2269f4d4fe91f654c99324df9123`: MEASURED.

Lines: 100.0% (18/18); branches: 100.0% (22/22).

Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.
