# Combined Java coverage

Single-run measurement for [a55a6717a66e0a943a5061cee48d0d2b5f7d6910](https://github.com/zwilcox/GhidraDwarfForge/commit/a55a6717a66e0a943a5061cee48d0d2b5f7d6910); [CI run 45703599546](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45703599546).

This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.

The native-java layer includes standalone integration JVMs and measured interactive Linux GUI suites. Per-suite receipts identify the workflows and any uninstrumented child processes.

1270 measured JVM sessions; 904 production classes; 256 source files.

| Measurement | Lines | Branches |
| --- | ---: | ---: |
| [Combined Java](combined.md) | 97.2% (29,146/29,976) | 89.2% (23,209/26,018) |
| [JavaExec](javaexec.md) | 82.4% (24,714/29,976) | 79.3% (20,625/26,018) |
| [Headless Ghidra](headless.md) | 61.2% (18,347/29,976) | 46.1% (12,002/26,018) |
| [Native-Java integration](native-java.md) | 58.4% (17,496/29,976) | 37.1% (9,663/26,018) |
| [Windows Java](windows.md) | 18.8% (5,632/29,976) | 11.5% (2,991/26,018) |

## Accepted targets

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 97.2% (29,146/29,976) / target 85% | 89.2% (23,209/26,018) / target 80% |
| binaryAndLocationCorrectness | 97.5% (18,827/19,316) / target 95% | 90.0% (16,965/18,846) / target 90% |
| fileTransactionsAndValidation | 97.6% (6,584/6,748) / target 95% | 90.2% (3,850/4,270) / target 90% |

**All accepted coverage targets met: yes.**

See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.

Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.

Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.

The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.

Production JAR SHA-256: `402eea63d9a6f1d4da11bb92fe032b61fbb46661c3bf6d3dbdc3ba3b5b60a7b4`.

## Changed executable Java

Compared with `8bcc8b76b277f698f620241d13bd652edb7eb812`: NOT_APPLICABLE.

Lines: not applicable; branches: not applicable.

Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.
