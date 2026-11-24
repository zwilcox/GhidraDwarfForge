# Combined Java coverage

Single-run measurement for [7f0b2272f1a919a906179f9a137800198f057287](https://github.com/zwilcox/GhidraDwarfForge/commit/7f0b2272f1a919a906179f9a137800198f057287); [CI run 45438911536](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45438911536).

This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.

The native-java layer includes standalone integration JVMs and measured interactive Linux GUI suites. Per-suite receipts identify the workflows and any uninstrumented child processes.

1270 measured JVM sessions; 901 production classes; 255 source files.

| Measurement | Lines | Branches |
| --- | ---: | ---: |
| [Combined Java](combined.md) | 97.3% (28,990/29,802) | 89.2% (23,101/25,902) |
| [JavaExec](javaexec.md) | 82.4% (24,570/29,802) | 79.3% (20,532/25,902) |
| [Headless Ghidra](headless.md) | 61.2% (18,236/29,802) | 46.1% (11,928/25,902) |
| [Native-Java integration](native-java.md) | 58.4% (17,398/29,802) | 37.0% (9,589/25,902) |
| [Windows Java](windows.md) | 18.9% (5,625/29,802) | 11.5% (2,985/25,902) |

## Accepted targets

| Scope | Lines | Branches |
| --- | ---: | ---: |
| Overall | 97.3% (28,990/29,802) / target 85% | 89.2% (23,101/25,902) / target 80% |
| binaryAndLocationCorrectness | 97.5% (18,733/19,213) / target 95% | 90.0% (16,876/18,750) / target 90% |
| fileTransactionsAndValidation | 97.7% (6,522/6,677) / target 95% | 90.1% (3,831/4,250) / target 90% |

**All accepted coverage targets met: yes.**

See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.

Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.

Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.

The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.

Production JAR SHA-256: `58bd7a71517452ca3f33e372060abd47f29166850cdcf464e3b3cb0f2a2a158b`.

## Changed executable Java

Compared with `9326d3acfcc07d880accdefea6d118aa0c4bb2dc`: NOT_APPLICABLE.

Lines: not applicable; branches: not applicable.

Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.
