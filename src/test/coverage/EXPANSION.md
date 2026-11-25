# Java coverage targets and evidence

| Scope | Line target | Branch target |
| --- | ---: | ---: |
| Overall production Java | 85% | 80% |
| Binary and location correctness | 95% | 90% |
| File transactions and validation | 95% | 90% |
| Substantially changed production Java | 90% | 85% minimum, 90% preferred |

The critical groups are evaluated independently. Their file membership and thresholds live in [critical-sources.json](critical-sources.json). Pair coverage with behavioral assertions for malformed and boundary inputs, cancellation, ownership, atomic replacement, and recovery. Validate emitted ELF and DWARF with independent readers and test debugger-visible values at the PCs where they are claimed.

## Reviewed baseline

The validated main run at `7f0b2272` reported 97.3% line coverage (28,990/29,802) and 89.2% branch coverage (23,101/25,902). Binary and location correctness reached 97.5% lines and 90.0% branches. File transactions and validation reached 97.7% lines and 90.1% branches. Source membership and denominators can change on subsequent revisions. [Run-specific report](https://github.com/zwilcox/GhidraDwarfForge/blob/955b278663eb4de8ce461ddc416c8f3cc00efc22/combined/README.md) · [Main CI](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45438911536)

Each combined figure is a union of JaCoCo probes from matching production bytecode in the same CI run. The report also provides JavaExec, headless Ghidra, native-Java integration and Windows views. It includes compiled Java classes that the measured suites never load. Native C, Python and shell have separate tests. Java exception handling needs explicit failure tests because JaCoCo does not count exception edges as branches. [Published coverage views](https://github.com/zwilcox/GhidraDwarfForge/blob/reports/test-coverage/combined/README.md) · [CI collection and admission](../../../support/ci/INTEGRATION.md)

The JavaExec badge retains its own test scope. The coverage report that Forge generates for an individual reverse-engineered binary describes recovered program evidence and has a different denominator. [JavaExec badge report](https://github.com/zwilcox/GhidraDwarfForge/blob/reports/test-coverage/README.md)

## Regression evidence

Mutation controls require a passing original and a behavioral failure from the changed implementation. Compilation failures and class-loading failures are rejected as detections. The coverage expansion and grouped CI work were accepted in issues [#209](https://github.com/zwilcox/GhidraDwarfForge/issues/209) and [#211](https://github.com/zwilcox/GhidraDwarfForge/issues/211).

Fine-grained fixture descriptions, historical limitations and the original experiment results remain available in the [full coverage record at the reviewed commit](https://github.com/zwilcox/GhidraDwarfForge/blob/7f0b2272f1a919a906179f9a137800198f057287/src/test/coverage/EXPANSION.md).
