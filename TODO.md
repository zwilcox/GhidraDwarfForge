# GhidraDwarfForge backlog

## Open work

| Work | Acceptance |
| --- | --- |
| [Upper-half ELF64 addresses, #216](https://github.com/zwilcox/GhidraDwarfForge/issues/216) | **PLANNED**. Carry unsigned target addresses through extraction, normalization and DWARF emission. Verify symbol addresses, ranges and source lookup in GDB. Until then, preflight identifies an address such as `0xffffffff81000000` and preserves the original ELF and both output paths. |
| [Upgrade pinned libdwarf, #193](https://github.com/zwilcox/GhidraDwarfForge/issues/193) | Verify upstream producer fixes, audit the selected revision and packaged libraries on Linux and Windows, then retire superseded patches. |
| [Evaluate Gimli, #194](https://github.com/zwilcox/GhidraDwarfForge/issues/194) | Compare a bounded producer experiment against the existing DWARF and debugger requirements and record a go/no-go decision. |
| [Numbered releases, #215](https://github.com/zwilcox/GhidraDwarfForge/issues/215) | After each validated main merge, publish the next 1.x version with installable ZIP, matching tar.gz and SHA-256 checksums. |
| [Comprehensive review, #191](https://github.com/zwilcox/GhidraDwarfForge/issues/191) | After implementation work, inspect source, failure handling, independent test oracles, emitted files and project claims. Record dispositions and regressions. |
| [README refresh, #192](https://github.com/zwilcox/GhidraDwarfForge/issues/192) | Update installation, usage, supported profiles and limits after the other issues and comprehensive review finish. |

## Acceptance for changes

- Default export preserves the original ELF and produces a matched DWARF 5 sidecar and deterministic synthetic C source. Target changes such as debuglink attachment require an explicit operation.
- A debugger claim needs a source-built fixture, independent structural validation and the corresponding GDB behavior. Validate the affected ELF class, byte order, ABI and address layout. Preserve sectionless, PIE, shared-object and rebased-program coverage.
- Use a location only over the PC interval where the program evidence supports it. Apply the same evidence standard to source mappings and types. Inline-instance emission remains conditional on defensible instance, origin and range evidence.
- Preserve cancellation, original bytes, existing outputs, ownership of files changed by others and recovery after partial publication. Check deterministic reruns and validate Linux and Windows host claims on those hosts.
- Retain the protected `required-validation` gate. Coverage targets and measured test scope are in [the coverage notes](src/test/coverage/EXPANSION.md). Architecture grouping, dependencies and timing checks are in [the integration inventory guide](support/ci/INTEGRATION.md).

## Accepted milestones

The grouped main pipeline passed on `7f0b2272` across all 45 jobs, including 24 architecture groups. This run completed the CI runtime milestone and reproduced the published Java coverage views. [Main run](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/45438911536) · [Coverage issue](https://github.com/zwilcox/GhidraDwarfForge/issues/209) · [CI issue](https://github.com/zwilcox/GhidraDwarfForge/issues/211)

The earlier implementation inventory, milestone acceptance criteria and dated validation records are preserved in the [historical backlog at the reviewed commit](https://github.com/zwilcox/GhidraDwarfForge/blob/7f0b2272f1a919a906179f9a137800198f057287/TODO.md).
