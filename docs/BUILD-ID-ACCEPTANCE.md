# Build-ID installation acceptance

Issue [#109](https://github.com/zwilcox/GhidraDwarfForge/issues/109) remains open.
Native Windows installation/recovery and corrected hosted downstream GDB
checks pass at `9d1ce2c` in run `42324179974`. The previous hosted
consumer failed because its test searched only global symbols; the corrected
oracle also checks file-local symbols, including absence controls. See the
[current Windows receipt](evidence/windows-build-id-current-acceptance.json).
Independent review now verifies all 25 retained native generations, their
1,050 manifest files and 175 supervised validator executions. Fifty strict
original/sidecar reports are reparsed, with original frame bytes and retained
source independently checked. The latest combined gate remains outstanding.

**CONFIRMED harness failure; corrected hosted gate pending:** the same run's
MIPS little-endian floating-register step fails because `LC_ALL=C` selects an
ASCII native filesystem encoding in Java. The Linux directory host correctly
refuses that encoding. The harness now uses `C.UTF-8`, preserving the production
guard. Twelve local plain/zlib exec/PIE export, validator and QEMU/GDB cases pass,
with four source-relocation and four derived-validation cases. The
[locale receipt](evidence/build-id-linux-locale.json) retains the failed hosted
artifact and isolated reproduction. This local correction must pass a new full
gate before integration; the successful Windows jobs retain only their own scope.

The table below maps its seven acceptance requirements to the implemented
checks and evidence. Local results, native Windows results and downstream
consumer replay each establish only their recorded scope. PR186 must pass the
complete latest-head gate and artifact review before normal protected integration.

| Requirement | Evidence and coverage | Remaining acceptance |
| --- | --- | --- |
| Existing identity and exact pair | `build-id-identity.py` and the production Linux matrix refuse missing, malformed, conflicting and mismatched IDs, a different original with the same ID, and input aliases. Export-report hashes bind the original, sidecar and source. [Linux receipt](evidence/build-id-command-linux.json). | Latest-head hosted results and artifact review. |
| Explicit destination and consumer setup | The packaged Bash/PowerShell command accepts a selected root and prints the GDB search command. Tests use fresh debugger sessions, empty-root controls and actual registered files. Native Windows command checks pass. Arbitrary-tree installation is not itself automatic discovery. [Command contract](BUILD-ID-INSTALLATION.md). | Latest-head gate and final artifact review. |
| Collisions, refresh and removal | Explicit update preserves managed provenance and source generations. Implicit replacement, foreign registrations and changed-original collisions are refused. Actual saved analyst function/type/member edits are exported again and discovered in fresh GDB sessions. Native Windows lifecycle and hosted GDB consumption of its transferred artifacts pass. [Linux receipt](evidence/build-id-command-linux.json), [Windows receipt](evidence/windows-build-id-current-acceptance.json). | Complete five-target gate and final artifact review. |
| Source, permissions, deterministic export, atomicity and unchanged input | Derived-artifact validation permits only the source-directory relocation, preserving original export files and plain/zlib encoding. Production Linux tests cover read-only modes, ACLs and user attributes, interrupted lifecycle boundaries, recovery, cancellation and aliases. Native Windows metadata/lifecycle checks and all retained generation evidence pass review. [Derived validation](evidence/build-id-derived-validation.json), [transaction](BUILD-ID-TRANSACTION.md), [Linux receipt](evidence/build-id-command-linux.json), [Windows receipt](evidence/windows-build-id-current-acceptance.json). | Latest-head Windows/consumer gate and final review. Installation generations have distinct retained paths; this does not change the original deterministic export. |
| No-build-ID inputs | Refusal retains the original bytes and reports the explicit debuglink/loader alternatives. The installer never injects or recomputes an original build ID. [Identity checks](evidence/build-id-identity.json). | Latest-head hosted results. |
| GDB exec/PIE/shared and applicable sectionless discovery | All five target lanes pass local exec/PIE/shared discovery and runtime checks. Matching compiler controls prove GDB 15.1 cannot discover the tested sectionless ET_EXEC sidecars automatically; the installer diagnoses this and explicit installed-sidecar loading is separately validated. [Layout evidence and limits](BUILD-ID-LAYOUTS.md). | Complete five-target matrix and final artifact review; current Windows-installed artifact validation passes. Sectionless PIE/shared automatic discovery is not claimed. |
| Independent LLDB and perf behavior | Production-installed x86-64/AArch64 exec/PIE pass local LLDB and offline perf checks, including cache operations and mismatch controls. [Consumer evidence](BUILD-ID-CONSUMERS.md). A required native x86-64 exec/PIE job tests actual recorded samples with independent compiler ELF-symbol and DWARF-only controls. | Sample/report characterization is confirmed: [recording receipt](evidence/build-id-perf-recording.json) proves a consumer limitation with independent controls; recovered-name sample reporting is unsupported. Latest-head hosted installed-consumer results remain required. |

The earlier Windows failures are **HISTORICAL**. The DACL-only fixture now
preserves absent SACL metadata and separately proves explicit null-SACL refusal.
Windows lock verification uses the locking handle; Linux uses an audited
open-file-description lock that survives other handle closes. The selected MSYS2
GNU readelf passes Unicode/long-path controls and actual supervised installation.
These corrections preserve the production metadata and validator requirements.
See the [SACL fixture receipt](evidence/windows-build-id-sacl-fixture.json),
[locking evidence](evidence/build-id-locking.json) and
[validator-path receipt](evidence/windows-build-id-validator-paths.json).

The corrected downstream consumer uses actual Windows-installed artifacts and
explicit source-path substitution after transfer. Both local replay and the
current hosted job pass. Linux simulations or cross-compilation do not establish
native Windows installation behavior. The complete five-target gate and its
artifact review remain required.

The final review must bind the accepted results to the exact tested commit and
packaged sources, inspect diagnostics and negative controls, verify original and
retained artifact hashes, and confirm the protected merge preserves the tested
tree. Existing local receipts identify their tested packages; they are not a
substitute for that final audit. No release publication is included in #109.
