# Build-ID installation acceptance

Issue [#109](https://github.com/zwilcox/GhidraDwarfForge/issues/109) remains open.
The table below maps its seven acceptance requirements to the implemented
checks and evidence. **CONFIRMED locally** is not final hosted acceptance or a
Windows support claim. PR186 must pass the complete latest-head gate and artifact
review before normal protected integration.

| Requirement | Evidence and coverage | Remaining acceptance |
| --- | --- | --- |
| Existing identity and exact pair | `build-id-identity.py` and the production Linux matrix refuse missing, malformed, conflicting and mismatched IDs, a different original with the same ID, and input aliases. Export-report hashes bind the original, sidecar and source. [Linux receipt](evidence/build-id-command-linux.json). | Latest-head hosted results and artifact review. |
| Explicit destination and consumer setup | The packaged Bash/PowerShell command accepts a selected root and prints the GDB search command. Tests use fresh debugger sessions, empty-root controls and actual registered files. Arbitrary-tree installation is not itself automatic discovery. [Command contract](BUILD-ID-INSTALLATION.md). | Native Windows command acceptance; latest-head gate. |
| Collisions, refresh and removal | Explicit update preserves managed provenance and source generations. Implicit replacement, foreign registrations and changed-original collisions are refused. Actual saved analyst function/type/member edits are exported again and discovered in fresh GDB sessions. [Linux receipt](evidence/build-id-command-linux.json). | Native Windows lifecycle and transferred-artifact checks; latest-head gate. |
| Source, permissions, deterministic export, atomicity and unchanged input | Derived-artifact validation permits only the source-directory relocation, preserving original export files and plain/zlib encoding. Production Linux tests cover read-only modes, ACLs and user attributes, interrupted lifecycle boundaries, recovery, cancellation and aliases. [Derived validation](evidence/build-id-derived-validation.json), [transaction](BUILD-ID-TRANSACTION.md), [Linux receipt](evidence/build-id-command-linux.json). | Corrected native Windows DACL fixture, metadata/lifecycle acceptance and full gate. Installation generations have distinct retained paths; this does not change the original deterministic export. |
| No-build-ID inputs | Refusal retains the original bytes and reports the explicit debuglink/loader alternatives. The installer never injects or recomputes an original build ID. [Identity checks](evidence/build-id-identity.json). | Latest-head hosted results. |
| GDB exec/PIE/shared and applicable sectionless discovery | All five target lanes pass local exec/PIE/shared discovery and runtime checks. Matching compiler controls prove GDB 15.1 cannot discover the tested sectionless ET_EXEC sidecars automatically; the installer diagnoses this and explicit installed-sidecar loading is separately validated. [Layout evidence and limits](BUILD-ID-LAYOUTS.md). | Latest-head full target matrix and downstream Windows-installed artifact validation. Sectionless PIE/shared automatic discovery is not claimed. |
| Independent LLDB and perf behavior | Production-installed x86-64/AArch64 exec/PIE pass local LLDB and offline perf checks, including cache operations and mismatch controls. [Consumer evidence](BUILD-ID-CONSUMERS.md). A required native x86-64 exec/PIE job tests actual recorded samples with independent compiler ELF-symbol and DWARF-only controls. | Actual perf sample/report characterization and hosted installed-consumer results. A passing offline query cannot substitute for sampled symbolization. |

The Windows installer fixture originally introduced unsupported SACL metadata
while setting up its DACL control. The corrected fixture uses the audited native
DACL-only operation and retains an explicit null-SACL refusal test; production
admission is unchanged. Those fixture controls now pass natively. The following
installation exposed a lock readback defect, and independent Linux testing
found a lost-lock defect in the old second-handle verification. The corrected
Linux lock passes isolated and transaction tests; the Windows lock correction
remains **PRESENT, UNVERIFIED**. See [locking evidence](evidence/build-id-locking.json).
The downstream consumer must use actual Windows-installed
artifacts and explicit source-path substitution after transfer. Linux simulations
or cross-compilation do not satisfy those checks.

The final review must bind the accepted results to the exact tested commit and
packaged sources, inspect diagnostics and negative controls, verify original and
retained artifact hashes, and confirm the protected merge preserves the tested
tree. Existing local receipts identify their tested packages; they are not a
substitute for that final audit. No release publication is included in #109.
