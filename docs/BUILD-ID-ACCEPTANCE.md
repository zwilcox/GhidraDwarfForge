# Build-ID installation acceptance

**CONFIRMED implementation acceptance at `d55842f` (2026-11-07 UTC):**
[run 42344072547](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42344072547)
passes all 16 jobs, including the strict combined `required-validation` gate.
Independent review accepts all five target lanes, native Windows installation,
its downstream Linux GDB consumer, native/package provenance and sampled perf
characterization. The [implementation receipt](evidence/build-id-implementation-acceptance.json)
binds 35 review receipts and 30 artifacts to this tested commit and the seven
original [#109 requirements](https://github.com/zwilcox/GhidraDwarfForge/issues/109).
Final documentation validation and normal protected integration follow the
contract below; implementation acceptance alone is not a release claim.

The [target receipt](evidence/build-id-targets-current-acceptance.json) covers
x86-64, AArch64, ARM32 and both MIPS32 byte orders: 226 installer checks, 50 GDB
lifecycle sessions, 109 retained generations, 4,480 manifest-file checks and
743 supervised validators. Complete target archives contain 2,904 positive
strict records and 139 intentional negatives. Shared-object automatic discovery
and the explicit sectionless ET_EXEC fallback pass on all five targets. Two
x86-64 saved-program refresh cases prove actual analyst function/type/member
edits survive export, installation update and fresh debugger lookup.

The x86-64/AArch64 installed-consumer reviews cover four exec/PIE roles, eight
runtime sessions, 64 offline perf queries and 16 absence-control sessions.
Their broader LLDB regression review covers 63 records. The target receipt lists
25 unretained x86-64 and 35 unretained AArch64 regression input paths: those remain
runtime-oracle evidence, not independently rehashed archive copies. Three
compiler-reference diagnostics are separately recorded and assessed.

The [Windows receipt](evidence/windows-build-id-current-acceptance.json) binds
73 native checks, 14 interruptions, 25 retained generations, 1,050 manifest
files, 175 supervised validator executions and 50 strict original/sidecar
reports. Actual Windows-installed initial and analyst-curated artifacts pass
two fresh Linux GDB runtime sessions and four controls. Shared regression review
checks 13 strict reports, 2,959 hash bindings and compiler/Forge unwind traces.
Windows runs installation and metadata/recovery checks; Linux executes the
transferred Linux ELF with explicit source-path substitution.

The [perf receipt](evidence/build-id-perf-current-acceptance.json) binds actual
x86-64 exec/PIE recordings, four retained generations, 168 manifest files and
independent replay. It confirms the sampled-report limitation with compiler
controls; it does not claim recovered-name sample reporting. Dated component
receipts preserve outstanding-work notes from their capture time; the
implementation receipt resolves acceptance of the complete implementation run.

## Requirement map

All seven original requirements are accepted within the explicitly tested profiles
below. Local checkpoints supplement the hosted evidence; they do not replace it.

| Requirement | Implementation and evidence | Acceptance scope |
| --- | --- | --- |
| Existing identity and exact original/sidecar pair | `build-id-identity.py` and the production matrix reject missing, malformed, conflicting and mismatched IDs, a different original with the same ID, and input aliases. Export-report hashes bind the original, sidecar and source. [Target receipt](evidence/build-id-targets-current-acceptance.json), [Windows receipt](evidence/windows-build-id-current-acceptance.json). | Confirmed by raw command outcomes and exact retained input/package hashes. No original ID is invented or changed. |
| Explicit destination and consumer setup | Packaged Bash/PowerShell commands accept a selected root and print consumer setup. Fresh debugger sessions, empty-root controls and actual registered files distinguish installation from discovery. [Command contract](BUILD-ID-INSTALLATION.md), [target receipt](evidence/build-id-targets-current-acceptance.json). | Confirmed on the documented Linux/Windows hosts. An arbitrary installation root still requires consumer search configuration. |
| Collisions, refresh and removal | Explicit update preserves managed provenance and retained source generations. Implicit replacement, foreign registrations and changed-original collisions are refused. Saved analyst function/type/member edits are re-exported and checked in fresh GDB sessions. [Target receipt](evidence/build-id-targets-current-acceptance.json), [Windows receipt](evidence/windows-build-id-current-acceptance.json). | Confirmed lifecycle and negative controls on all five targets; actual saved-program refresh on x86-64 and native Windows, followed by Linux GDB consumption. |
| Source, permissions, deterministic export, atomicity and unchanged input | Derived validation permits only source-directory relocation, retaining original export files and plain/zlib encoding. Linux tests cover read-only modes, ACLs, user attributes, interrupted lifecycle boundaries, recovery, cancellation and aliases. Native Windows metadata/lifecycle checks and all retained generations pass review. [Derived validation](evidence/build-id-derived-validation.json), [transaction contract](BUILD-ID-TRANSACTION.md), [implementation receipt](evidence/build-id-implementation-acceptance.json). | Confirmed by native runtime observations, source/original hashes and retained validator logs. Archive mode bits alone do not prove ACL or extended-attribute preservation. Distinct installation-generation paths do not change the deterministic original export. |
| No-build-ID inputs | Refusal preserves original bytes and reports the explicit debuglink/loader alternatives. The installer never injects or recomputes the original build ID. [Identity checks](evidence/build-id-identity.json), [current target receipt](evidence/build-id-targets-current-acceptance.json). | Confirmed by current x86-64 raw identity/command outcomes and input bindings. Any future original-copy ID injection requires its own identity/layout transaction. |
| GDB exec/PIE/shared and applicable sectionless discovery | All five hosted target lanes prove fresh-session exec/PIE/shared discovery, mismatch and lifecycle controls. Matching compiler controls establish the tested sectionless ET_EXEC automatic-discovery limitation; explicit installed-sidecar loading is separately validated. [Layout evidence](BUILD-ID-LAYOUTS.md), [target receipt](evidence/build-id-targets-current-acceptance.json). | Confirmed automatic discovery for tested exec/PIE/shared layouts, with a diagnosed explicit fallback for sectionless ET_EXEC. Sectionless PIE/shared automatic discovery is not claimed. |
| Independent LLDB and perf behavior | Production-installed x86-64/AArch64 exec/PIE pass LLDB and offline perf checks, including cache and mismatch controls. A required native job records real x86-64 samples with independent compiler ELF-symbol and DWARF-only controls. [Consumer behavior](BUILD-ID-CONSUMERS.md), [perf receipt](evidence/build-id-perf-current-acceptance.json), [implementation receipt](evidence/build-id-implementation-acceptance.json). | Confirmed within the recorded versions/profiles. Sampled reports do not recover Forge names; offline source lookup does not imply sampled-name support. |

## Compatibility boundaries

GDB 15.1 cannot automatically discover the tested sectionless ET_EXEC sidecars
for either Forge or matching compiler controls. The installer diagnoses this;
the supported tested fallback explicitly loads the installed sidecar.

In sampled perf reports, the compiler ELF symbol resolves `profile_hot`, while
the compiler DWARF-only control and installed Forge generations fail to recover
the requested name. Offline perf source lookup and GDB discovery have separate
positive evidence. A passing characterization establishes this consumer limit.
Perf also accepts a wrong-ID file placed at the matched path; the installer
rejects that mismatch. Perf's cache hard-links its inputs, while managed
installation files must remain single-link: cache use requires an independent
copy and explicit cache update/removal as described in the consumer guide.

The audited installation hosts are Linux Intel LP64 with ext4 and native Windows
with local NTFS. Windows source paths require GDB substitution after transfer to
Linux. Cross-compilation, Linux simulations and archived mode bits do not prove
native Windows filesystem behavior.

## Historical failures and corrections

Run `42329832669` passed all x86-64 test stages but failed artifact upload on
the intentional filename `request λ "literal".json`. No complete x86-64 archive
was available for review, and its required gate failed. Diagnostics now travel
inside one PAX tar.gz, preserving filenames, hidden files, contents and links.
All five corrected archives uploaded and passed raw review. The x86-64 review
binds the quoted filename and request bytes to both executed preview commands;
4,438 hidden generation members are retained. The
[historical retention receipt](evidence/build-id-target-artifact-retention.json)
preserves the failure; the [implementation receipt](evidence/build-id-implementation-acceptance.json)
records the successful hosted correction.

The earlier MIPS little-endian harness selected Java's ASCII filesystem encoding
with `LC_ALL=C`; it now selects `C.UTF-8` while retaining the production guard.
The [locale receipt](evidence/build-id-linux-locale.json) preserves the failed
run and isolated reproduction. Current MIPS jobs pass with that correction.

Earlier Windows corrections preserve the production metadata and validation
requirements: the DACL-only fixture distinguishes absent and explicit null SACLs;
lock readback uses the locking handle; Linux uses an audited open-file-description
lock; and MSYS2 GNU readelf passes Unicode/long-path and supervised-installation
checks. The downstream GDB oracle checks file-local as well as global symbols,
including absence controls. See the [SACL fixture receipt](evidence/windows-build-id-sacl-fixture.json),
[locking evidence](evidence/build-id-locking.json) and
[validator-path receipt](evidence/windows-build-id-validator-paths.json).

Two independent review-tool corrections are retained with their controls. The
archive reader recognizes only the exact retained absolute-link sentinel fixture
without following host paths; unrelated absolute or escaping links remain refused.
The command reviewer accepts only the exact test-configured `JAVA_TOOL_OPTIONS`
startup notice and expected JVM launch count, rejecting extra stderr. A local
Java 21 reproduction and 12 positive/negative controls corroborate that notice.
All five affected installer reviews were rerun; the failed attempt and superseded
reviews remain recorded. See [archive controls](evidence/build-id-review-archive-alias.json)
and [Java startup controls](evidence/build-id-review-java-startup.json). These
changes affect independent review tools, not production code or CI assertions.

## Integration contract

The implementation receipt binds the successful run, packaged sources, raw
reviews, artifact hashes and seven requirements. A documentation-only final head
must preserve that production implementation and pass its own strict
`required-validation` check before normal protected integration. The final head,
checks and integration are recorded in
[PR #186](https://github.com/zwilcox/GhidraDwarfForge/pull/186). No administrator
bypass or release publication is part of this acceptance.
