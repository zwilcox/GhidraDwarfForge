# Complete Windows security descriptor observation

**CONFIRMED native prerequisite:** run41624344819 at `49dd0b6` passes the
whole-security experiment and independent artifact review. The two native APIs
agree on the exact audit and integrity-label ACE bytes. Disabled privilege and
insufficient handle rights refuse, duplicate creation preserves the fixture,
read-only observations preserve metadata, and 128 cycles retain 82 handles.
The review verifies all 24 retained source files against Git and the archive
SHA-256; see [the evidence receipt](evidence/windows-security-visibility-41624344819.json).
This is component evidence, not a complete PR gate.

**PRESENT, UNVERIFIED on Windows:** `WindowsFileSecurity` implements the
corresponding fixed-width JNA reader. Its Java 21 compilation, extension build,
actual Java 21 unsupported-host refusal, native contract compilation,
PowerShell syntax and workflow/architecture checks pass locally. The new
isolated native Windows Java tests still require a passing hosted result and
artifact review before this binding is accepted.

The current reader uses `GetKernelObjectSecurity` with
`BACKUP_SECURITY_INFORMATION` (`0x10000`), preserving the raw whole-descriptor
request. This supersedes the earlier GetSecurityInfo union described in the
historical checkpoints below. The earlier BACKUP-only
GetSecurityInfo failure and corrected native behavior are documented in
[the investigation](research/WINDOWS-SECURITY-VISIBILITY.md). It opens a regular
file with READ_CONTROL and ACCESS_SYSTEM_SECURITY using the existing checked
metadata path, without privilege adjustment, impersonation or partial-read
fallback. The caller's current token must already authorize the open.

The retained snapshot includes opened-file identity/facts, complete raw
self-relative descriptor bytes, descriptor control, SACL presence/defaulted
flags and bounded SACL bytes. Absent and present-null SACLs remain distinct.
Both the handle and selected path are checked around the read, and a second
complete descriptor observation must agree. Caller-owned descriptor buffers are bounded and released
on success, error and cancellation; opened handles and bounded buffers use
scoped cleanup. Cancellation is checked around native calls, which themselves
may block. This primitive does not resolve all ancestor traversal, choose a
metadata-admission policy, preserve/apply SACLs or supply a complete Host.

Declarations and SDK revision are pinned in
`src/test/native/windows-security-visibility-api.json`. Native C assertions
cover the scalar/structure layouts and signatures before the isolated Java
probe executes. The probe alone temporarily adjusts its own process token's
already-owned SeSecurityPrivilege and verifies restoration; it is not installed
or exposed as an elevation helper, and does not change the parent token.
No libdwarf binding or native release library changes are required.

The native harness compares the production reader's control/presence/SACL bytes
with the independently seeded C fixture, checks failure without privilege,
cancellation before and after opening, changed selected paths, directories,
unchanged fixture bytes and metadata, and 128 interpreted Serial-GC cleanup
cycles. A final independent native read must still return the original SACL.

The strict attachment contract and unresolved product privilege/visibility
choice remain unchanged. Full A1 host admission and A2–A7 public attachment,
recovery and matrix acceptance are still required; this reader alone does not
close #72 or enable attachment.

## Retained Java transport failure

**CONFIRMED failed native run:** run41626330294 at `2bfbada` passes the native
C fixture but the Java probe fails in Path.of: its direct command-line argument
contains `?` where the owned fixture path contains lambda. This happens before
production inspection, so it proves neither a reader pass nor a reader failure.
All 26 source files and the raw failing command are verified in
[the failure receipt](evidence/windows-security-java-41626330294.json).

The probe now uses the existing UTF-8 JSON request-file convention shared by
other Windows metadata probes. The Unicode fixture is retained. Native tests
require normal/interpreted request round trips with Windows-1252 as the default
encoding; corresponding actual Java 21 local tests pass. Reader execution and
all native preservation/cleanup controls still require a corrected hosted run.

## Complete metadata composition for private stages

**PRESENT, UNVERIFIED:** `WindowsAttachmentMetadata` combines ordinary metadata,
complete security and backup-stream observations. It requires the same native
file facts across them, one hard link, supported ordinary attributes and only
ordinary data streams. Present SACLs (including null/empty ACLs), resource-manager
controls and unsupported control bits are rejected before metadata application.
This is the documented initial unsupported-metadata refusal boundary, not a
claim that SACLs or extended attributes are copied.

An absent SACL does not mean its control flags can be ignored. The pinned
header identifies `0x2a30` as presence/defaulted, auto-inherit request/result and
SACL protection. These source/stage flags must match before applying ordinary
metadata. Full control and ordinary preservation values must match after
application, with source readback and unchanged stage identity/size. The
existing setter changes only the private stage; no target is published. Complete
security reads require already authorized access and never adjust privileges.

Native tests independently inspect ordinary permissions, timestamps, attributes,
owner/group/DACL, content and file identity for inherited/protected DACL profiles.
The C observer's new read-only `observe` mode compares complete source/stage
security control even for absent SACLs. SACL and EA source/stage refusals,
insufficient privilege, aliases, stale source and cancellation must preserve the
unmodified inputs/stage; native re-reads verify retained SACL and EA payloads.
These controls are implemented and compile locally but are not yet native
acceptance. Full filesystem admission/durability, production privilege policy
and public attachment remain separate unfinished requirements.

## Earlier changed-file rejection in the path-replacement control

**CONFIRMED partial native Java evidence:** run41627414752 at `f09791b`
passes Unicode round trips, production reader comparison with the native
control/ACE bytes, insufficient privilege and cancellation before/after opening.
The selected-path replacement fixture is rejected at the earlier opened-file
facts comparison because renaming changes file facts. The harness incorrectly
required only the later selected-path error; the entire job remains failed.
See [the reviewed evidence](evidence/windows-security-java-41627414752.json).

The corrected test accepts either of those exact rejection messages and still
requires a nonzero process exit. It independently records the original,
retained and replacement file states: original bytes and file identity must
remain under the retained name and a different identity with the exact sentinel
must occupy the selected path. No production check changes. Remaining cleanup
and composed-stage cases were not reached and retain their unverified status.

## Ordinary-file descriptor disagreement

**CONFIRMED bounded reader evidence:** run41628187930 at `934f251` passes
the audit-bearing fixture's production Java inspection, independent control/ACE
byte comparison, privilege refusal, before/after-open cancellation, retained
versus replacement file identity, directory refusal and 128 cycles at302 handles.
A final native read proves the fixture security data unchanged. All27 retained
sources match Git; see
[the evidence receipt](evidence/windows-security-java-41628187930.json).

The following ordinary-file native control fails before Java staged application:
GetSecurityInfo and GetFileSecurityW disagree on descriptor state. Its original
log does not identify which control/presence/defaulted/ACL field differs. The
printed win32=122 is stale from buffer sizing, not proof of an access or sizing
failure. This contradicts treating the high-level descriptor representation as
universally canonical. Ordinary-file admission and complete reader acceptance
remain unverified even though the populated audit/label fixture passes.

The diagnostic now prints all compared snapshot fields and independently calls
[GetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getkernelobjectsecurity)
with BACKUP_SECURITY_INFORMATION on the same opened handle. Its signature is
audited against the pinned securitybaseapi.h and compiled in the native fixture
before any Java mapping is considered. Kernel/path and original high-level/path
comparisons must both still pass; no mismatch is ignored. Production code is
unchanged pending the native evidence. The kernel API uses caller-owned bounded
buffers and returns a self-relative descriptor with the same access-rights
requirements; it does not grant privileges or alter the file.

## Select the raw opened-handle representation

**CONFIRMED native evidence:** run41629294907 at `4310f20` logs
GetSecurityInfo control `0xa004` versus raw path/kernel control `0x8004` for
an ordinary file. Presence/defaulted state and ACL bytes otherwise agree; all
three report no SACL. The exact extra high-level bit is `SE_SACL_PROTECTED`
(`0x2000`). The kernel/path comparison also passes on the populated audit/label
fixture. All27 sources, commands and raw artifact bytes are verified in
[the representation receipt](evidence/windows-security-representation-41629294907.json).
This identifies the observable API difference, not an undocumented Windows
implementation cause.

The selected production reader now uses GetKernelObjectSecurity BACKUP through
the existing authorized handle. Its caller-owned buffer is sized, bounded to one
MiB, checked against the returned size and parsed only after native validity
checks. A changed size or failed call is rejected; it never falls back to a
partial descriptor. No raw control bit is masked or synthesized. The existing
identity/path/readback/cancellation checks remain in place.

The native oracle now requires raw kernel/path equality for ordinary and
populated files and repeats both for128cycles. High-level output is retained as
a diagnostic, with the observed absent-SACL protection discrepancy explicitly
classified; it is never used as preservation input. A real insufficient-rights
raw query must fail. Native Java tests additionally compare ordinary source
control with the raw oracle before staged application, so the old representation
fails even before that application begins. Full Java/runtime/staging acceptance
of this API correction remains **PRESENT, UNVERIFIED** until its hosted run and
artifact review pass. The complete metadata requirement has not changed.

## Separate DACL protection from null-SACL fixture setup

**CONFIRMED native progress:** run41630413755 at `1fe9635` passes the corrected
raw reader's audit/label comparison and cleanup controls. The inherited-DACL
source and applied stage both report raw control `0x8004` through Java and the
independent kernel/path observer. The application returns success and the
harness's ordinary metadata/content/identity assertions pass. Its before/after
states were still only in parent memory, so this does not substitute for the
complete per-profile retained evidence now added to the harness.

The following protected fixture has a present-null SACL after PowerShell
Set-Acl; raw control is `0xbc14`, SACL-present is true and ACL bytes are null.
The harness's required ordinary-fixture precondition correctly fails before
production protected-stage application. The source/artifact review is retained
in [the receipt](evidence/windows-security-staging-41630413755.json).

The native fixture's new `protect-dacl` mode selects only DACL protection on
an explicitly owned file. It verifies that all SACL flags/presence/defaulted
state/bytes remain unchanged. A separate `null-sacl` mode deliberately creates
a present-null SACL on another owned file; source and stage admission must
reject it, preserving its full native security state and file bytes. Neither
mode is installed as a product helper or changes account/parent-token policy.
These replace an accidentally mixed positive fixture with distinct positive
and negative cases without admitting unsupported SACLs.

Before/after states and completed profile results are now retained immediately,
even if a later profile fails. Java probe exceptions with suppressed cleanup
failures are rejected by the harness. Native validation of these corrections
and all staged metadata cases remains pending.

## Raw inherited ACE preservation defect

**CONFIRMED:** the completed Windows job41632042195 at `77a3c0f` passes
its original assertions, including protected-DACL application, ten refusals and
128 full-security cleanup cycles. Independent raw artifact review found that
the inherited case changes three ACE flags from `0` to `INHERITED_ACE (0x10)`.
The ordinary GetSecurityInfo view synthesizes those flags for the source, so
its comparison accepts the changed stage. The raw GetKernelObjectSecurity
source and stage disagree. The protected case matches byte for byte.

The receipt `evidence/windows-security-raw-ace-41632042195.json` records archive
SHA-256 verification, all 27 retained source comparisons, exact descriptor bytes
and changed offsets. A green job therefore does not establish complete metadata
preservation. Prior component observations retain their original scope.

The composed attachment path now supplies the complete kernel descriptor to
the existing legacy SetFileSecurityW branch, rather than writing synthesized
GetSecurityInfo bytes. The fields mask still requests only owner/group/DACL.
Complete raw descriptor equality is required in production preservation and
in the native integration harness. The ordinary metadata-only API retains its
existing contract; it is not sufficient for complete attachment admission.

Local `javac --release 21`, `./gradlew buildExtension` with Ghidra12.0.3,
PowerShell AST parsing, architecture neutrality and whitespace checks pass.
The correction's actual Windows execution is **PRESENT, UNVERIFIED** until a
new hosted run succeeds. No public attachment or privilege policy is selected.

**CONFIRMED corrected native acceptance:** completed Windows job41633832399
at `2f7ea4d` passes independent artifact SHA/source review and raw inherited/
protected descriptor equality. All ten intended refusals and resource controls
pass. See `evidence/windows-security-staging-41633832399.json`. This supersedes
the correction's pending component status, not the full attachment requirements.
