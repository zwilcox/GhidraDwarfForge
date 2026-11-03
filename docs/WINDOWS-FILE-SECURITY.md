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

The reader uses `BACKUP_SECURITY_INFORMATION` plus explicit component fields
(`0x101ff`), preserving the whole-descriptor request. The earlier BACKUP-only
GetSecurityInfo failure and corrected native behavior are documented in
[the investigation](research/WINDOWS-SECURITY-VISIBILITY.md). It opens a regular
file with READ_CONTROL and ACCESS_SYSTEM_SECURITY using the existing checked
metadata path, without privilege adjustment, impersonation or partial-read
fallback. The caller's current token must already authorize the open.

The retained snapshot includes opened-file identity/facts, complete raw
self-relative descriptor bytes, descriptor control, SACL presence/defaulted
flags and bounded SACL bytes. Absent and present-null SACLs remain distinct.
Both the handle and selected path are checked around the read, and a second
complete descriptor observation must agree. Allocated descriptors are freed
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
