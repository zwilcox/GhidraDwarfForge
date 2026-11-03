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
