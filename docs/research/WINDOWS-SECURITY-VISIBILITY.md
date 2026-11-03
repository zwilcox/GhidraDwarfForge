# Whole Windows security-descriptor visibility

**PRESENT, UNVERIFIED on Windows:** a native test-only fixture now exercises
`BACKUP_SECURITY_INFORMATION`, ordinary owner/group/DACL inspection, audit ACEs
and a mandatory integrity label. It cross-compiles with warnings treated as
errors and its PowerShell harness parses locally. Actual Windows outcomes must
be reviewed before adding a production mapping or claiming complete visibility.

The existing `WindowsFileMetadata` owner/group/DACL reader does not prove that
other security metadata is absent. Microsoft defines
[`BACKUP_SECURITY_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
as requesting all descriptor parts, with both `READ_CONTROL` and
`ACCESS_SYSTEM_SECURITY` required. Audit entries, mandatory labels, resource
attributes and scoped policy information are distinct security fields.
The [GetSecurityInfo contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
requires an appropriately authorized handle for the SACL. Successful ordinary
ACL inspection must not be treated as complete metadata admission.

`src/test/native/windows-security-visibility.c` has two explicit test modes:

- `create` exclusively creates a five-byte owned fixture before adding one
  successful-read audit ACE and one medium integrity/no-write-up label. It
  never overwrites an existing file or changes its owner/DACL.
- `read` observes that retained fixture without modifying it.

Both modes manipulate only their own child-process token. The test runner must
already possess `SeSecurityPrivilege`; the child does not elevate, impersonate,
grant privileges, alter the parent token or change any account policy. It
temporarily disables the privilege for refusal controls, enables it to query
the fixture and restores its initial enabled state before successful exit.
This test machinery is never installed as a product helper. It does not select
the pending product privilege/visibility policy.

The intended native assertions are:

1. A full-security open with the security privilege disabled fails with error
   1314, and a read-control-only handle cannot read the complete descriptor.
2. With an authorized handle, whole-descriptor inspection observes both audit
   and label ACEs. Ordinary owner/group/DACL inspection omits the SACL.
3. Opened-handle `GetSecurityInfo` and independent path-based `GetFileSecurityW`
   agree on the full SACL bytes, presence/defaulted flags and descriptor control.
4. Repeated reads release descriptor allocations/handles for 128 cycles and
   retain an exact native process-handle count.
5. The parent harness verifies fixture bytes, unchanged ordinary metadata on
   read/refusal, restored privilege state and unchanged full SACL after an
   existing-file creation refusal. Raw commands, source hashes, SDK revision
   and outputs are retained even on failure.

Declarations/constants are pinned by
`src/test/native/windows-security-visibility-api.json`, including the shared
SDK `sddl.h` and process-token declarations. No libdwarf producer declaration
or release native library is changed. The strict attachment contract remains
in force; neither accessible-only preservation nor an administrator-only
default is selected. A1, full host admission and public attachment remain
incomplete regardless of this experiment's eventual outcome.

## First native failure and diagnostic follow-up

Run `41621873395` at `bae80be` fails the new native child with
`GetSecurityInfo failed: win32=5`. The archive digest and exact source/command
review are retained in
[`windows-security-visibility-41621873395.json`](../evidence/windows-security-visibility-41621873395.json).
The log does not establish which whole-security query failed, so it does not
prove that the audit/label fixture was seeded or that full visibility works.
The failed run remains failed.

The follow-up requests the access mask derived by the pinned
`QuerySecurityAccessMask` declaration, retaining the explicit read-control and
system-security requirements. On failure it records the query phase, requested
fields, required/opened masks and independent handle/path outcomes for the
individual and combined security fields. These are diagnostic observations,
not a fallback: the original full-query error still fails the test. The next
native result must establish the actual behavior before a production binding
is added. No preservation contract or privilege policy is weakened.

## Located query-flag failure

**CONFIRMED:** diagnostic run `41623565789` at `d6f520b` fails before
fixture seeding. Its handle was opened with `0x010a0000`, containing the
`0x01020000` rights returned by QuerySecurityAccessMask. On that same handle,
BACKUP alone (`0x10000`) returns error 5; BACKUP plus explicit fields
(`0x1001f` or `0x101ff`) returns success. Independent GetFileSecurityW with
BACKUP alone returns the expected buffer-sizing error 122 and 140-byte size.
The exact diagnostic artifact, all 24 source files and compiler/child outcomes
are verified in
[`windows-security-visibility-41623565789.json`](../evidence/windows-security-visibility-41623565789.json).
This locates the observable API difference; it does not establish Windows'
internal cause or prove populated security metadata was read.

The corrected experiment selects BACKUP plus every explicit component flag in
the pinned SDK (`0x101ff`), retaining the whole-descriptor requirement. The
independent path observer still uses BACKUP alone. Both APIs must agree after
seeding real audit and mandatory-label ACEs; insufficient access still fails.
[GetSecurityInfo permits combined security flags](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
There is no fallback to an ordinary owner/group/DACL read. Native acceptance
of this correction remains **PRESENT, UNVERIFIED** until the updated run passes.
