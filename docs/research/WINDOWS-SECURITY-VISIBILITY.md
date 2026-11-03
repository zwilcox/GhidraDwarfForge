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
