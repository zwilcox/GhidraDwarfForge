# Windows opened-directory synchronization

**PRESENT, UNVERIFIED on Windows:** `WindowsDirectorySync` supplies opened
directory identity, filesystem facts and an explicit `FlushFileBuffers` call.
The extension/test sources compile, its isolated probe compiles for Java 21,
and actual Java 21 rejects the Linux host before any Windows API access. Native
Windows binding execution remains required. This is not an attachment Host or
a completed A5 durability contract.

The prerequisite independent native experiment **CONFIRMED** that the Windows
runner's NTFS directory accepts `FlushFileBuffers` with `GENERIC_WRITE`, before
and after an owned child rename. Attributes-only access returns error 5.
Ordinary-file controls, independent C# identity and 128 cycles with a constant
57-handle count pass. Backup, restore, security and manage-volume privileges
were listed disabled; the probe never adjusted them. This is not a restricted
token or power-loss test. Exact source/archive/raw-command review is retained in
[`windows-directory-41617008207.json`](evidence/windows-directory-41617008207.json).

The new JNA mapping is audited against the same pinned SDK headers and native
C scalar/layout/signature assertions. It uses Windows Intel 64-bit HANDLEs,
32-bit BOOL/DWORD values and UTF-16 paths. `FileAttributeTagInfo` is eight bytes;
`FileIdInfo` is 24 bytes. Native resources are owned by try-with-resources.

Inspection opens the selected directory with read-attributes access; sync adds
generic write access. Both allow sharing and use `OPEN_EXISTING`,
`OPEN_REPARSE_POINT` and `BACKUP_SEMANTICS`. Non-directory/reparse handles,
alternate stream paths, ambiguous suffixes and unresolved dot traversal are
rejected. Caller-selected paths retain their exact Unicode spelling. The
primitive does not establish that every ancestor is safe; the transaction's
complete traversal/admission checks remain mandatory.

The snapshot binds the opened volume/128-bit file identity, volume serial,
filesystem name, capability flags and filename bound. Expected identity and
filesystem facts must still match before sync. Fresh path observations before
and after the flush must match the still-open handle. Changed paths and all API
errors propagate; there is no no-op, volume flush, native-service fallback or
privilege enabling. Cancellation closes opened resources. Blocking kernel calls
cannot be interrupted and no adversarial race guarantee follows from these
checks.

The isolated Windows harness runs only after the C experiment. It compares
the JNA snapshot with C/C# observations and checks successful sync without
changing the child file, stale and changed-after-open directories, cancellation
before/after open, ordinary-file/junction/stream/traversal refusal, actual DACL
write denial and 128 successful/cancelled cycles with exact handle equality.
The denied directory must remain inspectable and unchanged while sync fails.
Those checks are pending native execution. Full host metadata admission,
filesystem durability selection, public controls and end-to-end recovery remain
required before #72 is complete.
