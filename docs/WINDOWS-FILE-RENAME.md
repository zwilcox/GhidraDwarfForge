# Windows opened-stage rename

**PRESENT, UNVERIFIED on native Windows:** `WindowsFileRename` implements
new-name publication and existing-target replacement through one opened-stage
`FileRenameInfo` request. The extension and isolated Java 21 sources compile;
the Windows64 C contract cross-compiles. Native Windows execution of the new
cases is required before the transaction may rely on this primitive.

This is a namespace mechanism for #72, not a complete attachment host or a
durability claim. Full metadata admission, filesystem/storage selection,
backup/receipt validation and post-publication flush/recovery remain the
caller's obligations. Default export does not invoke it.

## Operation

The caller supplies the expected private-stage metadata snapshot and, for
replacement, the expected destination snapshot. The primitive rejects stale
observations, aliases, multiple links and unresolved/ambiguous drive path or
alternate-stream spellings. Existing symlink/reparse leaves are rejected by
metadata inspection; new-name publication refuses every existing leaf,
including a dangling link. Cross-role preflight and complete metadata admission
remain mandatory above this component.

A handle is opened with DELETE/FILE_READ_ATTRIBUTES and reparse-point
inspection. The shared metadata observer checks the opened handle against the
expected stage; both selected paths are rechecked before the native request.
`FileRenameInfo` sets only `ReplaceIfExists` and the absolute UTF-16 destination
name with a byte count. It does not request copying, delayed reboot, readonly
override, POSIX sharing bypass, or security-descriptor merging. Windows must
perform the rename or return an error; no alternate backend is tried.

After the call, readback verifies the same stage identity, size/link count,
supported preservation metadata and stream inventory at the destination, and
that the stage name is absent. Change time may change during rename; creation
and modification times, attributes, owner/group/DACL and its control flags must
match. Cancellation before the request closes the handle without publication.
After publication, readback/cleanup finishes even if cancellation arrives.
An error after the native call is an uncertain outcome requiring transaction
reconciliation, not permission to assume the old target remains.

The checks detect ordinary concurrent changes. They do not claim protection
against an adversarial path race. Native errors, readonly/sharing restrictions
and different-volume failures are propagated; no copy/delete fallback exists.
Filesystem admission and durable namespace semantics are still incomplete.

## ABI and validation

`src/test/native/windows-rename-api.json` pins the inspected Microsoft SDK
headers at `2f767671802301cf043c717d66bf004ed7863487`.
The [SetFileInformationByHandle declaration](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
and [FILE_RENAME_INFO layout](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
are checked by `windows-rename-contract.c`: pointer/scalar widths, the 24-byte
structure, field offsets, FileRenameInfo value, access and open flags. The
variable filename allocation is bounded and includes zero-filled termination.
No producer ABI declaration changes are involved.

The existing isolated Windows metadata job now compiles/runs the C rename
contract before its Java calls, and retains exact source/dependency hashes and
raw command output. Independent PowerShell/C# observations compare original,
stage and installed bytes, file IDs, owner/group/DACL, times and attributes.
Cases cover Unicode and literal special characters/spaces, publish/replace,
existing/dangling destinations, hardlinks/aliases, stream paths, stale snapshots,
changes after opening, cancellation, a native no-overwrite collision, sharing
locks and readonly targets. An interpreted Java process performs repeated
forward/reverse renames and post-open cancellation, checking handle counts
across 128 cycles after warmup.

Local results under `build/test-results/windows-rename/` prove C cross-compilation,
Java 21 compilation and actual harness request transport in normal/interpreted
JVM modes. They do not prove native rename, metadata preservation or power-loss
behavior. Hosted execution and artifact review remain required.
