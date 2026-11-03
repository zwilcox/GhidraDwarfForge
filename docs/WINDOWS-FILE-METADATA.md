# Windows opened-file metadata

**PRESENT, UNVERIFIED on native Windows:** `WindowsFileMetadata` implements
opened-handle identity and accessible metadata inspection/application. The
extension and isolated Java probe compile; the Windows C ABI assertions
cross-compile. Those checks do not prove Windows runtime behavior. The native
Windows CI job runs the probe before building the producer libraries.

This is a primitive for A1 in the [completion ledger](DEBUG-LOADING-COMPLETION-PLAN.md),
not a complete attachment host or permission to replace an executable. A1–A7
remain required, including full metadata admission, durability and public
CLI/GUI controls. No attachment option is enabled by this checkpoint.

## API and ownership boundary

The audited host ABI is Windows Intel 64-bit, independent of the target ELF
processor. `src/test/native/windows-metadata-api.json` records the inspected
Microsoft SDK revision, header hashes and API documentation. The C contract
checks calling signatures, fixed-width fields, structure sizes/offsets and
constants against the runner's MinGW headers before any isolated Java call.
No native producer declaration changes are involved.

Inspection opens an existing local-drive regular file with Unicode paths,
explicit read/control access, shared read/write/delete and reparse-point
inspection. It rejects alternate-stream paths, directories, reparse files,
pending deletion and ambiguous path suffixes. The opened handle supplies the
volume and 128-bit file ID, link count, size, attributes and file times. Owner,
group and DACL are read with `GetSecurityInfo`, validated and copied within
bounded native allocations. Stream names/sizes are read with bounded
`FileStreamInfo` records. Before/after handle observations and reopened path
identity checks detect ordinary concurrent changes; they are not a claim of
adversarial race resistance.

Application accepts an expected source snapshot and an already owned private
stage. It rejects changed sources, aliases, hardlinks, named streams and
unsupported attributes before applying owner/group/DACL, DACL protection,
ordinary attributes, creation time and modification time. Readback must match
the source preservation fields exactly; the stage retains its original content,
size and identity. Source metadata is rechecked. Access/change times are not
copied. Native handles and security buffers have explicit cleanup on failure
and cancellation. A failed application can leave the private stage partially
adjusted; it never changes the source or publishes the stage.

The primitive does not enable privileges, query SACLs or extended attributes,
or prove their absence. It does not create files, copy file contents, flush,
rename or replace a live target. The strict ADR-0004 preservation contract
remains in force. The pending metadata visibility/privilege policy decision
must be resolved before completing host admission; neither an elevated default
nor accessible-only preservation has been selected implicitly.

## Independent native test

`src/test/integration/windows-file-metadata.ps1` requires Windows, actual Java
21, a Windows64 compiler, the selected Ghidra JNA/Gson dependencies and a fresh
result directory. The CI invocation records these exact inputs and retains
their bytes and hashes. Test dependencies are isolated from release packaging.

The harness compares Java observations with independently read .NET security
descriptors, timestamps, attributes and a C# native file-ID observer. It tests
ordinary inherited and protected DACLs, readonly/hidden attributes, Unicode and
space-containing names, stale snapshots, cancellation, aliases/hardlinks, named
streams, symlinks, directories, empty files and sharing locks. Stage content
and identity and original content/metadata must remain unchanged as applicable.
A standalone interpreted Java process repeats inspection and cancellation
128 times and compares native handle counts. Raw commands, outputs and JVM
crash logs remain under the result directory even when a case fails.

Local evidence under `build/test-results/windows-file-metadata/` consists of
extension/test compilation, the cross-compiled C contract and a portable
PowerShell parser/process-capture check on Linux. None substitutes for the
native Windows run or the complete Linux/Windows attachment acceptance matrix.
