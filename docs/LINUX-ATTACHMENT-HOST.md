# Linux attachment host

**PRESENT, UNVERIFIED for privileged transaction use:** the internal
`LinuxAttachmentHost` implements `AttachmentOperation.Host` with an already
authorized platform thread. It creates no public attachment/elevation action.
The strict metadata policy remains in force. Ordinary export is unchanged.

The factory calls the same read-only all-role path preflight used by the
operation, including refresh roles and `.debug` discovery-shadow rejection,
before creating its owned visibility workspace. It rechecks the plan after
creation. Callers use try-with-resources and must keep the host open through
transaction/recovery. Existing operations still perform their own preflight;
the factory does not substitute for content/validator/receipt binding.

Each filesystem operation brackets observations with the visibility session.
Opened mount IDs/devices and mountinfo records require writable ext4. Inspection
requires a regular single-link file and the existing admitted ordinary
owner/mode/mtime, user attributes/access ACL and inode-policy profile. Unsupported
visible namespaces, privileged modes, policy flags and failed queries refuse.
Fingerprints bind native identity and the versioned preservation hash. Directory
identities include stable mount facts and the exact selected mount record.

Stage metadata uses the previously audited fd-based application/readback. Native
renameat2 NOREPLACE publishes exclusive backups and receipts; flags0 performs
replacement after matching source/target preservation fingerprints. Cross-mount
renames and aliased replacement fail. Installed identity/size/metadata and both
parent mount records are rechecked. There is no copy fallback. Stores force file
contents; host directory synchronization uses fsync and repeated mount checks.
This is not a power-loss guarantee or adversarial race protection. Loss of
visibility/changed canary state retains its private workspace rather than
removing an unverified object.

The standalone smoke uses only new owned sentinel files. Its privileged branch
checks independent byte/metadata-preserving backup with actual owner/group
application from root-owned stages to the invoking user, existing-backup refusal,
metadata-mismatch refusal, atomic replacement, staged restoration, directory
sync, hardlink/symlink/set-ID/trusted-namespace rejection and native UTF-8 names.
The initial invalid-path test must fail before a canary is created. Both
unprivileged refusal and successful close require no remaining visibility
workspace. Sentinel files do not establish valid ELF/DWARF or debugger behavior.

**CONFIRMED locally:** extension build, actual Java21 mount154/session8 and Host
unprivileged checks pass in `build/test-results/linux-visibility-session/host-v2`.
The generic actualJava21 suites pass operation80, protocol138, receipt105,
file75, target63 and transaction532 checks, including existing crash controls.
Local Java21 is a runtime without javac; a direct Gradle JAVA_HOME switch fails
compiler discovery. The successful run uses the installed compiler with
`--release21` and actualJava21 JavaExec through an ignored local init script.
Workflow lint with ShellCheck, architecture isolation and diff checks pass.

The initial privileged visibility lifecycle at18d0d97 is independently reviewed
in [its evidence receipt](evidence/linux-visibility-session-41648910608.json).
That evidence is separate from this Host and later mount binding. Privileged
Host execution, real exported ELF/validator/GDB behavior, coordinator crash and
refresh recovery, public controls and final required-validation remain required.
No A1–A7/C1 row is closed by these local component checks alone.

**CONFIRMED mount-bound session prerequisite:** extension-build41650311183 at
2b89ec3 passes154 mount,8 unprivileged and168 privileged lifecycle checks.
Source/dependency/command and independent native mount comparisons are reviewed
in [the mount-session receipt](evidence/linux-visibility-mount-41650311183.json).
That component acceptance does not cover the later Host or public operation.
