# Linux attachment host

**CONFIRMED current runtime acceptance at `be2e806`:** both native host public
journeys, active cancellation, changed-curation refresh, recovery and GDB/CRC
checks pass reviewed run41882141913. See the
[complete acceptance audit](DEBUGLINK-ATTACHMENT-ACCEPTANCE.md) and
[Windows evidence](evidence/windows-attachment-41882141913.json).
The full required target gate and final C1 protected integration remain pending.
Development checkpoint paragraphs below are **HISTORICAL** where superseded by
this audit; they retain their original evidence scope.

**CONFIRMED scoped production Host and real-ELF acceptance:** the internal
`LinuxAttachmentHost` implements `AttachmentOperation.Host` with an already
authorized platform thread. Public attachment runs through the isolated helper;
the launcher requests pkexec only when the user explicitly selects authorization.
The host adapter itself does not acquire privileges. The strict metadata policy
remains in force. Ordinary export is unchanged.

Reviewed real-ELF CLI/refresh/recovery and GUI evidence is recorded in
[the Linux transaction receipt](evidence/linux-attachment-41693381663.json) and
[the complete GUI job receipt](evidence/linux-gui-attachment-41697807284.json).
These are scoped prior-head results. Current passing native active-GUI
cancellation and pending integration are tracked in
[the completion ledger](DEBUGLINK-ATTACHMENT-ACCEPTANCE.md).

The latest independent readback at `e2ccccf`, run41657292709, corroborates
actual uid/gid1001, regular mode0710, nanosecond mtime1700000000123000000,
`user.fixture=00ff0a`, original bytes and distinct inodes for target/backup.
All ten retained commands pass under Java21; source/dependency bytes match
their manifests and exact published source. See
[the readback receipt](evidence/linux-attachment-host-readback-41657292709.json).
This is isolated mechanism evidence, not full transaction/ELF/GDB acceptance.
CI now publishes the production attachment and saved-curation refresh archives
immediately after their steps, so they can be reviewed while broader ABI tests
continue. Missing or partial evidence does not establish a passing test.

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

## Production integration and interrupted sessions

**CONFIRMED isolated Host acceptance:** extension-build41652044404 at
`bdef6f6` passes the privileged 26-check Host fixture and seven unprivileged
checks. See [the independently reviewed receipt](evidence/linux-attachment-host-41652044404.json).
This supersedes the pending isolated-Host statement above, not the outstanding
real-ELF and public-action requirements.

**PRESENT, UNVERIFIED:** real ELF and saved-curation refresh harnesses now use
the production Host through an explicit test switch. CI invokes only these
owned fixture processes with `sudo -n`, retains private results in RUNNER_TEMP,
and archives them using privileged read access without changing metadata.
This is test setup, not automatic elevation or a public privilege policy.
Independent Python readback also checks actual target/backup uid/gid, mode,
mtime, xattrs, bytes and distinct identities in the isolated Host fixture.

`openPrepared` and `openRecovery` share the coordinator's read-only role
preflights before creating a visibility workspace. A prepared candidate has
existing independent backups; recovery also permits the candidate to have
been consumed by replacement. Neither entry point infers selected paths from
a receipt. Eight owned sentinel child processes halt at PREPARED,
TARGET_REPLACED, BEFORE_COMMIT and COMMITTED in initial and refresh cases;
fresh recovery sessions must restore the previous bytes/metadata and retain
the original receipt and prior generation. Abrupt-child visibility workspaces
remain as evidence; successful sessions close their own workspaces. These
sentinels exercise recovery, not ELF validation or power-loss survival.

Local commands: the six attachment Gradle smoke tasks and `buildExtension`
with `-I build/java21-smokes.init.gradle` pass under actual Java21; counts are
80, 138, 105, 75, 63 and 532. `javac --release 21` compiles the integration
probes, Python AST parsing accepts the three changed harnesses, and actionlint
with ShellCheck plus `git diff --check` pass. Privileged production-host
ELF/GDB, saved-curation refresh and crash execution remain assigned to CI.

## Reviewed real operation and recovery

**CONFIRMED at `e3601f9`:** early artifacts from41660525292 independently
establish fifteen real initial commit/rollback cases across x86-64, AArch64,
ARM32 and both MIPS32 byte orders, with exec/PIE/no-build-ID roles; two saved-curation
exec/PIE refreshes; and eight sentinel abrupt-process recoveries through fresh
production Host sessions. The [acceptance receipt](evidence/linux-attachment-operation-41660525292.json)
records artifact digests, exact release/test provenance, metadata/identity
checks, ELF preservation, live validator replay and actual native/QEMU GDB
source/type/argument/CRC outcomes. Fresh local LLVM verifies all retained
sidecars. The ARM32/AArch64 vDSO warning is corroborated by the compiler reference.
This supersedes earlier pending statements for these exact scopes. It does
not establish Windows execution, public helper/GUI or
full final-head acceptance; A1–A7/C1 remain incomplete.
