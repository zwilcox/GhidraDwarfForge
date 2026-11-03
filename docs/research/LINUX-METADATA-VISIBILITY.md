# Linux protected metadata visibility

**CONFIRMED source behavior; production admission remains incomplete.** The
Linux v6.8 [VFS xattr permission check](https://github.com/torvalds/linux/blob/v6.8/fs/xattr.c#L123-L128)
returns ENODATA for a trusted-attribute read without CAP_SYS_ADMIN. The
[ext4 trusted-name list callback](https://github.com/torvalds/linux/blob/v6.8/fs/ext4/xattr_trusted.c#L14-L18)
also depends on that capability. Consequently, neither an empty list nor a
missing-attribute response establishes absence of protected metadata. A numeric
capability mask alone also needs namespace context; it is not a replacement
for effective access evidence.

`src/test/native/linux-metadata-visibility.c` is a standalone experiment for a
possible admission mechanism. It exclusively creates a new private directory
and regular file under an explicitly selected test parent. In the authorized
mode it stores a fresh 32-byte random value in a trusted attribute, verifies
exact readback and listing, then forks a child that drops all its own effective,
permitted and inheritable capabilities. The child must observe ENODATA and no
listed marker on the same opened inode. The unchanged parent must still read
the exact value and list it. This distinguishes hidden metadata from absence
without ever opening or modifying an existing executable.

The probe never elevates itself, alters the parent token or installs a helper.
It checks the exclusively created leaf's identity before cleanup and removes
only its owned canary and directory. The CI invocation explicitly uses its
existing sudo authority for this disposable test; no product elevation or
administrator-only default is selected. Output records the filesystem type.
A failed authorized control fails the experiment rather than accepting partial
visibility.

**CONFIRMED locally:** warning-clean compilation with
`cc -std=c11 -O2 -Wall -Wextra -Werror`; the unprivileged control reports set
EPERM=1, get ENODATA=61, no marker and filesystem type61267 (ext4). Its owned
files are removed. Noninteractive local sudo is unavailable, so the privileged
positive and dropped-capability child are **PRESENT, UNVERIFIED** until CI runs.
The required native-linux job retains source, binary, hashes and both outputs.

This does not yet implement a Linux Host or prove full target metadata
visibility. A production design must bind the canary's lifetime and repeated
access observations to the actual thread/host/filesystem operations, preflight
its exclusively owned workspace, select supported filesystems, and separately
reject unsupported target metadata. Source/stage attributes, identities,
backups, replacement and recovery must all pass the existing A1–A7 contract.
The outstanding public privilege-invocation decision remains unchanged.

**CONFIRMED hosted experiment:** native-linux41645197563 at `89567c0` passes
both controls on ext4. The privileged parent reads all32 marker bytes and lists
the name before/after the child. The child drops its own capabilities and gets
ENODATA=61 with no listed marker on the same opened inode. Retained source and
binary hashes match, and successful exit includes identity-checked cleanup.
See [the review receipt](../evidence/linux-metadata-visibility-41645197563.json).
The separate workflow lint failed SC2024 for redirecting sudo output; that
redirect was intentionally unprivileged. An unprivileged tee pipeline now makes
the intended ownership explicit. The experiment passed, not the full workflow.

## Planned session boundary

**PLANNED, not implemented:** initialize an exclusively owned temporary
workspace only after caller path preflight, on the selected supported ext4
filesystem. Keep a regular, single-link canary containing a random trusted
attribute alive for the entire host transaction. A platform-thread-bound
session would verify its native identity, complete snapshot and exact attribute
value before and after metadata reads; loss of visibility or mutation would
fail the operation. An empty attribute list would never become evidence of
absence. The same already-authorized caller must perform these observations;
no privilege adjustment or automatic elevation belongs in the session.

The native setters/readers already audited for LinuxFileMetadata can support
this experiment without new libdwarf/JNA declarations. Creation, cancellation,
metadata changes, thread changes, alias protection and identity-checked cleanup
need isolated Java21 tests before connecting the session to LinuxAttachmentHost.
That adapter must then use the existing native rename and directory-fsync
mechanisms and pass real ELF/validator/GDB plus recovery tests. Testing a
privileged internal session does not settle how a user explicitly invokes the
public operation; that separate product decision remains pending.
