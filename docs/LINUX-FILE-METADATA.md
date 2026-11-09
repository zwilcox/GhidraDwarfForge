# Linux opened-file metadata

**CONFIRMED locally; prior baseline also confirmed on hosted Linux:** `LinuxFileMetadata` is a production-code primitive for
native inspection and private-stage metadata application. It is deliberately
not an `AttachmentOperation.Host`, admission decision or public action. A1 in
the [attachment acceptance record](DEBUGLINK-ATTACHMENT-ACCEPTANCE.md) remains incomplete.
The objective still requires the complete Linux/Windows host contract.

## Visibility decision still required

[Linux listxattr](https://man7.org/linux/man-pages/man2/listxattr.2.html) can omit
names inaccessible to the caller. In particular, the
[trusted namespace](https://man7.org/linux/man-pages/man7/xattr.7.html) requires
CAP_SYS_ADMIN for visibility. Successful enumeration, even of zero names, does
not prove absence of unsupported metadata. The earlier read-only research
already recorded this limitation; the implementation must not turn that
uncertainty into permission to replace a target.

The user has been asked whether to retain strict preservation with a separately
invoked elevated check when needed, or explicitly revise the contract to cover
only accessible metadata. No answer has yet been applied. The strict ADR-0004
contract remains in force. This primitive cannot authorize replacement under
either interpretation without the corresponding complete host admission and
independent verification. Neither an administrator-only default nor a permissive
accessible-only default has been silently selected.

## Implemented boundary

The current host ABI is Linux Intel LP64 with UTF-8 Java native paths, matching
the selected Linux release host. This is unrelated to the ELF target processor.
The native contract test compiles function-pointer assignments, field offsets,
sizes and flags against the host headers before the isolated Java call. It
checks `statx`, open/close, fd-based xattr operations, ownership/mode and
`futimens`; no libdwarf declaration or producer ABI changes.

`statx` observes the no-follow path before opening it, then observes the opened
descriptor. Nonregular paths are rejected before attribute access. The open
uses NOFOLLOW/NONBLOCK/CLOEXEC; a changed path or changed descriptor metadata is
rejected. Descriptor identity contains device major/minor and the unsigned inode
number. Snapshot comparisons include link count, complete mode, uid/gid, byte
size, nanosecond mtime/ctime and observed statx attribute bits/mask. Access time
is deliberately excluded because ordinary reads may change it.

All returned attribute names/values are retained as hexadecimal bytes, including
non-UTF-8 names, NUL-containing values and empty values. Enumeration and value
reads are bounded to 64 KiB each, 1,024 attributes and 8 MiB total. Errors,
truncation, malformed names, duplicates and concurrent metadata changes fail;
there is no unavailable-attribute fallback. Snapshots are immutable. The
preservation digest uses versioned, length-delimited binary fields in stable
name order; it covers the ordinary preservation fields only and makes no claim
about hidden namespaces, birth time or change time. Version 2 additionally
binds the observed inode-policy fields described below.

Application accepts an expected snapshot and an existing, independently owned
private stage. It checks both descriptors before changes, rejects aliases and
multiple links, rejects special file modes/statx attributes and visible
namespaces other than `user.*` and `system.posix_acl_access`, then applies
ownership if needed, permissions, exact attributes/access ACL and nanosecond
mtime. Extra visible stage attributes, including inherited access ACLs absent
from the original, are removed. Access time uses UTIME_OMIT. Readback must match
the intended preservation digest; source and destination path identities are
rechecked. The primitive neither creates nor renames files, replaces a live
target, copies file contents nor promises durable publication. The caller must
own the stage and retain/discard it according to the transaction protocol.

Cancellation and failures close descriptors and native buffers. A cancellation
during application may leave the private stage partially adjusted; it never
changes the source. Native filesystem calls can block, so cancellation is checked
around calls rather than claimed to interrupt the kernel. Ordinary concurrent
change detection is not adversarial race protection.

## Independent validation

Run against actual Java 21:

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew compileTestJava buildExtension
JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java \
    python3 -B src/test/integration/linux-file-metadata.py \
    --jar build/libs/GhidraDwarfForge.jar \
    --ghidra /home/ziggy/ghidra_12.0.3_PUBLIC \
    --results build/test-results/linux-file-metadata/run-final
```

The harness requires a fresh result directory and retains exact production JAR,
JNA/Gson dependencies, Java/C/Python sources, command outputs and input hashes.
Python's independent native stat/xattr calls verify each observed field and
attribute byte. It independently constructs Linux ACL blobs to exercise an
explicit source ACL, a different inherited stage ACL, and removal of an
inherited ACL for a source without one. Stage contents and identity remain
unchanged while its supported metadata matches the source. A supplementary-group
change is tested when the runner has one; the result explicitly records whether
that branch ran instead of reporting a skip as a pass.

Local `run-final/result.json` passes eleven independent observations and the
supplementary-group branch. It also proves unchanged source bytes/metadata on
stale-snapshot, set-ID, hardlink, alias and cancellation rejection; symlink/FIFO/
directory inspection fails promptly. A separate Java process repeats successful
inspection, nonregular rejection and cancellation after opening 128 times with
no descriptor growth. The first `run-v1` failed in the test bridge because Gson
2.9.0 cannot deserialize Java record fields; explicit typed parsing fixes the
bridge, and the failed evidence remains retained. Production serialization was
not involved. `run-v2`, `run-v3` and the final strengthened run pass.

The extension-build CI job now runs this isolated harness after building the
production JAR. Hosted run 41597206175 passes all eleven observations, supplementary-group
application and 128 descriptor cycles. Artifact 13213530428 was independently
reviewed against retained source/dependency hashes, actual Java 21 and raw
native observations. The archive SHA-256 is
`37705fdf37c31ee230b9773d81567cd7b7666d71dadbb58af9264ba0ebb4de03`.
The extension build, workflow lint, architecture isolation and diff checks pass
locally. There is no new Ghidra native call, target ELF/DWARF change, public host
support or complete metadata-preservation claim from this checkpoint.

## Inode policy omitted by statx

**CONFIRMED local correction:** the earlier primitive could successfully copy
ordinary fields while losing `FS_NOATIME_FL`. In an owned fixture, the source
had flags `0x80080`, the stage had `0x80000`, and statx attributes were zero.
The old operation returned success. Evidence and the prior JAR are retained
under `build/test-results/linux-inode-policy/`; this primitive was not yet a
public attachment host. An initial NODUMP control was already rejected by the
statx guard and is not reported as reproducing the gap.

The primitive now queries both `FS_IOC_GETFLAGS` and `FS_IOC_FSGETXATTR` on the
same opened descriptor, checks policy stability across enumeration, and binds
flags, extended flags, allocation hints and project ID in its version-2
preservation digest. The audited LP64 request numbers and 28-byte fsxattr
layout are asserted in the native C contract. GETFLAGS's result is an `int *`
even though the request encoding includes `sizeof(long)`; see the
[Linux inode-flag interface](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html).

Application admits ordinary policy only: the EXTENTS storage marker and
HASATTR presence marker are allowed, while other inode-policy bits, nonzero
project IDs and allocation hints are refused before changing metadata.
Missing/unsupported queries and unknown reserved fields are errors, never
proof of ordinary policy. Allocation extent counts are physical layout, not a
preservation field. No setter or privilege escalation is used by production.
Hidden xattr visibility and complete filesystem admission remain separate.

The actual Java 21 harness passes fourteen independent observations plus the
existing ACL/group/cancellation/descriptor controls. Python independently
queries the ioctl fields. New actual source/stage NOATIME cases prove refusal
without mutation, and a stale policy change is detected. These replace the
old successful-but-incomplete behavior. The local filesystem refuses setting
a nonzero project ID with EOPNOTSUPP; no successful native project-ID mutation
test is claimed. Native query layout is independently checked; nonzero project
policy remains an explicit refusal, not supported preservation. Hosted
acceptance of these new inode-policy queries is **PRESENT, UNVERIFIED**.

**CONFIRMED hosted inode-policy acceptance:** run 41607172238 at `bdfae02`
passes the corrected harness. Independent artifact review verifies all fourteen
stat/xattr/inode-policy observations, actual source/stage NOATIME and stale-policy
refusals, native C ABI checks, Java 21 and 128 descriptor cycles. See
[the review receipt](evidence/linux-inode-policy-41607172238.json).
The superseded whole workflow was cancelled; this is acceptance of its completed
metadata job, not a full passing integration gate or complete host admission.
