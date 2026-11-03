# Attachment transaction protocol

**PRESENT, UNVERIFIED as an attachment feature.** `AttachmentPaths` and
`AttachmentReceipt` implement all-role path preflight and versioned recovery
claims. `AttachmentReceiptStore` adds complete-record publication and updates
with mandatory host operations. They are not invoked by ordinary export and
do not modify an executable, create a backup, authorize an attachment or establish
a complete host metadata contract.
The complete transaction remains required by ADR-0004 and ADR-0005. Ghidra,
Java and libdwarf baselines are unchanged. The producer ABI is unchanged;
the separate Linux namespace primitive below adds one audited libc declaration.

## Path plan

The transaction must submit every selected input, retained generation, report,
validation evidence file, backup destination, new receipt and optional log
before opening any output. Each role is unique; all paths must have existing
parents. Parent traversal is resolved before any lexical normalization, so
symlink/`..` selections cannot disguise aliases. Existing input leaf links are
read-only selections; the live target must have a regular non-link leaf. A new
file destination must be absent, including dangling links. Every pair of
existing files is checked using `Files.isSameFile`; new-name collisions are
also rejected. The preflight itself never writes diagnostics to a selected log.

`Plan.recheck` repeats absence, regularity, parent traversal and available
provider-key/size/mtime checks after slow validation. Some providers expose no
Java file key. This does not waive the separate mandatory native host identity,
link-count, content-hash and metadata checks. These observations do not defeat
an adversarial filesystem race. New internal stages must be created exclusively
inside an owned directory; the transaction must bind and recheck that ownership.

## Receipt schema 2 and legacy schema 1

The receipt records:

- A canonical operation UUID, `INITIAL` or `REFRESH` mode, phase, selected
  receipt path, backend, host contract, durability contract and unsigned GNU
  debuglink CRC.
- For each selected artifact: recorded path, SHA-256, byte count, host file
  identity and supported-metadata SHA-256. Byte counts are canonical decimal
  strings to preserve the full Java nonnegative `long` range in JSON consumers.
- Initial roles: `targetBefore`, `targetAfter`, `originalBackup`, `sidecar`,
  `source`, `exportReport`, `validationEvidence`.
- Additional refresh roles: `previousReceipt`, `previousSidecar`,
  `previousSource`, `priorTargetBackup`. The previous receipt artifact binds
  both its selected path and complete hash; it is never rewritten.
- Schema 2 adds a required `recovery` field: null for ordinary operations, or
  an object containing `priorReceipt` and nullable `observedTarget` artifacts.
  A separate recovery record binds the original receipt's actual bytes and
  identity plus a fresh target observation, without modifying that receipt.
  Recovery records cannot become COMMITTED. A ROLLED_BACK recovery record must
  observe the prior image's complete hash/size/metadata at the selected target
  path; its inode may differ because restoration creates an independent copy.

The reader accepts schema 1 only with its original exact field set and no
recovery field; new serialization uses schema 2. Neither a missing schema-2
recovery field nor a schema-1 record with extra recovery claims is accepted.

The target's before/after records use the same final path, distinct image hashes
and identities, and equal supported-metadata hashes. The independently created
backup must match the prior image's bytes/hash/metadata and have a different
identity. Initial attachment uses `originalBackup`; refresh retains that first
backup and also uses `priorTargetBackup`. Repeated artifact path strings are
rejected except for the intentional target before/after pair. Actual aliases
still require native/path checks; string inequality is not file independence.
The serializer emits stable field/role ordering. The reader rejects unknown or
duplicate fields, incomplete role sets, wrong versions, invalid scalar types,
malformed UTF-8/escapes/surrogates, oversized strings/input, invalid hashes/CRC,
noncanonical or overflowing sizes, truncated/trailing JSON and inconsistent
backup/phase claims. It owns and closes its input stream on failure and preserves
cancellation as cancellation. It never opens paths embedded in a receipt.

A receipt is an unauthenticated claim. A structurally valid COMMITTED record is
not proof of current files, validation or successful execution. Attachment and
recovery must compare every explicitly selected file and supported native
metadata snapshot before acting. `metadataSha256` must cover the host contract's
serialized preservation attributes, excluding expected changes such as file
identity and content length. The concrete host formats remain **PLANNED**;
`test-host-v1` in the smoke test is explicitly not a production contract.

## Phases and receipt publication

Allowed transitions are PREPARED to COMMITTED, ROLLED_BACK or RECOVERY_REQUIRED,
and RECOVERY_REQUIRED to ROLLED_BACK. COMMITTED and ROLLED_BACK records cannot
advance. PREPARED/COMMITTED have no failure diagnostic; rollback/recovery states
require one. Advancing produces a new immutable value without writing a file.

Before replacing the executable, the transaction must durably publish a complete
PREPARED record plus a verified independent backup. Receipt updates must verify
that the existing record is still the operation's own expected bytes/identity,
use a complete staged record and atomic replacement, and never overwrite another
operation or immutable committed receipt.

`AttachmentReceiptStore` implements these record operations independently of
the executable transaction. It writes and forces a complete record inside an
exclusively created private directory, validates its identity and bytes, then
publishes it using the host's mandatory atomic no-overwrite operation. Updates
recheck the expected old record's complete bytes, identity, supported metadata
and single-link status, preserve its supported metadata on the stage, and use
atomic replacement. No copy fallback is allowed. The host must provide actual
identity, metadata application/readback and directory synchronization; there is
no permissive production default adapter.

Failures after a namespace operation was attempted produce `PublicationFailure`
with the selected receipt path, requiring reconciliation even if the operation
may have failed before changing the namespace. Cancellation before publication
leaves the prior record or no final record; after publication the store finishes
flush and readback before returning. Cleanup verifies the private directory and
stage identities and retains an unrelated replacement rather than deleting it.
Abrupt termination can retain an owned temporary directory; it does not publish
a partial record. Recovery must validate the selected receipt and actual backup,
target and artifacts before using its phase claims. The record reader never
follows artifact paths embedded in JSON.

The first uncommitted implementation used a temporary hardlink for create-new
publication. Review found that termination between linking and unlinking could
leave two links, conflicting with recovery's single-link requirement. It was
replaced by a single atomic no-overwrite rename before integration. Exception
tests alone did not establish this process-termination property.

## Linux namespace ABI and isolated acceptance

`LinuxAtomicRename` maps exactly:

```c
int renameat2(int olddirfd, const char *oldpath,
    int newdirfd, const char *newpath, unsigned int flags);
```

The declaration was inspected in the host's `/usr/include/stdio.h`; constants
are `AT_FDCWD = -100` and `RENAME_NOREPLACE = 1`, cross-checked with
`linux/fcntl.h` and `linux/fs.h`. The maintained
`src/test/native/linux-rename-contract.c` checks the function pointer signature,
32-bit integer widths and constants against each CI host's actual headers.
JNA uses Java `int` for the result, descriptors and flags and explicit
NUL-terminated UTF-8 byte arrays for paths. Lossy Java path round trips are
rejected. The libc binding is loaded only on Linux when explicitly constructed;
missing symbols, unsupported operations/filesystems and errno failures propagate
without fallback. This host primitive does not depend on the ELF target's ABI.
The pinned producer remains libdwarf 2.3.2 at `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`.

The [Linux rename contract](https://man7.org/linux/man-pages/man2/rename.2.html)
defines no-overwrite behavior and requires filesystem support. It does not
establish power-loss durability; the full host adapter must identify supported
filesystems and flush behavior. In particular, remote filesystem errors cannot
be assumed to mean the namespace was unchanged.

The standalone Linux smoke uses actual native rename and directory fsync with
a **test-only** metadata adapter (device/inode/link count, mode, uid, gid and
mtime). It is not a production ACL/xattr-preservation contract. Six child JVMs
halt without `finally` cleanup before/after initial publication and updates.
Parent observations prove absent/complete prior/complete next records, one link
for published records, readable prepared recovery records and retained private
stages. These are process-termination tests, not power-cut or executable-rollback
tests. Native Windows receipt publication and the full Linux/Windows identity,
metadata, backup, attachment, rollback, refresh and UI contracts remain required.

## Independent backup publication

`AttachmentFileStore` now provides the transaction's independent copy operation.
Its snapshot records a canonical selected path, streamed SHA-256/CRC/byte count,
and the mandatory host identity/metadata/link observation. Native regular-file
and single-link checks surround each digest; selected leaf links are not followed.
The transaction still must preflight all of its roles and validate its selected
ELF, export report and validator evidence before calling this operation.

The backup destination must be absent, including dangling links. Copying uses a
64 KiB buffer and a CREATE_NEW stage in an owned private directory beside the
destination. Growth beyond the expected byte count, truncation, no-progress I/O,
cancellation, changed source/stage identity and digest mismatches reject the
operation. The complete source is rechecked before metadata application and
again before publication. The host applies supported metadata and the store
independently verifies its hash, source/copy content equality and different file
identities. The writable channel is opened before applying read-only metadata,
so a supported read-only file can still be flushed without reopening it for
writing. Receipt updates use the same ordering.

Only a verified and flushed complete copy reaches the final backup name through
the host's atomic no-overwrite rename. The directory is synchronized and the
published file is read back. The backup is never a hardlink and never overwrites
an existing name. Post-publication cancellation finishes synchronization and
verification; failures after a publication attempt return `PublicationFailure`
with the backup path. A published backup is retained on failure. Cleanup checks
ownership and retains a concurrent stage replacement. The caller must reconcile
retained recovery material rather than retry by overwriting it.

**CONFIRMED locally:** 75 backup controls pass on Java 25 and actual Java 21,
including four abrupt child-process exits, read-only permission/mtime
preservation, original hashes/identity, existing/dangling/hardlink collisions,
a competing creator after preflight, failed metadata application, directory
flush failures, a 16 MiB copy cancellation, source mutation and stage replacement.
The 101 receipt controls still pass, now updating a deliberately read-only
receipt. Logs are `build/attachment-file-store.log` and
`build/attachment-file-store-java21.log`. The tests use the explicitly limited
Linux smoke metadata adapter above; they do not establish production ACL/xattr
preservation or native Windows backup support. This class does not replace the
target or implement the complete attachment/rollback state machine.

## Conditional replacement and restoration

`AttachmentTargetStore` supplies the next internal filesystem operation. It
requires explicit current-target and owned-stage snapshots, distinct identities,
matching supported metadata and the same filesystem. It rechecks both complete
files and their parent identities immediately before invoking the mandatory host
atomic replacement operation. There is no copy-over-target fallback. After the
attempt, it synchronizes the affected directories and verifies the installed
image's full bytes, identity and supported metadata against the owned stage.
Late cancellation does not skip these observations. A native failure is never
assumed to mean that the namespace is unchanged: `ReplacementFailure` requires
reconciliation of the explicit target/stage paths with retained recovery material.

Restoration creates another independently verified copy of the selected backup,
then conditionally replaces the expected current target. It never consumes or
rewrites the backup. A concurrent target change before or during creation of the
restore copy is preserved, and a failed replacement retains the copy if it still
exists. If reconciliation proves that the target name is absent, the existing
no-overwrite backup operation can restore a copy at that name; a new concurrent
creator is still protected by the host's no-overwrite operation. Selecting these
recovery actions from the complete receipt/association state remains the
transaction controller's responsibility, not an inference made by this primitive.

**CONFIRMED locally:** 63 replacement/restore controls pass in actual Java 21,
including successful replacement and restoration, pre/post-operation failures,
failed directory flush, uncertain native failures before/after a real rename,
an injected missing-target namespace, independent-backup retention, metadata
conflicts, concurrent changes during both replacement and restoration,
cancellation and two abrupt child-process exits. The missing-target test is a
Linux filesystem injection, not a native Windows API acceptance claim. The
test host uses actual Linux atomic moves and the explicitly limited test-only
metadata adapter. Evidence is `build/attachment-target-store-java21-r2.log`;
the earlier 52-control set is `build/attachment-target-store.log`.

These methods are not invoked by ordinary export and expose no attachment UI.
They do not establish ELF validity, successful structural validation or an
authorized transaction merely from hashes. Before enabling attachment, the
controller must bind all explicit selected paths, reports, validator evidence,
prepared receipts and retained generations, then journal replacement, failure
and refresh outcomes. In particular, a receipt publication failure after a
COMMITTED record became visible must be reconciled without mutating an existing
committed record or treating visibility alone as durable success. That controller
is implemented below for filesystem coordination. Production host contracts,
real ELF/validation preparation and end-to-end GDB evidence remain required.

## Commit and explicit interrupted-operation recovery

`AttachmentTransaction` now coordinates the prepared filesystem operation.
Its caller supplies every file role plus explicit main receipt, recovery receipt
and restore-image paths. The controller checks cross-role aliases before any
of its writes, verifies every selected file's complete SHA/size/native identity/
supported metadata against the prepared claims, verifies the actual sidecar CRC,
and binds the host contract. Preparation still must perform the earlier all-role
preflight before creating the backup/candidate and validate the real ELF, export
report and structural evidence. This controller does not accept a matching hash
as proof of DWARF validity and is not exposed as a public attachment command.

After publishing PREPARED, the controller rechecks all files, the record and
parent identities, performs conditional replacement, verifies retained inputs
again, and publishes COMMITTED. A failed or cancelled operation attempts to
restore only the observed owned candidate; an unrelated concurrent target is
preserved. A proven absent target can be restored with atomic no-overwrite copy
publication. Refresh recovery first verifies the intact prior sidecar/source,
prior committed receipt and original backup, and restores from the separate
prior-target backup. It never invents a missing old debug association.

Failure handling publishes a **separate** recovery record. This applies even if
the final COMMITTED record was already made visible before a flush or later
operation reported failure. Existing committed records remain unchanged. The
recovery record binds their actual hash/identity and a fresh observation of the
target after recovery. A journal failure reports RECOVERY_REQUIRED, even if a
complete restored image or terminal recovery record is visible; visibility alone
is not claimed as durable completion. Conflicting recovery records are preserved.
Cancellation does not interrupt restoration or journal reconciliation halfway.

`recoverInterrupted` supports explicit restart recovery using the selected
original PREPARED claims and an agreeing current PREPARED or COMMITTED record.
It revalidates the independent backup and, for refresh, the entire retained
prior association. The new candidate/pair can be missing or damaged because
recovery does not need to install them. All paths are selected explicitly;
none is followed from JSON. A fresh recovery receipt and restore-image destination
are required, and each output directory's observed identity is checked before
writing. A complete prior image already restored by an interrupted recovery is
recognized without overwriting it. A later refresh may match a prior attachment
by exact selected path, image bytes and metadata after rollback changed its inode;
the new operation still observes and guards the current native identity throughout.

**CONFIRMED locally:** 525 actual Java 21 filesystem-controller checks pass for
initial attachment and changed-CRC refresh fixtures, normal and failed receipt
publication, metadata/alias binding, cancellation, immutable committed records,
concurrent target/journal changes, missing-target recovery, damaged prior pairs,
recovery-journal failure and refresh after rollback. Eight child JVMs terminate
without cleanup after preparation, replacement, before final commit and after
COMMITTED publication; the parent resumes recovery from the retained files and
verifies the prior complete image and untouched backups/pairs/committed receipts.
All filesystem primitives still pass (63 replacement, 75 backup, 101 receipt
controls), and schema/path coverage is now 138 controls including legacy parsing
and malformed recovery records. Evidence is `build/attachment-transaction-java21-r2.log`.
Earlier 375/516-control sets remain in their separate logs.

These tests intentionally use non-ELF owned file contents and the limited Linux
test metadata adapter. They prove filesystem state coordination, not actual
debuglink/ELF correctness, Ghidra curation/re-export, structural-validator
approval, native Windows recovery, or GDB automatic discovery. Those requirements
remain in the full completion ledger and must pass through the eventual public
preparation/UI path. No supported-host or attachment-completion claim follows
from this component alone.

The Windows replacement adapter must handle documented non-success states,
including errors where file names have already changed, and must not use flags
that ignore metadata/ACL errors. `REPLACEFILE_WRITE_THROUGH` is documented as
unsupported, so it cannot establish durability. See [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
The separate independent backup and receipt remain necessary; the Win32 backup
parameter alone does not satisfy this project's pre-replacement backup contract.

## Local verification

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew \
    attachmentTransactionSmoke attachmentTargetStoreSmoke attachmentFileStoreSmoke attachmentReceiptStoreSmoke attachmentProtocolSmoke exportReportClaimsSmoke companionArtifactPublisherSmoke \
    buildExtension
cc -std=c11 -Wall -Wextra -Werror src/test/native/linux-rename-contract.c -o build/linux-rename-contract
build/linux-rename-contract
actionlint .github/workflows/ci.yml
git diff --check
```

**CONFIRMED locally:** 101 filesystem/publication controls and 116 receipt/path
controls pass. The filesystem tests exercise native no-overwrite behavior,
Unicode/space paths, existing/dangling/directory collisions, actual process
termination, conditional updates, immutable committed states, metadata readback,
flush failures, concurrent changes and cancellation. The protocol checks include both modes,
permitted/forbidden transitions, maximum file sizes, corrupt receipts, all pairs
of nine input/output roles, hardlinks, symlinks, actual parent traversal,
concurrent selection changes, no-write rejection and stream closure on
cancellation. The existing export-report reader and three-artifact publisher
regressions pass; the extension builds. The candidate workflow includes the
protocol smoke on Linux and native Windows and the filesystem/ABI smokes on
Linux only. Native Windows protocol execution is still
**PRESENT, UNVERIFIED**. No emitted ELF/DWARF changes or new GDB-support claims
are made by this component checkpoint.

The final filesystem smoke also passes in an actual Java 21 runtime, including
its six child JVMs (`build/attachment-receipt-store-java21-r2.log`). Production
classes already use Java 21 bytecode. The first local Java 21 test attempt
rejected Java 25 test classes before executing any test; its log is retained
separately. The corrected local init script compiles tests with `--release 21`
and selects `/usr/lib/jvm/java-21-openjdk-amd64/bin/java` for this task. CI's
selected JDK supplies its own compiler/runtime. The initial immutable-attribute-map
test-adapter error is retained in `build/attachment-receipt-store.log`; the
passing expanded run is `build/attachment-receipt-store-r4.log`. Neither failed
attempt is counted as successful validation.
