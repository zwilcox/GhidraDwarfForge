# Attachment transaction protocol

**CONFIRMED implementation; complete product acceptance remains pending.**
`AttachmentPaths`, `AttachmentReceipt` and `AttachmentReceiptStore` supply
all-role preflight, versioned claims and complete-record publication to
`AttachmentOperation` and `AttachmentTransaction`. The isolated helper performs
explicit initial attachment, refresh and saved-request recovery. Ordinary export
does not enter this transaction. Native component and real-export evidence,
including remaining Windows/GUI/integration checks, is tracked by
[the completion ledger](DEBUG-LOADING-COMPLETION-PLAN.md).

ADR-0004 and ADR-0005 remain the required operation contract. Ghidra, Java and
libdwarf baselines are unchanged. The producer ABI is unchanged; the separate
Linux namespace primitive below uses its audited libc binding.

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
identity and content length. The concrete production formats are documented in
[the Linux host contract](LINUX-ATTACHMENT-HOST.md) and
[the Windows host contract](WINDOWS-ATTACHMENT-HOST.md). `test-host-v1` in the smoke
test is explicitly not a production contract. Read-only validator tools use a
separate identity/content observation; their validation-evidence schema2 does not
claim recovery metadata preservation. Receipt schema2 is a distinct format.

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

## ELF/report binding and real-ELF controller checkpoint

**CONFIRMED locally:** `AttachmentExportBinding` adds read-only production
preparation checks for four explicitly selected files. It verifies complete
report SHA claims against host-observed file identities/metadata and streamed
SHA/size/CRC values, the matched sidecar's copied prefix and allocated metadata,
build-ID relationship and reported target. All inputs are checked again before
returning, and callers can recheck before later writes. For refresh the selected
export original must be the retained unmodified backup, not the attached image.
The binding does not follow paths from JSON, alter PARTIAL/NOT_RUN, validate
DWARF, prove source lookup or replace the full transaction path preflight.

Thirty Java 21 controls cover valid and PARTIAL reports, mismatched hashes,
rehash-consistent damaged ELF bytes, wrong target claims, identity changes,
same-length changes with restored mtime, links/aliases, cancellation and changes
during observation. Deliberately invalid DWARF in the positive identity fixture
proves that this layer never upgrades report validation to PASS. The existing
525 controller and 574 report-binding checks and extension build pass.

`attachment-elf-controller.py` freshly validates an explicitly selected real
export before invoking the test-only `AttachmentElfTransactionProbe`. The probe
copies inputs into private case directories, binds their report/ELF evidence,
creates an independent backup and owned candidate, applies test-host metadata,
flushes, and invokes the production transaction controller. Separate cases prove
successful commitment and injected post-replacement rollback. Raw `readelf -lW`
observations agree with the original; backups retain original bytes.

Actual GDB sessions must automatically load DWARF from the exact attached
sidecar, resolve the compiler-oracle function address, list the recorded source,
display signatures/types, hit the named breakpoint with arguments 19/23, and
exit normally. x86 runs natively; AArch64 and MIPS use isolated QEMU UNIX sockets.
A separate deliberately corrupted copy must lose full-DWARF discovery through
CRC rejection. The valid committed generation is never corrupted/restored by
that negative test. Its receipt, artifacts and backup, and the rolled-back
generation, retain full bytes, inode/device, mode, ownership, link count, size
and mtime across consumer checks. This is the limited Linux test contract, not
complete Linux ACL/xattr or Windows metadata acceptance.

Seven final local cases pass under
`build/test-results/attachment-elf-controller/*-preserved/`:

| Target | Roles | Strict inherited frame diagnostics |
| --- | --- | --- |
| x86-64 | exec, PIE, exec without build ID | 3, 1, 3 |
| AArch64 | exec, PIE | 5, 5 |
| MIPS32 big-endian | exec, PIE | 0, 0 |

All 17 frame diagnostics are independently corroborated against the retained
original by the existing strict checker. GNU/LLVM have no unexplained diagnostics.
AArch64 GDB's QEMU-supplied vDSO warning is retained and independently reproduced
with the compiler reference; other discovery diagnostics are rejected. The
validator inputs are retained separately so later exports cannot overwrite the
evidence. The report-retention guard passes all 23 local receipts, including
earlier calibration runs; only the seven named final cases establish this
checkpoint's complete behavior.

Reproduce after building the extension, with explicit existing fixture/report
paths (repeat for each target/role):

```sh
JAVA=/path/to/java21/bin/java python3 src/test/integration/attachment-elf-controller.py \
    --jar build/libs/GhidraDwarfForge.jar --ghidra "$GHIDRA_INSTALL_DIR" \
    --fixture-dir /absolute/path/to/build/fixtures --target x86_64 --role exec \
    --report-log /absolute/path/to/headless-symbol-export/x86_64.exec.log \
    --strict-validator /absolute/path/to/pinned-validator/bin/dwarfdump \
    --result-dir /absolute/path/to/new-results
```

The first integration calibration used the wrong compiler symbol name; the
reference actually defines `recovered_add`. A remote-startup calibration then
encountered a non-UTF-8 unrelated pathname in `/proc/net/unix`; socket readiness
now compares raw bytes. Both failures are retained. The first no-build-ID export
invoked the system dwarfdump and failed its checker; a fresh complete export
with the pinned validator passed, followed by the final controller test. No
failed attempt is counted as a passing full case.

CI includes the binding smoke and schedules this real-ELF bridge immediately
after exec/PIE/no-ID exports on all five target lanes. ARM32, MIPS little-endian
and additional no-ID cases remain **PRESENT, UNVERIFIED** for this bridge until
that exact workflow runs. Hosted acceptance, production Linux/Windows host
metadata, production validator supervision/binding, fresh curated re-export and
refresh, and public CLI/GUI controls remain required. This test bridge does not
enable attachment or close #72.


## Production preparation coordinator

**CONFIRMED locally:** `AttachmentOperation` replaces manual preparation in the
real-ELF test bridge. One production operation now preflights every requested
input/output/backup/receipt path before invoking its mandatory validator,
observes native host identities and parent identities, binds the report/ELF
pair, requires the selected source to match its recorded path, checks sidecar
placement and rejects a shadowing file before `.debug` lookup. It rechecks
inputs after validation, creates the independent backup, constructs from that
unmodified backup, applies/flushes metadata and hands complete claims to the
transaction controller. Failures before handoff retain complete recovery files
and report selected stage paths; a failure just before receipt publication also
retains those paths. No preparation failure replaces the target.

Refresh uses the retained original backup for the new export/candidate and
creates a separate backup of the current attached image. Before validation it
requires the committed prior receipt and unchanged original backup/old pair,
matching current bytes/metadata, a matching actual prior GNU debuglink and
fresh sidecar/source basenames. A previously restored target may have a new
inode; the operation reobserves and protects that current identity while
preserving the older committed receipt. Initial/refresh selection does not
change Ghidra's imported executable hash.

Host metadata/namespace operations, consumer basename encoding and a live
validator service are mandatory dependencies. There is no production default
that accepts arbitrary JSON or uses the Linux test metadata adapter. The real
integration bridge supplies a fixture adapter that binds the controlling
harness's freshly produced validator evidence; it is not a production validator
implementation. The source remains at its actual recorded path rather than
moving an identical copy and assuming DWARF lookup will find it.

`attachmentOperationSmoke` passes 72 actual Java 21 controls for initial and
refresh sequencing, rollback and refresh after rollback, validation rejection,
cancellation, missing evidence, concurrent changed input, metadata failure,
unsafe selections, recorded-source mismatch, shadowing lookup and retained
artifacts on a pre-publication handoff failure. Its validator is an explicit
unit-test seam, and its small ELF fixture is not a DWARF validity claim.
The 525 controller and 30 export-binding regressions and extension build pass.

Seven real cases are separately rerun through the coordinator in
`build/test-results/attachment-operation/*-retained/`: x86-64 exec/PIE/no-ID,
AArch64 exec/PIE and MIPS32 big-endian exec/PIE. Fresh GNU/LLVM/pinned-strict
checks, actual automatic GDB lookup/source/types/arguments, native/QEMU runtime,
CRC rejection, original preservation and stable completed-generation metadata
pass. The same 17 independently corroborated frame diagnostics remain visible.
Every case retains and runs its exact production JAR and dependency copies,
plus Java test sources, GDB oracle and Python driver. Earlier local runs recorded
JAR hashes without retaining a copy; they are not substituted for this retained
checkpoint. The raw-report retention guard passes all 15 receipts in this new
directory, including the earlier coordinator calibrations.

The first compilation used a nonpublic ELF section field; it was corrected to
the existing public accessor before any runtime test. The compile failure is
retained in `build/attachment-operation-compile.log`; the final build/smoke log
is `build/attachment-operation-final.log`. Workflow lint, architecture isolation
and diff checks pass. CI includes the operation smoke and uses this coordinator
in the existing five-target real-ELF bridge. Exact-head hosted acceptance is
**PRESENT, UNVERIFIED**. Production metadata/live validation adapters, actual
curated saved-program re-export/refresh and the CLI/GUI remain required; neither
#72 nor any complete A1–A7 row is closed by this checkpoint.

## Saved analyst edits and changed-CRC refresh checkpoint

**CONFIRMED locally:** `attachment-curated-refresh.py` imports an owned target,
applies a real saved variable type and exports the initial pair. It invokes
`AttachmentOperation` through a test-only Java bridge, verifies automatic GDB
discovery/runtime, then reopens the same project to rename the function,
structure and a structure member. Another fresh process verifies those saved
edits and unchanged imported path/hash before and after re-export against the
retained original backup. Direct export against the attached executable is
separately rejected and leaves no output pair.

The fresh basename's actual CRC differs. The operation verifies the previous
receipt and association, preserves the first original backup, independently
backs up the prior attached image, and commits the refreshed association.
The harness checks the receipt's exact previous receipt/pair hashes and original
backup identity, complete program headers, and old generation bytes/metadata.
A fresh GDB session discovers only the selected new sidecar and checks the
curated function, source, type/member, arguments 19/23 and normal execution.

Both x86-64 exec and PIE cases pass in
`build/test-results/attachment-curated-refresh/{exec,pie}-final/`.
Each generation passes GNU readelf, LLVM verification and the pinned strict
validator. The exec generations each report three inherited frame diagnostics;
the PIE generations each report one. Every diagnostic is independently
corroborated against the exact original backup/input, with zero unexplained
errors. The exact operation/exporter JARs, dependencies, scripts and validator
outputs are retained. Actual Java 21 runs the attachment coordinator; local
Ghidra uses its configured Java 25 runtime. The baseline remains Java
21-compatible bytecode. CI runs both cases with its packaged extension/natives.

The first `exec-v1` calibration committed both images but failed GDB's refreshed
type assertion: the fixture marked an otherwise unused type as a session favorite,
which was absent from type roots after reopening. The corrected fixture applies
the type to a saved analyst local with explicitly unavailable storage; subsequent
processes verify that real variable/type link. It does not invent a location or
change exporter type-selection policy. The failed transcript remains retained.
`exec-v2` passes; the two final cases additionally verify the full receipt chain
and use owned Linux process-group cleanup on harness timeouts.

The existing real-ELF x86-64 PIE commit/rollback/discovery/CRC test also passes
after sharing the fixture validator adapter and parameterizing the GDB oracle;
default function/type expectations remain unchanged. All test Java compiles,
workflow lint, architecture isolation and diff checks pass. No new production
native declaration or exporter behavior is introduced by these fixtures.

This establishes actual curated refresh through the coordinator, not a public
attachment workflow. The explicit limited Linux host and externally captured
validator adapter still do not meet the production host/live-validator contract.
Native Windows, CLI/GUI, exact-head hosted acceptance and remaining A1–A7/C1
requirements remain open. Neither issue is complete.

The first hosted saved-refresh run (`41582470882`) failed before Ghidra import:
CI selected the same installed JAR for the operation and exporter roles. A
path-keyed provenance map retained only `installed-exporter.jar`, leaving the
compiler's `operation.jar` classpath entry absent. The downloaded x86-64 artifact
(`13207910777`, SHA-256
`efaa94c469b3451fc2730c5b3b8ae930533aeeaf76fdefe192b3c4f36530b5d8`)
confirms the missing file and compiler diagnostics. The harness now retains both
role names even when they originate from one path. Fresh exec/PIE runs using that
same installed-JAR arrangement pass in `*-same-jar/`; all twelve retained local
strict reports pass the raw-output retention guard. The full hosted gate still
requires a new passing run; no failing check is waived.

### Saved-program refresh through the live validator

**CONFIRMED locally:** `AttachmentCuratedRefreshProbe` now requires explicit
supervisor/GNU/LLVM/raw-strict/configuration selections and invokes the real
`AttachmentValidator` for initial attachment and refresh. There is no captured
validator fallback in this saved-program harness. Independent checks bind all
pre-mutation inputs, tool hashes, complete published evidence and raw logs, and
retain first-generation logs alongside pairs, backups and receipts.

Fresh x86-64 non-PIE and PIE runs pass in
`build/test-results/live-refresh/{exec,pie}/`: saved analyst function/type/member
edits survive reopening and backup-based re-export, both generations pass live
validation, and GDB discovers the changed symbols/types/member with correct
source and available arguments. The original import hash, original backup,
previous target backup and prior generations remain intact. The workflow now
requires the installed helper for both cases. These results still use the
explicit limited Linux metadata host, not a production host adapter. Windows,
public controls and full protected integration remain required.

## Production Linux replacement namespace primitive

**CONFIRMED locally:** `LinuxAtomicRename.replaceAtomic` uses the already
audited `renameat2` declaration with flags zero to consume a verified stage in
one replacement. `publishNew` retains `RENAME_NOREPLACE`. Both operations reject
non-UTF-8 native path configurations and propagate native failures without a
copy fallback. This primitive does not authorize attachment: callers must still
bind/recheck files and metadata, establish host admission, and synchronize both
affected directories under the documented durability contract.

The target-store, transaction, operation and real-ELF test hosts now use this
production namespace operation instead of their previous Java move seam. On
actual Java 21, receipt/store/target/transaction/operation suites pass
101/75/63/525/72 controls, including process termination, rollback, refresh and
retained backups. The x86-64 executable replay passes live GNU/LLVM/pinned-strict
validation, automatic GDB discovery/runtime, CRC mismatch rejection and rollback
with the new operation. Evidence: `build/test-results/linux-native-replacement/`.
The metadata adapters in these tests remain explicitly limited. Full Linux/
Windows host admission, durability acceptance and public CLI/GUI are still
required. No ELF/DWARF or default-export behavior changed.

## Production Linux directory identity and flush

**CONFIRMED locally:** the shared transaction test host now delegates directory
identity and flush to `LinuxDirectorySync`, retaining opened directory/mount
checks and propagating native errors. The standalone independent C/Java 21
harness, all five transaction suites and the real x86-64 live-validator/GDB
replay pass. This supplies a required host mechanism, not complete filesystem
admission or power-loss acceptance. See [the contract and commands](LINUX-DIRECTORY-SYNC.md).

## Windows opened-stage namespace implementation

**PRESENT, UNVERIFIED:** `WindowsFileRename` implements no-overwrite publication
and conditional replacement through one `FileRenameInfo` request, followed by
identity/preservation readback. It neither merges target metadata nor falls back
to copying. The native ABI is audited and the isolated Windows job now tests
actual namespace operations, concurrent/cancellation/lock controls and handle
cleanup. Local compilation/transport passes; native execution, complete host
admission and durability acceptance remain required. See
[the operation contract](WINDOWS-FILE-RENAME.md).

## Receipt replacement through the host

**CONFIRMED locally:** advancing an existing receipt now uses the required
Host `replaceAtomic` operation instead of bypassing the adapter with
`Files.move`. Readback must match the entire staged fingerprint, including
preservation metadata. A refusing host must leave the old receipt intact; a
host that changes metadata during replacement causes a publication failure.

The existing target-removal fault initially also intercepted recovery-receipt
replacement after this change and correctly returned RECOVERY_REQUIRED. The
fixture now distinguishes a target-only native failure (successful rollback)
from a persistent failure that also prevents recording recovery (complete
restored target/retained backup, but RECOVERY_REQUIRED). Neither outcome is
relabelled to force a successful transaction claim.

Actual Java21 runs compiled with `javac --release 21` pass receipt105, file75,
target63, transaction532 and operation80 checks. Logs are under
`build/test-results/receipt-host-replacement/*-java21.*`. The first direct
Java21 launch against default-JDK25 Gradle test classes failed the bytecode
version check; those classes were then rebuilt explicitly for Java21. The
extension's production bytecode baseline remains Java21-compatible.

`attachment-elf-controller.py` with the current built JAR, x86_64/exec fixture,
actual Java21 and the supervised live validator passes fresh GNU/LLVM/pinned
checks, runtime GDB discovery/value/CRC checks and rollback. Exact commands,
inputs and outputs are retained under
`build/test-results/receipt-host-replacement/controller-x86-exec`. Its Linux
metadata host remains deliberately limited; this is no full production-host
claim. The Windows Host fixture now adds native receipt preparation, phase
update, raw descriptor preservation and exact readback. Hosted acceptance of
that integration remains required.
