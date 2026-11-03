# Attachment transaction protocol

**PRESENT, UNVERIFIED as an attachment feature.** `AttachmentPaths` and
`AttachmentReceipt` implement all-role path preflight and versioned recovery
claims. They are not invoked by ordinary export and do not modify an executable,
create a backup, authorize an attachment or establish a host metadata contract.
The complete transaction remains required by ADR-0004 and ADR-0005. Ghidra,
Java and libdwarf baselines are unchanged; no native declaration is added.

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

## Receipt schema 1

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

## Phases and remaining publication work

Allowed transitions are PREPARED to COMMITTED, ROLLED_BACK or RECOVERY_REQUIRED,
and RECOVERY_REQUIRED to ROLLED_BACK. COMMITTED and ROLLED_BACK records cannot
advance. PREPARED/COMMITTED have no failure diagnostic; rollback/recovery states
require one. Advancing produces a new immutable value without writing a file.

Before replacing the executable, the transaction must durably publish a complete
PREPARED record plus a verified independent backup. Receipt updates must verify
that the existing record is still the operation's own expected bytes/identity,
use a complete staged record and atomic replacement, and never overwrite another
operation or immutable committed receipt. These filesystem operations are not
implemented by the value object. Host-specific flush/durability, interruptions,
concurrent changes, safe rollback, refresh, validator binding and CLI/GUI
integration remain required; none is implied by a passing parser test.

The Windows replacement adapter must handle documented non-success states,
including errors where file names have already changed, and must not use flags
that ignore metadata/ACL errors. `REPLACEFILE_WRITE_THROUGH` is documented as
unsupported, so it cannot establish durability. See [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
The separate independent backup and receipt remain necessary; the Win32 backup
parameter alone does not satisfy this project's pre-replacement backup contract.

## Local verification

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew \
    attachmentProtocolSmoke exportReportClaimsSmoke companionArtifactPublisherSmoke \
    buildExtension
actionlint .github/workflows/ci.yml
git diff --check
```

**CONFIRMED locally:** 116 receipt/path controls pass, including both modes,
permitted/forbidden transitions, maximum file sizes, corrupt receipts, all pairs
of nine input/output roles, hardlinks, symlinks, actual parent traversal,
concurrent selection changes, no-write rejection and stream closure on
cancellation. The existing export-report reader and three-artifact publisher
regressions pass; the extension builds. The candidate workflow includes the
new smoke on Linux and native Windows, but native Windows execution is still
**PRESENT, UNVERIFIED**. No emitted ELF/DWARF changes or new GDB-support claims
are made by this component checkpoint.
