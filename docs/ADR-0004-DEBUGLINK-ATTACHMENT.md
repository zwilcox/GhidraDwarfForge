# ADR-0004: Stage optional debuglink attachment behind a verified backup transaction

- Status: Accepted design; product attachment remains **PLANNED**
- Date: 2026-10-23
- Refined: 2026-10-24 (owned append-only candidate direction in ADR-0005)
- Scope: P2.8, separate from default export and the corrective alpha.2 release

## Decision

Keep ordinary export non-mutating. A future attachment operation must be an
explicit choice after a successful export pair, with a mandatory original
backup, independently verified target/sidecar identity, and atomic replacement
of the target. This investigation does not add an attachment command or close
P2.8. The research harness modifies only its own disposable fixture copies.

Use the separate native-free append-only candidate direction selected in
[ADR-0005](ADR-0005-OWNED-DEBUGLINK-CANDIDATE.md). This explicitly supersedes
the initial GNU backend selection below. GNU-created private candidates remain
independent test references, with no silent fallback. The writer passes local
source/installed checks and PR #39's complete hosted gate at `a190026` /
`40116314882`, including all five target artifacts and both GUI hosts. This
private constructor does not complete the transaction below. Ordinary export
continues supporting its wider ELF input contract.

Do not reuse `MatchedElfSidecarWriter`: its deliberate removal of program
headers and retirement of relocation metadata produce a non-loadable sidecar,
not a replacement executable. The separate candidate implementation must preserve
executable semantics and still satisfy every transaction requirement below.

## Historical GNU evidence and subsequent backend choice

[GNU objcopy's documentation](https://sourceware.org/binutils/docs/binutils/objcopy.html)
provides separate input/output operation and `--add-gnu-debuglink`. Its accepted
object formats depend on how the tool was configured; the host tool is not
proof of cross-target support. [GDB's separate-debug-file contract](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html)
uses a basename, padding, and a target-endian CRC of the complete debug file.
The CRC detects stale/corrupt associations; it does not prove target identity.

Local Linux GNU 2.42 experiments cover x86-64, AArch64, and both MIPS32 byte
orders. Standard ET_EXEC/PIE copies pass exact program-header/load-byte and
debuglink CRC checks. Program-header-only and unnamed-section-table inputs are
rejected by these tools. PN_XNUM fixtures are accepted by the tools but change
`e_phoff`, so the proposed strict preservation check rejects them. This is a
conservative backend exclusion, not evidence that every rewritten image is
invalid. `objcopy` also accepts a plain-text file as the debug file, proving why
its success status alone is insufficient. ARM32 and native Windows backend
behavior were not tested in that initial investigation. See the reproducible
[evidence record](research/DEBUGLINK-EVIDENCE.md).

A later bounded Linux investigation adds ARM32 hard-float exec/PIE controls.
It also proves that a changed PT_NOTE payload outside every LOAD escaped the
old load-only probe. The read-only `ExecutableProgramBytes` observer and the
corrected research probe compare all non-NULL program payloads, the complete
declared ELF header and raw program table. Existing-link exit-zero diagnostics
are another explicit rejection case. These results do not establish Windows
backend support or a transaction; see `EXECUTABLE-PROGRAM-BYTES.md`.

## Proposed operation contract

1. Require an explicit attach action with the final target and sidecar paths,
   an export receipt, and new backup and transaction-receipt paths. Explain
   that the target changes. A refresh also supplies its previous committed
   attachment receipt and a separate prior-attached-image backup path.
   A completed `PARTIAL` export can be eligible if its artifacts and diagnostics
   satisfy the ordinary export contract; fatal/cancelled exports cannot.
2. For initial attachment, verify the current files against the receipt's
   original-input, sidecar and source SHA-256 hashes. For explicit refresh,
   require the previous attachment receipt: the current target must match its
   attached-image hash, while the retained original backup must match the new
   export's input hash. Do not infer this chain from build ID or CRC alone.
   Validate ELF class, byte order, machine, flags, entry,
   type and allocated address relationships, and build ID when present. Hashes
   establish which export is being attached; CRC alone never does. Reject an
   unrelated sidecar even if `objcopy` accepts it.
3. Initially require the final sidecar beside the executable or in its `.debug`
   subdirectory. `.gnu_debuglink` cannot encode an arbitrary output directory.
   Do not silently relocate either artifact or rewrite its source directory.
   Verify literal basename encoding, padding and target-endian CRC after the
   backend returns. Reject an existing association unless explicit replacement
   was requested; a different previous association is never silently replaced.
4. Resolve actual filesystem traversal, including symlink/`..` ancestors,
   before comparing paths. Reject a symlink/reparse-point target leaf, nonregular
   file, alternate data stream, and target with multiple hard links in the
   initial implementation, including refresh. A newly requested backup
   destination must not exist; the retained original backup required for
   refresh is instead read and verified without replacement.
   Compare file identity as well as paths among
   input, sidecar, source, original backup, prior-attached-image backup, both
   input receipts (new export receipt and previous committed attachment
   receipt), the new transaction receipt, stages, temporary receipts and every
   file log/backend-output destination. Include all of these in preflight before
   opening any output, including failure diagnostics. An unsafe requested log
   must not be truncated to report its own rejection; report that on stderr. New
   receipts and backups are exclusively created regular files; reject existing
   paths, dangling links, reparse points and alternate streams. Private temporary
   outputs must be exclusively created in an owned directory. Fail closed if
   the host cannot establish identity/link count. Path normalization alone is
   insufficient; compare canonical traversal and existing file identity.
5. Invoke the selected candidate writer in a fresh owned subdirectory under
   the target directory, against a verified private snapshot. Preserve the complete declared ELF
   header, raw program table and every non-NULL program header's file-backed
   payload, except the ELF header's section-table fields. Resolve and preserve
   extended program counts; require positive file-backed LOAD evidence for
   this initial operation. Validate every
   deliberate header change, retained build identity and section relationships;
   reject unexplained changes. Any external reference-tool diagnostics are
   explicit test failures. No candidate path may alias the live target.
6. Preserve the supported permission/ownership/ACL metadata, or reject an
   unsupported case before replacing anything. An ordinary byte copy plus
   `COPY_ATTRIBUTES` is not proof of preserving capabilities, extended
   attributes, Windows streams or security descriptors. Privileged/set-ID,
   capability-bearing and otherwise unsupported metadata must fail closed in
   the first slice. These restrictions apply to attachment, not ordinary export.
7. Exclusively create an independent backup, verify its full bytes and supported
   metadata, flush it, and retain it after success. Never use a hard link as
   the backup and never overwrite an existing backup. Recheck target identity
   and artifact hashes before commitment. Publish the candidate with a single
   atomic replacement in the target directory; unsupported atomic replacement
   is a failure, not permission to copy over the live executable.
8. Retain a versioned transaction receipt recording the operation ID and phase,
   previous receipt hash when applicable, all canonical artifact/backup paths,
   original/prior-target/candidate/backup/sidecar/source hashes, CRC and backend
   identity. Persist a prepared record and verified recovery material before
   target replacement, then record its committed or recovery outcome. Existing
   committed receipts are immutable. Only this operation's own new record may
   advance through staged atomic updates, after verifying its expected identity
   and hash; never overwrite a different record at that path. Define host-specific
   flush/directory durability and recovery behavior before claiming crash
   recovery. The backup, receipt and target are not one atomic filesystem
   transaction. An interrupted operation must identify a complete original or
   complete attached image and a recoverable verified backup.
9. On an observed post-replacement failure, restore the pre-operation target
   from its verified independent backup through another staged atomic
   replacement. Do not overwrite an unrelated
   concurrent target change during rollback. Report the retained backup and
   recovery state if restoration is blocked. Windows sharing locks and access
   failures must leave a complete target and recoverable backup.

This contract detects ordinary concurrent changes; it is not a claim of
defeating an adversary racing filesystem operations. An implementation must
also keep temporary-file cleanup and cancellation bounded without deleting
the retained backup or publishing a partial target.

## Re-export after attachment

The current imported-executable SHA guard correctly rejects the modified
target. Keep that guard unchanged and do not silently update the curated
Program's recorded import identity. Re-export from the mandatory original
backup. For refresh, choose a fresh generation-specific output path beside
the target or in its `.debug` directory, leaving the attached pair unchanged:

```bash
ghidra-dwarf-forge-headless --ghidra-dir=/path/to/ghidra \
    --project-dir=/path/to/project --project-name=Analysis --program=app \
    --input=/path/to/app.pre-debuglink --output=/path/to/app.rev2.dbg
```

This existing-project operation uses the current curated Program, not a new
import. The research fixture proves preservation of an analyst-applied name,
strict rejection of the attached original, and byte-identical re-export using
the unchanged backup. It does not prove changed-content refresh or rollback.
A sidecar change after genuine analyst edits requires a fresh CRC and an
explicit attachment refresh. Preserve the first original backup; refresh
must not replace it with already-modified bytes.

The investigation separately found transient `undefined` type IDs can change
DIE ordering between initial import and reopening the same saved Program.
Normalized model/source equality and repeated-reopen byte identity were proved;
this is a bounded determinism follow-up, not target corruption or a reason to
relax CRC/identity checks. See the evidence record.

### Refresh transaction boundary

The attachment operation changes only the target's association after the new
pair has been successfully exported at its final generation-specific paths.
It rejects a refresh whose new sidecar or source aliases the currently
attached pair. It does not rename an already-generated source pair to create
a new generation, because DWARF records the source path. The new pair is
selected explicitly; ordinary export keeps its existing output policy.

Before refresh, verify the previous receipt, current attached target, original
backup and previous sidecar/source hashes. Require the previous debuglink CRC
to match its retained pair. If the old pair has already been overwritten by
an independent export or edited, fail without modifying the target; report
that the previous association cannot be treated as a verified rollback state.
Do not infer or fabricate the missing previous bytes.

Refresh retains the old pair and committed receipt unchanged and exclusively
creates a verified independent backup of the prior attached target. The
staged candidate points to the new sidecar basename. A single atomic target
replacement switches the association; it is not a transaction that atomically
replaces an executable, sidecar and source. Failure before replacement leaves
the old association intact. After replacement, rollback restores the prior
attached image, whose untouched sidecar/source still satisfy its CRC and source
paths. Verify that complete association after rollback. Preserve both pairs,
the original backup and prior-target backup on success or recovery failure;
automatic generation deletion is outside this first operation.

Cancellation and injected faults must be checked around the prepared receipt,
target replacement and final receipt update. Recovery compares the live target
with the recorded prior and candidate hashes before deciding its state; an
unrelated concurrent change must never be overwritten. A complete runtime
image alone does not prove recovery of its debug association. Crash/durability
claims still require the host-specific tests above and below.

## Host feasibility and acceptance before implementation is complete

Candidate bytes use the native-free direction in ADR-0005. Linux transaction
identity/link counts and Windows handle-based file identities remain separate
requirements; the current wrapper's native file-information structure includes
a link count, but there is no attachment transaction using it. Portable Java
alone does not establish all required Windows metadata/sharing behavior. No
native Windows attachment support is claimed by this design or the existing
Windows export/GUI tests.

The first implementation is complete only after all of the following pass:

- Default export remains byte-for-byte non-mutating; no attach action is
  inferred from an output path, report or existing debuglink.
- Explicit exec/PIE attachment and replacement prove matching identity, exact
  CRC, complete independent backups, unchanged load image, normal runtime,
  automatic GDB lookup and actual `.dbg` objfile selection. Build-ID fallback
  and debuginfod are disabled or removed in negative controls.
- Wrong target/sidecar/report hashes and corrupted or stale CRCs are rejected;
  genuine curation followed by backup-based re-export to a fresh generation
  and changed-CRC refresh works. GDB selects that exact new objfile and source;
  rollback selects the unchanged old pair, with build-ID/debuginfod fallback
  disabled. Re-exporting identical bytes alone is not this test.
- Symlink/`..`, hard links, path aliases, literal special characters/spaces,
  existing backups, missing/read-only directories, Windows reparse points,
  streams and sharing locks either work under the documented contract or fail
  without mutation. Test identity and bytes, not only return status.
- Direct, relative, symlink/`..` and hard-link aliases from transaction
  receipts, staged receipts and logs to any protected input, pair or backup
  fail before writes/candidate preparation. Preserve sentinel contents and metadata;
  rejection diagnostics must not corrupt a protected file. Existing previous
  receipts stay immutable, and interrupted owned receipt updates are tested.
- Fault injection before/after backup, candidate failure/diagnostics, failed
  metadata application, failed atomic replacement, cancellation and rollback
  proves preservation/recovery. The previous target and backup are never
  silently overwritten by a partial or unrelated image.
- Refresh faults before/after target replacement and receipt publication prove
  either the previous or new complete association with exact target/pair hashes,
  retained original and prior-target backups, and an explicit receipt/recovery
  state. Reject an overwritten old pair, attempted reuse of a retained pair or
  transaction destination, and unrelated concurrent modifications without
  hiding an invalid association.
- All accepted target layouts pass GNU/LLVM and applicable independent DWARF
  checks plus GDB behavior. Unsupported attachment layouts still export normally.
- Native Linux and Windows jobs exercise their actual filesystem contracts;
  target/profile claims are restricted to observed results. Document backend
  dependencies, receipts, recovery and backup-based re-export in both wrappers
  and GUI/help before exposing the option.

These are implementation acceptance criteria, not completed work. A product
transaction with the above guarantees is not a small append-only prototype,
and remains planned. ADR-0005 defines the accepted private candidate component;
that component does not complete the transaction guarantees.
