# ADR-0004: Stage optional debuglink attachment behind a verified backup transaction

- Status: Accepted design; product attachment remains **PLANNED**
- Date: 2026-10-23
- Scope: P2.8, separate from default export and the corrective alpha.2 release

## Decision

Keep ordinary export non-mutating. A future attachment operation must be an
explicit choice after a successful export pair, with a mandatory original
backup, independently verified target/sidecar identity, and atomic replacement
of the target. This investigation does not add an attachment command or close
P2.8. The research harness modifies only its own disposable fixture copies.

Use a configured GNU `objcopy` as the first candidate backend, operating on a
staged copy with an explicit output filename. Restrict each supported host,
tool and target profile to layouts that pass the checks below. Reject a layout
before mutation when the backend cannot preserve it. Ordinary Forge export
continues supporting its wider ELF input contract. Do not silently fall back
to another backend.

Do not reuse `MatchedElfSidecarWriter`: its deliberate removal of program
headers and retirement of relocation metadata produce a non-loadable sidecar,
not a replacement executable. A native-free append backend would need its own
audited executable-preserving implementation and the same transaction tests.
That is a larger change than introducing a section name and CRC.

## Evidence and backend choice

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
behavior were not tested in this investigation. See the reproducible
[evidence record](research/DEBUGLINK-EVIDENCE.md).

## Proposed operation contract

1. Require an explicit attach action with the final target and sidecar paths,
   an export receipt, and a new backup path. Explain that the target changes.
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
   before comparing paths. Reject a symlink/reparse-point target leaf, existing
   backup, nonregular file, alternate data stream, and target with multiple hard
   links in the initial operation. Compare file identity as well as paths among
   input, sidecar, source, backup and stage. Fail closed if the host cannot
   establish identity/link count. Path normalization alone is insufficient.
5. Create the candidate in the target directory and run the configured backend
   against a verified private snapshot. Preserve all program-header bytes and
   loaded bytes except the ELF header's section-table fields. Validate every
   deliberate header change, retained build identity and section relationships;
   reject tool diagnostics and unexplained changes. Never invoke `objcopy`
   with omitted output against the live target.
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
8. Retain a transaction receipt recording the original, backup, attached image,
   sidecar/source hashes, CRC, tool identity and result. Define host-specific
   flush/directory durability and recovery behavior before claiming crash
   recovery. The backup, receipt and target are not one atomic filesystem
   transaction. An interrupted operation must identify a complete original or
   complete attached image and a recoverable verified backup.
9. On an observed post-replacement failure, restore from the verified backup
   through another staged atomic replacement. Do not overwrite an unrelated
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
backup while retaining the intended output path:

```bash
ghidra-dwarf-forge-headless --ghidra-dir=/path/to/ghidra \
    --project-dir=/path/to/project --project-name=Analysis --program=app \
    --input=/path/to/app.pre-debuglink --output=/path/to/app.dbg
```

This existing-project operation uses the current curated Program, not a new
import. The research fixture proves preservation of an analyst-applied name,
strict rejection of the attached original, and re-export using the unchanged
backup. A sidecar change after genuine analyst edits requires a fresh CRC and
an explicit attachment refresh. Preserve the first original backup; refresh
must not replace it with already-modified bytes. A new transaction may also
retain its own prior-attached-image backup.

The investigation separately found transient `undefined` type IDs can change
DIE ordering between initial import and reopening the same saved Program.
Normalized model/source equality and repeated-reopen byte identity were proved;
this is a bounded determinism follow-up, not target corruption or a reason to
relax CRC/identity checks. See the evidence record.

## Host feasibility and acceptance before implementation is complete

Linux can use a configured target `objcopy` and Unix file identities/link
counts. Windows can use an appropriate GNU tool and handle-based file
identities; the current wrapper's native file-information structure includes
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
  genuine curation followed by backup-based re-export and refresh works.
- Symlink/`..`, hard links, path aliases, literal special characters/spaces,
  existing backups, missing/read-only directories, Windows reparse points,
  streams and sharing locks either work under the documented contract or fail
  without mutation. Test identity and bytes, not only return status.
- Fault injection before/after backup, backend failure/diagnostics, failed
  metadata application, failed atomic replacement, cancellation and rollback
  proves preservation/recovery. The previous target and backup are never
  silently overwritten by a partial or unrelated image.
- All accepted target layouts pass GNU/LLVM and applicable independent DWARF
  checks plus GDB behavior. Unsupported attachment layouts still export normally.
- Native Linux and Windows jobs exercise their actual filesystem contracts;
  target tool/profile claims are restricted to observed results. Document tool
  dependencies, receipts, recovery and backup-based re-export in both wrappers
  and GUI/help before exposing the option.

These are implementation acceptance criteria, not completed work. A product
transaction with the above guarantees is not a small append-only prototype,
so this branch stops at tested backend/identity research and a precise design.
