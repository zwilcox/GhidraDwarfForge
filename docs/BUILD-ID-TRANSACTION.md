# Build-ID installation transaction checkpoint

Tracking: #109. **CONFIRMED locally:** the transaction, packaged public command
and Linux ext4 host pass the checks below. Windows installer acceptance, the
remaining consumer matrix and protected integration are incomplete. This is not
a completed installer feature or a release claim. See the
[command guide](BUILD-ID-INSTALLATION.md) and
[latest Linux receipt](evidence/build-id-command-linux.json).

## Contract

`BuildIdInstallation` accepts an explicit existing debug root and selected
original, exported sidecar, source and report. It binds their observed bytes to
the report and matched ELF before creating an installation. It requires the
existing build ID, without changing the original executable. Missing IDs report
the explicit GDB loader and opt-in debuglink alternatives. The filename profile
currently admits canonical lowercase even-length hex IDs of 1–124 bytes.

An installation retains the selected report, sidecar and source, a source copy
at the path referenced by the derived DWARF, the derived sidecar, and fresh
GNU/LLVM/pinned-libdwarf validation evidence and raw outputs. The bounded seal
records every retained file's bytes, native identity and supported metadata.
Unknown or additional files, changed directory identities, links, changed bytes
and malformed records are refused. The original report is never rewritten to
describe the derived output.

The layout is:

```text
<root>/.build-id/xx/rest.debug
<root>/.forge-build-id/v1/<id>/lock
<root>/.forge-build-id/v1/<id>/state.json
<root>/.forge-build-id/v1/<id>/generations/<uuid>/...
<root>/.forge-build-id/v1/<id>/transactions/<uuid>/...
```

The permanent OS file lock serializes cooperating writers. Complete generation
files are forced and directories synchronized before an atomic no-replace
publication makes the sidecar searchable. An explicit update requires the same
original executable hash, verifies the existing registration and retained
generation, and atomically replaces only that verified registration. Identical
original/sidecar/source hashes are an idempotent no-op; report timing changes do
not choose a new generation. A changed export requires explicit update.

Removal atomically moves the verified registration to an owned tombstone. It
retains source generations, including those used by existing debugger sessions.
No pruning is implemented. Unpublished preparations and their diagnostics also
remain on failure and are never silently adopted or deleted.

The state record distinguishes PREPARED, COMMITTED and ABORTED operations and
binds the root's canonical absolute path, fixed namespace identities, transaction
directory identity, host contract, original hash and before/after installations.
Recovery completes an already-observed publication or aborts an unapplied intent;
it does not publish a cancelled preparation. Neither matching state means refusal
and manual reconciliation. Once publication starts, synchronization/readback
finishes despite late cooperative cancellation. Errors remain errors.

Moving an installation root is refused because the retained DWARF source paths
would be stale. Reinstall the retained export into a fresh root to relocate it.
Changing and restoring files adversarially between observations is outside this
ordinary concurrency-detection contract. File forcing and directory synchronization
are not proof of survival across a host power loss.

## Host scope

`LinuxBuildIdHost` uses the previously audited native metadata, rename and
directory-sync primitives. It runs as the current user, without elevation, on
the initial Linux Intel LP64/ext4 profile. Selected input files and installation
files must satisfy that host profile. It preserves mode, uid/gid, modification
time, visible user attributes and access ACLs; unsupported visible namespaces,
inode policies, hard links and failed metadata copies are errors. Refresh keeps
the registration's existing supported access metadata while retaining the new
export's metadata separately. Hidden attributes and access/change/birth times
are not preservation claims. This distinct contract does not weaken the stricter
executable-modifying attachment host.

The probe can also select the existing Windows host, but **PRESENT, UNVERIFIED**
applies to installer use of that host. Its attachment tests do not prove Windows
installation, locking, generation records or recovery.

## Historical transaction-only validation

The receipt is [build-id-transaction.json](evidence/build-id-transaction.json).

- Model metadata host: 123 checks and four x86-64 non-PIE GDB sessions. Checks
  include all 14 process-exit boundaries, before/after-publication cancellation,
  directory-sync failures, repeated recovery, locks, foreign registrations,
  altered source/sidecar/evidence/seal/raw validator output, moved roots,
  hard/symbolic links, malformed records, conflicting recovery state, replaced
  transaction directories and reinstalling retained exports without old inputs.
- Eight additional AArch64/ARM32/MIPS big-/little-endian exec/PIE lifecycles and
  x86-64 PIE pass seven checks and four GDB sessions each. GDB starts fresh with
  only its debug-root setting and original executable; no explicit symbol-loading
  command is used. The old export source/sidecar are absent during positive checks.
  The oracle checks source path, values and stepping; empty and removed roots
  provide negative controls. These target cases use the model metadata host.
- Production Linux ext4 host: the same 123 controls and four x86-64 non-PIE GDB
  sessions pass using copied fixtures with non-default permissions, a named-user
  access ACL and a user attribute. Six independent metadata comparisons cover
  retained report, source copies, exported/derived sidecars and registration.
- Extension build and test-class compilation pass. Both control runs invoke
  fresh production structural validators before successful publication. All
  selected input hashes remain unchanged.
- Thirteen additional production Linux identity controls pass; see
  [build-id-identity.json](evidence/build-id-identity.json). Owned ELF64
  little-endian fixture copies model absent, malformed and conflicting IDs,
  different original bytes sharing an ID, selected-input aliases/hardlinks and
  six invalid path IDs. Test reports are explicitly adjusted for those artificial
  mutations; they are not presented as real producer exports. Refusals leave
  existing registrations unchanged or a fresh debug root empty. The unchanged
  positive baseline invokes the production structural validators.

Historical interrupted harness runs are retained: one assumed raw logs had a
`.log` suffix (they use `tool.stdout`), and another encountered JNA temporary-file
ENOSPC before an operation. The corrected suite explicitly selects its JNA
temporary directory. Neither interrupted run is counted as a pass.

## Command and production Linux acceptance

The final tested package passes 226 checks and 50 fresh GDB sessions on all five
targets' exec/PIE layouts, using the production Linux ext4 host throughout. Twenty
sessions are empty/removed-root negative controls; the remaining thirty prove
installed source/value/stepping behavior. The command subset contributes 27
checks and ten GDB sessions, including spaces, Unicode, literal quotes/dollar
signs, request refusal, cancellation and four read-only permission profiles.

Two regressions were reproduced against the preceding package: applying user
attributes after a final read-only chmod failed with errno 13, and reopening a
sealed read-only stage during refresh failed with AccessDeniedException. Metadata
application now temporarily enables owner-write only on the private owned stage,
applies the access ACL after user attributes, and restores the exact final mode.
Publication copies new bytes with the selected existing registration metadata in
one operation, without reopening the completed read-only file for writing.
Independent native checks cover modes 0444/0555, raw user attributes and access
ACLs. Four real-command install/refresh cases independently compare mode, uid/gid,
mtime and all visible attributes; every original input retains its bytes/metadata.

The shared file-store, target-store, transaction and operation smoke suites pass
75, 63, 532 and 103 checks respectively. Their model-host scope is recorded and
does not substitute for the production Linux checks. Four fresh packaged headless
exports from saved Ghidra programs additionally prove actual analyst name/type/
member edits survive explicit refresh in exec and PIE; four fresh GDB sessions
use only the installation and retained source with old exports absent.

## Remaining acceptance

Add shared and applicable sectionless installation/discovery, installation-specific
LLDB and perf checks, native Windows acceptance and protected integration. The
workflow now invokes the production Linux matrix and saved-program refresh tests,
but the updated hosted gate is not yet accepted. The Windows command is present
and explicitly unverified. Retained component tests do not establish those
remaining requirements.
