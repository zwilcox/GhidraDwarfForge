# Export consistency checks (#112 prerequisite)

**CONFIRMED locally:** the ordinary installed exporter now rechecks the original
input bytes and Ghidra's modification counter after extraction and immediately
before publishing the staged generation. Pair, fresh attachment-preparation and
companion publication all use the same final check. This closes a pre-existing
publication gap discovered while preparing recovered-frame integration.

Previously the ordinary pair path checked only cancellation at publication.
A real installed-export reproduction changed an owned fixture input during
report construction, after both artifacts were staged; the exporter still
reported success and published. The failing-before log is retained. The
companion path already checked input correspondence, but did not check Ghidra
edits during extraction/reporting.

`GhidraExportConsistency` records the program's modification number and a
bounded-memory digest of the original input before extraction. Ghidra 12.0.3's
`DomainObject.getModificationNumber()` contract increments on changes, undo and
redo. A program edit followed by restoration still invalidates the old guard.
A new export captures a fresh counter and can succeed. Original-file comparison
uses SHA-256, CRC32 and the observed byte count, with cancellation between reads.
The existing imported-executable SHA-256 check remains mandatory when available.

A failed check throws before final publication, allowing the existing publishers
to clean their staging files and preserve the previous complete generation.
Source/report bytes remain deterministic. No new native/JNA calls or synthetic
CFI enablement are introduced.

## Validation

- The focused native Ghidra suite passes 26 checks covering program edits and
  restoration, same-size changed input, restored input, missing input, cancellation
  at every observed capture/check poll and successful retries.
- Installed headless exports on x86-64 and AArch64 pass eight injected failure
  controls across pair and companion modes. Changes occur during staged report
  construction. Previous outputs remain byte-identical and staging files are
  removed. The earlier companion correspondence rejection is accepted when it
  detects a changed input before the new final guard.
- Twelve successful exports (baselines and retries) are deterministic. The four
  final sidecars pass GNU, LLVM and the pinned strict checker. Four generated
  sidecar GDB sessions exercise function lookup, breakpoints, synthetic source,
  signatures, argument values, next, step and completion. Two independent
  compiler-DWARF sessions establish the permitted QEMU system-DSO warning.
- Build, workflow lint, architecture guard and script syntax checks pass.
  CI includes the unit check and the two installed target regressions.

See `docs/evidence/export-consistency.json` for commands, package identity,
raw failures and passing results. The first local launch referenced a stale
installation and did not run; it is retained separately. An initial harness
expectation was corrected to recognize the existing companion's earlier input
correspondence rejection; no production acceptance condition was removed.

## Limits and follow-up

This is an optimistic check, not a file snapshot or Ghidra modification lock.
It detects observed changes across the export; it does not freeze an external
writer between the final check and filesystem publication, nor detect a file
changed and restored between digest reads. The program should be quiescent for
export. Ghidra's script runner already owns a transaction; forcibly terminating
that transaction to acquire a modification lock would risk analyst work and is
not part of this change. Large inputs incur additional digest reads, whose cost
must be included in subsequent workload profiling.

The fresh GUI attachment-preparation path is wired to the check but has not been
rerun interactively in this checkpoint. Hosted acceptance is **PRESENT,
UNVERIFIED**. Recovered frames still need real-export integration and remaining
compiler/reference/failure acceptance before ADR-0002 can change. The strict
stack/global alias refusal is unchanged. PR166 remains first integration priority.
