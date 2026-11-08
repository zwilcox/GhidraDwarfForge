# Captured unwind evidence description (#112)

**CONFIRMED locally; hosted acceptance pending:** `UnwindEvidenceJson` serializes
the program recovery result into a deterministic, bounded JSON description.
The native integration harness binds it to the exact input, staged sidecar and
staged synthetic source. This is an internal reporting component. Standard
CLI/GUI synthesis and report publication remain disabled under ADR-0002.

## Recorded information and limits

Schema version 1 records:

- Explicit recovered provenance, the current conservative memory policy and
  `validationStatus: NOT_RUN`. Serialization does not perform independent DWARF
  validation or debugger execution.
- Input/sidecar/source SHA-256 hashes, ELF machine, address width, byte order and
  database rebase delta. Instruction addresses use original ELF virtual addresses;
  database addresses separately retain their Ghidra address-space names.
- Verified function entries, refused roots with reasons, and every captured
  instruction's length, original file offset and byte hash.
- Covered/omitted instruction decisions, omission reasons and unavailable
  register reasons. Existing unwind coverage remains authoritative.
- The proposed CIE return column and initial rules, frame ranges, and every
  instruction's CFA and caller-register recovery rules. Unchanged adjacent rules
  remain visible here even though the DWARF encoder elides redundant transitions.

Addresses and file offsets use hexadecimal strings. Signed CFA/rule offsets and
frame lengths use decimal strings, avoiding JSON consumer precision loss. Ordering
comes from immutable sorted recovery/plan collections; no timestamp or output
pathname enters the description. The default output bound is 64 MiB of UTF-8.
Population limits match recovery, and traversal/writing honor cancellation.

Before serialization, consistency checks reject missing byte observations,
conflicting verified/refused roots, incorrect owners or rebases, duplicate
normalized addresses, and rows that disagree with their captured projections.
Covered instructions must exactly fill the reported frames. Refusal-only results
can be described without inventing a plan. An entirely original-covered plan can
retain its omitted observations without introducing generated frames.

This description is **not a standalone proof certificate**. Its public internal
API accepts caller-supplied hashes and captured recovery data; it does not reopen
the input and re-prove their truth. It does not yet capture the full control-flow
graph, ABI/profile revision, callee obligations or original unwind inventory.
The caller must protect input/program consistency. The native harness uses the
existing optimistic consistency guard, not a locked snapshot. A future optional
memory policy must change the recorded policy rather than reuse today's label.

## Publication and failure tests

The test-only `ExportRecoveredFrames.java` constructs the JSON after both outputs
are staged and before the pair publisher commits them. On success it separately
publishes `<sidecar>.unwind.json` via temporary-file/atomic replacement. That
attachment is not a third member of the pair's transaction and is not a supported
product export mode. Its hashes detect a stale attachment; normal-entry-point
publication and lifecycle integration remain work for #112.

`RecoveredFrameExportControls` now requires nine successful exports and four
failure controls per case: cancellation and an injected exception during both
frame serialization and report serialization. Each control must preserve the
previous sidecar, source and unwind description, leave no staging files, and
allow a successful retry. Reports must repeat byte-for-byte for an unchanged
program at each image base. Rebasing can change source and report hashes.

## Local acceptance

The Java 21 component suite passes 720 checks, including all observed cancellation
polls, UTF-8 exact/short limits, contradictory evidence, rule forms, escaping and
retry. The final installed package has 682 Java 21 classes matching the tested
build; its source archive contains the exact reporting source.

Sixteen real native-export cases pass on native x86-64 and QEMU AArch64:

- Ordinary assembler fixtures without original CFI: executable, PIE and shared
  object on both targets.
- Split/shrink-wrapped fixtures with original runtime CFI: the same six roles.
- Shared objects with compressed original `.debug_frame`: both targets.
- Executables with deliberately failed `cf_checkpoint` decompilation: both targets.

Together these perform 144 successful exports, 64 injected failure/cancellation
controls, 64 retained sidecars and 144 GDB sessions. GNU/LLVM/pinned strict checks,
raw validator-report retention, original hashes, deterministic repeats and
before/after-rebase runtime comparisons pass. Each JSON report independently
matches the emitted frame transitions and the original instruction bytes. Ten
damaged-report controls reject changed hashes, rules, coverage, offsets and
rebases. Existing validator-retention controls also pass (3 positive, 10 rejected).

Initial failures remain in the evidence archive: a Java compound `var` declaration,
a comparison that incorrectly expected one encoded row per instruction, and a
package reviewer using the wrong source ZIP prefix. An exploratory failure of
`cf_recurse` itself passed unwind checks but failed the source oracle, which
explicitly requires source stepping in that function. The final failed-source
cases use the established `cf_checkpoint` control without weakening that oracle.

See [the receipt](evidence/unwind-evidence-report.json) for exact source/package
hashes, commands, results and retained raw evidence. Existing
[native-export reproduction](NATIVE-FRAME-EXPORT.md#reproduction) now also checks
these descriptions; run `./gradlew unwindEvidenceJsonSmoke` for the component.
No JNA signatures, instruction proof rules or supported target profiles change.
Full compiler-reference acceptance, the unresolved memory-policy decision, ADR
enablement, normal CLI/GUI integration and hosted acceptance remain incomplete.
