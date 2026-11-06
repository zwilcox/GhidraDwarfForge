# Conditioned compiler unwind export (#112)

The later [relocated-pointer matrix](RELOCATED-POINTER-UNWIND.md) extends this
historical non-PIE checkpoint to PIE and shared objects on both initial targets,
with explicit immutable-pointer conditions and native refusal controls.

**CONFIRMED locally:** the real headless exporter can now project an explicitly
conditioned call proof, retain the condition in its evidence report, and emit
frames that match the unchanged compiler fixture's observed GDB behavior on
x86-64 and AArch64. This is an internal test path. Normal CLI/GUI synthesis is
still off, and no shipping memory policy has been selected.

## Acceptance and provenance

The unchanged `synthetic-cfi.c` writes the global `cfi_sink`. Strict verification
cannot prove that this absolute address never aliases saved stack storage.
The test supplies its exact eight-byte range as an **external condition**:
this range never overlaps live stack storage of the analyzed group or its
callers. An ELF symbol supplies the location, not proof of separation.

`GhidraUnwindFrames.plan` continues to reject conditional evidence.
`planConditioned` requires acknowledgement of the exact condition, including its
basis and bounds; empty or different acknowledgements fail. The returned
projection and program-wide collection retain the condition. Collection rejects
inconsistent conditions across groups. Default recovery still uses `NONE`.

The bounded evidence JSON distinguishes strict recovery from conditional
recovery. It records `EXTERNAL_CONDITION_NOT_PROVED`, the external basis and
ranges normalized to original ELF virtual addresses. Runtime consumers must
apply image load bias. Wrong widths and normalized wrapping ranges fail report
creation. `validationStatus` remains `NOT_RUN`: the recovery report itself does
not pretend to be an independent validator result.

The test-only headless scripts accept an optional original-image range and
translate it to the current database coordinates after each rebase. All nine
exports and four cancellation/failure controls carry the same explicit
condition. Serialization precedes pair publication; failure preserves the
previous artifact/source pair and evidence attachment.

## Independent behavior checks

`compiler-unwind-export.py` builds the unchanged C and startup source twice,
checks byte identity, and strips debug information from a separate execution
copy. Allocated bytes and program headers remain equal. The existing compiler
oracle runs first with compiler frames, absent frames and disabled DWARF
unwinders. The exporter then imports the no-CFI executable through real Ghidra
analysis, decompilation, types and the pinned native producer.

For each target, four outputs (plain/zlib, original/rebased database) pass:

- GNU, LLVM and pinned strict DWARF validation.
- Original input preservation and deterministic repeated export.
- Exact agreement between captured instruction bytes, report rules and emitted
  CFI transitions; the normalized condition is unchanged after rebasing.
- The independent eight-frame compiler backtrace, including six register
  witnesses, `finish`, each recursive epilogue instruction, and normal exit.
- Actual selection of GDB's DWARF unwinder at all seven ordinary frame levels;
  disabling that unwinder removes those selections.

All eight generated-output runtime results equal their target's compiler
reference, including normalized PCs and saved-register values. The x86-64 trace
contains 25 snapshots; AArch64 contains 21. The same compiler oracle is used
without weakening its positive assertions. AArch64's pre-existing QEMU system
DSO warning must agree with the compiler/negative controls. No new warning is
accepted; saved pre-rebase artifacts may report the known source timestamp
warning after later exports update their source path.

Totals: 18 conditioned exports, 8 staged failure controls, 8 sidecars and 16
GDB sessions including independent references and disabled/absent controls.
Strict exporter regressions add 18 exports, 8 controls, 8 sidecars and 18 GDB
sessions across both targets. All 18 passing strict checker receipts retain
complete raw reports. Component tests pass 82 separation checks, 1,494 report
checks and 13,770 native call/projection checks. The installed Java 21 package
matches all 732 production classes and 208 production sources.

See [the evidence receipt](evidence/conditioned-compiler-unwind.json) for commands,
hashes and archived raw evidence. The workflow adds this test to both target
lanes; its hosted acceptance is **PRESENT, UNVERIFIED**.

## Complete executed instruction-path follow-up

A separate GDB oracle now stops at `cfi_main` entry and single-steps through every
executed ordinary instruction until returning to `_start`. It observes all four
functions, four recursive depths and both recursive branch outcomes. For each
boundary, it records the complete caller chain, relative PCs, caller stack-pointer
offsets and saved-register witnesses. The log is delimited per snapshot and the
harness requires actual DWARF unwinder selection at every ordinary frame level
in **each** snapshot; a successful fallback backtrace is insufficient.

The independent compiler reference runs first. All four generated variants then
match its entire trace exactly: 90 snapshots on x86-64, 77 on AArch64. This spans
the executed prologues, bodies, global increment, nested/recursive calls and
returns. The original checkpoint/`finish`/epilogue oracle remains unchanged and
also runs. The stronger matrix passes 18 exports, 8 failure controls, 8 sidecars
and 26 GDB sessions, with 10 complete strict reports retained. No production
Java/native code changes at this follow-up; the same tested package is used.
See [the instruction-path receipt](evidence/compiler-unwind-boundaries.json).

## Remaining scope

These results cover all ordinary boundaries on this fixture's executed path,
not all possible inputs, ABI, signal, exception or asynchronous states. Compiler
PIE/shared and additional compiler variation remain outside this checkpoint. A passing run does not prove
the external condition for arbitrary executions. Full #112 still requires its
remaining compiler/state matrix, production policy and ADR, and normal
CLI/GUI integration with explicit provenance. LLDB (#110) and build-ID
installation (#109) remain later goal items. The separate PR176 integration run
failed standalone large-ELF compilation; correction `34c42c3` passes locally and
has a new hosted run pending on its own branch. PR175's required gate retains first integration priority.
