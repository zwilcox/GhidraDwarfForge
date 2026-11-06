# Conditional relocated-pointer recovery and compiler image roles (#112)

**CONFIRMED locally, internal explicitly conditioned path.** The unchanged
compiler C fixture now passes real export, validators and GDB on both initial
targets in fixed executables, PIE executables and loaded shared objects. The
shared-object cases bind internal definitions with `-Bsymbolic`; interposable
calls are separately rejected. This does not enable synthesis in normal CLI/GUI
exports or establish universal pointer immutability or stack separation.

## The AArch64 gap and its evidence

PIE passed on both targets with the existing separation condition. The x86-64
shared library also passed. AArch64 instead emitted an ADRP/load sequence that
reads `cfi_sink`'s address from a GOT slot. That slot has a symbol-zero RELATIVE
RELA record, while the actual write still targets the original global object.
The former analysis correctly refused the unknown pointer, so no complete frame
plan was published. The compiler source and global increment were not changed
to avoid this case.

The pinned AAELF64 document describes RELATIVE as a load adjustment plus addend,
including the symbol-zero case; its SHA-256 remains
`6879ea95aaa365d62a9c251d468c6f9df0eeaa6a3324e77f0b9e262443dad8fc`.
The existing audited target relocation profile supplies the relocation type and
width. Generic code derives pointer width from the ELF, rather than assuming a
processor or register layout.

`ElfRelocatedPointers` qualifies **candidates**, not runtime facts. A candidate
must be an explicit-addend, symbol-zero relative relocation under an audited
profile, with one readable/writable non-executable file-backed load mapping,
one declared RELRO covering the whole slot, one readable mapping for the target,
and no overlapping loader writes. Unsupported records, missing protection or
unqualified mappings cannot supply a pointer value. The original slot hash,
record offset, file offset, address and addend are retained. Population and
comparison budgets, cancellation, original-file consistency and resource cleanup
apply. Initial slot bytes do not replace a RELA record's explicit addend.

## Explicit additional conditions

The existing immutable separation object can optionally carry fixed pointer
slots and values. Its old three-argument constructor still means separation only.
The stronger condition says the entire pointer retains that value throughout
the analyzed execution and all stack-relative accesses remain disjoint from its
slot. Slots must be bounded, non-overlapping and contained in the separated
regions. This condition is **not proved by an ELF symbol, RELRO declaration,
Ghidra data value, ABI name or one successful debugger run**.

Only an exact full-width load can use a fixed pointer. Partial and differently
sized/addressed loads remain unknown. Conflicting, wrapping or unknown writes,
opaque effects and calls with unbounded memory effects refuse the conditional
analysis. A verified summary retains the complete condition; a caller missing
its fixed pointer facts cannot consume it. Strict callers and default recovery
remain unchanged. Unqualified projection still rejects conditional proofs.

The evidence report retains `EXTERNAL_CONDITION_NOT_PROVED`, the external basis,
separated ranges and fixed pointer address/value pairs normalized to original
ELF virtual addresses. Runtime use requires the image's load bias. The test-only
exporter accepts an explicit `relocated-pointers` option; it never enables these
facts based solely on detecting a candidate. Existing exact condition
acknowledgement, consistency guards and staged publication still apply.

Ghidra 12.0.3 rebasing moves the slot address without rewriting its stored pointer
literal. An initial test-only equality check therefore rejected the first rebase.
The corrected harness records that database observation separately and derives
its explicitly assumed runtime value from the original ELF relocation. It does
not rewrite analyst memory. GDB independently checks the actual loaded pointer at
every executed instruction boundary; this demonstrates the condition for the
observed run only.

## Validation and retained failures

The final installed package passes six compiler cases: x86-64/AArch64 times
executable/PIE/shared. Each case performs nine exports, four real serialization
failure/cancellation controls and four plain/zlib/original-base/rebased variants.
GNU, LLVM and the pinned strict checker validate every artifact. Source and
artifact hashes, original instruction bytes, captured rules and emitted CFI
transitions agree; original inputs remain unchanged and repeated exports match.

The independent compiler and generated output agree at every executed ordinary
boundary, including caller PCs, stack-pointer offsets and saved-register values.
Actual DWARF selection is required at every ordinary level of each snapshot.
Executed paths contain 90/77 snapshots for x86-64/AArch64 executable and PIE,
and 92/79 for their shared libraries. The original checkpoint/`finish`/recursive
return tests also pass. Shared-library and driver addresses are normalized in
their respective image domains, so ASLR is not mistaken for disagreement.

Totals: 54 conditioned exports, 24 staged controls, 24 sidecars and 78 GDB
sessions. Two strict exporter regressions add 18 exports, 8 controls, 8 sidecars
and 18 GDB sessions. All 38 passing strict receipts retain complete raw reports.
Five additional native-import cases prove 14 refusals: strict/default recovery,
a shortened global range, missing pointer acknowledgement, interposable calls,
and a non-RELRO AArch64 slot. Each preserves its original and the previous
artifact/source/evidence generation and leaves no staging files.

The isolated suites pass 205 pointer-inventory checks, 125 condition checks,
1,521 bounded-report checks and 13,770 native call/projection checks, plus the
existing flow, closed-call and frame-row suites. The new condition tests caught
an initially missing constructor validation block; malformed slots now refuse.
The original AArch64 refusal and rebase test failure remain archived alongside
the final passing evidence. No failed run is counted as a successful case.
See [the receipt](evidence/relocated-pointer-unwind.json) for exact hashes,
commands, package readback and archived raw artifacts.

## Remaining work

The workflow includes these cases in both target lanes; hosted acceptance is
**PRESENT, UNVERIFIED** for this branch. The separate PR176 CI correction has
been merged here normally; its hosted gate is still running. PR175 passed its
fifteen jobs and merged normally as `5b4ca014`; #116/#114 are closed. The new condition has not been adopted as a supported
shipping policy. Additional compiler/state variation, the updated ADR and normal
CLI/GUI integration remain required for full #112 acceptance. Signal/exception,
pre-loader, mutable GOT and arbitrary indirect-call recovery are not claimed.
Issues #110 and #109 remain later goal items.
