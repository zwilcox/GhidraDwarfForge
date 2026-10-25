# Incoming composite register lifetimes

**CONFIRMED locally; hosted acceptance pending:** a parameter
split across registers can have a defensible incoming value even when one
register is overwritten later. The preceding exporter rejects the complete
location with `REGISTER_MODIFIED`. This bounded P1.11a follow-up retains a
complete value only through the first overwriting instruction, before that
instruction executes, then makes the whole value unavailable at its
fallthrough address.

## Evidence and selected boundary

The unchanged preceding packaged runtime `2d787e33...` was exercised on two
source-built ET_EXEC programs. Ordinary C takes a two-field, sixteen-byte
aggregate; a declared inline-assembly clobber overwrites one incoming register.
The compiler preserves its C value in other storage, so compiler DWARF supplies
an independent typed-value oracle. These compiler-created backups are outside
the Forge proof.

The initial analyst operation applies a `USER_DEFINED` signature and aggregate
type while requesting computed storage. Ghidra supplies the registers. Normal
conversion to custom storage, saving and reopening leave the type, storage and
meaningful decompiled member uses unchanged. No manually assigned register
storage, instruction patch, flow override or context repair is involved.

The x86-64 fixture overwrites the low sixteen bits of RDI through DI. The
AArch64 fixture writes W0, which changes X0. Machine instructions, p-code and
debugger observations establish the first physical register write; source
labels alone do not establish it. Before that write both incoming fields are
correct. The preceding Forge runtime honestly reports both fields unavailable
throughout each function.

## Required proof

- Refine only an incoming parameter rejected with `REGISTER_MODIFIED`, with
  valid direct register-only composite storage of exactly the declared size.
- Revalidate every piece and its register mapping before constructing a
  location. The initial rejection may have hidden an unsupported later piece.
  Require matching formal, parameter and storage sizes and nonoverlapping
  physical register pieces. Resolve each slice through the language's exact
  address-and-size lookup: in Ghidra 12.0.3, a big-endian low slice can start
  inside the larger register returned by that lookup. Retain the existing
  LSB-relative slice semantics.
- Preserve the shared join normalization: Ghidra lists significance order;
  DWARF pieces use object-memory order. Each register slice keeps its existing
  bit offset and width.
- Require one entry-first contiguous function body, completely decoded into
  ordinary instructions with no additional or offcut entry. Reject calls,
  branches, opaque effects, delay slots, instruction-length or fallthrough
  overrides, and unproven STORE effects throughout the body, including after
  the proposed first-write boundary.
- Find the earliest write to any piece's physical base register, including
  partial or unnamed aliases. Register-space STOREs remain unproven and reject
  refinement. Require the complete
  straight-line leaf proof before accepting its fallthrough as the boundary.
- Emit the complete composite prefix and a whole-value unavailable tail.
  Failed refinement leaves the preceding omission intact. Honor cancellation.

This work does not retain surviving pieces, track composite backups, recover
later locals, or prove storage across calls, branches or delay slots. Existing
single-register backup behavior and local-variable rules remain separate.

## Acceptance criteria

**CONFIRMED focused validation:** actual Java 21 at 256 MiB passes 469 checks,
including actual decoded x86-64/AArch64 computed, custom and immutable-reopened
parameters and the raw location-list encoding. Controlled tests cover an
earlier clobber in a later raw-order piece, stable pieces, invalid later pieces,
partial aliases, hazards after the boundary, reference offcuts, decoding and
override failures, cancellation and unchanged omission precedence. A
big-endian test uses real language storage and controlled straight-line p-code;
it is not a MIPS execution claim. The preceding `2d787e33...` JAR fails the
new public-API positive assertion as expected. Independent source and retained
evidence review passes.

Ten relevant Gradle storage/lifetime tests and the extension build also pass
under Java 25, compiling Java 21-compatible bytecode. Those runs are separate
from the actual Java 21 focused test. The installed package also passes actual
Java 21 checks 469/1480/154/182 with production classes loaded from its JAR.

**CONFIRMED local runtime validation:** both exact source-built fixtures pass
through the installed `3f9e46b5...` package, GNU/LLVM/strict validators and
compiler/Forge GDB. Across the two targets, computed and custom variants each
visit sixteen PCs: six have both correct typed fields, and ten are explicitly
unavailable. Each target has positive values at entry, before the overwrite
and at the writing instruction, with the whole-value unavailable tail starting
at its exact fallthrough. The compiler retains correct fields at all sixteen
PCs using its independently described storage.

All eight exports, six debugger sessions and two plain executions pass on
their first runtime attempt. Repeat and reopened outputs are byte-identical,
and the stripped inputs exactly match the preceding `2d787e33...` investigation.
Original inputs and observed module/test files remain unchanged; all three
owned AArch64 QEMU sessions exit normally and their private endpoints are
removed. Independent raw artifact review passes without repeating execution.

The new runtime cases are ET_EXEC only. Existing scalar-prefix PIE/rebase
regressions remain required; these two cases add no composite PIE/rebase or
additional architecture claim. Linux and Windows focused checks plus the full
five-target integration gate are required before integration.

Both the preceding investigation and the corrected local runtime use Java 25
headless execution. Fresh strict output contains four x86-64 and six AArch64
findings corroborated against inherited original frame data, with zero
unexplained errors. Each AArch64 GDB session has one explicitly checked vDSO
warning, matching the compiler oracle. These are explained diagnostics rather
than warning-free runs.

Runtime receipt SHA-256 is
`703fc5ba467cb9a61fdd3bfaf089a54ef8d107ebc54dd7f77e9b266f76c8b77c`;
independent raw review is
`1bebf993bc534ad0af0113d1e920ee9b93eddfa5219476c2b0cee348aae46a12`.
Packaged focused receipt is
`c9ae84ab6c8d1f169af6dded8a6aeecf70839af154fc8dc582a4f67675e613e3`.
Final committed packaging and the separate full hosted gate remain required.
