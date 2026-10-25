# Incoming composite register lifetimes

**PRESENT, UNVERIFIED end to end:** a parameter
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
the proposed Forge proof.

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
  partial or unnamed aliases and register-space STOREs. Require the complete
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
from the actual Java 21 focused test. Packaged focused tests and real
exporter/validator/GDB acceptance remain pending.

**PLANNED:** both exact source-built fixtures must pass through the packaged
exporter, GNU/LLVM/strict validators and compiler/Forge GDB. Computed and custom
storage must expose both typed fields at entry and at the first-write
instruction, then report the whole value unavailable at its fallthrough.
Repeat and reopened exports must be deterministic; original inputs remain
unchanged. The preceding runtime's retained failure supplies the negative
comparison.

The new runtime cases are ET_EXEC only. Existing scalar-prefix PIE/rebase
regressions remain required; these two cases add no composite PIE/rebase or
additional architecture claim. Linux and Windows focused checks plus the full
five-target integration gate are required before integration.

The investigation used Java 25 headless execution. Its strict validator output
contains four x86-64 and six AArch64 findings corroborated against inherited
original frame data, with zero unexplained errors. Each AArch64 GDB session has
one explicitly checked vDSO warning. Those baseline results are not fresh
acceptance of the proposed implementation.
