# ABI profile selection investigation

**CONFIRMED (2026-11-01):** Ghidra 12.0.3's compiler-specification name alone
is insufficient to select the AArch64 ELF debugger ABI. This is the next
component of P2.3/#68, following the indirect-argument candidate PR121. It does
not complete the AArch64 profile or change the P2.3–P2.3c scope.

The existing `GhidraTargetAgreement` checks processor, data-pointer width and
byte order. Before this candidate, `DwarfTarget.compilerSpecCallRestriction` additionally
checked only the compiler ID. Both `AARCH64:LE:64:v8A` and `AARCH64:LE:64:AppleSilicon` have an
eight-byte data pointer and a compiler named `default`. The preceding checks
therefore could not distinguish these two default compiler models.

The installed `AARCH64.opinion` chooses v8A/default for ELF and
AppleSilicon/default for Mach-O. The corresponding compiler XML files differ
in an Apple variadic rule. A native-free Java 21 probe instantiated real
`ProgramDB` objects for all six compatible compiler/language combinations and
called the pinned `PrototypeModel.assignParameterStorage` API using
`PrototypePieces.firstVarArgSlot = 1`. The prototype has one named 64-bit
integer, followed by a variadic 64-bit integer, double and 24-byte structure.

| Language / compiler | Named integer | Variadic integer | Variadic double | Variadic structure |
| --- | --- | --- | --- | --- |
| v8A / default | x0 | x1 | d0 | pointer in x2 |
| v8A / windows | x0 | x1 | x2 | pointer in x3 |
| v8A / golang | x0 | x1 | d0 | 24 bytes at stack +8 |
| AppleSilicon / default | x0 | stack +0 | stack +8 | pointer at stack +16 |
| AppleSilicon / swift | x0 | x1 | d0 | x4/x3/x2 join |
| AppleSilicon / golang | x0 | x1 | d0 | 24 bytes at stack +8 |

These are Ghidra model observations, not runtime support claims. A separate
ordinary ten-character-plus-structure signature had the same final stack
positions under v8A/default and AppleSilicon/default, so an ordinary signature
alone would have missed the distinction. The probe creates and releases
separate temporary programs; it runs against the saved fixture in read-only
mode and does not change its curated signature.

Reproduction evidence is retained in the `abi-classification` worktree under
`build/abi-classification/`: `scripts/ObserveAbiProfiles.java`, `probe.log`,
`profiles.json`, `probe-varargs.log` and `profiles-varargs.json`. The selected
runtime is Java 21 and the Ghidra installation is the same physical 12.0.3 copy
used for PR121's packaged tests. Native DWARF production is not invoked by this
probe.

**CONFIRMED local candidate:** the selected language/compiler combination and
ELF call-profile metadata now participate in the isolated target policy,
preserving curated types/storage and restricting unvalidated debugger calls.
Model, producer and runtime evidence and remaining acceptance are recorded in
`../AARCH64-ABI-SELECTION.md`. Zero OS-ABI does not establish Linux. The pinned [Arm ELF specification, 2025Q4](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aaelf64/aaelf64.rst)
requires zero AArch64 processor flags and generally zero OS-ABI unless
OS-specific meanings are used. Its class/byte-order variants are distinct
from Forge's currently tested LP64 little-endian profile.

The acceptance tests cover the actual same-width alternative language,
nondefault/unknown compiler selections, reserved ELF flags and unsupported
class/byte-order profiles. Positive baseline behavior and all existing
processor/width/endian contradiction tests must remain intact. Model policy
checks alone are insufficient: the candidate harness also requires emitted
calling-convention attributes and actual GDB behavior. MIPS, ARM32 and i386 selection requirements
remain in the full completion plan.
