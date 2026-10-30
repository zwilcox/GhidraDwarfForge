# Bounded register-copy lifetimes

**CONFIRMED in exact hosted run `40079317009`:** the implementation extends a
simple incoming parameter's location when an earlier instruction demonstrably saved
its bits in another register. The final reviewed package passes real exporter,
validator and GDB acceptance on x86-64/AArch64 non-PIE, PIE and rebased PIE.
All twelve jobs and independent package/targeted runtime/host-artifact reviews
pass for PR #29 head `698e939`; normal merge `25f9830` preserves the tested tree.
This remains a bounded profile claim.

The existing whole-function register proof and its opaque-effect guard remain
in force. Only a rejected, single direct-register parameter can enter the
fallback. The function must have one completely decoded contiguous body, its
entry at the first address, no known secondary entry (including references
into instruction interiors), and an ordinary final return. Calls, branches,
delays, flow overrides, unimplemented p-code and user
operations reject the entire fallback, including hazards after the first write.

The added proof requires agreement between the formal type, parameter and
concrete storage widths. It uses exact named low register slices from Ghidra's
register hierarchy. A lookup that merely returns a larger containing register
is insufficient. An equal-width `COPY`, or a widening `INT_ZEXT` of the full
parameter width, can preserve those bits in one distinct register. Only the
tracked low bits belong to the variable; zero extension does not turn a signed
32-bit value into a signed 64-bit value.

Raw p-code is processed in order and facts become usable only after a complete
instruction. This handles a narrow copy followed by widening of the same
destination, while rejecting a subsequent partial overwrite. The saved copy
must exist before the original-writing instruction begins. The first completed
eligible backup is the sole candidate; arbitrary copy chains and recovery of a
lost fact are outside this proof. Listing result objects, raw partial writes,
register-space stores and independent length/fallthrough overrides cannot silently bypass
the boundary checks. Cancellation propagates normally.

The emitted location sequence describes the incoming register through the
original writing instruction, the proven backup starting at its fallthrough,
and no location after an unproved backup write. A location at an instruction
address describes its pre-execution state. The existing DWARF 5 location-list
encoder represents these intervals; no native binding or DWARF operation is
added. Names, types, source correlation and PIE/rebase normalization retain
their established paths.

The shared register-write check also compares physical storage bytes when a
listing result register lies outside the named parent tree. This prevents the
stable and original-prefix proofs from disagreeing with the saved-copy proof
about the first write. A hierarchy-only negative control reproduces the missed
write and is rejected by the corrected checks.

Store destinations are resolved through the program's address-space table.
Only a well-formed store to a known memory space with the correct pointer
width preserves the proof. Unknown, malformed or nonmemory stores invalidate
whole-function stability and reject the entire prefix/copy fallback; they
cannot leave an original-register interval extending beyond an unknown effect.
Ordinary RAM stores remain valid and never create a memory location claim.
Known modeled-write/call diagnostics keep their established precedence.

This does not implement memory migration, call preservation, general control
flow, mixed pieces, later-starting locals or compiler entry-value recovery.
Additional processor/ABI profiles require their own runtime evidence.

Production commit `5ba6f39` has independent code/control review and passing
focused Java 21 tests. Final local run `run.V0gUehki` covers six roles, twelve
exports and 72 calls per compiler/Forge mode. Exact intervals, kill-tail
omissions, input hashes, deterministic pairs and zero unexplained validator
errors are independently verified. The final JAR SHA-256 is
`70514244380b83df22644bc8ea4c5c73a504f5ba87cb2e21ed3f6cdf7ee3457c`.
See `docs/VALIDATION.md` for package identity, commands and earlier failed runs.

## Acceptance fixtures

`register-copy.c` supplies four compiler-backed functions: 32/64-bit values
whose copied register survives, and matching functions that explicitly destroy
the backup. Each receives `19`, `-19`, and a wider negative bit pattern. The
GDB oracle observes entry, copy completion, the original writing instruction,
its fallthrough, and the backup write and unavailable tail where applicable.
It checks the raw backup bits, signed types/values, globals, source lookup,
stepping and normal exit. GCC's compiler DWARF recovers the original value using
an entry-value expression after backup destruction; Forge must instead show an
unavailable value. The compiler and Forge expectations are exact and separate.

The integration harness builds stripped x86-64/AArch64 inputs, invokes the real
packaged exporter for non-PIE, PIE and rebased PIE, and repeats each export.
An independent raw-location-list check requires the exact original-to-backup
intervals derived from compiler symbol addresses, with no post-kill coverage.
GNU, LLVM and strict libdwarf checks, exact code-index coverage, byte-identical
reruns and unchanged input hashes remain mandatory. The earlier
`register_prefix.c` fixture is now a positive copy case; the new backup-kill
functions retain explicit unavailable-boundary coverage. Existing floating,
opaque-supervisor-call and other target tests remain required.

Run the local focused checks with the selected Ghidra baseline:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew registerCopySmoke
src/test/integration/register-copy-export.sh /path/to/private-packaged-ghidra
```

The local complete JDK is Java 25; production bytecode remains Java 21-compatible.
Actual Java 21 smoke and hosted full-JDK tests are recorded separately. An older
research report's claim that local headless ran on Java 21 is historical and
incorrect: its retained launch logs show `25.0.4.1`. Neither that correction nor
this implementation changes the supported Ghidra/Java baseline.

## Bounded second-copy follow-up

**CONFIRMED locally; hosted acceptance pending:** the first proof can now be
composed with one second exact copy proof for an attached incoming parameter
in a call-free leaf. The two proofs must agree on the handoff; earlier copies
and arbitrary chains are still not inferred. See
[the second-copy contract](SECOND-REGISTER-COPY.md) for scoped evidence and
remaining limits. Earlier one-copy-only descriptions above remain historical
for the original accepted checkpoint.
