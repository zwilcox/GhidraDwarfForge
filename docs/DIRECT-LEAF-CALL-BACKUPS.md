# Saved parameter registers across direct leaf calls

**CONFIRMED locally; full hosted acceptance pending (2026-10-25).** This is a
bounded P1.11a improvement. It does not complete general call-crossing lifetimes,
memory migration, mixed pieces, indirect calls or later-starting locals.

## Contract

The existing ordered p-code proof can retain one direct, completed low-bit
register copy of an incoming scalar parameter. The incoming register must be
overwritten before the first call. The caller still needs one fully decoded,
straight-line body, ordinary boundaries and no secondary entry, delay slot,
branch, opaque operation or flow override. Complete incoming composites retain
their existing leaf-only policy.

A supported call has exactly one direct p-code target matching the listing
flow, in the caller's code address space. The target must be the exact entry of
a known, nonexternal, nonthunk, returning function with an explicit selected
calling convention and no call fixup. Its entire body must decode contiguously
through a normal terminal return; nested calls, branches, opaque operations,
unproved stores and boundary overrides reject this proof. There is no recursive
call-graph inference or assumption about an unresolved library function.

The saved register survives only if the callee's actual convention declares its
whole physical base register unaffected **and** every decoded callee instruction
leaves it unwritten. Explicit p-code writes and independent listing result
objects both matter. Call-instruction writes are evaluated in order as well.
An AArch64 link register can appear in the unaffected list while the `BL`
instruction writes it; metadata alone is insufficient.

A callee write, including a partial write or a save/restore sequence, ends the
backup at the call's fallthrough. A later caller restore similarly ends it at
that instruction's fallthrough. These instructions themselves still describe
the pre-execution value. No memory fact, new backup chain, lost-fact
reacquisition or guessed frame recovery fills the resulting unavailable tail.
There are no new native producer calls or generic architecture constants.

## Evidence and reproducibility

The initial compiler-oracle probe was independently reviewed on x86-64 and
AArch64: compiler DWARF exposes the argument at entry, at the call, after the
call and before restore; the preceding exporter omitted it throughout. The
physical saved register retained the value. Baseline receipt SHA-256:
`904ffc466d401f8e86b446868af03f125da1f43516e145e26c618ea268210200`.

`DirectLeafCallSmoke` passes 140 checks with actual pinned Ghidra decoders and
ProgramDB functions. Controls cover callee and call-instruction clobbers,
partial/result-only writes, missing or insufficient ABI declarations, unknown
conventions, call fixups, no-return targets, indirect/mismatched/multiple calls,
nested calls, opaque effects, register-space stores, missing returns, overrides,
delay slots and cancellation. Rejected call evidence is also checked through
the public parameter extractor. Existing register copy, prefix, composite,
opaque-effect, dynamic-storage and variable-storage suites pass.

Five packaged suites pass on actual Java 21, with the loaded production class
origin checked against installed JAR SHA-256
`39b913437f1f8e2d7d4e8fa69f145c45b482a675b61cc6766dd7242660041f54`.
The focused receipt is
`5421c1477a0568770f98b93d9f889cb84f659f6ced24612c5114a030ed2a4a54`.
Local headless Ghidra uses Java **25.0.4.1**, separately from those Java 21
checks; the hosted workflow uses Java 21 and remains required.

The runtime fixture is compiled as two ordinary C translation units at `-O2`,
without forced parameter registers or inline assembly. Its compiler reference
retains DWARF; the imported copy has debug sections stripped but retains ELF
names. A saved curated `int(int)` signature uses the actual compiler-spec
convention and dynamic storage. Fresh read-only exports must preserve the
program and original executable and produce identical sidecar/source bytes.

The native x86-64 and QEMU AArch64 oracles compare three arguments (17, -17,
19088743) at five PCs: entry, call, return from the call, before restore and
after restore. Four PCs retain the correct value; the final PC is explicitly
unavailable in Forge. Compiler DWARF and the preceding exporter run separately.
Ordinary returns are 57, -45 and 57266235. Raw DIE/location-list assertions,
source listing, type lookup, `next`, `step`, unchanged-input hashes, GNU views,
LLVM verification and the strict standalone validator are required.

The final local full-harness runs are `x86_64.xuhk8nrq` and
`aarch64.dte1c21b` under `build/test-results/direct-leaf-call`. Their result
SHA-256 values are respectively
`48a62315173587b03edac1d648ccb00761c8e4574e45f33fb2c7c444f73aac7a`
and `da49f1b35be49129a55cdcf03d0b28e9c271dca0e542316ad7625a4f70876ac0`.
Root review of raw DIEs, both location-list ranges, all 90 GDB observations,
normal returns, source commands and preservation yields receipt
`10cdcda14ed175faf6fbe848aa57b20ad0d8c9035090cbb4f52220f8cd7ae1ae`.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew directLeafCallSmoke
python3 src/test/integration/direct-leaf-call-export.py "$GHIDRA_INSTALL_DIR" x86_64
python3 src/test/integration/direct-leaf-call-export.py "$GHIDRA_INSTALL_DIR" aarch64
```

An optional `--previous-ghidra` installation reproduces the old omission. Both
target lanes and Linux/native Windows model suites are wired into the same
production integration workflow. This does not establish MIPS, ARM32, PIE,
shared-library or general ABI call-preservation coverage for this new proof.

## Retained unsuccessful checks

- The first cancellation control used a monitor with cancellation disabled.
  Enabling cancellation makes the unchanged production check throw as required.
- LLVM 18.1.3's verifier stalled at full CPU on the original compiler fixture's
  array-loop driver. The owned process was stopped, and its binary, original
  source reconstructed against its recorded SHA, and logs remain under
  `build/test-results/direct-leaf-call/x86_64.yi_96357`. No pass is claimed.
  The final driver performs the same three calls explicitly; all verifier
  assertions remain, with a 60-second timeout.
- An exploratory copied-artifact GDB replay omitted executable permission when
  copying its test binary and correctly failed. A fresh mode-preserving copy
  passes. The durable fixture compiles its own executable and is unaffected.

Full exact-head hosted package/runtime review and subsequent main acceptance
remain separate from this local evidence. No release is published by this work.

## First hosted driver correction

**CONFIRMED:** AArch64 job `121256326242` in run `40221737406` completed export,
raw location-list checks, validators and the compiler GDB oracle, then failed
with exit 127 because the driver used `rg`, which is not installed in the CI
lane. Forge GDB had not yet run. The driver now uses standard `grep -Fxq` for
the same exact PASS marker; exporter and native code are unchanged.

The retained CI compiler/input/sidecar artifacts pass a local QEMU replay with
a deliberately failing `rg` stub and debugger source-prefix substitutions only.
All 30 compiler/Forge PC observations, unavailable tails, ordinary returns and
`next`/`step` checks pass; the stub is never called. Replay receipt:
`7d905c981fc81805e29cf43e87544577baf3790391f72ad1f2f4a4bc65d955c3`.
Fresh complete x86-64/AArch64 runs with `rg` disabled also pass, including the
preceding-package reproduction. Their result receipts are
`d1dd4088ed839b68a95a342b96c889d6513e25a5736827b2d732325e75545fa4`
and `7acb93ae745433957b69ab8f6ce6259e37b5cce21dd5433441aa1fb032c1dd91`.
Root correction review receipt:
`1c3ece73339a5134f16598879b64c291ffe18bcdd10af0b055492d246568e450`.
The original failed job remains retained; a new full exact-head gate is required.

The first hosted package independently passes its 50-source/226-class/native
provenance audit and five fresh actual Java 21 suites. Those checks do not turn
the failed integration job into a pass. Hosted JAR SHA-256:
`686708c0b09c5cb6c8e56e219b16b3110ecf050d016cc51a4cac33e905e0a16b`;
focused receipt `35dd1a17462e9caf29e0570cfbc74a056d08b4ecf458ae38b66c25dce81d1a44`.
