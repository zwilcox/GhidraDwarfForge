# Curated later register locals

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** The exporter
can preserve a bounded location for an explicitly curated function-owned local
whose single register becomes live after function entry. General non-entry
lifetimes and original lexical scopes remain **PLANNED**.

The following describes the original read-start checkpoint. The subsequent
[definition-boundary extension](LOCAL-DEFINITION-BOUNDARIES.md) also accepts a
full-width writing first-use, with availability delayed until completion. Its
evidence and pending hosted gate are recorded separately.

## Acceptance and limits

The local must be attached to the same Ghidra function/program, have
`USER_DEFINED` provenance, and have one exact mapped register whose width
matches its stored type. The recorded positive first-use offset must identify
an instruction that reads that exact register without writing any alias.
A prior completed full-width definition must exist. Another parameter/local
overlapping the physical register rejects the proof even if it appears to use
a different lifetime.

The entire function must be one contiguous, fully decoded straight-line leaf
starting at its entry. Calls, jumps, secondary entries, delay slots, overridden
decoding, unproved stores, opaque effects and missing instructions reject it.
The established terminal-return boundary remains applicable. Cancellation is
checked throughout. No new native/JNA call is introduced.

The location list starts at the recorded read and ends after the first
overwriting instruction, or at function end if no overwrite exists. The state
at an instruction address is the state before that instruction executes.
Explicit unavailable intervals cover the earlier prefix and any later tail.
There is no backup, migration, reacquisition or inference from an arbitrary
decompiler varnode. Zero-offset and unsupported stack-local behavior remains
on the existing paths.

This describes an analyst's function-owned variable. It does not reconstruct
an original C lexical block. The fixture deliberately distinguishes the two:
the compiler's nested `held` local has left scope at the overwrite instruction,
although its register still contains the old value. Forge's separately curated
`curated_held` remains physically available there, and becomes unavailable
after the overwrite. The oracle asserts the compiler lookup is absent at that
point and compares the curated value with independently read register bits.
Only the common read point is used for the named compiler-local comparison.

## Local evidence

At the original read-start checkpoint, `laterRegisterLocalSmoke` passes **108** checks with real x86-64/AArch64
decoders. Negative controls include partial/no initialization, wrong/offcut
first-use offsets, a writing first-use instruction, conflicting locals,
uncurated/detached storage, missing register maps, opaque and call tails,
second entries, missing decoding, overridden flow and cancellation.
Eighteen packaged suites pass on actual Java 21 with a 256 MiB heap and checked
class origins. The local headless exports use Java 25; these are distinct
observations, not an assertion that the headless run used Java 21.

The real exporter passes x86-64/AArch64 exec, PIE and rebased PIE: twelve
candidate exports, six preceding-package comparisons, and **594 GDB stops**.
The preceding package retains the name/type but omits this location. The
candidate exposes exact signed 32/64-bit values only within its established
interval. The harness checks `list`, `ptype`, `next`, `step`, six return values
per debugger invocation, normal program exit and nonzero PIE runtime biases.
Original inputs and package bytes remain unchanged. Repeated sidecar/source
pairs are byte-identical; PIE/rebased inputs and normalized boundaries match.
Saved program data is unchanged; only Ghidra's two documented backup files may
rotate on reopening.

GNU and LLVM validation pass. Strict libdwarf checking has no uncorroborated
errors. Its inherited frame-length diagnostics exactly match the originals
(x86 exec 5, x86 PIE/rebase 3, AArch64 6); the copied `.eh_frame` bytes match.
The independent review checks raw location-list bytes, symbol boundaries,
reported unavailable intervals, debugger values, preserved inputs and package
source binding. Receipt:

```text
build/later-local-review/acceptance.json
SHA-256 f1d20ebccd6a857f7a4037d40d111724e8dfe98d239b6918a7eff2fc1f634afa
tested JAR 97eed4c205f6470cb64850c1cecd366181c1fcd80003e76c5de5feac63372b2b
actual Java 21: build/later-local-review/packaged.3qh68t6d/result.json
```

Accepted local cases under `build/test-results/later-register-local/`:

```text
x86_64.exec.47f9ynls             aarch64.exec.co1fbv4m
x86_64.pie.iv00zu2c              aarch64.pie.btsbbups
x86_64.pie-rebased.3gl7168h       aarch64.pie-rebased.b5m78so2
```

Run each case with a packaged installation and the configured strict checker:

```bash
./gradlew laterRegisterLocalSmoke
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" x86_64 --role exec
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie
python3 src/test/integration/later-register-local-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie-rebased
```

CI requires all three roles in each of the two target lanes and the model
suite on Linux and native Windows. Those new hosted checks are **PRESENT,
UNVERIFIED** until the exact-head full gate and raw artifact review pass.

Adjacent regressions also pass on the same package: six x86-64/AArch64
exec/PIE/rebase stack-first-use cases, preserving unsupported later stack-local
omissions and zero-offset values, plus two real stack-spill cases with repeated
exports. Their validators and compiler/GDB checks pass. Evidence is retained in
`build/later-local-review/stack-regressions.log`,
`build/test-results/stack-first-use/run.CkXK6qlo/`, and
`build/test-results/stack-spill/{x86_64.exec.2ehz8w5v,aarch64.exec.nlo32u73}/`.

## Retained failures and investigation

The first model attempt constructed an invalid empty register map; the next
used a non-cancellable `TaskMonitorAdapter`. The corrected controls use a
nonempty unrelated mapping and explicitly enable cancellation. Both failed
logs remain under `build/later-local-review/`.

Initial case `x86_64.exec.mttx7kqc` timed out after 60 seconds in LLVM 18.1.3
while validating the compiler's own DWARF, before the Forge validation/GDB
stage. The caller had local constant arrays and a loop. Its exact source is
retained as `retained-loop-fixture.c`, checked against the original protected
hash, alongside the original binary and timeout log. The cause is **UNCERTAIN**;
this is not accepted validator evidence. The caller now makes the same six
calls explicitly, as in the existing stack-spill harness. The two functions
under test are unchanged, and LLVM remains mandatory for both compiler and
Forge artifacts.

Pre-implementation evidence in the root checkout's
`build/local-register-first-use-research/run.0v43vm1q/` confirms the compiler
scope distinction, Ghidra's retained curated first-use metadata, and the
preceding exporter's honest omission on both targets. Auto-analysis eliminated
the temporary from its decompiled expression; it supplied no original lexical
scope evidence. This feature therefore does not infer that information.


### Initial hosted fixture-inventory failure

Run `40247500844` at PR61 head `6d530f0` failed all five target lanes in
`Build source fixture`: the new C source was absent from the explicit audited
fixture inventory. Exporter integration and native Windows did not run.
The exact package and eighteen actual Java 21 suites passed independently,
but are not accepted as a full gate. Logs/artifacts remain under the root's
`build/pr61-hosted/` with `review-stopped.json`.

The inventory now explicitly includes `later-register-local.c`. Its existing
unreviewed-file rejection remains intact. Fresh local reproducibility checks
pass x86-64, AArch64, ARM32 and both MIPS byte orders; see
`build/later-local-review/fixtures-*.log`. A fresh complete exact-head hosted
gate is required. This correction changes no production ELF/DWARF behavior.
