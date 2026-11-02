# ARM homogeneous floating aggregate storage

**CONFIRMED locally; hosted acceptance pending.** Computed ARM VFP homogeneous
floating aggregates now retain their logical S/D members when Ghidra coalesces
them into a larger physical register. The shared incoming-piece analysis accepts
exact upper aliases and models terminal input states consistently with scalar
incoming values. This advances #70; the full #68–#71 requirements remain open.

## Defect and representation

The preceding package (`7ad5779760f94ee0d24985d286a49069dc65902b011883803b7ff4417b8a64fd`
production JAR) emits a BE8 two-float HFA as one D register. GDB consequently
prints `{7.5, 6.25}` for source-known `{6.25, 7.5}` at entry. A little-endian
immutable HFA also becomes unavailable after the result overwrites its incoming
register despite a surviving copy. Both failures are retained and required by
the local preceding-package controls, rather than inferred from missing sections.

`ArmHfaParameterAllocation` is an isolated, read-only representation policy:

- It requires matching ARM v8 LE or LEBE language, default compiler specification,
  and unambiguous supported EABI5 metadata. The actual selected dynamic prototype
  must be VFP; explicit custom storage and variadic signatures remain untouched.
- It rederives storage using that same prototype and compares it with every saved
  parameter before accepting a change. It neither reallocates arguments nor
  modifies the saved program or decompiler output.
- It flattens bounded, contiguous structures/arrays/typedefs containing two to
  four equal-width float/double members. Padding, unions, mixed fields, oversized
  shapes and nonregister/exhausted storage are not reinterpreted.
- It checks the original physical extent against the actual S0–S15/D0–D7 argument
  bank, then supplies significance-ordered member varnodes to the existing
  shared extraction path. DWARF still uses the audited D-register numbers and
  logical S-register bit slices; there is no blanket Q-register scalar mapping.

A logical member can occupy upper bits of a Q register. Shared piece facts now
track the exact varnode bytes, just as scalar incoming facts already do.
Overlapping writes retire those facts; disjoint writes preserve them. A whole
aggregate is available only while every member has a proven location. Terminal
input states do not become callee-effect summaries or propagate through an
opaque return.

## Local acceptance

The assembled package SHA-256 is
`e7ae8f1fe0c2fa1f3be8fb671825e863fcc9594f005935e74a724affa1745903`;
its production JAR SHA-256 is
`3466d301048383f3f509d676a0765d21719b515e8340737e2ec0650712043ad2`.
Production-source hashes remained unchanged throughout validation.

The actual Ghidra model checks pass:

- HFA representation: 792 checks across both data orders, 4/8-byte elements,
  2/3/4-member structures, nested structures, arrays, typedefs, register-bank
  offsets/exhaustion, custom/base/variadic storage and rejected layouts.
- Logical upper aliases: 237 checks, including composite copies, overlapping
  writes, overwritten slots and frame release in both data orders.
- Existing composite flow: 1,032 checks; terminal input states: 74 checks.
- Stack value, composite-prefix, mixed-prefix, MIPS FP32 pair, indirect parameter
  and register-alias regression suites also pass.

Four real aggregate export cases (LE/BE8 × base/VFP default PCS) pass 48 typed
entry observations and 176 instruction-level HFA-prefix observations, in addition
to the existing 48 raw transfers, 48 captured arguments, 36 typed returns,
72 injected calls and 24 unchanged-state rejections. Compiler references remain
independent and strict at their documented observation points.

The new immutable `arm-hfa-lifetimes.c` fixture passes in LE and BE8. Each case
checks two 14-instruction functions against independently audited machine bytes.
Forge displays both fields correctly at all 28 instructions, including the result
register overwrite and frame release. Across both cases, this is 56 typed Forge
observations and 20 typed compiler observations. Both symbol-file runs independently
check source-known raw register carriers at all 28 instructions per case. Compiler
stack locations are checked only after initialization and before release; they
are not treated as valid references outside that interval.

Each new case passes GNU views, LLVM verification and the pinned strict libdwarf
validator, preserves original input and saved program bytes (allowing only Ghidra
index/journal backup rotation), and produces byte-identical repeated sidecar and
synthetic-source output. QEMU's existing synthetic-vDSO warning is corroborated
against the mapped ELF bytes; no new warning is waived.

Five runtime regressions pass: LE and BE8 scalar convention/declaration/custom
storage controls, existing ARM aggregate returns, and x86-64/AArch64 rebased-PIE
composite flow. All five fixture reproducibility lanes pass with the new source
registered in their explicit inventory. The new model and runtime checks are
wired into the maintained CI workflow; this does not assert a hosted pass.

## Reproduction and retained evidence

Use Ghidra 12.0.3 and Java 21, with the repository's existing pinned natives.
The LE runtime uses GDB 15.1; BE8 uses the documented unmodified GDB 17.1 profile.
Both use the previously validated private QEMU D/Q-alias correction. No system
debugger or emulator was modified by this component.

```bash
./gradlew armHfaParameterAllocationSmoke upperAliasValueFlowSmoke \
    compositeValueFlowSmoke terminalStackValueSmoke buildExtension
python3 src/test/integration/arm-aggregate-calls.py "$ghidra" \
    --order "$order" --pcs "$pcs" --gdb "$gdb" --gdb-data "$data" --qemu "$qemu"
python3 src/test/integration/arm-hfa-lifetimes.py "$ghidra" \
    --order "$order" --gdb "$gdb" --gdb-data "$data" --qemu "$qemu"
```

Local commands, per-case results, source/package hashes, prior-package controls
and the acceptance receipt are retained under `build/arm-hfa-storage/`. Actual
runtime case directories are linked from `acceptance.json`.

Retained development failures include two incorrect test constructor signatures;
a missing terminal-input admission in shared composite decoding; a test that
incorrectly discarded a proven S14 backup on frame release; a missing local
objdump environment setting; JSON key-order comparison instead of observation
content comparison; and an incorrectly sorted fixture inventory entry. Each was
corrected and its affected check rerun. None is recorded as a passing run.

## Remaining scope

This does not complete broad aggregate or ARM ABI support. Additional saved
ordinary aggregates, mutable identities, discontiguous/control-flow and layout
compositions, runtime negative piece/clobber controls, unsupported shapes, and
full hosted/protected integration remain governed by
`TARGET-ABI-COMPLETION-PLAN.md`. All original MIPS, AArch64 and i386 requirements
remain active. No umbrella issue should close from this component alone.
