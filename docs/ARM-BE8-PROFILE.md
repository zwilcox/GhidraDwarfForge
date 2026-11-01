# ARM BE8 profile progress

**CONFIRMED locally; full ABI acceptance incomplete:** the candidate separates
ARM ELF data encoding from instruction encoding. EABI5 BE8 uses four-byte,
big-endian ELF/DWARF data and little-endian instructions. Ghidra's actual LEBE
language descriptions must agree before extraction or native production.
BE32, contradictory flags and a BE-data/BE-instruction language remain rejected.
This is progress toward #70, not completion of #68–#71 or a release claim.

The encoding policy is isolated in `Arm32EndianProfile`. Generic target agreement
asks for the required instruction byte order without embedding processor names.
The audited producer interface is unchanged: the pinned `arm` producer ISA
accepts independently selected big-endian data. Preceding native/symbol-only
experiments are in [the research record](research/ARM-BE8-REFERENCE.md).

## Real exporter checkpoint

`src/test/fixtures/arm-be8` builds a freestanding ARMv7 EABI5 hard-float BE8
executable with GCC 13. The unsigned argument is 7, global is `0x11223344`, and
result is `0x1122334b`. A fresh stripped import selects
`ARM:LEBE:32:v8LEInstruction:default`. Preparation applies source-known unsigned
types and the recovered name, without repairing decoding or inventing storage.
Ghidra assigns parameter/return to `r0:4` and decodes thirteen instructions.

The harness performs two real read-only packaged exports, requiring byte-identical
sidecars/source and preserved original, fixture, harness, package and database
hashes. GNU, LLVM and strict libdwarf validate compiler and Forge artifacts with
no diagnostics. Independent QEMU/GDB executions compare every instruction,
raw bytes and source-known register/global values. Forge displays the parameter
at all ten PCs before its register changes. Compiler stack-slot values are
checked after the initializing store, without granting Forge a wrong-value exception.

Both symbol files pass listing and `next`/`step` from `/tmp` with absolute paths.
A common return-address breakpoint checks the result before caller execution;
synthetic/compiler caller lines need not share addresses. This does not certify
automatic typed return or injected-call ABI. The exact synthetic-vDSO BFD warning
is corroborated with both symbol files; other debugger diagnostics fail.

Commands (Java 21 and the existing private ARM compiler/validator environment):

```bash
./gradlew dwarfTargetSmoke ghidraTargetAgreementSmoke ghidraArmBe8ProfileSmoke buildExtension
./gradlew nativeProducerSmoke -PtargetProfile=arm32be8 -PnativeIterations=32 \
    -PlibdwarfPath=/path/to/package/os/linux_x86_64/libdwarf.so.2.3.2 \
    -PlibdwarfpPath=/path/to/package/os/linux_x86_64/libdwarfp.so.2.3.2
python3 src/test/integration/arm-be8-reference.py /path/to/private/ghidra
bash src/test/integration/architecture-neutrality.sh
```

The real-language model passes 61 checks. Native smoke passes 32 lifetimes,
deterministic output, controlled errors and finish; resident growth is 6,189,056
bytes against a 33,554,432-byte bound. Private package SHA-256:
`5c632743475d139292fafa4b7d0305b1a359f931061c1cb20c36b46e8685b67c`;
production JAR SHA-256:
`50d896fdaa199c56d657584938347118503874fb94de735e8003e726f6216fa0`.

Evidence in the `arm-be8-profile` worktree:

- `build/arm-be8-profile/{build-model,package-v1,native-v1}.log`.
- `build/test-results/arm-be8-reference/scalar.luuwkzez/result.json`: 26 instruction
  and ten source-step observations, six normal exits, deterministic outputs and
  no program-file changes.
- `build/arm-be8-profile/scalar.3f7zuozv`: exploratory runs with retained failing
  type-name/static-symbol lookup and source-step endpoint assumptions. The final
  harness checks semantic type size/signedness, resolves either global or
  file-static symbols and uses a common return breakpoint. Earlier failed runs
  are not counted as passes.

CI invokes the real-language model on Linux/Windows, isolated BE8 producer
lifetimes on both native hosts and the scalar harness in the ARM32 target lane.
**PRESENT, UNVERIFIED:** these new hosted checks have not yet passed.

## Remaining required work

- The saved parameter is not recovered after `r0` changes. Offsets 40, 44 and 48
  are unavailable; offset 40 still has an allocated source-known copy and needs
  shared lifetime analysis. Later frame release must not manufacture availability.
  This is an implementation gap, not the desired completed behavior.
  Read-only raw-pcode inspection (`build/arm-be8-profile/pcode-diagnostic.log`)
  shows an opaque `CALLOTHER` before the terminal `RETURN` in `bx lr`.
  `RegisterDefinitionFlow.orderedControl` rejects that entire body. Any correction
  must retain only proven pre-instruction state and must not assume the opaque
  operation preserves registers or memory across a call.
- BE8 debugger calls remain guarded by `DW_CC_nocall` pending per-function
  base/VFP argument and return classification. The required compiler-relative
  call/return validation cannot be replaced with a blanket guard.
- Wider/FP/vector transfers, aggregate/piece ordering, additional stack arguments,
  applicable PIE/rebase/shared/sectionless forms and runtime negative/failure/
  cancellation controls remain required before broad acceptance.
- Current-head hosted validation, independent artifact review and protected
  integration remain required. BE32 is outside this selected BE8 profile.
