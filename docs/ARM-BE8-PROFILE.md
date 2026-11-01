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

- BE8 debugger calls remain guarded by `DW_CC_nocall` pending per-function
  base/VFP argument and return classification. The required compiler-relative
  call/return validation cannot be replaced with a blanket guard.
- Wider/FP/vector transfers, aggregate/piece ordering, additional stack arguments,
  applicable PIE/rebase/shared/sectionless forms and runtime negative/failure/
  cancellation controls remain required before broad acceptance.
- Current-head hosted validation, independent artifact review and protected
  integration remain required. BE32 is outside this selected BE8 profile.

## Saved-parameter lifetime correction

**CONFIRMED locally:** initial v1 exports lost the parameter after `r0` changed,
although offset 40 still had its allocated stack copy. Read-only raw-pcode
inspection (`build/arm-be8-profile/pcode-diagnostic.log`) found an opaque
`CALLOTHER` before terminal `RETURN` in `bx lr`; the CFG decoder rejected the
entire function. The shared parameter-flow decoder now optionally admits the
input state of a validated unconditional terminal with no successors. It never
evaluates or propagates that instruction's opaque effects. Default decoding and
callee-effect summaries remain strict, with an explicit opaque-callee rejection
test. There is no processor/userop whitelist in generic analysis.

The v2 package passes the same real exporter/validator/debugger harness for both
BE8 and ordinary little-endian ARM. GDB now requires parameter 7 at offset 40,
whose raw location is `DW_OP_bregx 13, 4` over `[0x100e0, 0x100e4)`. Offsets 44
and 48 must remain unavailable after frame release. All 52 compiler/Forge
instruction observations and twenty source-step observations pass, with twelve
normal exits and unchanged originals/programs/packages. Repeated outputs are
byte-identical. The source-known paired runtime evidence is:

- `build/test-results/arm-be8-reference/scalar.big.ut53dsww/result.json`.
- `build/test-results/arm-be8-reference/scalar.little.elygwnv7/result.json`.

`terminalStackValueSmoke` passes 74 real-language checks across both encodings,
including overwritten/unknown stack stores, a nonterminal opaque instruction,
conditional/overridden returns, caller-effect isolation and cancellation.
`stackValueFlowSmoke`, `stackControlFlowSmoke`, `directLeafCallSmoke` pass
332/832/140 checks; `opaqueRegisterEffectsSmoke` also passes, including its 24
terminal-boundary negatives. `build/arm-be8-profile/terminal-model-v2.log` retains
the command output. Architecture-neutrality, syntax, actionlint and diff checks
pass. CI includes the new model and paired runtime checks; hosted acceptance is
still pending.

v2 package SHA-256:
`2fbad287f19578b1a5cea882e9d97f6992f91b7cce03f0cbb3d1e6901f14e9ff`;
production JAR SHA-256:
`db5da9cda3c31f7fed4ee338ef1df8b8d8924fefe67b352c7ff8a198dd9d6722`.
The earlier checkpoint/failed experiments remain retained; the original full
ABI, storage, layout and control requirements remain open.
