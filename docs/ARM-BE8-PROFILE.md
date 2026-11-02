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
  The independent [call reference](research/ARM-PCS-CALL-REFERENCE.md) now
  reproduces GDB's global PCS choice and a separate QEMU BE8 register-write defect;
  investigate corrected consumers before claiming injected-call acceptance.
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

## Logical floating registers and surviving scalar values

**CONFIRMED locally:** the existing mixed base/VFP dynamic-parameter fixture now
runs in both data orders. Two independent defects were reproduced and corrected.
First, shared scalar flow rejected complete upper logical registers, losing `s1`
after a disjoint write to `s0`. Exact varnode facts now preserve disjoint values
and retire overlapping writes. Second, Ghidra 12.0.3's LEBE descriptions reuse
`ARM*_le.sla`, whose physical register layout is little endian despite the
language's big-endian data override. The old inferred bit positions swapped
`s0` and `s1` in their `d0` parent.

`TargetRegisterMap` now supplies independently checked logical register slices
and physical register byte order for this ELF profile. Extraction checks the
loaded child, parent, widths, address space and byte displacement before using
the ABI bit offset. Scalar flow uses that physical order only for registers;
memory retains the language data order. Generic code has no ARM register names.
The selected ABI keeps even S registers in the low 32 bits and odd S registers
in the high 32 bits of D registers. A register `DW_OP_bit_piece` offset is relative
to its least significant end; see the [DWARF clarification](https://dwarfstd.org/issues/161206.2.html).

The real `vfp_sum(6.25f, 7.5f)` now keeps the first argument in surviving `s14`
and the second in unchanged `s1`, including three PCs through frame release and
the terminal return. Independently decoded raw location bytes require these
exact register pieces and intervals. Other functions prove base arguments in
core registers and VFP arguments in their logical halves. Both compiler and
Forge artifacts pass GNU, LLVM and strict libdwarf validation. Repeated exports
are byte-identical, all 191 protected files are unchanged, and saved program
hashes are unchanged. Current-harness receipts are:

- `build/test-results/arm-dynamic-pcs/run.smxJyJUP/result.json` (LE, GDB 15.1).
- `build/test-results/arm-dynamic-pcs/run.k12AynQK/result.json` (BE8, GDB 17.1).

`upperAliasValueFlowSmoke` passes 139 checks in the actual LE/LEBE languages:
neighbor writes, upper/full-parent overlap, stale stack-slot reuse, released
frames and contradictory child width/parent/displacement. The complete current
Linux extension model command passes in `full-extension-model-v3.log`, with
119 Gradle tasks (115 executed). The three final alias mismatch controls pass
separately in `upper-alias-negatives-v3.log`. No shipped native ABI changed.

### Explicit debugger compatibility

GDB 15.1 misreads the valid big-endian upper `DW_OP_bit_piece 32,32`: its register
piece offset calculation selects the low half when offset plus size equals the
register size. The private unmodified GDB 17.1 build handles that boundary
correctly. This is an additional BE8 floating validation profile, not a silent
replacement of the system debugger or the previously validated scalar baseline.
The source archive, SHA-256, exact configure/build commands and executable hash
are retained in `build/arm-be8-profile/gdb17-arm/`; CI reproduces it with
`support/validation/build-mips-gdb.py --target-profile arm32`. The first local
build used a private copy of the same recipe with the two ARM target options;
the maintained optional profile preserves those exact build arguments.

Causal controls remain retained:

- `pcs-be8-reference`: old Forge mapping fails while compiler DWARF passes.
- `pcs-gdb17-v2-control`: GDB 17.1 reads the old sidecar's first/second values
  as 4.5/3.25 instead of 3.25/4.5, proving the exporter defect independently.
- `pcs-gdb15-control`: GDB 15.1 reads the corrected sidecar's second value as
  3.25 instead of 4.5, proving the independent consumer defect.
- `run.OHRjGxOl`: the prior regression oracle incorrectly expected the retained
  first argument to be unavailable. It now requires the source-known values.

All paths above are under `build/arm-be8-profile` except the last, which is under
`build/test-results/arm-dynamic-pcs`. The v3 package SHA-256 is
`e9edfaf4055cff30b58c165d10344b6b7f4e0e50ac9a750dd686cd55b4fd2a8d`, and its
production JAR is `575f550f32b22f494c3283946221b7132feac6fb705da004030878fcb184c6d2`.

Hosted run `41361515592` failed an older alias negative test: contradictory
little-endian ELF plus BE8 flags now correctly fail preflight before alias
extraction. The corrected test requires that exact rejection, separately checks
the direct alias-plan guard and verifies original bytes/mtime. All focused
preflight/alias regressions pass; that failed hosted run remains failed. Current
hosted acceptance, per-function calls/returns, broader storage/layouts and
failure/cancellation composition are still required before #70 can close.

The v3 scalar regression also passes in both data orders at
`build/test-results/arm-be8-reference/scalar.big.kb4ffzso/result.json` and
`scalar.little.m9jjxyqb/result.json`. The complete four-command scalar/floating
receipt is `build/arm-be8-profile/v3-current-regressions.json`.

## Fixture inventory repair

Hosted run `41364588706` failed in fixture setup before exporter validation:
`arm-pcs-call-reference.c` and `arm-pcs-start.S`, introduced by this branch,
were missing from the explicit source-only inventory. Registering those two
reviewed source files preserves the guard against unreviewed fixture contents.
No production code, fixture bytes or validation assertions change.

Local `bash src/test/integration/fixture-reproducibility.sh <target>` passes for
`x86_64`, `aarch64`, `arm32`, `mips32be` and `mips32le`: each checks 13 artifacts,
byte-identical rebuilds, partial stripping and ELF metadata. A copied fixture
tree containing `unreviewed-probe.c` still exits 1 with the exact inventory
error before any build. Logs and checked receipts are retained under
`build/arm-be8-profile/inventory-correction/`, including `acceptance.json`.
`bash -n` and `git diff --check` also pass. Hosted acceptance requires a new
run at the corrected head; the failed run is not relabeled as passing.

## Shared-parameter assertion repair

Hosted run `41372370267` at `a5962ea` passes ARM export through the shared
fixture, then fails an inherited assertion that both parameters have only
incoming-register lifetimes. The same assertion fails in descendant PR133.
The unchanged exporter actually tracks `left` into a register copy and `right`
through a stack spill. This is an oracle correction, not relaxed validation or
a new production location claim.

Acceptance requires the exact new shared diagnostics, all existing nonshared
expectations, structural validation, and runtime evidence for the longer
locations. The exact hosted sidecar passes the existing shared-library GDB
workflow and an additional instruction-by-instruction check:

- At every one of the 27 instructions, `left` is 19; its physical carrier is
  `r0` through function offset `0x5c` and `r1` from `0x60` through `0x68`.
- `right` is 23 through offset `0x40`, including its stack and temporary register
  locations. It is unavailable from `0x44` onward after the unknown-address
  global store invalidates the saved memory proof.
- The function returns normally, and the driver exits zero.

The raw location intervals independently agree with those boundaries. This is
specific to the retained fixture instruction sequence; it is not a general
assertion about arbitrary ARM functions. The QEMU synthetic-vDSO warning is the
same existing compiler-corroborated warning handled by the shared runtime lane.
The first replay failed because the downloaded driver lacked executable mode;
only the private copied fixture's mode was corrected, and both logs are retained.

Fresh local shared and non-PIE exports using the exact hosted package also pass
GNU views, LLVM verification, strict libdwarf checking with zero reported errors,
original-input preservation, and their maintained GDB workflows. Commands:

```bash
FIXTURE_ROLE=shared bash src/test/integration/headless-symbol-export.sh "$ghidra" "$consumer" "$producer" arm32
bash src/test/integration/shared-object-gdb.sh arm32
FIXTURE_ROLE=exec bash src/test/integration/headless-symbol-export.sh "$ghidra" "$consumer" "$producer" arm32
FIXTURE_ROLE=exec bash src/test/integration/qemu-gdb-symbols.sh arm32
```

The installed JAR SHA-256 is
`575f550f32b22f494c3283946221b7132feac6fb705da004030878fcb184c6d2`.
Retained commands, debugger scripts, 27 observations, logs and hashed acceptance
receipt are under `build/arm-be8-profile/shared-lifetime-correction/`.
The patch changes only the two shared diagnostic expectations; nonshared
incoming-register assertions and all structural/runtime checks remain active.
New exact-head hosted validation remains required; the failed run stays failed.
