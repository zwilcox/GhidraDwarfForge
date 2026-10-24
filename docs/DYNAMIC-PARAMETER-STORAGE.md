# Computed parameter storage

## Pinned API behavior

**CONFIRMED in Ghidra 12.0.3:** `Parameter.hasAssignedStorage()` and
`Parameter.getVariableStorage()` answer different questions for parameters
whose calling convention computes their storage. `VariableDB` checks the
persisted symbol row for the former and returns its effective storage cache
for the latter. `FunctionDB` deliberately persists `UNASSIGNED_STORAGE` for
noncustom parameters, then computes their storage from the function prototype;
`ParameterDB.setDynamicStorage()` stores that result in the cache.

An actual saved/reopened program can therefore have `hasAssignedStorage() ==
false` while its effective parameter storage is valid, assigned and mapped to
a register. The old exporter rejected that parameter as `UNASSIGNED` before
examining the effective storage. This loses current analyst knowledge even
though the parameter's name and type still appear in DWARF.

The parameter-only correction uses the already retrieved effective storage to
decide whether it is unassigned. It retains all existing checks for invalid,
bad, forced-indirect, composite, stack and mapped register storage; register
writes, calls, opaque instruction effects, prefix eligibility and cancellation
also retain their existing policies. Local-variable assignment checks are
unchanged. A computed location is not automatically a proven lifetime.

## Focused and cross-target controls

**CONFIRMED locally; hosted acceptance pending:** `dynamicParameterStorageSmoke`
creates actual programs for x86-64, AArch64, ARM32 and both MIPS32 byte orders.
It observes the persisted/effective storage disagreement before and after
immutable database reopening, checks the public type/location extractor, and
retains null/unassigned/bad/indirect and cancellation controls. ARM additionally
exercises explicitly named base and VFP parameter conventions. The suite passes
154 checks on actual Java 21 with the packaged JAR first on the classpath.
The same compiled control against the previous JAR fails on the first computed
x86-64 parameter with the old `UNASSIGNED` reason; that negative run does not
establish later checks.

The generic integration fixture uses ordinary C integer parameters, a void
store function and an integer-returning function. Preparation applies
`USER_DEFINED` signatures with `DYNAMIC_STORAGE_ALL_PARAMS` and the current
compiler specification's default convention. It neither assigns registers
manually nor changes code. The harness records the resulting effective
registers, saved/reopened observations, compiler entry register bits and
compiler parameter values after the prologue. Forge values are checked at entry
and each observed debugger stop: an omitted interval must be unavailable, and
a reported location must produce the expected entry value. The store function
must have positive parameter values at entry. Full target execution, structural
validation and unchanged inputs are required, not just cross compilation.
All five local target runs pass. Integration is wired; exact evidence and
pending hosted acceptance are tracked in `docs/VALIDATION.md`.

## ARM per-function convention control

**CONFIRMED locally:** one ordinary ARM-state, ELF32 little-endian hard-float
executable contains explicit GCC `pcs("aapcs")` and `pcs("aapcs-vfp")`
functions. They share ELF flags `0x05000400` and the VFP argument attribute,
but their incoming floats occupy different registers. These whole-file
observations cannot determine every function's calling convention.

The test applies the justified analyst conventions `__stdcall_softfp` and
`__stdcall` to corresponding Ghidra functions and requests dynamic parameter
storage. No custom register storage is used. Separate saved-project export
observations show valid four-byte `r0`/`r1` versus `s0`/`s1` effective storage,
with false persisted-assignment flags in both cases. GDB shows float arguments
1.25/2.5 and 3.25/4.5 at the exact recovered entries. Emitted expressions retain
the existing covering-register/bit-piece handling for the VFP slice.

A natural float-returning addition function keeps its actual return and the
ARM `bx lr`/`setISAMode` behavior. Both parameters remain unavailable with the
existing `REGISTER_MODIFIED` reason; no lifetime rule is relaxed to make this
case positive. Its executable result and normal program exit are checked.
This is not a GDB-injected-call or return-value ABI support claim, and it does
not establish a general ARM/MIPS ABI classifier.

Compiler debug information uses stack homes initialized by the prologue;
entry checks therefore inspect actual argument registers, while compiler named
parameters are checked after that prologue. Forge's proven register parameters
are checked at the actual function entry. Both sides use the same compiled
code. The synthetic source remains explicitly decompiled output.

## Execution and evidence

Run with Ghidra 12.0.3 configured:

```sh
./gradlew dynamicParameterStorageSmoke
src/test/integration/dynamic-parameter-storage-export.sh "$GHIDRA_INSTALL_DIR" x86_64
src/test/integration/arm-dynamic-pcs-export.sh "$GHIDRA_INSTALL_DIR"
```

The generic harness also accepts `aarch64`, `arm32`, `mips32be`, and `mips32le`.
Cross-target runs require the fixture toolchain, sysroot and QEMU user emulator
used by the existing target lanes. Both harnesses use packaged production
natives, GNU/LLVM/strict libdwarf validation, compiler/Forge GDB sessions and
same-saved-program deterministic reruns. CI executes the focused control on
both hosts, the integer harness in all five target lanes and the convention
control in the ARM lane.

Local evidence is retained under `build/dynamic-parameter-review/` and
`build/test-results/`. Initial ARM harness failures are preserved separately:
GDB 15.1 lacks the initially used `Value.is_unavailable` property; curated
nonexported Forge definitions require static-symbol lookup; GNU readelf writes
single-digit hex byte tokens. Correcting these harness assumptions does not
alter production behavior or make failed runs passing evidence.

The inherited Thumb test now requires its recovered right parameter's correct
R1 values and absence of an omission, while retaining the modified left
parameter's explicit unavailability. Its former `UNASSIGNED` expectation
represented this defect; the failed stale-oracle run and a fresh passing replay
are retained separately.
