# AArch64 ABI selection and debugger calls

**CONFIRMED local candidate (2026-11-01); hosted acceptance pending.** This
component of P2.3/#68 classifies the selected language/compiler pair and ELF
call-profile metadata. It does not finish P2.3 or the related MIPS, ARM32 and
i386 issues. The complete remaining scope is in `TARGET-ABI-COMPLETION-PLAN.md`.

## Contract

The bounded Linux LP64 little-endian call profile requires ELF64/EM_AARCH64,
`AARCH64:LE:64:v8A` with compiler `default`, ET_EXEC or ET_DYN, zero `e_flags`,
OS ABI 0 or 3 and ABI version zero. This is a necessary compatibility check,
not certification of every signature, instruction extension or operating
system. In particular, OS ABI zero means generic ELF; it does not prove Linux.
Existing per-function custom-storage and calling-convention guards still apply.

`AppleSilicon/default` has the same processor, byte order, data-pointer width
and compiler ID, but different variadic allocation. The actual pinned Ghidra
model observations are recorded in `research/ABI-PROFILE-SELECTION.md`. Checking
only the compiler ID silently admitted this different ABI.

An unvalidated language/compiler pair or ELF metadata combination retains
recovered names, types, locations, source mappings and ownership. Its function
DIEs, curated external declarations and callback types receive the existing
`DW_CC_nocall` representation. Diagnostics identify the mismatch. Unknown
compiler IDs are restricted too. Unsupported AArch64 ELF32/ILP32 and big-endian
producer profiles continue to fail before native production rather than being
silently widened or byte-swapped.

The target-neutral `DebuggerCallRestrictions` helper preserves prior reasons
and callable type identity. Language/compiler checks run through the Ghidra
adapter; ELF checks also run through the standalone producer entry point.
Cancellation during traversal becomes Ghidra's checked cancellation exception
at the adapter boundary. No native ABI declarations or producer calls changed.

## Evidence and reproduction

The actual Java 21 model suites pass 1,109 ELF-metadata assertions and 606
language/compiler assertions across 26 installed specifications. They cover
functions, declarations, callback types, prior restrictions, analyst data and
ownership, deterministic repetition, input preservation and cancellation before
and during traversal. Existing MIPS floating and aggregate policy suites pass
4,752 and 7,272 assertions respectively. The AArch64 ILP32 rejection is explicit
in `DwarfTargetSmoke`. Both host test lists include the new metadata suite.

`src/test/integration/abi-profile-export.py` uses the existing portable
`mips-floating-call.c` fixture (its historical name does not imply MIPS-only
code), compiled with the AArch64 GNU toolchain. It removes compiler debug
information, curates real Ghidra scalar signatures and typed global callbacks,
saves the program, and exports twice using the assembled production extension.
The synthetic metadata controls alter only owned fixture headers before import
and hash recording. Both compiler reference and stripped input receive the same
explicit metadata; the original compiler header and digest are retained.
These controls do not claim that GCC emits those metadata combinations itself.
The Go compiler model uses an eight-byte native integer. The fixture therefore
curates fixed four-byte signed/unsigned integer objects, corroborated by the
compiler and Forge GDB type sizes, instead of silently changing its C object
layout. Its first run exposed overlapping globals when native Go-sized `int`
was used. Forced Go import of a C program also emits two expected missing-Go-
runtime-analyzer errors; the harness accounts for exactly those messages and
rejects any other import error. These are negative compiler-selection controls,
not native Go or Swift runtime support claims.

Each successful case requires GNU/LLVM/pinned strict libdwarf validation,
explicit calling-convention DIE checks, byte-identical repeated sidecar/source
outputs, unchanged fixture/module/program-database hashes and the exact installed
JAR origin. Only documented Ghidra index backup rotation is permitted. GDB loads
the original and explicit sidecar, observes ordinary integer/double arguments
and source lookup, and attempts direct and function-pointer calls. Positive
cases require correct typed returns and recorded arguments/counters. Negative
cases require GDB rejection before execution, identical registers and 256 stack
bytes, unchanged counters and normal completion of the original program.

```bash
python3 src/test/integration/abi-profile-export.py "$GHIDRA_INSTALL_DIR"
python3 src/test/integration/abi-profile-export.py "$GHIDRA_INSTALL_DIR" --language AppleSilicon
python3 src/test/integration/abi-profile-export.py "$GHIDRA_INSTALL_DIR" --flags 1
```

Candidate CI includes ordinary exec/PIE/rebased-PIE, GNU OS-ABI PIE, all six
installed AArch64 language/compiler combinations, reserved flags, nonzero ABI
version and a deliberately FreeBSD-marked negative fixture. Hosted results are
still required; the local matrix receipt is recorded separately below.

## Reference and diagnostic bounds

The runtime is explicitly QEMU Cortex-A53, covering the tested LP64 scalar/NEON
profile. With local QEMU 8.2.2's default CPU and GDB 15.1, a compiler-DWARF call
`fp_call(19.5, -3.25)` executes but records two zero arguments and returns zero.
The integer control works, and ordinary floating calls have correct values.
The same strict test passes with Cortex-A53 for compiler and Forge symbols.
This identifies a CPU/debugger-transport-dependent reference failure; it does
not establish its root cause or claim SVE call support. The failed reference is
retained under `build/abi-classification/sve-reference-failure/`. Set
`ABI_PROFILE_QEMU_CPU=max` to exercise that configuration; the positive-call
assertions remain strict and no register state is repaired by the harness.

The FreeBSD-marked fixture is still a Linux source-built program. It tests
classification of inconsistent metadata, not a FreeBSD runtime. GDB 15 emits
an exact missing-FreeBSD-handler diagnostic for both `file` and `symbol-file`.
`abi-profile-diagnostics.py` accounts for it only when all three ELF headers
identify OS ABI 9 and the compiler and Forge logs contain the same two complete
messages. All other warnings still pass through the unchanged shared strict
GDB diagnostic gate. Mutation tests reject unmatched, repeated, changed and
wrong-profile exceptions. A GDB build with no such warnings needs no exception.
The existing compiler-corroborated QEMU synthetic-vDSO diagnostic policy remains
unchanged.

The first metadata run correctly failed strict frame-identity validation when
only the stripped input's OS ABI had been altered. The corrected fixture setup
binds the compiler reference and input metadata before stripping; validator
rules were not relaxed. Failed runs remain under the ignored results directory.

## Local matrix receipt

All twelve configurations pass with production JAR SHA-256
`12b76f077e7570f0ee6b7b17396a93589e1c4cb9333df5b05141f033739cd6a6`
and assembled package SHA-256
`3ffadb33a33ecf9f496e615b226998a4531095c1af8890c007946f1ac76b2300`.
The receipt is `build/abi-classification/matrix-receipt.json`, SHA-256
`147267de9f91a05c963440efb5a097c8d8b410709e26541f29c504474442eb59`.
It records 24 exports, 24 GDB processes, 48 ordinary entry observations and
96 injected-call attempts. All 32 expected Forge rejections preserve machine
state; the other 64 calls return the expected values. All required validators,
source lookup, preservation and deterministic-rerun assertions pass.

A separate raw review checks all twelve ELF identities, removed program-header
tables, every restricted callable DIE carrying a calling-convention attribute,
and all blocked-call state receipts (`build/abi-classification/raw-review.json`).
These local results do not substitute for the candidate's required hosted gate
or complete the remaining aggregate/vector/profile acceptance work.

Six existing packaged regressions also pass with that same JAR: x86-64
GCC/Windows compiler selections with custom parameter/return storage, and
MIPS O32 FP32/FPXX double calls in both byte orders. All six use rebased PIE
and retain their existing structural/runtime/preservation assertions. Commands
and result paths are recorded under `build/abi-classification/regressions.log`.

## Hosted acceptance and protected integration

**CONFIRMED:** PR #122 head `086eaee98e821f7fa9532d7bb85b1f347963cc39`
passes all twelve jobs in run `41346340841` and merged normally as
`a848391ac7463329b11ac20ed0e8ca8f3b47fad9`. Review compared all 86 packaged Java
sources with that commit, verified the release ZIP manifest and Java 21 class
versions, and checked 96 injected calls across twelve profile cases: 64 correct
returns and 32 refusals before register/stack changes. Ordinary typed/source
observations remain available on the rejected call profiles.

The independent review also checked 30 captured primary sidecars across five
target lanes, both hosts' GUI selection/cancellation images and reports, native
Windows results, and local GNU/LLVM/strict validation of three Windows-produced
sidecars. Independent dwarfdump and Linux ELF execution were not run on Windows.
The strict AArch64 review retains 168 compiler-corroborated inherited frame
diagnostics; each Windows sidecar retains three, with zero unexplained errors.
The review compares original frame bytes and full diagnostic lines. It does
not report these artifacts as having zero reported diagnostics.

The captured x86 exec artifact comes from a later file-digests export. Its hash
matches that export and the Windows Linux reference; a separate native GDB replay
of the captured bytes verifies values, signature, source listing, next/step and
normal exit. Local receipts are under the `abi-classification` worktree's
`build/abi-classification/hosted-41346340841`, including
`independent-aarch64-review.json`, `independent-host-target-review.json`,
`independent-windows-validators/result.json` and `independent-runtime/result.json`.
Review setup errors (nested source paths, hidden diagnostic-upload files and
missing executable permission on downloaded inputs) are retained and resolved
without a production change. Full #68–#71 requirements remain open.
