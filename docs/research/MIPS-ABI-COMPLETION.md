# MIPS ABI completion investigation

**CONFIRMED active scope:** P2.3a/#69 remains open, alongside #68/#70/#71.
The full requirement set is retained in `../TARGET-ABI-COMPLETION-PLAN.md`.
This investigation establishes independent references before changing target
selection or location emission. It does not replace the O32 aggregate, stack,
wide-value, executable-form and sectionless requirements with a narrower goal.

## N32 and N64 compiler references

A private toolchain extracted beneath `build/mips-abi-research/toolchain/`
provides GCC 12.4, binutils 2.42 and glibc 2.39 for big-endian N32/N64. Eighteen
Ubuntu packages are recorded with exact versions and SHA-256 hashes in
`build/mips-abi-research/packages.json`. No system package was installed.
The relocated binutils need the extracted `usr/lib/x86_64-linux-gnu` on their
library path; the first attempt without it is retained as a failed setup.

`compiler-reference/run.py` compiles the existing `fp_register_aliases.c` with
`-mabi=n32` and `-mabi=64`, `-march=mips64r2`, `-O1 -g -gdwarf-5`, non-PIE and
the matching private sysroot. Both executables run to exit zero in the installed
QEMU 8.2.2 N32/N64 emulators. The untouched compiler-DWARF GDB oracle verifies
exact float/double values at entry and before/after their stores, global values,
source stepping and normal completion. Both compiler oracles pass; there are
no stderr diagnostics. These are two non-PIE compiler references, not a complete
exporter or ABI matrix.

| Property | N32 reference | N64 reference |
| --- | --- | --- |
| ELF class | ELF32 | ELF64 |
| ELF flags | `0x80000025` | `0x80000007` |
| FPR width in ABI record | 64 bits | 64 bits |
| First two double arguments observed by GDB | f12/f13 | f12/f13 |
| Independent values | 21.5, -9.25 | 21.5, -9.25 |

Ghidra 12.0.3 naturally imports N32 as `MIPS:BE:64:64-32addr` with compiler
`n32`, a four-byte pointer and 64-bit GPR/FPR storage. Dynamic float parameters
use four-byte slices of f12/f13; dynamic doubles use their full eight bytes.
The existing exporter writes an N32 sidecar but restricts unvalidated debugger
calls. A focused follow-up loads that sidecar explicitly and observes all twelve
named float/double values at the six entry/before-store/after-store stops;
GNU/LLVM/pinned strict validation passes and execution exits zero. This is a
bounded non-PIE observation, not the full N32 matrix.

Ghidra naturally imports N64 as `MIPS:BE:64:default`, compiler `default`, with
an eight-byte pointer and the same f12/f13 float/double storage widths. The
current Forge exporter explicitly rejects it with `MIPS32 requires ELF32,
found ELF64`, before producing a final sidecar. N64 target selection remains a
separate implementation task.

GNU and LLVM accept both compiler artifacts. The pinned strict reader initially
rejected N64's valid, four-zero-byte `.eh_frame`, treating it as an incomplete
legacy IRIX eight-byte length. N32's identical section passed. The candidate
validation-only correction makes the unchanged N64 executable pass with zero
errors. See `../../support/validation/README.md`; no release native, native ABI
mapping or producer call changes are involved.

## FPXX runtime mode is not an ELF-only property

A separate owned copy of the existing scalar fixture explicitly calls Linux
`prctl(PR_SET_FP_MODE, mode)` before the tested functions, verifies the mode with
`PR_GET_FP_MODE`, and checks the actual FR status bit at the double entry in
GDB. The executable retains its FPXX ABI record. The debugger does not repair
registers, change ELF metadata or replace compiler locations.

All four plain executions pass. With strict untouched compiler DWARF:

| Byte order | FR=0 | FR=1 |
| --- | --- | --- |
| Little endian | Correct typed doubles at all tested stops | Incorrect zero at entry |
| Big endian | Incorrect tiny value at entry | Incorrect zero at entry |

The big-endian FR=0 raw register display reconstructs the correct 21.5 from
f12/f13, while the named compiler parameter is incorrect. GCC's FPXX expression
uses `DW_OP_regx 44; DW_OP_piece 8`. That observation distinguishes a named-DWARF
consumer problem from absent physical values; it does not yet establish the
root cause or authorize a compensating Forge expression. The previous FP64A
failures also remain unresolved. This partial FR=0 reference cannot be promoted
to broad FPXX support.

The inspected upstream QEMU v10.1.0 MIPS stub still uses `gdb_get_regl` for
FR=1 FPR values, and its O32 build uses `TARGET_LONG_BITS=32`:
[stub](https://github.com/qemu/qemu/blob/v10.1.0/target/mips/gdbstub.c),
[target configuration](https://github.com/qemu/qemu/blob/v10.1.0/configs/targets/mips-linux-user.mak).
Its [runtime-mode handling](https://github.com/qemu/qemu/blob/v10.1.0/linux-user/mips/target_prctl.h)
explicitly changes FR/FRE state and converts register contents. This is upstream
source evidence; it does not prove binary equivalence to Ubuntu's installed
QEMU. A newer-version upgrade alone is not yet a demonstrated remedy.

## Evidence and next work

All research files are under `build/mips-abi-research/` in the
`mips-abi-completion` worktree: compiler commands, ELF/register/value logs,
`fpxx-runtime-mode/`, exact upstream source snapshots and the separate old/new
strict-consumer outputs. Failed setup/validator/reference attempts remain
retained. The final local checker passes the focused frame suite (17 current positive
cases, 37 malformed-input rejections, two previous-tool failure reproductions
and one previous-tool IRIX positive), configuration relocation, extended ELF
program counts, line sequences, 32 calling-convention cases, diagnostic capacity
through 65,536 messages and 97 evidence-integrity controls. Native executable
SHA-256 is `a211d36ef040e717fa5550cb2a4af13ed54b0c58ca50c2c992a276786cb737f8`;
its whole-bundle checksum manifest also verifies. Results are retained in
`final-*.log` and `evidence-tests-final.log`. The first evidence-control attempt
omitted required command arguments and is retained separately; only the corrected
invocation passes.

Three existing Forge artifacts also pass the new strict checker with unchanged
input bytes: MIPS FP32 has zero errors; AArch64 and x86-64 retain their exact 20
and 14 compiler-corroborated inherited frame diagnostics. Those diagnostics were
not suppressed. Receipt: `forge-validator-regressions.json`. Hosted exact-head
acceptance and protected integration remain pending.

Next: expand the emitted N32 runtime matrix, establish the N64 producer/target
boundary, extend source-built ABI fixtures in both byte orders, and investigate
an independent trustworthy FP64A/FPXX transport. Then reconcile selected
ELF/ISA/FPU attributes with actual Ghidra language/compiler storage. PIE/shared,
rebase, failure/cancellation and the existing big-endian sectionless lane remain
required; none is implied by these two compiler references.
