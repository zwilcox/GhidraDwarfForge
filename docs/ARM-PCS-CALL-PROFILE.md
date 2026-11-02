# ARM PCS classification and scalar call checkpoint

**CONFIRMED locally; full ABI goal and integration remain incomplete.** This
component advances #70 within the unchanged #68–#71 completion plan. It does
not complete those issues or authorize a release. Ghidra 12.0.3, Java 21 and
libdwarf 2.3.2 remain the production baseline.

## Contract and implementation

The candidate compares the original ELF's EABI5 floating PCS flags and bounded
AEABI file attributes with each recorded Ghidra convention. It distinguishes
the executable's declared PCS from GDB's attribute-selected PCS: absent
attributes select base calls in GDB even if the ELF hard-float flag is set.
Conflicting flags/attributes, ambiguous file scopes, unsupported scoped or
mandatory attributes, toolchain-specific PCS, invalid extents, duplicate tags
and overflow are diagnosed rather than guessed. Input bytes remain unchanged.

`Arm32CallAbi` and `Arm32CallPolicy` form the isolated target boundary. The
selected `__stdcall`/default model uses VFP; `__stdcall_softfp` uses the base
PCS. Ghidra's compiler/language policy still applies independently. Definitions,
addressless declarations and function-pointer types receive the same decision.
The type model separates an unmapped convention from independent restrictions
so recognizing a convention cannot erase custom-storage/compiler guards.
Original convention names and analyst signatures are preserved.

The locally exercised call envelope includes float/double, 64-bit integer pairs,
and ten double arguments, exhausting both core and VFP argument registers.
Integer aggregate returns retain the existing two/three-word/doubleword layout
classification and verified hidden-return-pointer role. Aggregate parameters,
HFA/vector transfers and additional artificial roles still need classification
and runtime evidence; this is not their acceptance record.

Within one executable GDB still selects floating calls globally. A nonvariadic
floating signature whose selected PCS differs receives `DW_CC_nocall`, including
its callback type. Natural calls and parameter reading remain available. Tests
require rejection before registers, counters or captured arguments change.
This guard is not a claim that arbitrary mixed-PCS injected calls or their
automatic typed returns have been solved.

## Corrected emulator reference

The ten-double compiler control exposed a second QEMU defect after the earlier
D-register byte-order correction. Natural calls returned 55; an injected VFP
call returned 108 and captured `[1,55,4,3,6,5,7,8,9,10]`. The last two stack
arguments were correct. Remote tracing showed GDB omitted writes to registers
whose cached values appeared unchanged after a preceding dummy-call restore.

QEMU 8.2.2 passes the low/high D-register halves to `gdb_get_reg128` in the
opposite order from that helper's high/low parameters. Restoring overlapping Q
aliases therefore corrupts D registers. BE8 Q writes additionally decode bytes
as little-endian. The private validation patch swaps the getter arguments and
decodes Q writes in target order, with the high half first for big-endian data.
It does not change Forge DWARF or system-installed tools.

The maintained builder retains its original D-only option and adds
`--correct-q-register-aliases`, requiring the D correction. Source remains
QEMU 8.2.2, archive SHA-256
`847346c1b82c1a54b2c38f6edbd85549edeb17430b7d4d3da12620e2962bc4f3`.
The additional patch SHA-256 is
`689c2387dbfb495714b1815c7d648b5337c8b3c2c4e3c565cc53cf3b211665db`.
Build commands, both patch hashes and executable hashes are recorded in each
builder receipt.

`arm-q-alias-reference.py` checks all 16 Q/D alias pairs in both byte orders
against D-only and D/Q-corrected builds. It requires the old wrong read/write
results and corrected round trips, verifies 32 raw Q-write packets per process,
and preserves compiler/debugger/emulator bytes. The old LE read-modify-write
also fails because its second lane write reuses the wrongly read first lane.
This reference is independent of exported DWARF and does not claim general
vector-argument support.

## Consumer versions

The positive LE profile uses system GDB 15.1. BE8 uses the already pinned,
unmodified GDB 17.1 ARM build. The same source-known LE upper-float location
fails in GDB 17.1: `DW_OP_regx 256; DW_OP_bit_piece 32 32` displays the low
float (1.25) instead of the high float (2.5). The identical sidecar passes with
15.1. GDB 17.1 `gdb/dwarf2/expr.c` applies the bit offset only when
`offset + size < register_bits`; an upper piece ending at the register boundary
incorrectly skips that adjustment. BE8 happens to need a zero physical byte
offset for this upper piece and passes. No compensating exporter expression is
introduced. A unified corrected debugger profile remains follow-up work.

## Local evidence

All paths below are in the `arm-pcs-profile` worktree. Current production Java
is in `build/arm-pcs-profile/ghidra-v2`; its JAR SHA-256 is
`23e069fc4029c81c40422514421e433da3cef29d5abfa58f5e717fd6c3b8f5d8`.
The assembled ZIP SHA-256 is
`6344c535740ad6d006c1bbcb0bca5cccf5169ec087d8366e1d450f0cb36920b0`.

| Evidence | Outcome |
| --- | --- |
| `build/arm-pcs-profile/full-model-v2.log` and adjacent command JSON | All 120 tasks pass; new policy suite has 2,986 checks |
| `build/test-results/arm-q-alias-reference/run.0ygjqzrk/result.json` | Four differential compiler-only alias processes pass |
| `build/test-results/arm-pcs-profile/little.hard.empobd47/result.json` | LE VFP executable, GDB 15.1: pass |
| `build/test-results/arm-pcs-profile/little.softfp.x26b3z0l/result.json` | LE base executable, GDB 15.1: pass |
| `build/test-results/arm-pcs-profile/big.hard.9qlckes3/result.json` | BE8 VFP executable, GDB 17.1: pass |
| `build/test-results/arm-pcs-profile/big.softfp.m3n59q8f/result.json` | BE8 base executable, GDB 17.1: pass |
| `build/test-results/aggregate-return-calls/arm32.exec.fp32.lhbeg8tv/result.json` | Existing ARM integer aggregate return/callback regression: pass |
| `build/test-results/calling-convention/pie-rebased.zkpi5_ja/result.json` | Rebased alternate x86-64 convention regression: pass |
| `build/test-results/function-pointer-conventions/gcc.pie-rebased.i9k6pm5l/result.json` | Rebased function-pointer convention regression: pass |
| `build/test-results/function-pointer-conventions/windows.pie-rebased.vne08q0c/result.json` | Independent Windows compiler-spec restrictions: pass |

The four PCS cases contain 64 natural-call argument observations, 40 correct
automatic typed returns, 80 correct injected name/pointer calls and 24 unchanged
state rejections. Each case passes GNU/LLVM/strict-libdwarf checks for compiler
and Forge artifacts. Saved/reopened program observations match; repeated `.dbg`
and `.dbg.c` bytes match. Original ELF, package, tools and program database bytes
are preserved; only documented Ghidra filesystem backup files may rotate.

The initial aggregate run correctly caught an overly broad candidate rejection
of `triple64`; `aggregate-regression-v1.log` retains it. The corrected return
classification passes the unchanged behavior oracle. Earlier harness failures
(Java launch-banner accounting and whitespace before long readelf attributes)
are retained with their logs. They are not exporter passes.

## Remaining acceptance

**PLANNED / PRESENT, UNVERIFIED:** broaden real ELF/profile negative controls,
addressless declarations, custom-storage/cancellation compositions, executable
layouts and aggregate/mixed/HFA cases. Run the existing broader ARM runtime
matrix against this candidate, including implicit default-convention recovery.
Confirm the newly wired hosted tests and complete exact-package host/target
review before protected integration. All original rows in
`TARGET-ABI-COMPLETION-PLAN.md` remain binding; no issue is closed here.
