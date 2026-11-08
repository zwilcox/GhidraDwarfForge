# i386 ELF and compiler call-profile selection

**CONFIRMED locally; exact-head hosted acceptance and protected integration
pending.** This component addresses original #71's explicit target-ABI
classification requirement. The full #68–#71 scope remains open.

The previous exporter admitted debugger calls on any i386 ELF metadata whenever
the selected compiler specification was GCC. An owned fixture with `e_flags=1`
reproduces the missing guard: GDB executes `integer_call(19)`, returns 26 and
increments its counter from one to two. The Intel386 psABI specifies zero
processor flags ([ELF header, Machine Information](https://refspecs.linuxbase.org/elf/abi386-4.pdf)).
This experiment changes only the disposable fixture before import and hash
recording; it is not a claim that GCC emits the altered metadata.

## Contract

The selected ELF32/EM_386 little-endian System V call profile requires ET_EXEC
or ET_DYN, zero processor flags, OSABI 0 or 3, and ABI version zero. Generic
OSABI zero is not proof of Linux. This is a compatibility prerequisite; existing
signature/custom-storage restrictions still apply. The same ELF guard applies
to both the real extension and standalone producer entry points.

An unvalidated combination preserves recovered names, types, locations, source
and ownership while applying the existing `DW_CC_nocall` policy to functions,
external declarations and callback types. Prior reasons are preserved and
repeated application is idempotent. No native producer declarations changed.
The AArch64 guard and its diagnostic wording remain unchanged.

The existing compiler-specification guard separately distinguishes GCC from
Windows/clang-windows models. The new end-to-end controls select those actual
Ghidra specifications on an owned C ELF, preserve ordinary observed values,
and require refusal of named and typed function-pointer calls before any
register, stack or fixture-counter change. These are negative selection tests;
a Windows Ghidra host and a Windows-target compiler ABI remain distinct.

## Evidence

The 3,317 i386 model assertions cover both accepted ELF types plus null,
relocatable, core and an unknown type; four OSABI values; two ABI versions;
zero/nonzero/high-bit flags; all callable DIE forms; analyst data; prior reasons;
input preservation; and cancellation before/during traversal. Existing AArch64
selection (1,109 assertions) and all 26 compiler specifications (606 assertions)
pass. Linux and Windows CI task lists include the new model suite.

Nine actual i386 cases pass 18 deterministic production exports, GNU/LLVM/pinned
strict validation, ordinary integer/double arguments, source lookup, positive
calls or guarded rejection, original/package/program preservation and the exact
installed JAR-origin check. Four call attempts through names and callbacks run
for both compiler and Forge in every case: 36 positive compiler calls, sixteen
positive Forge calls and twenty guarded Forge rejections. Rejections preserve
all debugger registers, 256 stack bytes and fixture counters.

| Selection | Case under `build/test-results/abi-profile` | Calls |
| --- | --- | --- |
| default GCC non-PIE | `i386.default.gcc.0.0.0x0.exec.ye8vmen0` | admitted |
| default GCC PIE | `i386.default.gcc.0.0.0x0.pie.735qnb32` | admitted |
| default GCC rebased PIE | `i386.default.gcc.0.0.0x0.pie-rebased.qym3gwrz` | admitted |
| Windows compiler | `i386.default.windows.0.0.0x0.exec.yur0ufpd` | restricted |
| clang-windows compiler | `i386.default.clangwindows.0.0.0x0.exec.3dwqnzxw` | restricted |
| GNU/Linux OSABI | `i386.default.gcc.3.0.0x0.exec.18vxk55b` | admitted |
| FreeBSD-labelled metadata | `i386.default.gcc.9.0.0x0.exec.qsplv4qs` | restricted |
| ABI version one | `i386.default.gcc.0.1.0x0.exec.ux_ee2yu` | restricted |
| reserved flags | `i386.default.gcc.0.0.0x1.exec.yoq97nuw` | restricted |

Three AArch64 regression cases also pass: baseline `exec.nkw0i4b2`, flags
`exec.07645bqb`, and FreeBSD-labelled `exec.nnk42vqs` (full names in the receipt).
The existing rebased eleven-function i386 ABI matrix passes with the same
package at `build/test-results/i386-abi-matrix/pie-rebased.8qhtye_l`, including
repeated native decompiler failures, actual publication cancellation and four
structurally valid wrong-location rejections.

For both architectures, the FreeBSD-labelled control uses an explicit,
compiler-corroborated GDB fallback warning. Exactly two copies of the complete
architecture-specific missing-handler message are accounted for on each side;
other warnings remain errors. Unit controls reject wrong architecture, counts,
OSABI and unmatched reference diagnostics. This does not claim FreeBSD runtime
support. The first i386 attempt is retained because its ordinary compiler checks
passed but the warning policy had not yet been extended; the final reruns pass.

Installed JAR SHA-256:
`30d90f1c3d754ffba93c750a00703e1792df9cdd15f04964d3528153b8b4a929`.
Assembled package ZIP SHA-256:
`0697fbf08d315dce2e99dc53f028a74b797bdb46e7113d06e92a697ccbaac139`.
All 106 production-source hashes match the package. The `i386-abi-selection`
worktree receipt is `build/i386-abi-selection/validation-v3.json`, SHA-256
`19f01679dbb74d2e3a7f3c9ee98fce43f1c51400dbe62da0042e416ac1fc91de`.
BuildExtension, model suites, Python compilation, shell syntax, workflow lint
and diff checks pass. CI requires the nine i386 runtime selections; existing
AArch64 selections remain required too.

## Compatibility-mode research and remaining scope

**CONFIRMED separate limitation, not a passed profile:**
`x86:LE:64:compat32` selects the same `x86gcc.cspec` and uses four-byte pointers,
but the current exporter omits this fixture's entry stack parameters. An initial
assumption that compiler selection should reject this mode was not evidence of
an ABI mismatch; the subsequent positive experiment instead failed on actual
GDB parameter availability. Its retained case is
`i386.compat32.gcc.0.0.0x0.exec.we99fq3x`. No compatibility-mode call/storage
support is claimed by this component, and its existing call admission is not
changed. The research option remains available to reproduce the strict failure;
it is not included as a passing CI case.

The compatibility-mode storage finding, remaining original target requirements,
hosted/Windows gates, raw artifact review and normal protected integration still
need reconciliation. Neither this component nor the selected runtime matrix
closes the broader ABI goal.
