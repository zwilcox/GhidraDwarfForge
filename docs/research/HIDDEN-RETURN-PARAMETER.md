# Automatic return storage and formal prototypes

**CONFIRMED defect (2026-10-31):** the current exporter lists Ghidra's automatic
`RETURN_STORAGE_PTR` as an artificial formal parameter. For a natural x86-64
SysV 24-byte structure return, GDB shows three explicit arguments instead of
the compiler's two. The ordinary two-argument debugger call fails with too few
arguments. Supplying the extra pointer argument executes a call with shifted
arguments and returns `{0, 1432778632, 1432778632}` instead of the requested
structure. The executable still exits normally. The untouched compiler DWARF
returns the expected values from the normal two-argument call.

The reproduction uses the exact PR90 JAR, the existing source-built
`formal-function-return.c`, and the unchanged original target. Its GNU/LLVM/
pinned-libdwarf checks and normal execution all pass. Evidence is retained in
the ARM alias worktree's `build/return-call-review`; the original aggregate
case is `build/test-results/formal-function-return/x86_64.BGgmGtKp`.
The first attempted Forge debugger probe used `break main`, although that
stripped function had a default address-derived name, and never reached the
call. The corrected probes stop at the compiler-observed entry address and
establish the failure above. That first attempt is not evidence of the defect.

**PRESENT, UNVERIFIED beyond the initial native case:** retain the precise
Ghidra automatic-parameter kind in the extracted model. Emit only
`RETURN_STORAGE_PTR` as a function-owned `DW_TAG_variable` with
`DW_AT_artificial`, preserving its name, pointer type and independently proven
location. Ordinary and implicit `this` formal parameters retain their existing
roles. Do not infer a return carrier from its name, register, width or position.
Explicit custom parameters remain explicit, even if they have a similar name.
Addressless external declarations receive the same formal-argument policy.

DWARF 5 section 2.11 permits artificial object entries; section 3.3 describes
subprogram parameters. The choice to expose the carrier as a scoped variable
is a consumer-tested representation, not a claim that the standard mandates
this exact encoding. See [DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf).
The pinned Ghidra 12.0.3 `AutoParameterType` API explicitly distinguishes
`THIS` and `RETURN_STORAGE_PTR`. Native producer signatures are unchanged;
libdwarf remains pinned to 2.3.2 commit
`af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`.

Initial validation: extension build, 312 five-language model observations,
type-graph smoke and a separate three-iteration producer ABI process pass.
The updated real x86-64 fixture passes repeated export, all validators and
ordinary GDB behavior. Two additional injected calls now return the expected
structures in both compiler and Forge sessions while preserving stopped PC
and caller globals. No broad aggregate ABI support or complete P1.7 acceptance
is claimed. Cross-target behavior, external-declaration regressions, final
package/Java 21 checks and hosted acceptance remain pending.

## Cross-target probe

**CONFIRMED:** the corrected prototype and two injected calls pass fresh
source-built non-PIE cases on x86-64, AArch64 and ARMv7 hard-float. Initial
cross-target probes live in `build/hidden-return-review/cross`; these are
research harnesses pending promotion and full deterministic/preservation gates.

**CONFIRMED additional consumer limitation:** both MIPS32 byte orders return
incorrect aggregate values from this same signature even with untouched GCC
DWARF and the explicit FP32 profile. The corrected Forge prototype also fails
with two explicit arguments. Normal entry values are correct before injection.
The exact source of the transfer error has not yet been isolated; an O32
hidden-return/64-bit-argument alignment mismatch is a hypothesis, not a proven
implementation diagnosis. Do not treat compiler DWARF failure as permission to
accept Forge failure. A conservative target-specific call restriction and
unchanged-state negative tests are needed before accepting this change for
MIPS. Ordinary debugging and the formal return type must remain available.

The existing x86-64 integration fixture now explicitly requires two formal
parameters, preserves the hidden carrier as an artificial variable, validates
its unchanged location expressions, and checks two correct injected calls in
both compiler and Forge sessions. Its accepted scope is no longer limited to
ordinary calls alone. Broad aggregate ABI certification remains incomplete.
