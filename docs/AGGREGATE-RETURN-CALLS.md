# Aggregate return prototypes and debugger calls

**CONFIRMED locally and in committed packaging; hosted acceptance pending:** automatic
return-buffer storage is preserved separately from the formal argument list.
A target-specific MIPS policy prevents independently reproduced unsafe injected
calls while retaining supported integer/pointer argument transfers.

## Formal argument identity

Ghidra 12.0.3 distinguishes `RETURN_STORAGE_PTR` from `THIS` and ordinary
parameters. Extraction retains that exact distinction in the model. The
producer emits a return carrier as a function-owned artificial variable with
its original name, pointer type and independently established location. It is
not an additional `DW_TAG_formal_parameter`. Ordinary arguments, implicit
`this` arguments and explicitly materialized custom parameters retain their
roles. The same rule applies to curated addressless declarations, where the
carrier has no invented location or code address.

GDB supplies the return buffer from the formal aggregate return type. Treating
it as another formal argument formerly shifted injected arguments. The saved
Ghidra signature and decompiler text can still expose the ABI carrier; the
synthetic C file remains decompiler output. Its presence there does not make
it a source-language argument. No native/JNA signatures or register maps change.

## Selected MIPS call profile

Both endian variants of the classic ELF32 O32 MIPS32r2 profile are checked
against ELF flags and an unambiguous typed ABI record. FP32 and FPXX are
admitted for the integer-only aggregate-return cases. Existing floating-call
restrictions remain independently enforced.

Aggregate-return debugger calls require nonvariadic signatures with classified
integer, enum or pointer arguments no wider than one O32 word. Typedefs and
qualifiers are resolved with cycle/budget checks. Return storage is excluded
from this user-argument classification. Unknown, wide, floating, aggregate and
other unclassified argument forms remain restricted with a precise diagnostic
and `DW_CC_nocall`. Scalar-return policy is unchanged.

This restriction follows real compiler-DWARF controls: both MIPS byte orders,
under FP32 and FPXX, execute aggregate-return calls with wide arguments using
incorrect values. Ordinary calls and scalar 64-bit returns work. Positive
aggregate controls cover small signed/unsigned integers, enums, pointers,
stack arguments and a typedef return. The precise debugger implementation cause
has not been established; argument alignment is a hypothesis, not a required
assumption in the policy. Other ABI/ISA profiles are not silently admitted.

## Acceptance evidence

The 21 source-built cases cover exec, PIE and explicitly rebased PIE on x86-64,
AArch64, ARMv7 hard-float and MIPS32 BE/LE, with both FP32/FPXX MIPS profiles.
They pass 42 deterministic exports, GNU/LLVM/pinned-libdwarf validation and 42
compiler/Forge debugger processes. The observations include 162 correct
injected calls, 24 deliberately retained compiler failures and 24 Forge
rejections before registers, stack bytes, counters or execution state change.
The normal executable verifies all aggregate/scalar results and exits zero.
Protected inputs, installed modules, harness files and saved programs remain
unchanged apart from documented Ghidra backup rotations.

Independent raw review re-reads actual DWARF, verifies formal-parameter counts,
carrier roles, calling conventions, addresses and all runtime receipts. Receipt:
`335f0050b3d608df4b3e63a62b2bd0dfba2a03b759bb4ab023d5d61e03a4eee2`.
The new ABI policy passes 5,256 model checks; the formal-return model passes
342 checks across five real Ghidra language models, including addressless
aggregate declarations and immutable reopening. The extended native return
and external-declaration fixtures pass, as do controlled decompiler failure,
copy cancellation, all five fixture reproducibility inventories and workflow
lint. Packaged testing passes 38 suites on actual Java 21. The committed-package
audit verifies all 67 exact source files, 261 Java 21 classes, native provenance
and manifests; its production JAR matches the tested matrix byte-for-byte.
Six fresh stripped/rebased overload regressions, including ARM and Thumb, and
all five merged fixture inventories also pass.

The first new model test compared lexically sorted declaration names against
numeric indices after adding case 10; zero-padding corrected that harness
assumption. The first script compile used unsupported constructor overloads;
the corrected script compiles separately with Java 21 bytecode. The first
external oracle disallowed the new artificial variable role, and the first
raw audit assumed every aggregate—including small register-returned pairs—had
a return buffer. Those assertions now check the exact intended roles and target
observations. All failed attempts remain recorded. See also
[the retained reproduction](research/HIDDEN-RETURN-PARAMETER.md).

This component does not complete P1.7 or authorize release publication. The full hosted gate
and independent hosted artifact/GUI review remain pending.
