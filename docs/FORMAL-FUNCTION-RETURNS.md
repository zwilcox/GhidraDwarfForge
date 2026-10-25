# Formal function return types

A function returning a structure may use an implicit destination pointer in its
ABI. That pointer is a carrier for the result; it is not the function's declared
return type. Ghidra 12.0.3 distinguishes these views:

- `Function.getReturnType()` returns the effective ABI type. For forced-indirect
  returns this can be a pointer, or void for `INDIRECT_VOID_STORAGE`.
- `Function.getReturn().getFormalDataType()` preserves the curated return type.

Forge now uses the second API for concrete function signature extraction, just
as it already does for explicit parameter types. This is architecture-neutral;
no register mapping, native binding, location expression or ABI classifier changes.

The naturally allocated return-storage parameter remains a separate pointer
parameter with `DW_AT_artificial`. Its pointee and the function's return type
reference the same canonical aggregate DIE. Explicit parameter order, types and
locations remain independent. A genuine pointer-returning function stays a
pointer-returning function.

## Signature changes and limitations

Converting Ghidra to custom variable storage can materialize its implicit
parameters as explicit parameters and commit an effective pointer/void return
as the new formal signature. Forge preserves that current signature. It does
not reconstruct the former structure return or infer artificial status from a
parameter named `__return_storage_ptr__`.

A forced-indirect by-value input retains its formal aggregate type and an
unavailable location. The fix does not reinterpret that pointer carrier as a
valid direct aggregate location. It adds neither C++ `this`/object-pointer
semantics nor support for additional calling conventions.

## Regression coverage

`formalFunctionReturnSmoke` uses real ProgramDB instances and Ghidra's dynamic
allocator for x86-64 SysV, AArch64, ARM32 and both MIPS32 byte orders. It checks
aggregate, genuine pointer, scalar and void returns, hidden parameter identity,
custom conversion, forced-indirect inputs, cancellation, deterministic models,
and immutable reopen without database byte or mtime changes. The old extractor
fails the first aggregate-return assertion. The corrected source passes 312
checks on Java 21 with a 256 MiB heap. These are model tests, not five target
runtime claims.

`src/test/integration/formal-function-return-export.sh <ghidra-dir>` builds one
ordinary x86-64 SysV non-PIE C fixture returning three 64-bit fields. Its source
and optimization flags preserve the earlier failing probe. It imports a stripped
ELF, applies a USER_DEFINED formal signature through dynamic storage, exports,
and reopens the saved program read-only for a deterministic second export.

The harness compares compiler and Forge structure/member DIEs, checks the
artificial destination pointer and raw parameter location encodings, runs
readelf, LLVM and the strict validator, then executes the normal caller in GDB.
It requires a 24-byte structure return type, correct available argument values
at every callee instruction, accurate unavailable tails, correct returned bytes
and caller globals, normal exit, and unchanged original inputs. It uses no
injected inferior call and does not read the destination before initialization.

The pipeline runs the model test on Linux and Windows and the real runtime
fixture in the x86-64 lane. Hosted acceptance must be recorded separately from
local results. Broader ABI behavior remains in TODO.md.
