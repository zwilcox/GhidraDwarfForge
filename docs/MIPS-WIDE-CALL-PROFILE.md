# N32/N64 debugger call and return profile

**CONFIRMED local runtime progress; hosted acceptance pending:** this component extends
#69 within the full P2.3–P2.3c goal. It does not complete an umbrella issue or
change the Ghidra 12.0.3, Java 21 or libdwarf 2.3.2 baseline.

The prior exporter emitted `DW_CC_nocall` for every N32/N64 function selected
by the standard ELF loader. In addition to preventing injected calls, GDB 15.1
therefore omitted automatic typed scalar and small-structure return values.
Compiler-DWARF calls for the four wider fixture signatures pass in both ABIs
and byte orders before enabling the corresponding exporter path.

## Exact decision and remaining limits

`MipsWideCallPolicy` owns the target-specific decision. ELF64 MIPS and ELF32
ABI2 inputs cannot fall through to O32 call guards. Admission requires ET_EXEC
or ET_DYN; OSABI 0 or 3, ABI version 0 or 1; MIPS64r2 flags with only the ordinary
NOREORDER/PIC/CPIC variations; and one unambiguous typed ABI record with version
zero, ISA 64 revision 2, eight-byte GPRs/FPRs, no second coprocessor, hard-float
ABI 1, no extensions/ASEs, and no unknown flags. Conflicting, absent or unsupported
metadata disables calls without discarding the recovered types and locations.

The production entry point now passes the original ELF to the Ghidra compiler
policy. It additionally requires the matching byte order and exactly
`MIPS:{BE,LE}:64:64-32addr` with `n32`, or `MIPS:{BE,LE}:64:default` with
`default`, respectively. The older API without original ELF evidence retains
its restrictive behavior. All decompilation-failure helpers use the same path.

The initial signature envelope covers ordinary 1/2/4/8-byte integer types,
enums, correctly sized pointers, four/eight-byte floating scalars, and flat
16/24-byte structures containing contiguous eight-byte integer members. Type
aliases must retain their target size. Void is permitted only as a return.
Hidden return pointers must match the returned aggregate and pointer width;
duplicate or inconsistent hidden arguments are restricted. Existing custom
storage/convention restrictions remain intact. Definitions, external declarations
and callback types receive the same classification. Cyclic aliases, unresolved
opaque types, variadics, references, arrays, long double, bit fields, unions,
nested/padded/mixed-FP structures and wider aggregates remain separate work;
this envelope is not the completion definition for #69.

The code does not implement a debugger call stub. GDB performs the actual ABI
transfer. Relevant upstream reference material includes the
[GCC MIPS ABI corrections](https://gcc.gnu.org/gcc-3.4/mips-abi.html) and
[GDB MIPS target implementation](https://gnu.googlesource.com/binutils-gdb/+/d01e823438c7dc264d6885fbbfeace4d8955dcb7/gdb/mips-tdep.c).
The runtime tests, including source-known results, determine the accepted
consumer behavior; source inspection alone does not establish support.

## Validation in progress

`mipsWideCallPolicySmoke` exercises real Ghidra language/compiler combinations,
synthetic independent ELF class/order/ABI records, metadata disagreements,
unsupported type layouts, aliases, hidden returns, existing restrictions,
definitions/declarations/callbacks, preserved ownership, idempotency and
cancellation. Its current local result is 11,696 checks. Existing compiler,
O32 floating and O32 aggregate call suites pass 606, 4,752 and 7,272 checks.

The wider runtime fixture has four ordinary calls plus typed callback globals.
Each symbol file must pass eight injected calls with correct typed results,
preserved stopped PC/stack pointer and normal process exit. The callbacks have
an explicitly curated calling convention. An earlier fixture omitted it and
was correctly rejected; that failed fixture remains retained as
`n32.be.exec.1wujw04f`. The subsequent corrected fixture passes at
`n32.be.exec.5udzx0mz` under `build/test-results/mips-wide-arguments/`.

The complete 20-case matrix receipt is
`build/mips-wide-allocation/call-matrix.json`: N32/N64, both byte orders, and
non-PIE/PIE/rebased-PIE/shared/rebased-shared. All 9,500 Forge instruction
observations and 320 injected calls (both symbol files, names and callbacks)
pass. Repeated exports are byte-identical and preserve original/package/program
database bytes. GNU, LLVM and pinned strict validation pass for both symbol
files with zero reported strict errors. The installed candidate is
`candidate-v4.zip`, SHA-256
`ae209dcbbbd7150758c3d5378a2b0920af8a89377a761cd841bc091047c27967`.
Its producer/native binaries are unchanged.

The four wider functions still require instruction-level values and deliberate
clobber gaps, separate source stepping, named/address breakpoints and type
lookup. Compiler aggregate pre-store and epilogue defects use the independently
decoded, bounded reference windows described in `MIPS-WIDE-ARGUMENT-ALLOCATION.md`;
Forge has no such exceptions. Scalar and 16-byte aggregate returns must be
automatically typed. For the 24-byte hidden-buffer return, GDB's compiler
reference also lacks automatic display; both modes separately check the actual
caller buffer using the return type, and record that automatic-display limit.
The independent oracle has raw byte-order/sign/slot controls and mutations of
home stores, clobbers, frame restoration and delayed-return instructions.

GNU/LLVM/pinned strict validation, deterministic exports, unchanged binaries,
unchanged saved program databases, failure/cancellation composition, exact
package regression, hosted validation and protected integration are required
before final component acceptance. A local passing case does not complete those
remaining gates or the wider allocation/storage/ABI work.


A separate extension of the existing floating-call fixture proves float and
double return values as well as argument transfer and typed callbacks. All 24
N32/N64/endian/scalar/exec-PIE-rebased cases pass in
`build/mips-wide-allocation/wide-floating-matrix.json`. Each case checks actual
callee-written globals and call counters, source/type lookup, exact typed
return values, deterministic repeat, original/program preservation, raw calling
convention DIEs and GNU/LLVM/strict validators. No floating transport exception
is permitted for these profiles.

The exact installed package also passes the AArch64 ABI non-PIE regression with
real decompilation-failure and copy-cancellation controls at
`build/mips-wide-allocation/call-policy-aarch64-regression/exec.s6w_nq7g`.
The original natural (unhomed) aggregate fixtures remain separate from the
compiler-calibrated homed fixtures; their updated-package regression is retained
in `build/mips-wide-allocation/natural-regression-v4.json`. These original
compiler aggregate locations remain incorrect and are not relabeled as a valid
compiler variable oracle.


All 20 failure/cancellation compositions pass in
`build/mips-wide-allocation/wide-controls-matrix.json`: 40 deterministic real
native decompilation-failure exports and 20 production copy cancellations.
The failed `wide_pair` retains its symbol and deliberately lacks variable and
return DIEs; the harness checks its raw result and requires neighboring typed
values and returns. Earlier harness code incorrectly expected an automatic
return from this symbol-only DIE; its failure is retained at
`n32.be.exec.3zr6ckt3/controls.n0d_vdkj`. Cancellation retains existing final
artifact bytes and leaves no partial output. The eight natural-source regression
cases also finish with 3,472 exact-value/gap observations, deterministic reruns,
clean validators and unchanged prior artifacts/program databases.


Four O32 regressions (FP32 and FPXX, both byte orders and scalar sizes) pass in
`build/mips-wide-allocation/o32-call-regressions.json`, retaining the existing
positive transfer and rejection-before-execution contracts. The strict compiler
pre-store failure is still reproducible with
`FORGE_MIPS_WIDE_STRICT_REFERENCE=1`; its output is separately retained in
`strict-reference-retained.log`. The ordinary calibrated compiler run was then
rerun successfully. The complete `--with-controls` driver also passes at
`n32.be.shared-rebased.t8lk1pj_`.

A final package rebuild follows an import-order cleanup. The only changed
production class is `GhidraCompilerCallPolicy`; its `javap -c -p` output is
byte-identical to the matrix-tested class (only source line metadata changed).
All other production class bytes match. The new archive is `candidate-v5.zip`,
SHA-256 `d8d17ef7c3c7edb9b501436c0926c4d3046677d367898614c0e04ecdc1d89a68`,
JAR SHA-256 `8c3931eed60e9e06d084e5026747d948f011dda278535e3abf9f524a2d93aadb`.
The earlier v4 matrices remain evidence for their recorded package; the final
rebased N64 little-endian driver passes against the rebuilt installed package at
`n64.le.pie-rebased.26g1soql`, including validators, calls, deterministic reruns,
real decompilation failure and production cancellation.
Hosted exact-head/package validation and protected integration remain pending.
