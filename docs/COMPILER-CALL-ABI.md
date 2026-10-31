# Compiler specification and ELF debugger call ABI

**CONFIRMED defect:** the program's default convention is relative to its chosen
Ghidra compiler specification. It does not establish the original ELF debugger's
ABI. An x86-64 ELF imported with the Windows compiler specification has
__fastcall as its resolved default. Microsoft custom parameter storage agrees
with that prototype; the preceding custom-storage safeguard consequently allows
GDB to inject a SysV call, returning 4389 instead of 1234 and incrementing the
function's counter. Structural validation passes despite the wrong call.

The retained reproduction is in the main checkout's build/default-abi-research.
Receipt: `f404520f1809b8dafae0dbf6dcca98c8e06588041c0b0ce89824a1f963d9feea`.
The first attempted import omitted the required processor when selecting a
compiler specification and failed before import. Only the corrected attempt
counts as evidence.

## Bounded policy

**CONFIRMED locally; hosted acceptance pending:** after target
agreement against the original ELF, restrict debugger-injected calls for a
compiler specification outside the existing target validation baseline. The
Ghidra 12.0.3 IDs are isolated in DwarfTarget: gcc for x86-32/x86-64 and default
for AArch64, ARM32 and both MIPS32 byte orders. Unknown targets or compiler IDs
remain restricted. The ID is a selection constraint, not a universal calling
convention name or proof of every signature's ABI.

The existing baseline policy is retained. This change does not newly certify
arbitrary language variants, patched compiler specifications, ABI flags,
aggregate/vector returns, or vendor conventions. Additional profiles require
independent behavior tests before admission. Alternate compiler choices remain
available for analysis; export does not silently change them or discard curated
signatures, names, types, source mappings or independent variable locations.

GhidraCompilerCallPolicy adds a diagnostic restriction to both definitions and
curated external declarations before native production. Existing custom-storage
and nondefault-convention restrictions remain intact. Serialization uses the
existing DW_CC_nocall path. Applying the policy repeatedly is idempotent; it
honors cancellation. The native/JNA boundary is unchanged.

## Local checkpoint and remaining validation

The build and model suite pass 381 checks across six languages and all 23
compatible compiler specifications in those selected Ghidra languages. They
check that metadata, formal types, globals, function-owned statics and storage
remain unchanged, that existing restrictions survive, and that unknown compiler
IDs are restricted. The initial cancellation test used a noncancellable monitor;
using a cancellation-enabled monitor corrected the test, and its failure log is
retained.

The first installed x86-64 Windows-compiler proof exports twice read-only,
passes GNU/LLVM/pinned-libdwarf checks, rejects the injected Microsoft call before
execution, and observes both ordinary calls returning 1234 with arguments
1,2,3,4 and normal exit. Original and protected module/source hashes are intact.
Receipt: `7d4506a4711e5899fe7c3a086f04528a38af45dfff20c55355ae31d39594e353`.

The Windows and GCC exec/PIE/rebase matrices pass twelve deterministic current
exports, six previous-package exports and 54 ordinary runtime calls across
compiler/current/previous variants. Independent review re-reads actual ELF/DWARF,
checks calling-convention attributes, formal types, exact addresses, original
build identity, read-only project changes and protected hashes. Windows-profile
receipt: `e4d1bbab28d057528244489f768d8d32c88cb1e0fc20e050cb3cd4442c80b319`.
GCC control receipt:
`7396a48914e3f1e06f5f262836b95e198815c9cf1aed2c3df7705d72eb4a55cd`.

Twenty-nine suites pass on actual Java 21 with class-loading origins checked
against the installed JAR; receipt
`e238430424885f449964dbe2bd3da2e00c4fee4f43a61b49f9050117792fdda7`.
Local headless runs use Java 25 with Java 21 bytecode; the isolated Java 21
runs are separate evidence.

Baseline exports and native/QEMU debugging pass on x86-64, AArch64, ARM32 and
both MIPS byte orders, plus ten dynamic-parameter exports, thirty floating
exports, twenty computed/custom aggregate exports, twelve MIPS FP32 piece
exports and the natural aggregate-return case. Controlled decompiler failure
and cancellation preserve the original and previous output pair. Independent
regression review rehashes 269 protected-file observations and 59 strict
validator artifacts: no uncorroborated errors; inherited compiler frame warnings
are recorded and corroborated. Receipt:
`187b786d03a36bab0da03c354ebf8070fc809354b4cd597358307cbcea72294b`.
Commands and raw outputs are retained in build/compiler-call-review.

Exact committed packaging and hosted acceptance remain pending. This is part
of P1.7/#66, not completion of general ABI or alias support.
