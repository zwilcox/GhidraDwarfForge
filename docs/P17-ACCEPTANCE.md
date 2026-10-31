# P1.7 signatures, calling conventions, thunks and aliases

**CONFIRMED development acceptance:** P1.7 function signatures,
calling conventions, declarations, thunks and aliases passed the combined
[PR95 run](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41195618723)
at `cad5e0dd3d5270cd5c83c09ccb2e2d1da29b5ee0` and merged normally as
`b78faab6263ae89f9b07d316502c5f6bd9afa702`. Final independently reviewed evidence receipt:
`9f2a1e03b32def2874f71f9a91052dd8e4717876fa4bb05a16ba16ae2febd1cd`.
The published alpha.2 release is unchanged. Richer class/lexical relationships
remain P3.3; broader variable lifetime recovery remains P1.11a.

## Verified combined results

All twelve CI jobs passed, including the mandatory x86-64/AArch64 lanes,
ARM32, both MIPS32 byte orders, Linux packaging and native Windows checks.
The exact hosted package passed 39 actual Java 21 suites. The Windows host
ran 59 model tasks and real export/GUI checks; Linux native/QEMU lanes provide
the ELF runtime GDB and strict libdwarf evidence. Both GUI console screenshots
were personally inspected. The normal merge has the identical reviewed tree.

| Focused evidence | Verified result |
| --- | --- |
| Overloaded signatures | 36 cases, 72 exports, 72 compiler/Forge GDB processes and 288 ordinary calls. |
| Aggregate returns | 21 cases, 42 exports, 162 positive injected calls and 24 unchanged-state refusals. The 24 corresponding compiler failures remain explicit negative controls. |
| Typed-pointer call policies | 51 cases across compiler, floating and aggregate profiles; 240 correct calls and 90 refused calls. Actual variable-to-pointer-to-subroutine DIE references were inspected. |
| Variadic/no-return function types | 1,994 model checks; three saved-program roles, 24 compiler/Forge variadic calls and six ordinary no-return pointer exits. Unsupported type-level no-return encoding is diagnosed. |
| Class-owned function display | 15 cases and 30 exports preserve qualified lookup and owned statics. Original C++ class semantics remain outside this display policy. |
| Failure/cancellation | A failed decompilation remains symbol-only while another function's source and static value remain usable. Cancellation after 16 MiB of ELF copying preserves the original and prior output pair, with no staging files left. |

The independent review rehashed 40 package/raw review records, plus the direct
failure/cancellation transcript review and both visual records. Original inputs,
installed modules, fixture sources and saved-program observations were checked
where retained by their harnesses. Repeated output pairs were byte-identical.
Ghidra index/journal backup rotation is allowed only where explicitly recorded.

The copy-cancellation fixture deletes its large input after its runtime hash
check, and its uploaded diagnostics omit the output pair. Its preservation and
cleanup evidence therefore consists of exact-head executable assertions and
retained hash-check transcripts; post-download rehashing of those particular
files is not claimed. Other preservation cases retain their files for independent
rehashing. Inherited compiler-frame diagnostics remain subject to the documented
strict corroboration policy, not blanket warning suppression.

## Required behavior and proof

| Requirement | Accepted behavior and test evidence |
| --- | --- |
| Formal return types | Preserve Ghidra's formal type independently of a hidden ABI carrier. Inspect type references and actual returned aggregate bytes in `aggregate-return-calls.py` and `FormalFunctionReturnSmoke`. |
| Formal parameters | Preserve names and types. Hidden return-storage carriers are artificial variables, not additional callable arguments. Check definitions and addressless declarations with aggregate and external-declaration oracles. |
| Variadic and no-return flags | Preserve direct flags and variadic types. Diagnose the no-return function-type property without inventing an unsupported encoding. Run `function-type-flags-export.py` and the five-language function-pointer model suite. |
| Analyst precedence | Restrict decompiler recovery to weaker DEFAULT metadata. Independently inspect recovered-return/parameter artifacts and GDB results; retain curated types and honest unavailable parameter locations. |
| Qualified and overloaded identity | Preserve actual namespace/class display paths and separate address/type/source ownership for same-name definitions. Run class-owned scope and all 36 overloaded-signature cases. |
| Calling conventions | Apply convention, compiler-profile, custom-storage and MIPS signature restrictions to definitions, declarations and typed pointers. Verify supported calls and refusals before target state changes; inspect the actual referenced subroutine DIEs. |
| Linkage lookup | Retain original ELF spellings beside curated DWARF identity. Use supplemental analyst aliases without overlapping definitions or a distinct linkage attribute that hides curated lookup in GDB. Verify retained and fully stripped controls. |
| Target alias semantics | Verify isolated i386, x86-64, AArch64, ARM/Thumb and MIPS mode/address rules, discontiguous bodies, sectionless inputs, dynamic inventories and versioned symbols with the applicable native/QEMU GDB cases. |
| Definitions, imports, declarations and thunks | Inventory external functions independently; emit curated declarations without invented addresses; preserve analyst-named memory thunks with their own body/signature and deliberate source omission. Check unsupported-policy diagnostics separately from decompiler failure. |
| Structural and debugger validity | Run GNU inspection, LLVM verification and the pinned strict libdwarf checker on generated artifacts, plus the corresponding GDB behavior tests. Explain inherited compiler diagnostics through the existing corroboration policy. |
| Preservation and determinism | Rehash original binaries, installed modules, harness sources and saved-program content. Require byte-identical repeated sidecar/source pairs; permit only documented Ghidra index/journal backup rotation. |
| Failure and cancellation | Prove original/prior complete output preservation and resource cleanup using controlled decompiler failure, ELF-copy cancellation and isolated native producer tests. |
| Host and target baseline | Build from a clean checkout for Ghidra 12.0.3, run actual Java 21 suites and native Windows checks, and pass all five required target lanes. Inspect both actual GUI console screenshots. |
| Integration and documentation | Preserve normal commit history and the enforced up-to-date `required-validation` check. Review the exact combined package/artifacts, reconcile TODO/context/issue #66, and close only after all requirements are proven. |

The integration PR retains the original component commits. It combines their
reviewed changes behind one complete main-based gate; it does not omit a target,
validator, fixture, behavior check or final artifact review. No force push,
history rewrite or branch-protection bypass is involved.

## Decisions and limits that remain part of the contract

The `.dbg.c` compilation unit describes synthetic C11 decompiler output. Recorded
class/namespace paths are display identities; this does not reconstruct original
C++ class declarations, `this` relationships, inheritance or lexical scopes.
Those richer relationships remain the separate P3.3 task.

Recovered metadata is not asserted to be original compiler truth. For example,
the unsigned-return fixture exposes a documented difference between the
compiler's four-byte return type and Ghidra's eight-byte inference. Stronger
analyst metadata still wins. Unsupported locations remain unavailable.

Alias ownership requires a defensible exported primary, original code identity,
unambiguous spelling and validated target semantics. Unsupported ownership,
ambiguous labels and unknown instruction modes are diagnosed rather than
attached to unrelated code. The primary remains the type/source/static owner.

An explicitly refused debugger-injected call does not certify the unsupported
ABI. The existing conservative policies preserve signatures and ordinary
debugging while preventing reproduced unsafe transfers. The standalone checker
recognizes the documented LLVM/GDB function-type convention extension; shipped
native sources remain unchanged by that compatibility correction.

See `FUNCTION-NAMING.md`, `CURATED-THUNKS.md`, `EXTERNAL-FUNCTION-DECLARATIONS.md`,
`OVERLOADED-SIGNATURES.md`, `FUNCTION-POINTER-CALL-ABI.md`, `FUNCTION-TYPE-FLAGS.md`,
`AGGREGATE-RETURN-CALLS.md` and the target-specific alias decision records for
the detailed policies, experiments, commands and limits. Their historical
component-pending wording does not override the final combined acceptance
record once established. No release publication is part of this milestone.
