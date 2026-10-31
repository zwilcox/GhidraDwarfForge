# Custom parameter and return storage callability

**CONFIRMED defect:** a default Ghidra convention name does not prove that a
custom parameter/return layout follows that ABI. The earlier exporter emitted
DW_CC_normal for an explicitly custom Microsoft parameter layout labeled with
the GCC default model. GDB injected a SysV call, executed the function and
returned 4389 instead of 1234. Ordinary calls still worked. The saved-program
reproduction passes structural validators and records unchanged input/module
hashes; validation alone does not prove callability.

**CONFIRMED locally, incomplete acceptance:** the initial fix and three-role
x86-64 exec/PIE/rebase matrix, cross-architecture regressions, independent local
artifact review and 26 actual Java 21 packaged suites pass. Final committed
package review and hosted CI remain pending. This is a P1.7/#66
component, not completion of general calling-convention or return-ABI support.

## Policy

Keep the recorded convention name and the existing nondefault-convention flag.
A separate diagnostic restriction records custom-storage uncertainty. This
avoids labeling a custom default-layout mismatch as a nondefault named model.
DW_CC_nocall is emitted when either restriction applies, including an explicitly
custom signature whose selected convention is unresolved. Legacy model
constructors retain their previous behavior.

For custom storage, require a resolved, non-placeholder default prototype,
known fixed scalar/pointer/enum types, and the complete ordered return/parameter
layout. Ask the pinned Ghidra 12.0.3 PrototypeModel.getStorageLocations API for
the return-first list, allowing it to report any automatic parameters. Compare
all storage metadata and ordered varnodes, including the return. Bad/unassigned,
automatic/forced-indirect, divergent, unknown, variadic and unclassified aggregate
cases remain noncallable. Do not infer ABI equivalence from one matching
register, a convention-name whitelist, or only the parameter list.

Equivalent custom layouts preserve ordinary callability. Noncustom signatures
retain the existing policy; this comparison does not certify arbitrary default
compiler specifications or prove that every Ghidra prototype agrees with GDB.
That broader profile work remains explicit P1.7 scope.

The same policy applies to curated external declarations. Formal types,
parameter names, signature provenance and independent variable-location evidence
are preserved. No native/JNA declarations or target-register mappings change.
GDB's no-call behavior also declines automatic return-value presentation after
finish; tests retain those exact warnings and independently observe the actual
return registers and normal program exit.

## Test design and local acceptance

The six-language ProgramDB model passes 486 checks, including equivalent and
swapped parameters, divergent returns, void returns, variadic/unknown/aggregate/
unassigned layouts, external declarations, cancellation, deterministic extraction
and immutable reopening. Existing convention policy checks now total 212: the
old unknown-convention custom control is explicitly noncallable. Formal return
and type-graph regressions pass.

The real source-built fixture has an ordinary SysV scalar function, a compiled
Microsoft scalar function, and an assembly function returning through EDX with a
deterministically wrong EAX value. Its assembly caller reads EDX correctly.
All three are curated using the default convention name and explicit storage.
The first stays callable; the other two must be rejected before counters change.
Previous exports/GCC metadata reproduce wrong injected values 4389 and 7.
Ordinary calls expose the real arguments, produce 1234 and exit normally.
Compiler metadata is a documented negative callability control for these custom
ABIs, not proof that a structurally valid original DIE describes the assembly.

Three exec/PIE/rebased-PIE roles pass current/repeat and previous-package exports,
GNU/LLVM/pinned-libdwarf checks, typed lookup, source listing, parameters and
return-register values. Inputs and packages are protected by hashes; read-only
program reopening allows only known Ghidra backup-file rotations. Final exact
package/hosted review remains required before integration.

## Retained investigation

Original unsafe-call receipt SHA-256:
`b5e6dc94d75b16247747ed007ff3494e9b452aabd0081e773d6b21f53270298b`.
Initial corrected two-function exec proof receipt:
`2a20191189f59f15391dd07ecdb4393f0a8751cd1edacd75af5e25b02c56261f`.
Research lives in the main checkout's build/custom-call-research; implementation
validation lives in build/custom-call-review in the custom-call-storage worktree.
An initial harness attempt put its script beside a nested private installation;
Ghidra could not load the script bundle. A dedicated scripts directory and a
fresh case passed. The failed case is retained and is not acceptance evidence.

## Local regression evidence

**CONFIRMED locally:** the same production JAR passes baseline export and
native/QEMU GDB checks on x86-64, AArch64, ARM32 and both MIPS byte orders;
ten dynamic-parameter exports; twenty computed/custom aggregate exports;
thirty floating-register exports; twelve explicit MIPS FP32 piece exports;
and the natural aggregate-return regression. Controlled decompiler failure and
copy cancellation pass, preserving the original and prior output pair.
Architecture neutrality and all seven guard regression cases pass.

Independent review rehashes 267 protected-file observations and checks 59
strict-validator artifacts, including corroboration for inherited compiler
frame diagnostics. There are no uncorroborated errors. Receipt SHA-256:
`0019bcd5d79cf88d5a45e6f10ae69bb115a28935b3629e42f9d2f549560dd2fa`.
The custom-call matrix receipt is
`6063bfcbe5db99e2494f585117a0a847ffc282a802e63ab8ac314e29e81f9f15`;
the 26-suite actual Java 21 receipt is
`e932b176195e7e91634673d728b7a0f44c56902a5a95feb02989303bdd356a14`.

Commands and raw outputs are retained in build/custom-call-review:
remaining-matrix.py, custom-regressions.py, failure-cancellation.py,
run-java21.py, audit-cases.py and review-regressions.py. The first semantic GDB
attempt incorrectly used the compiler-source oracle, which expected an original
local name absent from curated output. It is retained as a failed harness run;
the proper qemu-gdb-symbols.sh harness subsequently passed all five targets.
An initial receipt reviewer expected a scalar exitCode where two harnesses
record exitCodes; inspecting the raw JSON and checking every exit code corrected
that reviewer. Neither attempt counts as a passing test.

## Combined alias and custom-storage checkpoint

**CONFIRMED locally:** combined commit
`2bf119d7cd78fc733f4b66be93becc7659ac77cb` passes 28 actual Java 21 suites,
the three custom-call roles, twelve retained/stripped alias base cases and
twelve automatic alias cases. Independent raw reviews pass; automatic alias
artifacts equal the independently invoked writer byte for byte. The package
contains 56 exact production sources, two scripts and 241 Java 21 classes.
JAR SHA-256:
`502cb0bc0b8a6f72d4fc427f838a49cda7f625f79be6b0138c3446078a5e6777`.

Combined receipts: Java 21
`6fa5922ae304510509a27858763c4562e73d8320b1310ce928f9c1fb725bc2a7`,
custom calls `27e9937f053cbd07cadb765022069dca9779dd2a59cf5e8a0be093dc6d10204a`,
base aliases `bf5eb4e9aa2ffc9c8be811367c57af4256caf16575027445160b5b94e9c1b482`,
automatic aliases `38d46ce1f71f8a00ec13b500b92170f040dd33d906caa72daf008e0ebbb70f46`.

Retained setup failures: the combined package audit initially retained the old
source-plus-script count (57 instead of 58); exact source bytes already matched.
The alias harness first required missing base fixtures, then explicitly rejected
Java 25 for its standalone writer. Fresh base fixtures and FORGE_JAVA21_HOME
selecting actual Java 21 passed. No production change was needed for these
failures. The new fixture is included in the reviewed source inventory.

**CONFIRMED remaining ABI gap:** selecting Ghidra's Windows compiler model for
an ELF makes its default __fastcall agree with Microsoft custom storage while
GDB still injects a SysV call. An isolated reproduction on this combined JAR
returns 4389 instead of 1234; receipt
`f404520f1809b8dafae0dbf6dcca98c8e06588041c0b0ce89824a1f963d9feea`.
Classifying the selected default model against the original ELF debugger ABI
remains P1.7 work. This component only proves equivalence to the selected
program default; it does not certify an arbitrary compiler specification.
