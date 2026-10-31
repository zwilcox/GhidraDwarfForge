# Same-name types and qualified global lookup

**CONFIRMED locally; hosted/full-scope acceptance pending:** the saved-program
fixture preserves distinct recursive structures, typedefs and enums with the
same leaf names, including analyst-renamed types in different datatype
categories. Its six x86-64/AArch64 exec, PIE and rebased-PIE roles pass actual
Java 21 headless export, structural validation and compiler-correlated GDB
values. This is a P3.3 component, not completion of P1.11a or P3.3.

## Defect and representation

The fixture exposed an existing global lookup defect: a C11 variable named
`object` under a namespace DIE did not provide cold `alpha::object` lookup.
Retained ELF symbols could supply an untyped minimal symbol, disguising the
missing DWARF identity. Tests therefore use a fully stripped executable and
fresh debugger processes for qualified lookup.

`GlobalScopeNames` plans lookup separately from actual namespace ownership:

- An unambiguous scoped variable has one CU-owned definition with its recorded
  qualified name, canonical type and existing location or declaration status.
- An addressless `DW_TAG_imported_declaration` in the actual namespace references
  that definition through `DW_AT_import`. It does not duplicate the location.
- A short import name is supplied only when it does not conflict with other
  globals, functions, accepted function/class aliases, types or enumerators.
  Otherwise the import has no name attribute and inherits the qualified name.
- A conflicting full spelling is diagnosed; its original namespace, name,
  type and storage are retained. The exporter does not choose a different
  object merely to make that ambiguous spelling resolve.
- Root globals remain root globals. An external declaration remains addressless.

The short-name guard matters at runtime: an initial experiment imported both
namespaced `item` variables as `item`, causing GDB to read 17 instead of the
root object's 53 after CU expansion. The production fixture proves all four
actual values (17, 29, 41 and 53), the function's return of 140, and the absence
of an address for the declaration-only `left::missing`.

Use qualified names, for example `print 'alpha::object'.value`. A unique short
namespace import becomes available after CU expansion; cold short-name lookup
is not promised. Category paths are not source namespaces. For category-only
same-name types, querying their distinct variables exposes the appropriate type
(`ptype category_small`, `ptype category_large`). No arbitrary category-based
namespace or original-language identity is invented.

The CU remains synthetic C11. This change does not invent linkage names,
external flags for definitions, original source, or C++ calling-convention
support. Existing `__thiscall` debugger-injection restrictions remain intact;
the runtime fixture observes executed returns through the independently known
fixture ABI instead of calling methods from the debugger.

## Layout experiment

`src/test/research/namespace-globals/probe.py` compiles isolated alternate
exporter classes from the recorded pre-fix source at
`ad8f5fb3c854ffe99e393f33a6d66173fe20413c`. These classes never enter Ghidra.
The experiment compares nine layouts on both runtime targets:

| Layout | Cold qualified lookup |
| --- | --- |
| Existing namespace-owned leaf variable | Fails |
| Qualified CU import of that variable | Fails |
| Qualified name inside the namespace | Fails |
| Root definition with namespace specification | Fails |
| Specification plus short import | Fails |
| Specification plus explicit root type | Fails |
| Specification plus external flag | Fails |
| Root qualified definition | Passes |
| Root qualified definition plus namespace import | Passes |

The selected layout additionally preserves namespace association and existing
warm short-name lookup. The research receipt is explicitly not production
acceptance. The separate `namespace-globals-native.py` harness loads the real
packaged exporter, verifies its class origin and runs eight variants per target:
normal, short type/enum/function collisions, and full type/enum/function/global
collisions. It checks raw DIE ownership/references, independent cold lookup,
LLVM/pinned strict validation, unchanged inputs and native/QEMU runtime values.
The existing audited producer API is reused; no JNA declaration changes.

## Saved-program acceptance

`same-name-types.cpp` contains two distinct `Node` layouts, recursive pointers,
two `Record` typedefs and two `State` enums. Both scopes reuse the enumerator
`SHARED` with different values. The preparation script records actual class,
function, datatype ID and universal-ID evidence, verifies each automatic THIS
pointee against the exact global object's type, and saves explicit class/layout
bindings. No association is inferred from a common leaf name.

The analyst-edit portion moves and renames two additional structures to
`Packet` and both typedefs to `Handle` in separate categories. The saved IDs
remain unchanged. Export then reopens the project read-only without analysis,
twice, and observes the same model. Assertions cover:

- Separate canonical type references, class specifications, object parameters
  and recursive pointer targets; 16/24-byte class layouts and 4/16-byte category
  layouts retain their exact field widths.
- Both namespace objects and enum values simultaneously visible in GDB, actual
  method parameters/returns, self-pointers and the category objects' values.
- Eight fresh positive lookup queries and two negative invented-category
  namespace queries per role.
- Correct PIE runtime bias and Ghidra rebase normalization, source lookup,
  deterministic `.dbg`/`.dbg.c`, unchanged original/module/harness hashes and
  immutable project data (only documented index/journal backup rotation).
- GNU inspection, LLVM verification and the pinned strict checker. Inherited
  compiler-frame diagnostics require original-byte/diagnostic corroboration.

Local evidence lives under `build/same-name-types-runtime/collision`, with the
individual cases under `build/test-results/same-name-types` and
`build/test-results/namespace-globals-native`. Earlier failed setup/assertion
attempts are retained, not counted as passing cases: compiler enum display
includes namespaces, GDB cannot provide a typed `finish` result for a no-call
method, short imports are not cold indexed, and a raw-DIE checker must
distinguish root `item` from the intentionally retained conflicting child.

The reviewed local checkpoint includes twelve deterministic exports, 24
compiler/Forge method observations, sixteen isolated production artifacts,
seventeen collision model checks and 22 actual Java 21 suites with verified
production class origins. Twelve existing static-scope roles also pass across
x86-64, AArch64 and both MIPS byte orders. Four class/object and discontiguous
lexical regressions include genuine decompiler failure and copy cancellation.
The review rechecks raw DWARF, saved model identities, original/project/source
hashes, validator receipts and GDB values from the retained artifacts.

Tested JAR SHA-256:
`64c91bc6756cac18b9e471949563839fa53be30c39c2afccbbd3006c5c8ac36d`.
Local review receipt (`collision/acceptance.json`) SHA-256:
`18cd14d53e28c60d2afca75f474e96ad91f1c20fdf7a7295a7409f8aa50fe34d`.

## Reproduction and remaining gates

Use Ghidra 12.0.3 with the production extension installed, actual JDK 21 on
`PATH`, x86-64/AArch64 fixture toolchains, GDB multiarch, QEMU user, LLVM and the
pinned checker from `support/validation/README.md`:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew buildExtension globalScopeNamesSmoke
python3 src/test/integration/namespace-globals-native.py /path/to/packaged-ghidra x86_64
python3 src/test/integration/namespace-globals-native.py /path/to/packaged-ghidra aarch64
python3 src/test/integration/same-name-types-export.py /path/to/packaged-ghidra x86_64 --role exec
python3 src/test/integration/same-name-types-export.py /path/to/packaged-ghidra aarch64 --role pie-rebased
```

Run all three address roles on both targets. CI now includes the native lookup
controls and six saved-program roles, with `globalScopeNamesSmoke` in both host
model lists. **PRESENT, UNVERIFIED:** these new workflow steps still require the
combined branch's hosted gate. Existing required ARM32/MIPS lanes remain in
place; this fixture does not itself claim those new type cases on those targets.
Final combined package review, hosted acceptance, artificial-variable scope
audit and the remaining umbrella requirements stay open.
