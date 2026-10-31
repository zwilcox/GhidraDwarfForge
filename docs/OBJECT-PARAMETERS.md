# Explicit object parameters

**CONFIRMED locally; class ownership and hosted acceptance pending.** Ghidra
12.0.3's `AutoParameterType.THIS` now survives extraction as explicit parameter
metadata. A subprogram's `DW_AT_object_pointer` references that exact artificial
formal-parameter DIE. The reference is independent of whether a physical
location is available. Neither the name `this` nor `isAutoParameter()` alone
establishes object identity. Automatic parameters may have no database symbol.

The existing hidden return-storage carrier remains an artificial variable,
not an object parameter or an additional callable argument. Model validation
rejects conflicting object/return flags, duplicate object parameters and
non-indirection object types, including unresolved/cyclic typedef chains.
Qualified/typedef-wrapped pointers retain their canonical type identity.
External declarations can carry the same reference without gaining an address.
An actual source failure still emits a symbol-only function with no parameter
or dangling object reference. The CU remains synthetic C11.

The constant `DW_AT_object_pointer = 0x64` and existing
`dwarf_add_AT_reference_c` declaration were checked against the bundled
libdwarf 2.3.2 archive with SHA-256
`7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
No native binding or library change is required.

## Local acceptance

The isolated `ObjectParameterSmoke` runs on actual Java 21 before headless
export. It covers renamed object parameters, ordinary/artificial parameters
named `this`, invalid metadata, declaration-only references, deterministic
reruns and symbol-only failure. Raw reference checks require the target to be
the direct artificial formal child of its owner. Deliberately redirecting it
to the ordinary parameter or the owner itself must fail. GNU readelf, LLVM
verification and the pinned strict checker pass; inherited frame diagnostics
are corroborated against the original fixture.

The source-built `object-parameter.cpp` fixture imports compiler DWARF into
Ghidra, verifies the automatic object kind, and deliberately renames an
ordinary integer parameter to `this`. It saves the project and uses the
packaged production exporter through read-only reopen. The compiler runtime
oracle and Forge both execute the stripped binary with explicit symbol files.
No original DWARF or ELF symbols supply the Forge runtime values.

All six x86-64/AArch64 exec, PIE and rebased-PIE roles pass twelve production
exports. Each compiler/Forge run observes `this->value == 7`, `amount == 3`,
and the ordinary argument `41`; all processes exit successfully. Qualified
function lookup, source listing and type queries also pass. AArch64 runs under
QEMU. Raw references, target/build identity, validators, deterministic pairs,
read-only project contents and original hashes pass. QEMU's system-DSO warning
is matched to the compiler run. The existing real hidden aggregate-return
fixture also passes unchanged.

Nine relevant suites pass against the packaged production JAR on actual Java
21, with class origins verified. They cover lexical/range/location models,
canonical types, calling-policy copies, both isolated producer fixtures and
object metadata. Tested JAR SHA-256:
`51dbdb26b3fe55685695142df34fcfca16c881604735f45e52b440859538163f`.

Runtime receipt: `build/object-parameter-review/runtime-acceptance.json`,
SHA-256 `5abfbcd0809e5ee5627b8c793e1720867d36ffddcc24eead96e97649128e787f`.
The receipt binds the tested JAR and per-case raw artifacts. CI now includes
the model on both hosts and the six real target/address roles; those new
hosted checks have not yet run.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew objectParameterSmoke
python3 src/test/integration/object-parameter-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/object-parameter-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Run all three roles on both targets with the pinned `DWARFDUMP` from
`support/validation/README.md`. The isolated producer accepts the same six
consumer/producer/input/output/entry/size arguments as `LexicalScopeSmoke`.

Two initial test-fixture mistakes remain in local logs. Comparing outputs with
different filenames also compared intentionally different CU filenames; the
corrected determinism test repeats the same destination. The model's deliberate
cyclic typedef control was initially serialized in the positive fixture; the
strict checker correctly rejected its self-reference even though LLVM passed.
The corrected positive artifact excludes that invalid control. Neither failed
attempt counts as acceptance.

This component establishes the object-parameter relationship. Class-owned
method declarations, namespace/class type ownership, specification/origin
relationships, inferred statics and remaining same-name disambiguation are
still required by `LIFETIMES-AND-SCOPES-PLAN.md`. It introduces no new variable
location proof and does not complete either P1.11a or P3.3.
