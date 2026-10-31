# Class layout and association evidence

**CONFIRMED research; production class ownership is still PLANNED.** This
checkpoint follows the explicit object-parameter implementation. It selects a
consumer-compatible declaration layout and investigates class/type association.
It does not count as native producer or real exporter acceptance for classes.
Ghidra 12.0.3, Java 21 and synthetic C11 remain the supported baseline.

## C11 declaration layout

The probe builds the existing C++ scope fixture for x86-64 and AArch64 and edits
only task-owned separate-debug copies. It removes linkage-name semantics and
all executable ELF symbol-table payloads that could hide failed DWARF lookup.
The reference and stripped runtime executable remain unchanged. Modified C11
cases use a `.c` filename so GDB's automatic language stays C at the stop; the
research source view still contains C++ text and is not Forge-generated source
or a claim that the text compiles as C.

All fourteen target/layout combinations pass LLVM and the pinned strict
checker, raw readelf inspection and actual GDB/QEMU execution. Every run reads
object member `7`, argument `3` and the distinct same-name-type globals `5` and
`9`. The two selected root-definition layouts additionally pass raw class,
namespace, declaration, specification and object-reference tree checks, with
eight deliberately incorrect ownership/reference controls rejected.

| Layout, both targets | Qualified method lookup/breakpoint | Class display consequence |
| --- | --- | --- |
| Original C++ | Pass | Compiler reference only. |
| C11, with or without linkage name | Fails, explicitly asserted | Leaf class and method display survive, but required qualified lookup does not. |
| C11, qualified name on method declaration | Pass | Class displays the full qualified method name instead of its leaf name. |
| C11, qualified declaration and class names | Pass | Leaf class type lookup disappears. |
| C11, leaf declaration plus qualified root definition | Pass | Existing leaf class type lookup and leaf method display both survive. |
| C11, same root definition plus qualified class name | Pass | Qualified class lookup works, but existing leaf class lookup disappears. |

**Selected initial layout:** keep the definition at CU scope with its existing
qualified `DW_AT_name`; reference a leaf-named class-owned declaration using
`DW_AT_specification`. Keep the canonical class type's existing display name
when a defensible class/type association is established. Keep C11 and do not
invent a linkage name. Raw parent relationships provide the namespace/class
semantics; qualified display names continue to provide tested C lookup.

This choice does not settle every same-name type case. Renaming all class types
would break existing lookup, so the full plan still requires explicit
disambiguation and tests. A declaration/definition reference must be tied to
the same saved method identity, never inferred from matching names or addresses.
Failed decompilation must retain the existing symbol-only policy.

## A THIS pointee is not a durable class/type key

The installed-source audit follows `FunctionDB.updateParametersAndReturn()`
through `VariableUtilities.getAutoDataType()` into
`findOrCreateClassStruct()` and `DataTypeUtilities.findExistingClassStruct()`.
The selected type depends on preferred category and name matching. Missing
types can produce a placeholder. Thunks can also recompute their automatic
object type for their own owner. `GhidraClass` does not expose a persistent
canonical datatype association.

The independent headless association probe creates one research class and two
distinct same-named structures. On both x86-64 and AArch64, changing only the
preferred category selects a four-byte type, then an eight-byte type, then the
original four-byte type. Class and method IDs stay unchanged, the type IDs are
distinct, and `AutoParameterType.THIS` remains present throughout. The initial
missing-category case produces a placeholder. The imports are read-only and
discarded; no saved analyst project or original executable is modified.

This does not invalidate exporting Ghidra's current parameter type. It does
mean that type must not silently become a permanent or original-source
class/type identity. Preserve the distinction between:

- Actual saved method/class/namespace ownership, which can be read directly.
- Ghidra's current automatic object type, which includes inference and may
  change when preferences change.
- An explicit analyst class/type binding, which needs persistent IDs,
  provenance and stale/conflict validation when the APIs do not provide it.

**Next implementation:** represent these ownership relationships separately
from type identity. Add an explicit binding path for canonical class layout;
retain provenance for any use of the current automatic object type. Test
conflicting candidates, placeholders, renamed types/classes, rebasing,
read-only reopening and unsupported evidence without inventing a relationship.
The eventual exporter must preserve existing analyst lookup and object values,
then satisfy the remaining class, static, alias and same-name requirements.
Do not redefine completion as opaque class declarations alone.

## Reproduction and receipts

```bash
DWARFDUMP=/path/to/pinned/dwarfdump python3 src/test/research/class-layout/probe.py build/class-layout-new
python3 src/test/research/class-layout/association-probe.py /path/to/ghidra-with-java21 build/class-association-new
```

Output directories must be new. Prerequisites match `SCOPE-EVIDENCE.md`, plus
the pinned strict checker described in `support/validation/README.md`.

- Layout: `build/class-layout-final/observations.json`, SHA-256
  `3d52d03672a94e0d3d7f8df19a098d2fb8d6ef0d3b3af335453ada5480e84ad2`.
- Association: `build/class-association-final/acceptance.json`, SHA-256
  `02b5d023f87a2c14a2262bc8186ee9047ba15dcce467967b02b3b3a7add58510`.

The receipts bind input/probe hashes, observations and audited API source
hashes. Commands and all validator/GDB/headless logs are retained nearby.

Historical attempts are retained, not counted as acceptance. The earliest
probe retained ELF symbols and `.cpp` filenames, allowing symbol fallback and
automatic C++ to confound C11 conclusions. A later guard incorrectly rejected
an empty NOBITS `.dynsym`; another forced C while the filename still selected
C++, producing a language warning. The first strict run additionally found
that objcopy's empty NOBITS `.eh_frame` headers could be read as unrelated bytes.
The corrected research copies remove those empty frame headers; the runtime
original still supplies its unchanged unwind data. None of these corrections
changes the production sidecar packaging strategy or relaxes its validators.
