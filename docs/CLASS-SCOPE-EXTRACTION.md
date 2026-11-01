# Saved class ownership extraction

**CONFIRMED native emission checkpoint:** the extracted graph now feeds
class declarations, canonical definitions and identity-bound method
specifications. See `CLASS-SCOPE-EMISSION.md` for first-lookup corrections,
local acceptance and remaining scope/hosted requirements. The earlier
extractor-only statements below describe that historical component.


**CONFIRMED extraction component; native class emission remains PLANNED.**
`GhidraTypeGraph` now supplies `ProgramTypeModel.classScopes` from actual saved
Ghidra relationships. `GhidraClassScopes` records selected image methods and
curated external declarations using their saved function IDs and exact model
references. Image addresses use the existing ELF normalization; external
declarations retain an identity key and no image address.

Class parents and ancestor namespace/class IDs come from Ghidra, not parsing
qualified names. Nested classes retain their parents. An external library is a
linkage container, not a source namespace, so it terminates source ancestry;
the existing qualified external display name remains unchanged. Unsupported
ancestry through a function scope is diagnosed rather than flattened. No
declaration is invented for an image method excluded from the export.

Explicit class/layout records are read through `GhidraClassBindings`, and their
types join the canonical graph before it is drained. An explicit binding can
describe a class with only static methods or no selected methods. Otherwise,
the current automatic object parameters can establish an inferred snapshot,
with provenance explicitly distinguishing it from durable or original-source
identity. Empty/generated placeholder types do not establish an inferred
member layout; explicit empty-class bindings remain possible.

Rejected explicit records block inference fallback. Conflicting method object
types or an explicit layout that disagrees with the current object type omit
the layout association, retaining the recorded method ownership and current
signature types. A canonical layout cannot belong to multiple classes. One
explicit owner takes priority over competing inferred owners; multiple
explicit owners, or multiple inferred owners with no explicit choice, are
diagnosed and omitted. No parameter type or saved binding is silently changed.

## Validation

`ClassScopeExtractionSmoke` exercises the production extractor on actual
ProgramDB instances for x86-64, AArch64, ARM32 and both MIPS32 byte orders.
All 290 checks pass, including placeholder/explicit/inferred layouts, stale
records with a valid inference available, contradictory types, competing
owners, distinct same-name layouts, static methods, nested ownership,
addressless externals, literal `::` spelling, selected-function filtering,
rebasing, cancellation throughout collection and deterministic immutable
reopen. Database bytes and modification time remain unchanged by reopening.

Twelve relevant suites pass on actual Java 21 with production class origins
checked. Four existing isolated lexical/object producer artifacts, including
symbol-only failure variants, pass GNU/LLVM/pinned strict validation. Real
x86-64 and AArch64 object regressions pass four candidate exports, structural
validators and compiler/Forge GDB values. Two previous-package exports of the
same saved projects at the same destinations produce byte-identical output
pairs. These are regressions of existing emission: the native writer does not
yet emit the newly collected class ownership.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew classScopeExtractionSmoke buildExtension
```

Both host CI lists include the new suite; hosted acceptance is pending.
Commands and artifacts are retained under `build/class-extraction-review`.
Acceptance receipt SHA-256:
`b116c07a4bd9cf26aa5e4657d0c95bf144a80a54eff2dc6a0b481b9ecf053f0a`.

Next, emit the class-owned declaration and qualified root definition layout
proved in `research/CLASS-LAYOUT.md`, using saved method identity for the
specification reference. Reconcile canonical type display with actual class
scope names and test same-name lookup, explicit binding conflicts and genuine
decompiler failure in GDB. Class emission, other P3.3 rows and all remaining
lifetime integration gates remain required.
