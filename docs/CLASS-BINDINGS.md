# Explicit saved class layouts

**Current extraction checkpoint:** `CLASS-SCOPE-EXTRACTION.md` supersedes the
extractor-pending notes below. The provider/model evidence here retains its
original component scope; native class emission and hosted acceptance remain
pending.

**CONFIRMED provider component; extraction and class emission remain PLANNED.**
`GhidraClassBindings` saves an analyst's explicit class/layout relationship in
the Ghidra program. It separates durable identity from Ghidra's category/name
search for the current automatic THIS type. See `research/CLASS-LAYOUT.md` and
`CLASS-SCOPE-MODEL.md` for the evidence and ownership model.

Call `save(program, owner, structure, evidence, monitor)` inside a program
transaction. Both objects must belong to that program; the structure must be
saved. The record stores the class symbol ID, datatype ID, datatype universal
ID and bounded provenance text. It does not freeze names or layout. Renaming,
moving or intentionally editing the same class/type preserves the binding;
deletion and replacement do not. Export reads must never create or repair a
record. Explicit `remove` forgets the binding, and explicit `save` can replace
a malformed string record. An incompatible option type requires explicit
removal first.

The versioned binary payload is Base64-encoded with `GDFCB1:` under the flat
program-options group `GhidraDwarfForge Class Bindings v1`. Keys use class IDs,
not names. Decoded payloads are limited to 32 KiB and provenance to 8,192 Java
characters, with nonblank text and no NUL. Reads distinguish ABSENT, VALID and
REJECTED. A rejected explicit record is not permission to fall back to an
inferred layout. Cross-class and current-method conflicts still require
collector/model validation; this provider only validates each saved record.

## Validation

`ClassBindingEvidenceSmoke` passes 400 checks on real ProgramDB instances for
x86-64, AArch64, ARM32 and both MIPS32 byte orders. Cases include numerically
colliding foreign-program identities, distinct same-name types, preference
changes, rename/reparent/layout edits, rebasing, malformed/stale/incompatible
records, bounded multibyte text and cancellation at every provider checkpoint.
Immutable database reopen preserves file hash and modification time.

Eleven relevant suites pass on actual Java 21 using the current production
JAR, with class origins checked. Four existing isolated lexical/object
producer artifacts, including symbol-only failures, pass GNU/LLVM/pinned
strict validation. These are emission regressions; the new provider is not
yet called by extraction. Its task is in both host CI lists, whose new gate
remains pending.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew classBindingEvidenceSmoke buildExtension
```

Local receipt: `build/class-binding-review/acceptance.json`, SHA-256
`8b4aca954d27bb3bc90d6fffe4b1fbf2d1280456647c2cb948407ab5d1c904b4`.
Actual Java 21 commands and logs are retained beside that receipt. The initial
test compile error and a rejected nested-options implementation are retained
in `build/class-binding-*.log`. Dots delimit nested option groups, so the
uncommitted dotted group did not pass the read/absence test; the flat group
above passes all checks. Those failures are not acceptance evidence.

Next, collect actual saved namespace/class/method ownership and reconcile
explicit records with current object-parameter types. Connect that model to
the validated declaration/specification layout and prove real GDB behavior.
All rows in `LIFETIMES-AND-SCOPES-PLAN.md` remain required.
