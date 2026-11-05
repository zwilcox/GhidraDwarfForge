# Analyst annotations and optional instruction context

**PLANNED:** issues #116/#114 will preserve listing comments and equates in
synthetic source and debugger lookup, with optional assembly/p-code context.
The production exporter does not yet implement these features. Issue #108
remains the integration priority; this isolated branch prepares their fixtures.

**CONFIRMED fixture preparation:** `analyst-annotations.c` builds deterministic
PIE/non-PIE compiler references for x86-64, AArch64 and both MIPS32 byte orders.
GNU inspection, LLVM verification, pinned strict checks and actual native/QEMU
GDB pass eight cases, each with sixteen exact value/width observations. PIE
checks observe nonzero runtime load bias. Compiler/global/local/type/enum names
provide conflicts for later equate-lookup tests. The preparation script now
explicitly applies the global, structure and enum type and saves the conflicting
local in a separate function. Its stack offset comes from actual compiler GDB
observations relative to entry SP, and its first-use offset is the observed live
marker. No architecture-specific storage offset is guessed. This fixture
curation does not claim automatic recovery from stripped input.

`PrepareAnalystAnnotations.java` applies fifty comments across ten addresses
and all five categories, including instruction interiors, an explicit function
body gap, data, overlays, unmapped memory, external, register and stack spaces.
It adds fourteen equates with raw signed/unsigned extrema, Unicode, conflicting
names, malformed enum metadata, two one-byte enums sharing a display name, and a
dynamic-only reference to the folded four-byte constant `53` (`19 + 23 + 11`).
Four saved-program cases pass two independent read-only reopens with identical
observations. The original ELF files remain unchanged. Ghidra may rotate index
and journal backups on the first reopen; the second changes no project files.

The MIPS fixture exposed a required extraction detail: `AddressMapDB` masks
stack offsets to unsigned 32-bit keys, but does not split a non-memory range
whose signed minimum encodes above its maximum. A single full signed range
therefore missed existing comments. The preparation reader uses separate
negative and nonnegative scans in the database's encodable offset domain;
merging those scans into one AddressSet would reintroduce the omission. This
is a pinned Ghidra database constraint, not a target register or ABI assumption.
The complete scanned address count must still match `Listing.getCommentAddressCount()`.

PIE preparation translates compiler link-time addresses using the original
minimum load-segment virtual address and the actual Ghidra image base. Direct
use of compiler addresses failed on the AArch64 PIE fixture and is not accepted.

Run compiler preparation with the pinned strict checker selected by `DWARFDUMP`:

```bash
python3 src/test/integration/analyst-annotations-reference.py x86_64
python3 src/test/integration/analyst-annotations-reference.py aarch64 --role pie
python3 src/test/integration/analyst-annotations-prepare.py "$GHIDRA_INSTALL_DIR" /path/to/reference-case
```

The last command requires Java 21 and creates a new private project for each run.
It does not modify an existing analyst project. The script directory is isolated
so unrelated integration scripts need not compile against the selected install.

The [fixture receipt](evidence/annotation-fixture-preparation.json) records exact
commands/results, hashes, retained exploratory failures and limitations. ARM32
is present in the harness but unverified locally because its compiler is absent
from the current PATH. The [dynamic-reference receipt](evidence/annotation-dynamic-reference.json) adds
exact native-decompiler hash/value resolution on all four saved-program cases.
The stored operand index stays `-1`, and no decoded-instruction constant hash
claims this reference. Its scope is decompiler evidence, not original source
syntax or a proved C type. Production extraction/composition, complete named-constant
policy, genuine decompiler failure, cancellation and full
exported-artifact/GUI/headless tests
remain required. These fixtures do not close either issue.

The [saved-conflict receipt](evidence/annotation-saved-conflicts.json) extends the
fixture with a separate `annotation_conflicts` function so naming its local does
not disturb the probe's folded constant53. It records all eight compiler cases,
four complete saved-program cases and the preserved inputs. Readback requires
USER_DEFINED local provenance, exact storage/first-use/width, the applied
structure/member, enum member/value and real global label/value. The initial
constructor compilation error and nondeterministic test-JSON field order remain
in the evidence archive; corrected runs pass. This establishes collision inputs
for later real exporter/GDB tests, not the constant-name policy itself.

The [native-failure receipt](evidence/annotation-native-failures.json) proves the
reserved function can genuinely fail decompilation on all four saved-program
profiles using a one-instruction native budget. All five comments remain readable
through the listing API. Restoring the budget on the same interface recovers the
identical normal output. A separate pre-cancelled invocation returns no source,
and that interface also recovers. Two independent reopens have byte-identical
observations and change no project files. Run against a successful curation case:

```bash
python3 src/test/integration/analyst-annotations-failures.py "$GHIDRA_INSTALL_DIR" /path/to/curation-case
```

This is a reusable native failure fixture, not a production exporter acceptance
test. In-flight export cancellation, atomic cleanup, symbol-only failed output
and validator/GDB checks of the resulting diagnostic source remain required.

The [name-policy experiment](evidence/annotation-name-policy.json) consumes the
actual saved equate records and produces an independent synthetic constant unit
through the audited producer. GDB loads this alongside the original compiler
DWARF: 528 exact value/width/read-only checks pass in two real frames across four
profiles, with the original conflicting local/global/type/enum names intact.
The catalog provides stable ASCII aliases and file-qualified lookup. Only the
unique validated enum display `ANNOTATION_NEGATIVE` gets direct lookup in this
fixture; duplicate or conflicting names retain aliases. Signed stored values,
unsigned stored bit patterns, enum widths and dynamic unsigned bits remain
explicitly distinct views.

All four experimental sidecars pass GNU/LLVM/pinned strict validation and are
byte-identical across independent producer processes. AArch64 GDB's system-DSO
string-table warning also appears identically with only the compiler symbols;
the receipt retains that control. The candidate is not the complete production
name collector or exporter. Full real-name reservation, keyword/reference
conflict handling, source composition and production acceptance remain required.

`AnnotationText` is now a tested component for one physical comment-text field.
It preserves printable Unicode exactly, doubles literal backslashes, represents
CR/LF/tab and other controls reversibly, and uses hexadecimal escapes for unsafe
delimiters, trigraph adjacency, display controls and isolated UTF-16 surrogates.
It does not normalize names or silently truncate text. A checked encoded UTF-8
byte budget and cancellation callback apply throughout encoding. The caller must
still provide comment framing, placement and the aggregate export budget.

The [text receipt](evidence/annotation-text.json) records 65,659 independent
round-trip/budget cases including every UTF-16 code unit and all fifty saved
comments, 24 cancellation checkpoints and a GCC C-lexer corpus with trigraphs
and warnings-as-errors. The Gradle smoke task and extension build pass locally;
the task is wired into both host validation commands, with hosted execution
pending. No production emitted source or DWARF path uses the component yet. Production
source-line remapping, readable annotation composition and actual GDB stepping remain
required before claiming production support.

`AnnotatedSourceFile` now composes text and line evidence together as a separate
component. A statement insertion must cite an address already present in that
line's executable token evidence; callers must also prove the annotation belongs
there. Unmapped/uncertain records use the trailing catalog. Multiline text retains
explicit original separators while displaying one payload row per original line.
Function boundaries, declaration rows and token rows shift together. Inserted
comment rows receive no addresses. Duplicate identities and unsupported placement
fail explicitly, and the final UTF-8 byte bound includes all comment framing.

The [composition receipt](evidence/annotation-composition.json) verifies exact
source restoration after removing inserted rows, independent payload decoding,
unchanged address populations through the line writer, deterministic ordering,
538 cancellation checkpoints and negative/budget controls. GCC and Gradle pass.
This is component evidence; production extraction/composition and complete
validator/GDB source-stepping acceptance remain required.
