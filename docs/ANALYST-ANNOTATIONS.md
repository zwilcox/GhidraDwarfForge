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
