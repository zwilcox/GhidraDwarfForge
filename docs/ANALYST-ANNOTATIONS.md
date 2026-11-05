# Analyst annotations and optional instruction context

**PLANNED:** issues #116/#114 will preserve listing comments and equates in
synthetic source and debugger lookup, with optional assembly/p-code context.
The production exporter does not yet implement these features. Issue #108
remains the integration priority; this isolated branch prepares their fixtures.

**CONFIRMED fixture preparation:** `analyst-annotations.c` builds deterministic
PIE/non-PIE compiler references for x86-64, AArch64 and both MIPS32 byte orders.
GNU inspection, LLVM verification, pinned strict checks and actual native/QEMU
GDB pass eight cases, each with fourteen exact value/width observations. PIE
checks observe nonzero runtime load bias. Compiler/global/local/type/enum names
provide conflicts for later equate-lookup tests; their existence in compiler
DWARF does not mean the stripped Ghidra program has recovered all those names.

`PrepareAnalystAnnotations.java` applies fifty comments across ten addresses
and all five categories, including instruction interiors, an explicit function
body gap, data, overlays, unmapped memory, external, register and stack spaces.
It adds thirteen equates with raw signed/unsigned extrema, Unicode, conflicting
names, malformed enum metadata and two one-byte enums sharing a display name.
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
from the current PATH. Production extraction/composition, complete named-constant
policy, dynamic-only references, saved local/type collision curation, genuine
decompiler failure, cancellation and full exported-artifact/GUI/headless tests
remain required. These fixtures do not close either issue.
