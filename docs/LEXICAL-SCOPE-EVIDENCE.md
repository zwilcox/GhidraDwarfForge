# Explicit saved lexical evidence

**CONFIRMED locally: provider, extraction and initial lexical DWARF/GDB tests;
full scope and hosted acceptance pending.** `GhidraLexicalScopes` preserves
analyst-recorded lexical blocks and local ownership in the Ghidra program.
It does not infer a lexical tree from first-use offsets, suffixes, datatype
categories or decompiler formatting. See `research/SCOPE-EVIDENCE.md` for the
API evidence behind this choice. The production exporter now consumes this
explicit evidence; the validation bounds below do not complete P3.3.

The public `save(function, evidence, blocks, locals, monitor)` operation runs in
the caller's program transaction. `read(function, monitor, diagnostic)` only
reads; absent evidence returns an empty result without creating a property map.
The map is `GhidraDwarfForge.LexicalScopes.v1`, anchored to the function's entry.
It changes only the saved Ghidra program, not the original executable.

A block has an explicit identity, parent identity and copied AddressSet. An empty
parent denotes the function. Local bindings identify actual saved local symbols
and their block, with an explicit display spelling. Two locals can therefore
both display `shadow` in different nested scopes without renaming either saved
listing variable. Binding a display spelling does not establish storage or a
live range. Location extraction must continue to prove those separately.

The record retains the function symbol ID and local symbol IDs, saved names,
canonical datatype IDs/paths, byte sizes, first-use offsets and serialized
storage. A changed binding is diagnosed and the entire record is omitted;
it is never partially applied. In-place changes to a canonical datatype do not
invent a new identity; downstream extraction still exports its current layout.
Block ranges must remain within the current function body and their parent.
Cycles, missing/duplicate identities, ambiguous sibling overlap, duplicate local
ownership and same-scope name conflicts (including unbound locals and parameters)
are rejected. Nested equal display spellings are intentional shadowing.

Ranges remain Ghidra addresses during validation. Only persistence converts
endpoints to reversible signed offsets relative to the function entry, including
ranges below entry. Ghidra rebases the property anchor; the payload remains
unchanged and resolves back to current AddressSets. Defensive copies protect
block bounds from caller mutations. List ordering is canonical, with parents
before children, independently of caller input order.

The versioned binary envelope has explicit counts and bounds: 4,096 blocks,
16,384 bindings, 65,536 total ranges and 8 MiB of decoded payload. Unknown
versions, malformed/truncated/trailing data, invalid counts and incompatible
property-map types are rejected. Reads retain the stored data for inspection.
Saves validate and encode completely before replacing a record. Cancellation
propagates during validation and parsing and before publication; an existing
record survives a failed or cancelled save. No native calls were added.

## Validation

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC \
    ./gradlew lexicalScopeEvidenceSmoke buildExtension
```

`LexicalScopeEvidenceSmoke` uses real ProgramDB functions and variables on
x86-64, AArch64, ARM32 and both MIPS32 byte orders. Its 430 checks include nested,
discontiguous and below-entry blocks, immutable address ownership, deterministic
encoding, shadowed names, parent/body/identity conflicts, renamed or retyped
locals, changed first-use offsets, malformed records, wrong property-map types,
immediate and mid-record cancellation, actual image-base changes and reopening
an immutable database. Reopened file bytes and timestamps remain unchanged.
The test is registered in both Linux and Windows CI model lists; this is not
new architecture runtime support.

The extension build and all model checks pass locally. The Gradle process uses
Java 25 with Java 21 production bytecode. A separate actual Java 21.0.13 run
compiles the test with Java 21 and loads all four provider classes from the
production JAR, with their origins and source hashes checked. Receipt:
`build/lexical-evidence-review/acceptance.json`, SHA-256
`f645ab9025699df0e5282994f2746fa5a28f8ad0e75a772a0e697942ad12614c`.
Tested JAR SHA-256:
`fce89e03ab9ae7034e7d2ffc355516658ee993c8d93b4a1213992aae99f7dff2`.
Architecture neutrality, its seven negative controls and workflow lint pass.
That provider-only checkpoint did not emit ELF/DWARF. Its evidence is distinct
from the subsequent extraction/emission checkpoint below.

Retained setup failures: the first Java 21 launcher selected Gradle's Java 25
test classfiles and failed before running tests. The corrected launcher compiles
test sources with the actual Java 21 compiler. A subsequent origin auditor
mistakenly treated dynamically generated lambda classes as JAR entries; its
models passed, but the audit did not. The final auditor validates each lambda's
owner and the four concrete classes' exact JAR origin. Both failed attempts are
retained under the evidence directory and excluded from final acceptance.

## Extraction and emission checkpoint

**CONFIRMED locally:** extraction matches each saved binding to exactly one
canonical exported local by saved name and first-use identity. Missing or
coalesced bindings omit the entire scope record with a diagnostic. AddressSets
are normalized to original ELF addresses only when building `LexicalScopeModel`.
The model keeps physical location identity separate from the explicit display
name, intersects locations with block visibility, and preserves unavailable
initialization gaps. Repeated call-policy cloning does not extend a location.

Lexical DIEs use their recorded parent, a low/high pair for one interval, or
DWARF 5 range lists for multiple intervals. The CU address index still describes
function coverage. Symbolic relocation validation includes the addresses of
actually emitted contiguous blocks. Failed source functions take the existing
symbol-only path; additional genuine-failure scope validation remains required.

The isolated native test emits an outer block beginning after function entry
and a discontiguous inner block. This distinct start caught a real missing
relocation-expectation update; a block starting at function entry alone did not
expose it. `LexicalScopeModelSmoke` passes 105 ownership, clipping, raw range
encoding and negative checks, including both widths/byte orders and rejection
of 32-bit truncation. Seven model suites and the isolated producer pass against
the packaged production JAR on actual Java 21, with class origins checked.
GNU/LLVM and the pinned strict validator accept the isolated output; two
inherited frame diagnostics match the original input.

All six x86-64/AArch64 exec/PIE/rebased-PIE runtime roles pass with twelve real
exports and 138 instruction observations. Compiler GDB establishes distinct
stack slots and values 11/23/11. Explicit analyst metadata supplies the lexical
bounds. Forge GDB selects the inner name before initialization but reports it
unavailable, selects 23 while live, restores outer 11 after the inner block,
and omits the name outside the outer block. Checks include raw instruction and
stack bytes, exact emitted DIE parents/bounds, four wrong-bound negative
controls, function address-index coverage, validators, source lookup, zero exit
status, unchanged original inputs and byte-identical output pairs. Read-only
reopen preserves saved program contents; only Ghidra's known index/journal
backup files may rotate. AArch64's system DSO string-index warning is matched
to the compiler-reference run; it is not attributed to the sidecar.

Reproduce with a freshly assembled extension installed in a private Ghidra
12.0.3/Java 21 installation and the pinned `DWARFDUMP`:

```bash
./gradlew lexicalScopeModelSmoke dwarfRangeListsSmoke dwarfLocationListsSmoke
python3 src/test/integration/lexical-shadow-export.py /path/to/private-ghidra x86_64 --role exec
python3 src/test/integration/lexical-shadow-export.py /path/to/private-ghidra aarch64 --role pie-rebased
```

Run all three roles on both targets. The workflow now includes those six cases
and the new model suite in both host model lists; hosted results are pending.
Evidence is in `build/lexical-emission-review/{java21-acceptance,runtime-acceptance}.json`.
Tested JAR: `0de88a56a47db2fdfb2509419a1fb1299511ca17010e9fcd49e61899d1a858b3`.

Retained failures include native test constructor/Gradle argument setup errors,
a headless fixture cast error, the missing lexical relocation expectation,
and an unnecessary storage-model replacement caught by the compiler-call
regression. The first snapshot check included rotating project backup files;
the corrected check uses the established narrow backup exception. An initial
fixture wrote globals, which conservatively retired stack facts under the
existing memory-alias policy; the lexical fixture now accumulates in a proven
separate stack slot. This checkpoint does not claim improved global-store
non-aliasing. A supplementary log auditor initially mistook a displayed
synthetic-source warning comment for a debugger diagnostic; it now checks
actual diagnostic lines. Failed attempts are retained, not counted as passes.

## Discontiguous visibility and failure controls

**CONFIRMED locally; final package/hosted acceptance pending:** the discontiguous
fixture records an explicit analyst visibility gap around one effect-free
instruction. The original compiler source block stays continuous, and compiler
GDB sees 23 there. The analyst explicitly narrows that visibility: Forge GDB
must select the outer 11 in the gap and return to inner 23 afterward. This tests
preservation of saved analyst knowledge; it does not misrepresent the gap as an
original compiler fact. All six target/address roles pass with exact range-list
and location-list bounds, including exclusion of the gap and initialization
prefixes. Six wrong-bound controls reject altered expectations.

Two exporter controls exercise full records. Renaming the saved inner local
makes its fingerprint stale: the entire scope record is diagnosed and omitted,
while current saved names/types/physical locations remain available. A valid
binding to a local subsequently coalesced by Ghidra is also diagnosed and
omitted; it never borrows the surviving object's identity. The intentionally
unproved merged register definitions remain unavailable. Reopening the untouched
saved program reproduces the baseline output pair byte for byte.

A native decompiler instruction limit of one causes the actual decompiler to
return `Flow exceeded maximum allowable instructions` for the scoped function.
Restoring the default options lets later functions decompile successfully. The
failed function retains its symbol and address but has no lexical/local/type or
source-line attributes. GDB can break in it, and the synthetic source contains
the failure diagnostic. Repeated failure exports are deterministic.

This test caught a production bug: although the failed function's DIE children
were suppressed, its location lists remained serialized. GNU reported 146 unused
bytes. Range/location planning and DIE emission now share the same selection of
emitted signatures, suppressing orphan lexical and location lists. Intentional
source omissions remain distinct from actual failures. The isolated producer
regression asserts that an otherwise contiguous symbol-only function emits no
orphan `.debug_loclists` or lexical `.debug_rnglists`. Both isolated outputs pass
GNU/LLVM/pinned structural checks on actual Java 21.

Cancellation uses a separate, source-built enlarged input imported with its own
correct SHA-256 and saved scope metadata. The real installed export entry point
cancels after 16 MiB of copying. It retains the previous artifact pair, leaves
no temporary files, and preserves both original and enlarged input bytes. An
initial attempt to use an enlarged copy with the smaller input's saved program
was correctly rejected by the imported-input hash guard. The test was corrected
by importing the copy separately; the guard was not weakened.

All six x86-64/AArch64 exec/PIE/rebased roles pass the positive, stale/coalesced,
actual-failure and cancellation cases. That is 42 candidate exports and six
cancelled attempts. The previous-package comparison additionally demonstrates
that the older flat declarations selected outer 11 in the inner block, while
the candidate selects the explicitly bound inner 23. The tested production JAR
is `c1452faf3e8a64f6c36320edf509513a5f7e223267d7bd8cee15ceb9b6e4de88`.
Evidence is retained in `build/lexical-controls-review`, including the isolated
Java 21 suites, six-role logs and raw validators. Thunk regressions on both
targets, all three x86-64 static-local address roles and the x86-64 aggregate
return fixture pass. Existing ABI/source omission behavior is retained.

```bash
python3 src/test/integration/lexical-shadow-export.py /path/to/private-ghidra x86_64 --role exec --discontiguous --controls
python3 src/test/integration/lexical-shadow-export.py /path/to/private-ghidra aarch64 --role pie-rebased --discontiguous --controls
python3 src/test/integration/lexical-shadow-previous.py /path/to/completed-case /path/to/pre-lexical-ghidra
```

Run all three roles on both targets. The current workflow runs both contiguous
and discontiguous/control variants. Prior-package comparison is a local review
step requiring the documented pre-lexical package, not an implicit CI download.

## Required continuation

**PLANNED:** final package review, any remaining broader regression coverage and
the exact hosted integration gate. Complete namespace/class/object, inferred
statics, alias/origin and same-name type relationships, plus all remaining
lifetime integration requirements. Neither umbrella is complete at this
checkpoint. The passing local lexical component does not complete P3.3.
