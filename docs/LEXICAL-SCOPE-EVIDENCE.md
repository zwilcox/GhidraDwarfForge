# Explicit saved lexical evidence

**CONFIRMED provider implementation and local model validation; exporter hookup
and hosted acceptance pending.** `GhidraLexicalScopes` preserves analyst-recorded
lexical blocks and local ownership in the Ghidra program. It does not infer a
lexical tree from first-use offsets, suffixes, datatype categories or decompiler
formatting. See `research/SCOPE-EVIDENCE.md` for the API evidence behind this
choice. The provider is not yet consumed by the production exporter, so this
checkpoint does not emit lexical DIEs or claim GDB shadow lookup support.

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
No ELF/DWARF emission changes occur yet, so the provider tests do not substitute
for structural validators or GDB behavior tests of the forthcoming hookup.

Retained setup failures: the first Java 21 launcher selected Gradle's Java 25
test classfiles and failed before running tests. The corrected launcher compiles
test sources with the actual Java 21 compiler. A subsequent origin auditor
mistakenly treated dynamically generated lambda classes as JAR entries; its
models passed, but the audit did not. The final auditor validates each lambda's
owner and the four concrete classes' exact JAR origin. Both failed attempts are
retained under the evidence directory and excluded from final acceptance.

## Required continuation

**PLANNED:** normalize the validated evidence at the ELF serialization boundary,
associate it with exported canonical locals, restrict locations to lexical
visibility, and emit lexical-block DIEs with exact contiguous/discontiguous
ranges. Reject evidence referring to a local omitted or coalesced by extraction;
do not silently assign another object's location. Preserve symbol-only behavior
on genuine decompiler failure. Add real exporter/GDB fixtures for shadow lookup,
unavailable gaps, stale metadata, saved-program reopen and rebasing, then run
the structural validators, preservation/determinism/cleanup tests and hosted
matrix. Namespace/class/object, inferred statics, alias/origin and same-name type
relationships remain the other required P3.3 components. Neither umbrella is
complete at this checkpoint.
