# Analyst aliases without an ELF section table

**CONFIRMED locally (2026-10-31); committed-package and hosted acceptance pending.**
P1.7/#66 remains open. This extends the existing bounded alias policy to
program-header-only ELF inputs; it does not infer missing original section names.

## Problem and policy

Adding a static symbol table to a sectionless ELF can hide original dynamic
symbols from GDB. Four MIPS PIE/rebase experiments reproduced that loss. The
exporter now obtains a complete, bounded dynamic inventory before adding aliases,
preserves every original record in a static mirror, and inserts the analyst's
local symbols at the local/global boundary. Original input bytes remain intact.
See the preceding [consumer experiment](research/SECTIONLESS-FUNCTION-ALIASES.md).

`PT_DYNAMIC` virtual pointers must resolve uniquely to file-backed `PT_LOAD`
ranges. SysV hash counts, nonempty GNU hash chains and the isolated MIPS
`DT_MIPS_SYMTABNO` count must agree when present. An empty GNU hash is insufficient:
a real fixture has `symoffset=1` but three dynamic symbols. Neither neighboring
pointers nor relocation indices supply a guessed count. An absent `PT_DYNAMIC`
requires no mirror; an incomplete or unsupported inventory diagnoses and omits
aliases while primary DWARF export remains available.

The shared load-allocation helper assigns the same synthetic section indices to
the mirror, alias planner and writer. Defined symbol indices map to the unique
complete load allocation; undefined, absolute and common entries retain their
semantics. Large synthetic indices use `SHT_SYMTAB_SHNDX`. Each alias still needs
unchanged original executable bytes, unambiguous recovered ownership and a
collision-free name. Memory-only load tails cannot prove executable bytes.
Discontiguous bodies retain the preceding per-range checks.

GNU definition versions use the existing shared name decoder. Their qualified
names survive in the static mirror; the original dynamic bytes remain unchanged.
Unqualified GDB lookup is not promised to follow the loader's default version:
the V1-default fixture reproduces the same disagreement in compiler DWARF.

## Bounds and omissions

- At most 262,144 dynamic symbols; bounded hash and version chains.
- Existing 16 MiB name/dynamic and 64 MiB table limits; 128 MiB aggregate reads,
  16 million allocation comparisons, cancellation checks and 64 KiB I/O chunks.
- Source identity is checked before and after inventory reads; publication uses
  the existing transactional output path.
- Duplicate critical tags, inconsistent counts, overlapping mappings, malformed
  chains, unsupported reserved indices and defined TLS symbols are diagnosed.
  TLS-relative symbol placement requires a separate policy.
- Classic MIPS mode checks inspect sectionless dynamic code symbols; unverified
  processor-specific mode bits and tagged addresses prevent alias insertion.

This does not establish ARM/Thumb or i386 aliases, arbitrary MIPS modes, inferred
aliases, alias-owned lexical scopes, or broad floating/aggregate call ABI
support. Sectionless MIPS floating injected calls need their own behavior proof.

## Local acceptance evidence

The installed candidate uses Ghidra 12.0.3 and Java 21 bytecode. Its JAR SHA-256 is
`ffbdd3a646d8e47d2b00363a01b869989caa1f234ae80af4bf38b6969eac016f`.

- Twelve fresh headless imports: x86-64, AArch64 and MIPS32 BE/LE, each with exec,
  PIE and rebased PIE. Twenty-four deterministic exports pass GNU readelf,
  LLVM verification, pinned strict libdwarf checks and 48 native/QEMU GDB calls.
  Checks include original/curated lookup, types, source, argument/static values,
  stepping and normal returns. Original and saved-program evidence is retained.
- Four incomplete-count cases produce eight deterministic exports and preserve
  primary debugging (16 calls), with explicit alias omission and missing-alias
  lookup controls.
- Two freshly imported GNU-versioned sectionless DSOs pass 16 qualified lookups,
  four native versioned calls and equality with the independently invoked
  packaged writer. The section-backed versioned harness also passes.
- Independent raw checks compare all original dynamic records, names, binding,
  visibility, values, sizes, local/global boundary, synthetic load indices and
  the preserved original prefix. Thirty corruption controls reject missing
  records, wrong boundaries, changed binding and undefined/unnamed aliases.
- The new smoke suite passes 1,730 checks, including ELF32/64 in both byte
  orders, malformed inventories, cancellation, MIPS mode bits and high indices.
  Thirty-three suites ran with the actual Java 21 runtime; the expanded new
  suite was rerun against the same installed production JAR.
- Existing ELF regressions, a greater-than-2-GiB input with a 64-MiB Java heap,
  controlled decompiler failure and real copy cancellation pass. Strict checks
  retain independently corroborated inherited-frame diagnostics where expected.

Raw runtime receipt:
`c303b520d316b0cf620564684832b1dc5284783ee1c3061375eafa087f17d526`.
Artifacts are under `build/sectionless-alias-review/`; final runtime cases are
in `final-runtime/`, and the versioned run is
`build/test-results/sectionless-versioned-dynamic-symbols/run.txq_w0__`.

The first headless harness compared a model captured before alias creation;
that assertion was corrected to compare the post-curation snapshot. The raw
oracle initially treated readelf's synthesized `.init` display for an unnamed
section symbol as a real string; it now preserves the raw empty name and adds
only actual version suffixes. Both failed attempts remain in local evidence;
the final protected matrix passes without changing production to fit them.

## Reproduction and pipeline

Run `sectionlessDynamicSymbolsSmoke` with the normal extension build. The CI
workflow runs this model task on Linux and Windows. The four target lanes build
source fixtures, import them without section headers, export twice and run the
same validators/GDB checks. x86-64/AArch64 positive fixtures use `--hash-style
both`; default-toolchain fixtures supply the incomplete-count controls.

```bash
python3 src/test/integration/sectionless-function-aliases.py \
    "$GHIDRA_INSTALL_DIR" mips32be \
    --base-root "$PWD/build/test-results/retained-function-aliases"
python3 src/test/integration/versioned-dynamic-symbols.py \
    "$GHIDRA_INSTALL_DIR" --sectionless
```

Hosted results and final integration are still **PRESENT, UNVERIFIED** until the
exact submitted head passes its required checks and artifact review.
