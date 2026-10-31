# Lossless local symbol insertion into matched ELF sidecars

**CONFIRMED through accepted PR80:** the matched ELF writer accepts
explicit local function-symbol additions when the original image already has
one supported static symbol table. This is a prerequisite for
[P1.7/#66](https://github.com/zwilcox/GhidraDwarfForge/issues/66). That backend component did not add
an alias option or automatic secondary-label extraction to ordinary export.
The existing ARM instruction-mode planner retains its own conservative policy.

## Contract and limits

New records are `STB_LOCAL | STT_FUNC` and appear immediately before the first
original nonlocal record. Original records remain byte-identical, in order;
original string bytes remain a prefix, so every original `st_name` remains
valid. `sh_info` advances by the number of inserted locals. The original table
and string-table section indices stay intact. New payloads are appended after
original EOF; the original executable is never written. An empty additions list
keeps the old writer path and does not newly interpret original symbols.

A parallel `SHT_SYMTAB_SHNDX` table moves entries with their symbols. New high
section indices use `SHN_XINDEX` and a correctly linked parallel table, created
when necessary. Both ELF classes and byte orders use their native field widths.
Nonallocated strings use byte alignment; symbol and extended-index payloads use
canonical alignment. No program headers are introduced. Supplied record order
is preserved; callers remain responsible for deterministic planning.

Before any temporary output is opened, merging rejects:

- Multiple static symbol tables, unsupported table/string metadata, malformed
  null records, incorrect local/nonlocal partitioning and invalid name offsets.
- Missing, inconsistent or duplicate extended-index metadata and out-of-range
  ordinary/extended section indices.
- Active unknown symbol-index dependencies, including group records. Ordinary
  relocation sections already retired by the matched writer are inert and do
  not retain symbol references. No unknown index-bearing payload is rewritten.
- New names colliding with any existing static symbol name or with each other,
  nonexecutable destination sections, malformed Unicode and unrepresentable
  serialized fields.
- Resource-limit violations: 65,536 additions, 262,144 combined symbols,
  16 MiB string data/aggregate decoded-name bytes and 65,536 bytes per name.

Original ELF names are compared as exact bytes, without lossy UTF-8 replacement.
New Java names must encode exactly as UTF-8. This backend does not infer original
linkage, classify calling conventions, merge dynamic symbol tables or prove
that a caller-selected address/size describes code. Future alias planning must
bind source provenance, function ownership, original code/section extents,
dynamic-name conflicts and target-specific symbol values, including instruction
modes. Ambiguous or unsupported cases must be diagnosed explicitly.

## Validation

`localSymbolMergeSmoke` passes 1,272 checks across ELF32/ELF64 and both byte orders:
original local/global/weak records, all-local and null-only tables, reserved and
extended indices, arbitrary original name bytes, resource bounds, malformed
metadata, name collisions, cancellation, deterministic writes and preservation
of inputs/existing destinations with no temporary residue on rejection. Existing
ARM mode-symbol (231 checks), extended-section, inherited-DWARF, sectionless and
copy-cancellation suites pass. All five fixture-reproducibility lanes, seven
architecture guard controls and workflow lint pass.

Twenty-five model suites pass on actual Java 21 against the installed production
JAR. ARM/Thumb runtime behavior is not inferred from these model checks:
the existing real mixed ARM/Thumb export regression separately passes, with
strict validators and QEMU/GDB execution. This preserves its existing profile.

The real backend harness first consumes the twelve ordinary retained/stripped
alias cases from `retained-function-aliases-export.py`. Those pass 24 normal
exports and 96 compiler/Forge calls. It copies their saved projects, creates
explicit USER_DEFINED secondary labels, saves and reopens them read-only, and
performs another 24 baseline exports. The normal exporter still omits the
secondary labels; a negative GDB lookup proves that boundary.

An isolated test probe invokes the **installed production ELF writer** on the
original private ELF, those unchanged DWARF bytes and the observed symbol
records. Twelve exec/PIE/rebased-PIE cases on x86-64 and AArch64 pass 24 repeat
backend writes and 48 additional GDB runtime calls. These checks prove:

- Original mangled names and the original C alias retain typed lookup and single
  breakpoints when present; stripped controls do not fabricate them.
- New secondary names resolve to the right entry/type. Parameters, returns,
  primary-owned statics, curated frame identity, source listing, next and step
  remain correct under native/QEMU execution and nonzero PIE load biases.
- Raw symbol records, original string offsets, debug-section bytes, code and
  build ID are preserved as specified. GNU inspection, LLVM and strict libdwarf
  checks pass without unexplained diagnostics; inherited frame messages require
  the existing exact corroboration policy.
- Inputs, the installed module, test sources and original saved projects stay
  unchanged. Read-only copies allow only known Ghidra backup-file rotations;
  repeat exports and backend writes are byte-identical.

Local prior-package comparisons reproduce all six retained-table rejections
without modifying an existing destination. The six stripped cases produce
byte-identical old/new backend artifacts. The test probe uses actual Java 21;
local headless Ghidra uses Java 25 with Java 21 production bytecode.

Independent backend-review receipt SHA-256:
`a052f804f4c31e0fca87306856561fb8fd107087245dbdf62154426d598da15d`.
Independent ordinary-export review receipt SHA-256:
`6bf4a6faac33ac6c389ff0d4bfc1df33ac5db170ea342d7287d820d3245eb543`.
Evidence is retained in `build/symbol-merge-review/` in the implementation
worktree. CI adds the model suite on both hosts and the backend harness after
the retained-alias matrix on both target lanes. PR80 exact-head hosted acceptance passes all twelve jobs in `41144394175`,
with independent package/raw and both GUI console review. Receipt:
`adc82421f9ca89cab128399f9cb2b27da03e184b38c128c2f1e1df43725e1e4e`.

## Consumer limitation and remaining alias work

A supplemental ELF name is not another DWARF scope owner. The local GDB probes
resolve function-owned statics through the primary curated name but fail the
same query through the secondary name. Keep the primary definition, source and
ownership intact; do not add duplicate subprogram DIEs or a linkage attribute
that hides curated lookup. Full alias/scope semantics remain incomplete.

Automatic extraction/planning, dynamic-symbol collisions, unsupported namespace
ownership, interior labels, sectionless binding and target-specific symbol
values need their own model and real-export acceptance before ordinary export
can call this backend for analyst aliases. This change does not close #66 or
#73 and does not publish a release.

## Retained unsuccessful attempts

Two initial negative assertions mismatched diagnostic capitalization/wording;
the implementation rejected the intended invalid inputs. The tests now compare
normalized text and the actual ELF32 overflow diagnostic. One regression command
ran before fixture binaries existed in the fresh worktree; after source-built
fixtures were generated, sectionless/cancellation checks passed. Failed logs
remain retained. None is counted as passing runtime or format evidence.

The next ordinary-export component is documented in
[CURATED-FUNCTION-ALIASES.md](CURATED-FUNCTION-ALIASES.md); its pending acceptance
does not alter the historical backend-only boundary of PR80.
