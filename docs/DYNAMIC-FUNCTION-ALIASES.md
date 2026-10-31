# Analyst aliases on dynamic-only ELF inputs

**CONFIRMED failed hosted gate; corrected locally:** PR85 run `41170001875`
fails the standalone large-ELF source compile because its dependency list omitted
`DynamicSymbolMirror`, and the ARM/Thumb oracle because it still expected an
all-local symbol table. The compile list is repaired. The oracle now proves the
complete original dynamic inventory survives around inserted local mode symbols,
with exact string offsets, bindings, original dynamic bytes and a correct local/
global boundary. Five corruption controls reject missing/changed imports and
incorrect boundaries. Fresh large-ELF and full ARM/Thumb exporter/GDB checks pass;
production is unchanged. Receipt:
`c00c0dad986876ef14bbed896e8c53209c26df531e71ffacef6fe367d71bd3bb`.
Fresh hosted acceptance is pending; P1.7/#66 remains open.

**CONFIRMED locally; full acceptance pending:** a new static symbol table can
hide existing dynamic definitions in GDB. The original conservative omission
prevented this loss, but also prevented useful analyst aliases on stripped MIPS
PIE inputs. The exporter now mirrors the complete bounded dynamic inventory
before inserting new local aliases. This is a P1.7 prerequisite, not completion
of P1.7 or authorization to publish a release.

## Acceptance criteria

- Retain every original dynamic symbol record, binding, visibility, section,
  value and size. The separate static mirror may change only the name offset
  when retaining a GNU version-qualified spelling.
- Preserve original dynamic sections and their indexes; put new locals before
  mirrored nonlocals, and set the static table's local/global boundary correctly.
- Reject ambiguous or malformed inventories before publication. Preserve the
  original input and prior output on failure; honor cancellation.
- Preserve original and analyst lookup, typed primary definitions, parameters,
  owned statics, return values and source navigation in applicable native/QEMU
  GDB tests. Validate deterministic artifacts independently.
- Test both ELF classes and byte orders, and use the production headless exporter
  on stripped MIPS BE/LE, x86-64 and AArch64 exec/PIE/rebased fixtures.

## Implementation and limits

`DynamicSymbolMirror` is architecture-neutral. It bounds symbol/string counts,
checks framing and local ordering, and handles a linked extended section-index
table. It creates separate `.symtab`, `.strtab` and, when necessary,
`.symtab_shndx` payloads. Existing static-table insertion is unchanged. Target
policies still decide whether a processor's function-address semantics are
proved; this change grants no new target-mode support.

GNU version definitions and symbol-version entries supply the observed `@` and
`@@` spellings in the static mirror. Original dynamic bytes remain unchanged.
Both raw and qualified spellings participate in alias collision checks.
Undefined imports remain undefined; the mirror invents no definitions or
variable locations. Malformed/unsupported inventories cause alias omission
with a diagnostic; direct backend requests fail before replacing output.

**CONFIRMED consumer limitation:** on the tested GDB, an unqualified `api` can
select V2 even when the loader default is V1. This also occurs with the original
compiler and stripped inputs. The test requires preservation of that original
lookup behavior and separately verifies both qualified versions against native
`dlvsym`, including returned values. Export diagnostics recommend the qualified
spelling or curated definition. This does not claim that GDB's unqualified
selection implements the loader's default-version policy.

Sectionless aliases, discontiguous alias bindings, additional target-mode
policies, wider calling ABI work and full declaration/class relationships remain
open. The versioned DSO test validates GDB names/types/source and native loader
calls separately; it does not claim GDB-injected versioned DSO calls.

## Reproduction

Use Ghidra 12.0.3, the assembled extension with pinned native libraries, and the
repository's standard validator setup. The standalone writer probes require an
actual Java 21 runtime (`FORGE_JAVA21_HOME` may select it when the build/headless
JDK differs).

```bash
./gradlew dynamicSymbolMirrorSmoke functionAliasSymbolsSmoke localSymbolMergeSmoke
python3 src/test/integration/versioned-dynamic-symbols.py "$GHIDRA_INSTALL_DIR"
for target in x86_64 aarch64 mips32be mips32le; do
    for role in exec pie pie-rebased; do
        python3 src/test/integration/retained-function-aliases-export.py \
            "$GHIDRA_INSTALL_DIR" "$target" --role "$role" --symbols stripped
    done
    python3 src/test/integration/local-symbol-merge-integration.py \
        "$GHIDRA_INSTALL_DIR" "$target" --symbols stripped
done
```

CI adds the model test on both hosts, enables stripped-MIPS alias integration,
and runs both GNU default-version fixtures in the x86-64 lane. Hosted acceptance
of this change remains pending.

## Local evidence and retained failures

The candidate installed JAR is
`512231807df0473d91660f4bba76303bb054b631769ce1ccf26c0ddb3b7c2b65`.
The isolated private runtime and logs are under `build/dynamic-alias-review/`.
The three updated suites pass on actual Java 21: 1,008 dynamic mirror checks,
281 alias-planning checks and 1,272 existing table-merge checks.
Twelve stripped base and twelve alias roles pass across x86-64, AArch64 and
MIPS BE/LE exec/PIE/rebase, including 144 compiler/Forge GDB calls. Independent
raw review rechecks original inventories, addresses, values, source navigation,
protected inputs and deterministic output. All 31 packaged suites pass on
actual Java 21 with verified production-class origins. Final package and hosted
review remain pending.

Local runtime/model receipt:
`030ca11679eca880373bdeadff6c1b28e4924057d12855f14ddab37734d04fda`
(`build/dynamic-alias-review/local-acceptance.json`).

`build/test-results/versioned-dynamic-symbols/run.9_ej1xda/result.json` records
two full headless DSO cases, immutable rereads, byte-identical independent
writer results, qualified lookup, types/source and native version calls.
GNU readelf, LLVM verification and pinned strict libdwarf validation pass.

Retained development failures include an obsolete test expecting all dynamic
aliases to be omitted; a checker incorrectly requiring original `.shstrtab`
name offsets despite the writer rebuilding that table; a misplaced test block;
and an attempt to run Java-25-compiled test classes on Java 21. These were
corrected by testing the new complete-inventory behavior, comparing decoded
section names, moving the test block and compiling probes with `--release 21`.
No production workaround weakened the relevant checks.
