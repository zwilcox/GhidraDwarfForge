# Optional debuglink investigation evidence

Date: 2026-10-23. Product baseline: `ddad598`. This record supports
[ADR-0004](../ADR-0004-DEBUGLINK-ATTACHMENT.md); it is not a product attachment
implementation or a Windows attachment support claim.

## Reproduce the bounded backend experiment

On Linux with JDK 21, GNU binutils 2.42 and the indicated target tools:

```bash
make -C src/test/fixtures x86_64 aarch64 mips32be mips32le
java src/test/integration/ElfLayoutFixtures.java build/fixtures x86_64
java src/test/integration/ElfLayoutFixtures.java build/fixtures aarch64
java src/test/integration/ElfLayoutFixtures.java build/fixtures mips32be
java src/test/integration/ElfLayoutFixtures.java build/fixtures mips32le
src/test/research/debuglink/run.sh build/fixtures
```

The helper reads source-built inputs and changes only fresh private copies in
`build/test-results/debuglink-research/run.*`. It uses production `ElfImage`
for a bounded small-fixture inspection; it is not a second ELF writer. The
debug file for this backend probe is the fixture's compiler reference, not a
Forge export. For production-artifact behavior use the separate experiment
below and the existing association integration tests.

Observed in `run.UpRREkRJ`, using `objcopy`, `aarch64-linux-gnu-objcopy`,
`mips-linux-gnu-objcopy`, and `mipsel-linux-gnu-objcopy`, all GNU 2.42:

| Input, each of four target profiles | Tool result | Strict helper result |
| --- | --- | --- |
| ET_EXEC and PIE, named sections | exit 0 | Program headers/load bytes and CRC pass |
| No section-header table | exit 1, no sections | No candidate accepted |
| Section table without names | exit 1, corrupt string table index | No candidate accepted |
| PN_XNUM extended program headers | exit 0 | Reject changed non-section ELF header field (`e_phoff`) |

The helper allows only ELF section-table fields to change inside the original
header, checks exact program-header and PT_LOAD bytes otherwise, and decodes
basename/padding/CRC using the target byte order. All input fixture hashes
remain unchanged. A separate plain-text `unrelated.debug` is accepted by
`objcopy` and receives a correct CRC: tool success and CRC cannot establish
that the sidecar describes the target. The configured host `objcopy --info`
does not include all tested target machines; target-prefixed tools are required
here. ARM32 and native Windows were not run.

## Curated saved-Program re-export from the mandatory backup

```bash
src/test/research/debuglink/reexport.sh \
    /path/to/isolated-ghidra-with-packaged-extension \
    build/fixtures/x86_64/semantic.exec.stripped
```

The script imports a private copy, sets `debuglink_analyst_entry` as a
USER_DEFINED function name, settles analysis, and saves the Program. It then
exports through the installed production wrapper, makes an independent
original copy, and uses `objcopy` on a private candidate. This disposable
fixture operation is not the proposed backup/rollback implementation.

The attached target is rejected by the existing imported-SHA check (wrapper
exit 10, no rejected artifact pair). Existing-project re-export with explicit
`--input=<backup> --output=<original>.dbg` succeeds without weakening that
check; the saved analyst name, sidecar/source bytes, backup and target hashes
are preserved. GDB with debuginfod disabled and an empty global debug directory
loads that exact `.dbg` via debuglink and resolves the analyst name with empty
stderr. This is lookup evidence, not an additional post-attachment runtime test.

Final clean exact-baseline run: `run.8RvlttQW`. Its full GNU ELF/DWARF dumps,
LLVM verification and independent `dwarfdump` also pass without diagnostic
output. The private package is the `ddad598` native-inclusive baseline with
ZIP SHA-256 `fb6cb0b096c4627171d2d67c91548bb50b3c0a68dd2405ebd1985e734bb67ab3`
and Java JAR SHA-256
`eeba82ac7112cf33f745170d751242a43c8fc2cb36c11b51eac89ca3bb467a10`.

## Separate save/reopen determinism finding

```bash
src/test/research/debuglink/save-reopen.sh \
    /path/to/isolated-ghidra-with-packaged-extension \
    build/fixtures/x86_64/semantic.exec.stripped
```

There is no debuglink modification in this experiment. Every export uses the
same explicit input, output and native options. Analysis is settled after the
single name change; reopened processes use `-noanalysis -readOnly`. Snapshots
before and after each export compare the full extracted type records,
function signatures, globals, variable locations, function bodies, skipped
functions and diagnostics. The fixture-specific normalization replaces type
keys with unique kind/name/size labels and sorts records; it rejects ambiguous
labels rather than pretending to compare them. Generated source is compared
separately, byte for byte.

Observed first in `run.2c3gkI37` and confirmed against the exact `ddad598`
package above in `run.hF2jjnqF`:

```text
initial-versus-reopened=DIFFERS_WITH_EQUAL_NORMALIZED_MODEL
before-after-export-model=UNCHANGED
normalized-model=IDENTICAL
synthetic-source=IDENTICAL
repeat-reopened=BYTE_IDENTICAL
```

The only raw-model difference is `undefined`'s UID and ordering/references to
that key. In the initial process it is `uid:342d7af9ee6f9338`; on reopen it is
`uid:342d7afc65efbae3`. Persisted types retain their IDs. In the first DWARF
difference, the array's `DW_AT_type` at offset `0x25` changes from `0x92` to
`0x8d`. The initial `undefined` DIE at `0x8d` moves after the persisted types,
and `Elf64_Dyn` moves from `0x92` to `0x8d`; dependent references and strings
move consistently. Both outputs have 19 canonical types and identical source.

Pinned Ghidra 12.0.3 source in
`Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip` establishes
the cause: `DefaultDataType` is a JVM singleton extending `DataTypeImpl`, whose
constructor assigns `UniversalIdGenerator.nextID()` when given no ID. It
inherits that ID; unlike `BuiltIn`, it does not override `getUniversalID()` to
return null. Forge's `GhidraTypeGraph.Extractor.stableKey` chooses this ID, and
`TypeGraph` sorts nodes by key. A newly imported structure is newer than the
process singleton, while a reopened persisted structure is older than the new
singleton. The source ZIP SHA-256 is
`ae94f7ede157d57b865eaa7caefd72c9f98bfed04e122db6909dface0bd22748`.

This proves a bounded byte-determinism defect for this type/order combination,
not changed target bytes, source, variable locations or type semantics. It
does not justify replacing all type identity rules. A follow-up can give only
the exact generic `DefaultDataType` a stable built-in key and require the
initial/save/reopen/repeat artifacts to become byte-identical, with validators
and GDB still passing. The corrective release remains separate. CRC refresh
after genuine analyst edits is required independently of this finding.

Exact-baseline confirmation hashes:

| Artifact/model | SHA-256 |
| --- | --- |
| Initial `.dbg` | `195374d41d42adf766953d4575d2861603906e28bc38353cefd40f592f0d0acd` |
| Both reopened `.dbg` files | `e4e81c4b1ff7d51e115509ab8ede37179d70ff3e40e0ba498086deb144bac101` |
| All generated source files | `9880562ecc36efe1aec24b238539b3be1b4f6705cbec7bf015825d8557ea9021` |
| All six normalized model snapshots | `946a767a3af3553aef2bc971b5ee34938b4b0dbbd5851c1ea847b21f7d29275a` |

The first exploratory module preceded the allocated-relocation association
fix; its automatic GDB lookup emitted `.rela.dyn`/`.rela.plt` warnings. Those
were not suppressed or treated as success. Final lookup proof uses a private
extraction of the native-inclusive exact `ddad598` baseline package. No shared
or user Ghidra installation was modified.
