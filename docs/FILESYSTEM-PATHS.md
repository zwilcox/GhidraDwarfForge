# Filesystem traversal and output identity

**CONFIRMED:** lexical removal of `..` can select a different file from the
one requested through a directory symlink. In the Linux fixture,
`logical/link/../program.elf` opens `actual/program.elf`, while the old policy
selected the different `logical/program.elf`. An explicit output through the
same traversal was written into the wrong directory. The input SHA check
correctly rejected the mismatched input; it could not correct an independently
misdirected output path.

Resolve the existing parent using the host filesystem before appending the
literal filename. Do not create missing parents. Reject root, empty, `.` and
`..` leaves. Windows traversal semantics can differ from POSIX, so tests compare
the selected file with actual host lookup rather than imposing Unix behavior.
The Windows profile additionally rejects file leaves ending in a dot or space,
including extended-path spellings; these ambiguous names are not silently
trimmed. Unix filenames ending in a dot remain supported. A native Windows
probe must demonstrate the short `out`/`out.` alias and both publisher APIs'
pre-mutation rejection before this refinement is accepted. Actual runner
confirmation is still **UNCERTAIN** at this checkpoint; this is not an 8.3
alias or arbitrary-filesystem normalization guarantee.

Keep the final directory entry intact. If an input leaf `friendly.elf` points
to `elsewhere/real.elf`, its defaults remain `friendly.elf.dbg` and
`friendly.elf.dbg.c` beside the chosen name. Reading and identity checks follow
that link, but output naming does not silently change to `real.elf`. Replacing
an output symlink replaces that directory entry and preserves the unrelated
referent. Original-input aliases, including hard links and symlinks, remain
rejected before output mutation.

The same parent resolution applies to public pair publication, standalone
source writing and standalone exporter input, native-library and output paths.
The DWARF 5 line table records the selected output directory. Packaged native
module directories use actual directory resolution. Report serialization
preserves absolute path spelling without new filesystem access after export;
production reports receive already-resolved paths. Native bindings and emitted
address/type/location encodings are unchanged.

## Pair publication boundaries

The public publisher previously checked only some path pairs. A caller could
use an artifact stage as the final source, then success cleanup deleted the
new source. Another owned reproduction used a nonempty directory as the final
artifact: the publisher moved it to a backup, installed files, then failed
while deleting the nonempty backup. The normal script's path policy rejects
directory outputs, so this second finding concerns the public API.

Check all six pairwise relationships among both stages and both final paths,
using resolved directory entries and existing file identity, before timestamps,
moves or cleanup. Stages must be real regular files, not symlink leaves. Final
entries may be absent, regular files or replaceable symlink leaves; other
existing objects are rejected before callbacks or publication. A symlink leaf
is distinct from moving its referent directory. Backup detection and rollback
also retain dangling symlink leaves instead of losing them on failure.

Each final replacement remains atomic with the existing observed-failure
rollback policy. This change does not make two files one filesystem transaction,
prove crash durability or defeat adversarial filesystem races. The publisher
does not become the optional executable-modifying debuglink transaction.

## Validation contract

**CONFIRMED locally; hosted gate pending:** packaged run `run.ua6ucr7i`
passes eight exports and three rejection cases, with independent review.
Focused tests, actual Java 21 checks and the direct native exporter probe also
pass. A later Windows-only leaf refinement passes all five focused checks on
Linux/Java 21, including preservation of distinct legal dotted names, but its
native Windows probe remains pending. The original PR candidate is intermediate
evidence only; exact updated-head package and host acceptance remain required.

`PathTraversalSmoke` uses actual file/directory links and hard links, with no
silent capability skip. It checks host traversal, input-link naming, literal
names, missing parents/invalid leaves, original aliases, all six publisher
aliases, stage-link rejection, special/directory targets, ordinary and dangling
output-link replacement/rollback, standalone source behavior, packaged lookup
and native-free exporter preflight. Separate old/fixed controls prove the
traversal, cross-stage deletion and directory-target failures. Existing output,
report, source, native-library and publication tests remain required.

`path-traversal-export.py` imports a stripped x86-64 fixture once, applies the
analyst name/signature, then exports the saved Program through the installed
wrapper. Four cases cover traversed input, traversed output, input-leaf default
names and output-leaf replacement. Each requires two byte-identical exports,
exact reported paths/hashes, preserved inputs/lookalikes/referents, validators,
typed GDB values `19` and `23`, return value `42`, source lookup from an unrelated
working directory, next/step and normal exit. Input/source alias negatives
must publish nothing and preserve every inventoried file. A missing input
parent must retain the explicit `--input` hint without misleading `--output`
advice, and must not create the missing directory. A separate baseline
mode requires the old input-hash failure and wrong-directory export; it never
calls those outcomes a passing fix. The fixture uses no new proprietary input.

The saved-program oracle inventories every project file and requires an actual
`.gbf` database. Ghidra's filesystem can rotate exactly
`PathTraversal.rep/idata/~index.bak` and `~journal.bak` even when the Program is
opened read-only. The test records those differences and rejects any other
added, removed or changed file. Every program database, live index and property
must stay byte-identical. This is program-database preservation, not a claim
that the entire project directory never changes. The pinned
`IndexedLocalFileSystem` backup rotation and failed initial whole-directory
assertion remain in the evidence record.

An isolated standalone exporter probe separately passes raw traversed paths
without the wrapper resolving them first. It verifies the actual line-table
directory, source fullname, entry breakpoint, validators, normal exit, unchanged
input and deterministic repeat. It does not add a nonexistent CU
`DW_AT_comp_dir` requirement. Local headless uses the complete JDK 25; actual
Java 21 smoke results are recorded separately.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew pathTraversalSmoke
python3 src/test/integration/path-traversal-export.py /path/to/private-ghidra
```

The full pipeline retains its five target lanes and both GUI hosts. The new
real export fixture is Linux x86-64; native Windows must pass the host-derived
filesystem smoke and existing lock/GUI/export gates. No Windows traversal
success is inferred from Linux tests. Published alpha releases are unchanged.
