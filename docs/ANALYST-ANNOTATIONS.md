# Analyst annotations and optional instruction context

**CONFIRMED Linux default integration:** issues #116/#114 preserve listing
comments and equates through the shared exporter. Equates have a non-executable
source catalog and tested synthetic debugger constants. Optional assembly/p-code
context, Windows interaction and full hosted/workload acceptance remain
**PLANNED**. Earlier component-only notes describe their historical scope. #108
implementation is merged; its final documentation is tracked by PR #165.

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

The [emitted-annotation receipt](evidence/annotation-emission.json) adds an isolated
production-producer test using the existing x86-64 instruction-correlated fixture.
Controlled token-associated comments and an unassociated failed-function catalog
pass through `AnnotatedSourceFile`, the real exporter and matched ELF writer.
Independent raw DWARF reads and actual GDB prove that inserted comments have no
executable rows, source stepping and variable values survive, and absolute source
lookup works from an unrelated working directory. GNU/LLVM/pinned strict checks
pass for every sidecar, including the three existing type-pair controls. Eight
files are byte-identical across fresh producer processes; the baseline mode also
passes. This is not yet saved-program extraction or installed-export acceptance.

```bash
python3 src/test/integration/emission-evidence.py "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 --annotations
```

The x86-64 workflow invokes this mode separately. Hosted execution, other target
runtime checks, real annotation inventory/association and production integration
remain required. The modeled unavailable source here complements the separate
real native failure fixture; it does not replace that acceptance requirement.

The [packaged inventory receipt](evidence/annotation-inventory.json) establishes
read-only extraction from the four actual saved-program profiles. The inventory
retains Ghidra `Address` objects, every listing category, exact stored equate
names/64-bit values and each reference's address, operand and dynamic hash. It
retains automatic listing comments too; the API does not prove human authorship.
It intentionally does not call enum display helpers or infer a C type from raw
stored values. All fifty fixture comments and fourteen equates match independent
readback, including malformed names and dynamic-only references.

Explicit limits count comments, equates and references as records and names/text
as UTF-16 units. They fail with an actionable message instead of truncating. The
final source serialization budget is a separate constraint. A complete address
count check detects omitted spaces or a changing inventory; the Ghidra stack
encoding split described above is used independently of target architecture.
Limits, mismatch rejection and every observed cancellation checkpoint pass, with
unchanged project data and byte-identical independent reopens.

```bash
python3 src/test/integration/annotation-inventory.py "$GHIDRA_INSTALL_DIR" /path/to/curation-case
python3 src/test/integration/annotation-inventory-pipeline.py "$GHIDRA_INSTALL_DIR" x86_64
```

The second command builds/validates the compiler reference and curates a fresh
private project first. This whole sequence passes locally on x86-64. The workflow
adds x86-64, AArch64 PIE and both MIPS32 byte orders; hosted execution is pending.
The inventory still has no production export call site. Typed/display-name
validation, token association, context options and complete source/debugger
integration remain required before either issue is complete.

The [saved-comment placement receipt](evidence/annotation-placement.json) adds
`GhidraListingAnnotationSource`: a comment may precede an existing token row
only when its default-space address belongs to a decoded instruction wholly
inside the owning exported function and that instruction has exactly one source
row. Interior addresses use the containing instruction. Ambiguous, unmapped,
non-default-space and failed-function records remain in a labeled catalog.
Original address spaces and comment categories survive; insertion never creates
an executable source row. Stored text is escaped reversibly without attributing
unknown authorship to the analyst.

Four saved profiles and a separate fresh x86-64 pipeline pass structural
validation and native/QEMU GDB from an unrelated working directory. Two additional
comments per private fixture are saved at independently observed native token
addresses to exercise positive placement. All fifty original fixture comments
are preserved. The harness independently reverses source/line remapping and
reads emitted line tables. A real native instruction-limit failure retains the
function symbol and comments without fabricating a source location. Two fresh
export JVMs produce identical annotated and unannotated sidecars and source.
Exact/short budgets, three composition cancellation checkpoints, unchanged
original ELF/project and deterministic ordering are checked.

AArch64's system-DSO warning is also present in the compiler-only control.
MIPS warns at the deliberately excluded function-body gap with both annotated
and unannotated Forge sidecars. The harness compares exact diagnostics and gap
bounds; these are not ignored as generic debugger warnings.

```bash
python3 src/test/integration/annotation-inventory-pipeline.py "$GHIDRA_INSTALL_DIR" x86_64 \
    --consumer /path/to/libdwarf.so.2.3.2 --producer /path/to/libdwarfp.so.2.3.2
```

The CI pipeline supplies these native paths for all four profiles; hosted
execution remains unverified. This controlled export has three functions and no
type model. It does not establish the default GUI/headless integration, equate
lookup or optional instruction context. Those remain required for #116/#114.

The shared GUI/headless script now reads the stored annotation inventory and
composes listing comments before DWARF/report creation. Incidental listing
comments are disabled in native decompilation; native warnings remain enabled.
Type recovery still uses the same decompilation results, and coverage consumes
the remapped executable evidence. Complete comment metadata remains in the
synthetic source; this change does not add fields to the strict report schema or
count annotations as recovered variables. Equate values still require their
separate implementation.

Per-export limits default to 1,000,000 inventory records (comments, equates and
references), 16,777,216 stored UTF-16 units and 134,217,728 complete source UTF-8
bytes. Exceeding a limit fails before publication; it never truncates stored
text. These initial limits are resource bounds, not measured workload guarantees.
All three may be set to decimal integers from 0 through 2,147,483,647 in the
script or headless wrapper:

- `--annotation-record-limit=<n>`
- `--annotation-text-limit=<n>`
- `--annotation-source-limit=<n>`

The PowerShell wrapper spells these `-AnnotationRecordLimit`,
`-AnnotationTextLimit` and `-AnnotationSourceLimit`. The GUI uses the same defaults;
for larger limits use the script arguments or headless wrapper. The separate
`source-annotations` JFR phase makes composition cost visible without changing
the measured decompilation phase. The phase reader continues to accept historical
complete recordings and rejects incomplete current recordings.

The [installed default-export receipt](evidence/annotation-default-export.json)
records successful x86-64, AArch64 PIE and MIPS32 BE/LE cases plus a fresh full
x86-64 pipeline. Each invokes the packaged shared export script with the real
type model, validates its sidecar, recovers all fifty fixture comment payloads,
and checks source lookup/stepping, the applied structure tag and real global
values in GDB. A second JVM produces identical output. Record/text/source-limit
failures and an invalid numeric option preserve the existing output pair and
saved project. The actual JFR recording passes the updated reader and retains
identical output hashes. All 603 Java 21 classes in the final extension match
the tested installed module; current wrappers are packaged.

The first debugger oracle requested a compiler typedef absent from the saved
Ghidra model. The actual saved type and emitted DIE are a structure tag, so the
correct lookup is `ptype struct ANNOTATION_TYPE`. This test correction did not
change the exporter. GUI interaction, Windows wrapper execution and the complete
hosted/workload gates remain pending. No equate debugger or optional context
support is claimed yet.

`GhidraEquateEvidence` now validates stored enum metadata against the current
Ghidra data-type manager and keeps it separate from operand and high-p-code
observations. Malformed names, missing/wrong types, missing members, encoded
value mismatches and values outside the declared width retain explicit reasons.
The implementation reads exact stored names without invoking Ghidra's unsafe
display helpers on malformed records. No stored value is truncated to fit a type.

Decoded scalar evidence retains the operand's actual bit width, signedness and
value. Dynamic hashes resolve against the live owning `HighFunction`; only small
value records survive that call. Such a constant establishes unsigned bits and
width, not C signedness. Operand and hash ownership stay independent. The current
fixture illustrates why this matters: its enums are one byte while both decoded
scalar observations are 32 bits on all four profiles. The dynamic-only folded
constant is also 32 bits, with operand index `-1`.

The [equate evidence receipt](evidence/equate-evidence.json) records four saved
profiles plus a fresh full x86-64 pipeline. Eleven negative controls include a
stored value whose low bits match but whose full value does not fit, so the
implementation must reject truncation. Interpretation cancellation is tested at
all 26 observed checkpoints. The decompilation callback now explicitly permits
checked cancellation; a collector cancellation propagates instead of becoming
an ordinary symbol-only failed function. Independent JVM readbacks and original
project/input hashes agree.

```bash
python3 src/test/integration/equate-evidence.py "$GHIDRA_INSTALL_DIR" /path/to/curation-case
```

The interpretation checkpoint above preceded the allocator and isolated
production emitter described below. Default exporter collection and the source
lookup catalog remain required for #116.

The constant plan now reserves modeled function, parameter, local, global,
static, type, member, enumerator, class and namespace names, plus retained ELF
symbol bytes. Stable ASCII aliases encode an exact UTF-16 stored-name identity;
value/reference edits do not change that identity. Every equate retains signed
64-bit database and unsigned 64-bit bit-pattern views. Enum, decoded operand
and dynamic views remain distinct. A direct display name requires a unique,
unreserved safe identifier and defensible typed evidence. Ambiguous or malformed
records retain aliases and an explicit reason instead of claiming a typed name.
Independent Python hashing/value checks supplement the packaged Java checks.

The producer accepts a separate Ghidra-independent constant value model. It emits
artificial CU-owned const variables with `DW_AT_const_value` and no location,
lexical lifetime or executable source row. Synthetic types and constants do not
enter recovered-type/variable coverage. Generated type names are also allocated
against reserved names; unnamed base types were standards-valid but GDB rendered
them as an invalid type. Signed and unsigned values use the existing audited
64-bit libdwarf 2.3.2 LEB128 bindings, with no new native declarations.

An actual big-endian GDB failure exposed missing padding on partial-byte base
types. The corrected emitter uses the target byte order for
`DW_AT_data_bit_offset`, as specified by [DWARF 5 section 5.1](https://dwarfstd.org/doc/DWARF5.pdf).
Unsigned constant 1 with a one-bit type now displays as 1 on big-endian MIPS;
the prior encoding displayed 0 despite passing all structural validators.
The pinned producer rejects its restricted unsigned-constant helper for this
attribute; its already-audited arbitrary ULEB helper is used instead. Both failed
experiments remain in the evidence archive.

See [the constant-emission receipt](evidence/equate-constants.json) for isolated
real-producer GNU/LLVM/pinned strict validation, two-process deterministic output,
and GDB value/width/const-type/addresslessness checks on x86-64, AArch64 PIE and
MIPS32 in both byte orders. Each case includes the saved 35 constant views,
sixteen extra width/extreme controls and a generated-type collision. Bare and
file-qualified expressions are both checked. Duplicate/real-name collisions,
cancellation and out-of-range values are rejected without replacing a prior
output. The integration pipeline runs this process before the existing comment
placement/default-export checks.

**CONFIRMED default integration:** inventory is captured before decompilation;
dynamic observations are collected while each successful high function remains
live. After type extraction, name reservations include the curated model, raw
ELF bytes and read-only observations from applicable Ghidra demanglers. Nothing
is applied back to the program. Invalid UTF-8 symbol bytes remain reserved
exactly; they are not decoded lossily. A separate producer value object carries
additional reservations so generated type names cannot shadow retained functions.

The reversible appended catalog records each exact stored name, database signed
value and unsigned bit pattern, direct-name decision, all typed lookup names,
enum status/member metadata, and each address-space/operand/dynamic-hash owner
with its resolution status and resolved width/sign/value. Enum storage width and
use-site width remain separately visible. It has no executable rows or fabricated lifetime.
Annotation inventory and composition have separate complete JFR phases.

[Default export evidence](evidence/equate-default-export.json) covers four saved
profiles and a fresh full x86-64 pipeline: 35 constants, bare and file-qualified
lookup in two live frames (140 checks per case), assignment rejection, unchanged
real globals/types, exact reruns, independent validators and atomic limit failures.
The saved conflicting local still has an unsupported nonzero first-use offset:
GDB retains the four-byte local symbol and reports its value unavailable. The
test proves an equate does not replace that local; it does not establish its
location or claim that its value is available. Non-artifact report content,
including recovered coverage, matches the previous comment-only exports exactly.

A separate GNU C++ fixture renames two functions in Ghidra while retaining their
original mangled ELF symbols. Both original demangled names still break in the
correct curated functions; ten synthetic constants pass twenty lookups, and a
synthetic type name receives a collision suffix. This fixture now runs in the
x86-64 annotation pipeline. Completeness for all consumer-specific demangled
spellings remains **UNCERTAIN**; this evidence establishes the tested GNU C++ case.
Windows interaction, full hosted/workload acceptance and optional #114
assembly/p-code context remain required.

The earlier Windows workload run `42134637694` stopped at its historical
cross-version source-byte assertion. Inspection of its actual SQLite artifact
proves that DWARF and report semantics are unchanged and that removing only the
appended 12,044-comment catalog reproduces the recorded baseline source SHA-256.
The comparison now recognizes that exact prefix/catalog relation, retains both
source versions, and still rejects other source changes, any DWARF difference,
and any per-version/profile nondeterminism. Eleven malformed/executable mutation
controls reject. The three portable comparison tests and three phase-reader tests
pass; fresh complete Windows/U-Boot pairs and downstream GDB remain pending.
See [the hosted artifact review](evidence/annotation-windows-catalog.json).

**CONFIRMED combined cancellation and Linux desktop acceptance:** the installed
entry point is interrupted during inventory, live high-function collection,
interpretation, retained-name observation, equate catalog construction, actual
equate composition, and native constant emission. The compositor interruption
requires an enclosing equate-source frame, so an earlier listing-comment pass
cannot satisfy that control. Five cases pass all seven interruptions, retain the
previous output pair without temporary files, report cancellation rather than
failure, and then produce byte-identical output in the same JVM. Saved projects
and original executables remain unchanged.

The shared Script Manager fixture now stores all five comment categories with
Unicode and delimiter escapes, a typed 32-bit equate, and a conflicting function
name. Ordinary and compressed Linux GUI journeys pass actual Script Manager
export, output selection, chooser cancellation, stored-annotation preservation,
report save/comparison, explicit attachment decline and preparation. GNU/LLVM/
pinned strict validators and GDB confirm the direct constant value, width and
addresslessness alongside the original function breakpoint and source stepping.
A separate copied compressed-artifact consumer passes source relocation and the
same typed lookup, without changing incoming artifacts. Its existing strict
checker recognizes three independently corroborated GNU frame terminators;
there are no unexplained validator findings.

See [the combined evidence](evidence/equate-cancellation-gui.json). The Java GUI
fixture and compressed consumer are shared by Windows CI, but local Linux
success does not establish Windows acceptance. Full hosted/workload validation,
optional #114 context and broader consumer-specific demangling remain pending.
