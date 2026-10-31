# ARM and Thumb analyst function aliases

**CONFIRMED initial ARM/Thumb alias implementation locally (2026-10-31):**
separate saved/current instruction-mode evidence now tags only ELF alias values.
The isolated planner reconciles original mapping/function tags and retains generic
full-body ownership, collision and byte checks. Twelve retained/stripped ARM/Thumb
exec/PIE/rebase cases pass repeated automatic export, unchanged DWARF/source,
GNU/LLVM/strict validation and QEMU/GDB static decode, lookup, stepping and returns.
304 target-policy checks, 59 extraction checks and seven actual Java 21 suites pass.
Receipt: `aea3c3e28605ae12cb56c244261341ba5b702ae60208236a2bf9cef027280ad3`.
The sectionless profile checkpoint below is now locally established; mixed/
conflicting-mode runtime proof, pipeline expansion and final acceptance remain pending. P1.7/#66 stays open; see `docs/ARM-FUNCTION-ALIASES.md`.

The implementation uses independent alias mode evidence rather than relying on
optional primary mode symbols. Ghidra's stored instruction context and fully
known current TMode must agree throughout the entry-containing range. Exact
instruction tiling, alignment, entry boundaries and hashes bind that evidence
to the generic alias extraction. Discontiguous and interior-entry model controls
preserve the full primary body without extending an ELF symbol over gaps.

The ARM planner requires little-endian ELF32 EABI5 and applies mode tagging only
after the ordinary alias planner proves names, ownership, original bytes and
allocation. It checks original mapping intervals, tagged function entries and
reserved supplemental symbols. A function tag describes its entry, not every
byte covered by its size: mixed-mode veneers and literal pools must not be
misinterpreted as a homogeneous interval. Unknown, contradictory or unbounded
evidence is diagnosed and omitted. Original metadata is preserved.

The [pinned Arm ELF ABI](https://github.com/ARM-software/abi-aa/blob/17f2cc8ee6645c1709088f4e0cb4438ce75a14ff/aaelf32/aaelf32.rst)
defines the tagged ELF function value; code and DWARF addresses stay untagged.
See [the compiler and packaging experiments](research/ARM-FUNCTION-ALIASES.md)
for the failure controls that motivated this path.

Initial runtime evidence is under `build/arm-alias-review/production/` and uses
JAR `6525b854406a345977c32c88fb731eb3f850c190a53785f396e13fc3adf6b72a`.
All twelve automatic exports retain original/mirrored inventory, insert exactly
two typed aliases, preserve the baseline DWARF and source, and repeat identically.
Tests check static decoding before QEMU attachment, then four actual calls per
case with types, owned values, source stepping and returns. The unchanged saved
programs come from the separately retained compiler/base-export experiments.

Seven suites were compiled explicitly with `javac --release 21` and executed
with Java 21 against the packaged JAR. An initial attempt to use Gradle's local
Java 25 test classes failed at class loading; that evidence is retained. The
production extension bytecode was already Java 21 compatible.

Acceptance is incomplete. Broader sectionless profiles and mixed-neighbor/indirect-call fixtures,
dynamic defined symbols, conflicting original mode runtime controls, broader
regressions and hosted Windows/Linux gates remain. Defined vendor/resolver symbol
types outside ordinary STT_FUNC and big-endian ARM remain unverified. Existing
primary mode cues still have their documented ET_EXEC-only scope; this change
does not add synthetic original names when no analyst alias exists.

## Sectionless ARMv7-A runtime checkpoint

**CONFIRMED locally, bounded profile:** the same initial ARM candidate JAR above
passes six fresh sectionless imports: ARM and Thumb exec, PIE and rebased PIE.
Each repeats automatic export byte-for-byte, preserves the original input and
saved program apart from documented project backup rotation, validates with GNU,
LLVM and strict libdwarf, and passes four real QEMU/GDB calls with typed lookup,
owned values, source stepping and exact returns. The raw inventory oracle checks
original dynamic records and inserted values independently. Twelve exec inventory
mutations reject, including mode-tag corruption. Six additional runtime controls
flip a new alias tag and all fail the decoder before the first `continue`.
Fifteen existing i386/x86-64/AArch64/both-endian-MIPS artifacts also pass a replay
of the changed inventory oracle; these are not fresh export/runtime claims.
Receipt: `3444e8de979b9baf9fba159474cad2df377f608ab9a26cf2f42df5a106c6370b`.

The source-built fixtures explicitly use `-march=armv7-a` and both GNU and SysV
hash tables. Their compiler oracle passes all six roles. The ordinary unaliased
Thumb PIE/rebase baseline still fails its previously recorded mode check; this
is retained and is not treated as a passing Forge baseline. The sectionless
harness requires the compiler evidence and performs fresh alias imports itself.
An initial empty-GNU-hash fixture correctly omits aliases because it cannot
establish a complete dynamic-symbol count; the completeness restriction remains.

Two debugger boundaries are explicit. GDB cannot read file memory from the
sectionless-original/NOBITS-sidecar pair before remote attachment, so the test
checks every instruction boundary and the terminal `bx lr` in stopped remote
memory before continuing. Also, without original `.ARM.attributes`, this GDB
selects `armv3m` and misdecodes modern ARM instructions. The fixture harness now
records that selection and explicitly sets `armv7` from the checked compiler
command. This selects the ISA; ARM versus Thumb still comes from symbol tags,
as the six rejecting controls demonstrate. No original ARM attributes are
fabricated, and automatic sectionless ISA discovery is not claimed.

Evidence lives under `build/arm-alias-review/production/sectionless-*`.
The initial file-memory and automatic-ISA failures, the fixture-wrapper CLI
mistake and the regression-wrapper directory mistake are retained. The last
wrapper now selects all fifteen intended cases rather than reducing the count.
Full pipeline wiring, mixed/indirect and contradictory-mode cases, dynamic
boundary symbols, the final merged package and hosted acceptance remain pending.

## Reproducible pipeline and mixed-mode checkpoint

**CONFIRMED locally; hosted acceptance pending:** the repository harness now
prepares compiler-validated fixtures with status `PREPARED_FOR_ALIAS_RUNTIME`.
That preparation checks Forge structure and determinism but explicitly defers
Forge runtime to the automatic-alias follow-up; it is never recorded as a full
passing export test. `arm-function-aliases.py` then proves saved-program alias
extraction, exact values, original inventory, unchanged DWARF/source and byte
identity with a separate invocation of the installed writer on actual Java 21.
Existing primary mode cues are checked against compiler mapping intervals before
being passed as explicit records to that writer. The normal four-field writer
probe protocol still requires exactly two records; the ARM experiment explicitly
supplies tagged values and the expected record count.

The local matrix contains 18 ordinary cases (ARM, Thumb and mixed-mode, each
retained/stripped exec/PIE/rebase) and nine freshly imported sectionless cases.
All 27 pass structural validators and four runtime calls each. Twelve sectionless
wrong-tag controls reject before the first continue. They isolate alias mode
hints by using fixtures without original mapping symbols. A mixed-mode fixture
has neighboring ARM/Thumb functions and four compiler-disassembled `blx` register
calls through volatile function pointers; both function tags are separately
corrupted. The fixture preserves the compiler's attributed function type using
[`__typeof__` and `copy`](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html),
after two retained compile failures exposed incompatible alias declarations.
No compiler warning filter was relaxed.

The rebuilt package JAR is
`de5c0e35fa3fb7a9b539a7e056ba55d15ae7f3e22e6314872fc2828ee12217a8`.
36 packaged suites run on actual Java 21; the five existing fixture
reproducibility lanes and workflow lint pass. Receipt:
`2c794c6336ad054184237c56ce40281d207ae2d4afb09606cd83f2ec62bb1588`.
The ARM target lane now installs its C++ cross compiler and runs the same
repository preparation/export/writer/sectionless/negative-control scripts.
Hosted acceptance is still pending.

**HISTORICAL boundary defect, subsequently fixed locally below:** the installed sectionless inventory
rejects a Thumb `STT_FUNC` at tagged value `0x4071`, size 16, inside a load ending
at `0x4080`, although the code range is `0x4070..0x4080`. Its allocation check uses
the mode bit as part of the byte address. The isolated actual-Java-21 reproduction
is retained under `build/arm-alias-review/pipeline/dynamic-boundary/`.
Do not claim broad sectionless ARM dynamic-symbol support before a targeted fix,
negative controls and runtime evidence. Contradictory mode/source evidence and
final package/hosted review also remain outstanding.

## Thumb dynamic-symbol load boundary

**CONFIRMED locally; hosted acceptance pending:** `Arm32SymbolValues` isolates
ARM EABI5 function-value interpretation. Only ELF32 ARM EABI5 `STT_FUNC` values
lose bit zero for allocation containment; serialized original values retain it.
This follows the instruction-address distinction in
[AAELF32 Symbol Values](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#553symbol-values).
Other machines, ELF classes, ABI versions and symbol types keep their address
bits. Both byte orders pass model checks; this is not big-endian ARM runtime
support. No DWARF addresses or native bindings change.

The source-built `arm-symbol-boundary.S`/`.ld` reference places four Thumb bytes
at `0x101c..0x1020`, exactly at the executable PT_LOAD end, with raw symbol value
`0x101d`. A separate sectionless copy runs without an interpreter. Repeated
reference builds are identical after an explicit `.file` directive removes the
assembler's temporary object basename; the first failed comparison is retained.
The old and fixed installed packages export the same saved curated program. The
old package diagnoses an allocation crossing and omits `alternate_boundary`;
the fixed package preserves both it and original `boundary`, with identical
synthetic source. Both artifacts validate structurally, illustrating why debugger
behavior is also required.

The repository harness repeats fresh import and read-only export, checks the
installed class origin, preserves input/module/program hashes except documented
Ghidra backup rotation, and independently compares all original dynamic records.
Six raw corruption controls reject changed bindings, missing records, boundary,
undefined/unnamed aliases and an incorrect mode tag. GNU, LLVM and strict
libdwarf checks pass. QEMU/GDB resolves original/curated/alias names, lists the
synthetic source, reads argument 7, steps both two-byte Thumb instructions,
observes result 12 and ARM interworking return, then exits zero. The reference
run independently reproduces QEMU's exact vDSO string-table warning; the existing
diagnostic checker admits only that corroborated warning. ARMv7 is an explicit
fixture ISA, not inferred sectionless metadata.

Validation at candidate JAR
`d8881634f2e0baba581f07aa4f78fffefd14c43714e132cc178856c7c2fae5ff`:
452 ARM alias policy checks, 1,730 sectionless dynamic checks and all 36 packaged
suites on actual Java 21 pass. Fresh x86-64, AArch64, MIPS BE and MIPS LE
sectionless exec imports, repeated exports, raw checks, validators and GDB pass.
All five fixture reproducibility lanes, architecture guard and workflow lint pass.
The >2 GiB standalone writer/validator/GDB test passes on Java 25; its first
launcher attempt mixed Java 25 compilation with a Java 21 runtime and failed.
That retained setup failure is not a Java 21 large-file pass.

Run the CI regression with:

```bash
python3 src/test/integration/arm-symbol-boundary.py "$GHIDRA_INSTALL_DIR"
```

The harness requires the ARM cross compiler, QEMU, GDB and configured structural
validators. Detailed evidence is under `build/arm-alias-review/boundary/`, including
`pipeline-reviewed/run.rsk5yokn` and the old/fixed comparison. Acceptance receipt:
`490f33b5ed076977ce7fa8d5990e5cebd9b34e92af0fa3cf4ea788a75bc8495e`.
Final combined ARM validation, contradictory-mode evidence and hosted review
remain pending; P1.7 is not complete.

## Original mode contradictions

**CONFIRMED locally; final combined and hosted acceptance pending:** the boundary
harness also accepts `--conflict function-tag` and `--conflict mapping`. Each
keeps an independently compiled reference, changes only specified ELF metadata
in a separate input, imports it fresh and confirms that Ghidra retains the
four-byte Thumb function. The function-tag case clears the original symbol bit
in both `.dynsym` and `.symtab`; the mapping case changes its sole `$t` label to
`$a`. No executable bytes change, and both inputs still execute normally under
QEMU. Recorded mutations are checked before export.

Repeated read-only production exports diagnose the precise contradiction and
omit `alternate_boundary`. Original static/dynamic symbol and string tables are
byte-for-byte preserved. GNU/LLVM/strict validation and original/module/program
preservation pass. In the function-tag case, GDB still resolves the curated
function, lists source, reads 7, steps the Thumb addition and interworking return,
and observes 12 with exit zero. This does not require overriding ARM/Thumb mode.

The incorrect mapping case demonstrates a consumer limit: GDB decodes the
preserved original metadata as a four-byte ARM instruction. The test explicitly
requires that mismatch while still stopped at `_start`, records
`EXPECTED_MAPPING_DECODE_REJECTION`, and disconnects before any continue. It does
not count that case as successful Forge execution or rewrite original metadata
to hide the contradiction. The initial exploratory failed decode is retained.
Every compiler reference passes its independent runtime first; existing precise
QEMU vDSO diagnostic checks still apply. Saved/current context mismatches remain
separately covered by actual `InstructionDB` objects with controlled context
views in the extractor model suite; no claim of an end-to-end saved-context
mutation is made.

The three fresh cases (ordinary boundary plus both conflicts) pass at
`build/arm-alias-review/conflicts/pipeline.nsq0s0gy`. Receipt:
`d9cefc626cda90996b52554d0cde7ccfbe254524d6828fc465483e2819b27693`.
CI now runs the same three harness modes. Production classes are unchanged from
the boundary fix. Final combined package/matrix and hosted review remain pending.
