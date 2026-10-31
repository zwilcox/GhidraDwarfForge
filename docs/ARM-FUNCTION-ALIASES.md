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
