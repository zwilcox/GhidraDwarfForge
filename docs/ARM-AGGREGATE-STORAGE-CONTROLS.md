# ARM aggregate storage and clobber controls

**CONFIRMED locally; hosted acceptance pending:** all 48 production runtime
cases pass. The source-built, instruction-audited controls cover additional
ARM aggregate storage and clobber boundaries in #70. The full #68–#71 requirements in
`TARGET-ABI-COMPLETION-PLAN.md` remain binding. This component changes tests and
workflow coverage; it uses the production implementation from PR136.

## Acceptance contract

Each of three argument profiles runs eight controls in little-endian ARM and
BE8, for 48 packaged cases. Every case must pass original-byte preservation,
saved-program preservation, deterministic fixture rebuilds and repeated `.dbg`
and `.dbg.c` output, GNU views, LLVM verification and pinned strict libdwarf.
GDB must observe the actual ABI registers and stack memory at every one of the
function's fourteen instruction boundaries. Every emitted aggregate value must
have both exact source-known fields; every lost complete proof must be reported
unavailable at the independently specified boundary.

The three profiles are:

- `hfa`: VFP PCS, two floats initially in S0/S1.
- `base`: base PCS, two floats initially in R0/R1.
- `mixed`: VFP PCS ordinary aggregate, unsigned integer plus float in R0/R1.

The mixed first field is the unsigned value `0x40c80000`, deliberately equal to
the representation of 6.25f. The assembly explicitly moves those bits into S14
for its arithmetic. The mixed function returns an unsigned raw result through
R0; the other two profiles return a float through their selected PCS. The
oracle checks the mixed field as an integer, not as a recovered floating type.

## Independent control boundaries

The first member is copied into S14 and saved below the frame pointer; the
second is copied into S15 and saved in the adjacent slot. A subsequent addition
replaces the second backup with 13.75. Selected final writes exercise incoming
register overlap. Frame release ends any surviving stack proof. The complete
56-byte function is checked against explicitly audited instruction words before
import; the contract is independent of emitted DWARF locations.

| Control | Deliberate effect | First unavailable instruction offset |
| --- | --- | --- |
| `lower` | Overwrite first incoming carrier; its S14 copy survives | None |
| `neighbor` | Write a separate register; both incoming carriers survive | None |
| `upper` | Overwrite second incoming carrier; its stack save survives until release | 48 |
| `wide` | Write both incoming carriers; first value is unchanged, second is replaced | 48 |
| `reuse` | Overwrite second saved slot, then its incoming carrier | 44 |
| `adjacent` | Write beside saved fields; second save survives until release | 48 |
| `unknown-disjoint` | Indirect write to an actual separate global; analysis cannot prove disjointness | 44 |
| `unknown-alias` | Indirect write to the actual second saved slot | 44 |

The indirect-alias wrapper supplies the real saved-slot address before tail
branching to the same body. Runtime checks distinguish the aliased overwritten
slot from the disjoint unchanged slot. Conservative unavailability in the
unknown-disjoint case is required even though the actual memory still holds the
old value. No fabricated memory proof is admitted.

## Reference and limitations

A separate C caller establishes the selected compiler ABI and owns the typed,
immutable input. Assembly owns the exact clobber instructions and CFI. Its body
has no compiler-produced parameter DIE, so these controls do **not** claim a
compiler typed-parameter comparison. Both symbol-file runs instead check the
typed caller input, raw ABI carriers and actual memory at all fourteen PCs.
Forge additionally checks its aggregate parameter at every PC, without reference
exceptions. The existing C-only float/double lifetime regression retains its
separate strict typed compiler checks where compiler DWARF is valid.

An earlier naked-C experiment emitted compiler aggregate spills before the
hand-written prologue. It was discarded; the retained `probe.c` and its two
binaries are failed research alternatives, not accepted fixtures. Separating
the assembly body avoids relying on compiler-generated naked-function storage.

The package is the unchanged PR136 implementation: JAR SHA-256
`3466d301048383f3f509d676a0765d21719b515e8340737e2ec0650712043ad2`.
The local source manifest is compared against the parent package's build
manifest. Baseline remains Ghidra 12.0.3, Java 21 and pinned libdwarf 2.3.2.
Little-endian uses GDB 15.1; BE8 uses unmodified GDB 17.1. Both use the documented
private QEMU 8.2.2 register-alias correction from `ARM-PCS-CALL-PROFILE.md`.
No system debugger or emulator is patched.

## Reproduction

Run `python3 src/test/integration/arm-hfa-lifetimes.py <packaged-ghidra>` with
`--order little|big --storage hfa|base|mixed --control <table-name>` and explicit
`--gdb`, `--gdb-data` and `--qemu` paths. Set `JAVA_HOME`, `ARM32_CC`,
`ARM32_OBJCOPY` and `DWARFDUMP` to the validated tools. The workflow runs the same
48 combinations after the existing two default lifetime cases. Both new fixture
sources are included in the explicit redistributable-source inventory.

Local full commands, raw results, preservation manifests and validator outputs
are indexed below `build/arm-hfa-controls/` and
`build/test-results/arm-hfa-lifetimes/`. Three deliberate oracle corruptions
require rejection: missing gap at offset 48, premature gap at offset 28 and
wrong field value at entry. Their runtime failures are retained under
`build/arm-hfa-controls/oracle-controls/`.

Remaining scope includes additional aggregate layouts, incoming exhausted-stack
compositions, failure/cancellation compositions for these new bodies and the
original cross-target requirement audit. Hosted gates and protected integration
remain required. Passing this matrix alone does not complete ARM32 or any of
P2.3/P2.3a/P2.3b/P2.3c.

## Local acceptance receipt

All 48 cases pass 672 raw instruction observations per symbol file, 582 typed
Forge aggregate observations and 90 exact unavailable boundaries. The two
unchanged default C lifetime cases also pass 56 Forge typed observations and
20 strict compiler typed observations. Every case passes the validators,
determinism and original/program/package preservation contract above.
All five fixture source/reproducibility checks pass, as do actionlint, Python
syntax, shell syntax and whitespace checks. All 100 production source files
match the parent package's source manifest. The three deliberately incorrect
oracle expectations fail at precisely the intended offsets.

Receipt `build/arm-hfa-controls/acceptance.json` SHA-256:
`e3b29063328e9af274c13ba17b4dbd2999835625332a85fdfd21b2a8a4b6b3bd`.
The complete command lists are `full-matrix.commands.json` and
`default-current.commands.json` beside it. Earlier pilot/matrix runs are retained
as development evidence, and are not substituted for this final 48-case run.
