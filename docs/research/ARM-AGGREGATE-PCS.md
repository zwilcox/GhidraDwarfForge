# ARM aggregate PCS references and exporter gaps

**CONFIRMED subsequent call-classification progress:** the isolated policy now
passes four local packaged call/return cases; see `../ARM-AGGREGATE-CALLS.md`.
The blanket call restrictions observed below describe the retained v4 baseline.
**CONFIRMED subsequent HFA storage progress:** `../ARM-HFA-STORAGE.md` now
records locally passing logical HFA members and surviving copies through frame
release. The Q-register omissions below describe the retained baseline, not the
current candidate. Ordinary aggregate/mutable/layout compositions and hosted
acceptance remain active work.

**CONFIRMED compiler/consumer reference; exporter completion remains PLANNED.**
This checkpoint advances the full #68–#71 scope in
`../TARGET-ABI-COMPLETION-PLAN.md`. It does not complete #70, advertise aggregate
support, change the production baseline, or authorize a release.

## Reference contract

`arm-aggregate-pcs.c` contains twelve source-known functions: base and VFP
versions of a two-integer structure, three-float HFA, two-double HFA, mixed
integer/float structure, core-register/stack split structure after three integer
arguments, and an exhausted HFA after seven double arguments. The main program
checks each natural result. Captured arguments and a call counter independently
check debugger-injected calls through both names and typed function pointers.

The independent ABI reference is Arm's
[AAPCS32 2025Q1](https://github.com/ARM-software/abi-aa/blob/c51addc3dc03e73a016a1e4edf25440bcac76431/aapcs32/aapcs32.rst),
particularly result return, base argument allocation rule C.5 and VFP allocation
rules C.1.vfp/C.2.vfp. The downloaded text SHA-256 is
`765b29d17a1256fbb5ddb32c10595a29ccbee69c9579a80e7f8aa11f144d4ae0`.
The fixture checks ordinary aggregates through core registers, hidden result
buffers for non-HFA structures, HFA VFP transfers, an actual split at the last
core argument register, and a whole-stack HFA when too few VFP slots remain.
These are separately observed transfers, not inferred from a target identifier.

The harness reads raw entry registers and stack bytes before consulting compiler
variable locations. It checks typed arguments at explicit inline observation
labels after their saved copies are established. Mixed integer/float aggregates
use ordinary structure transport and can be called under either selected PCS.
HFA and floating scalar signatures are injected only when the executable's
automatic GDB floating model matches the function; the existing independently
reproduced global-PCS limitation remains in force.

## Reproduction and local evidence

Run from this worktree with the existing ARM compiler environment:

```bash
python3 src/test/integration/arm-aggregate-pcs-reference.py \
    --order little --pcs hard \
    --gdb /usr/bin/gdb-multiarch --gdb-data /usr/share/gdb \
    --qemu /path/to/corrected-qemu-arm
```

Repeat with `--pcs softfp`, and both `--pcs` values with `--order big`, the pinned
GDB 17.1/data directory and corrected `qemu-armeb`. The private QEMU 8.2.2 D/Q
alias correction and its provenance are unchanged from
`../ARM-PCS-CALL-PROFILE.md`; system tools are not patched. LE uses GDB 15.1.
Each command records full tool paths, versions, input/source/tool hashes and
commands in its unique result directory. It requires byte-identical compiler
rebuilds, unchanged protected files, GNU/LLVM/pinned strict libdwarf validation,
normal inferior exit and exact source-known values. The known private QEMU
vDSO warning is checked against actual mapped ELF bytes; other warnings fail.

All four reference combinations pass. Together they contain 48 raw entry
transfers, 48 typed aggregate observations, 36 automatic typed returns and
72 injected calls. `build/arm-aggregate-pcs/compiler-reference-v3.json` links
the four complete receipts. Two additional copied-input controls change the
first integer argument from 17 to 18, one in each byte order. Both fail at the
first raw-entry assertion before accepting any natural call; the baseline
inputs remain unchanged. Commands and expected failures are retained in
`negative-controls.py` and `negative-controls.json` in the same evidence directory.

All five `fixture-reproducibility.sh` target checks pass with the new source
explicitly registered (13 existing reproducibility artifacts per lane). The
aggregate fixture itself is built and validated by the separate reference
harness above. Python parsing and whitespace checks pass. The new preparation
script also runs under the real Java 21/Ghidra 12.0.3 headless installation.
The ARM CI lane is wired to run all four compiler references with the same
private consumer builds; hosted execution of this new step is
**PRESENT, UNVERIFIED**. This step does not substitute for future aggregate
exporter/runtime acceptance.

## Current exporter observations

The unchanged PR133 v4 package is used for four fresh stripped imports,
curation, saved-project reopen and repeated exports. Its JAR SHA-256 is
`e414c524ef288e0b8a0d2448759b919f48764fb4763f706b180547a02f9bb27c`.
`PrepareArmAggregatePcs.java` applies source-known types and explicit conventions
using Ghidra's dynamic storage, preserving the distinction between formal return
types and their hidden pointer carriers. Reopened observations match, repeated
source/sidecar bytes match, protected originals/module files remain unchanged,
and GNU/LLVM/strict validators pass. Only documented project backup rotations
change. These structural observations are not feature acceptance.

The diagnostic runtime probe observes these gaps in both executable PCS roles:

| Shape | LE incoming storage/value | BE8 incoming storage/value | Value at body observation |
| --- | --- | --- | --- |
| VFP Float3 | Ghidra combines into `q0:12`; Forge omits location | Ghidra keeps three S-register pieces; Forge reads correctly | LE unavailable; BE8 correct |
| VFP Double2 | `q0:16`; Forge omits location | `q0:16`; Forge omits location | Unavailable in both |
| Base aggregates, ordinary VFP structures, split structures | Incoming register/piece values correct | Incoming register/piece values correct | Unavailable after initial carriers are overwritten |
| Exhausted HFA on stack | Correct | Correct | Correct |

No wrong reported values were observed in these probes. The missing values are
real gaps, not accepted limitations of the requested end state. All tested
aggregate function/callback calls are currently restricted by the bounded scalar
PCS policy, including ordinary structures the compiler reference can call.

`build/arm-aggregate-pcs/baseline-gaps.json` records every entry/body observation.
`observe-export.py`, `export-observations-v3.json`, `probe-runtime.py` and
`runtime-probe-outcomes.json` retain the exploratory commands and outcomes.
These probes deliberately label results as observations, not passing ABI
acceptance. The current Ghidra language is `ARM:LE:32:v8` for LE and
`ARM:LEBE:32:v8LEInstruction` for BE8. Their different HFA storage must be
respected rather than assuming one physical vector layout.

## Retained pilot failures and next implementation

- Reference v1 differed only in the temporary assembly object's ELF `STT_FILE`
  name. Compiling startup assembly to a fixed object name makes repeated links
  byte-identical without stripping or ignoring differences.
- Reference v2 stopped `vfp_double2` at GDB's selected post-prologue breakpoint
  before two VFP stores established the compiler's stack location. Raw incoming
  doubles were correct, while the compiler display read stale stack bytes.
  Explicit source observation labels after argument capture now define the typed
  observation boundary. This is not permission to accept stale exporter values.
- Export probe v1 compared an indirect return's physical pointer type with its
  formal structure. It now checks `getFormalDataType()` and records both roles.
- Export probe v2 treated all exporter diagnostic log lines as fatal errors.
  The corrected probe retains those diagnostics and requires a null export
  failure; unexpected headless errors still fail.

Next implement independently tested aggregate/HFA transfer classification,
including correct hidden-return roles and PCS-independent ordinary aggregates.
Then resolve the missing Q-register descriptions through audited logical pieces
and extend shared lifetime analysis to proven saved aggregate copies, with
per-instruction values and explicit clobber gaps. Do not blanket-map Q registers
without checking the language's physical layout and object ordering. Runtime
acceptance, layout/control composition, hosted checks and protected integration
remain required; all original AArch64/MIPS/ARM/i386 requirements remain open.
