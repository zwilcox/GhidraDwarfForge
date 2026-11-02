# MIPS wide argument allocation and stack-depth investigation

**CONFIRMED local defects; full component acceptance pending.** This work
continues #69 under `TARGET-ABI-COMPLETION-PLAN.md`. It does not close #69 or
any of #68–#71, and does not change the Ghidra 12.0.3 / Java 21 / libdwarf 2.3.2
baseline.

## Observed defects and correction

The pinned N32 default prototype allocates floating registers independently of
integer argument positions and assigns by-value structures incorrectly. An
owned GCC 12.4 N32 fixture initially displayed only 10 of 25 source-known entry
values correctly. Raw compiler instructions independently establish the
positional registers and aggregate pieces; compiler DWARF itself has seven
incorrect aggregate entry observations and is not an unconditional oracle.

The candidate constructs a separate prototype for export only. It replaces the
input rules with the pinned N64 positional-slot rules, retaining the original
N32 output rules, automatic return pointer and four-byte pointer types. The
selected N32 serialized prototype must have SHA-256
`7779b39a220a4ef8fc5da8c838311138a0cec39e6724ed3afeb076b0652bd9a2`.
Selection additionally requires the exact ELF32 MIPS64r2 N32 metadata, matching
byte order/language, `n32` compiler, and matching typed ABI attributes. Explicit
custom storage is preserved. Saved dynamic storage must match the original
prototype; replacement size, automatic status, indirect status and return
allocation are checked. The saved program and its decompiler model remain
unchanged, so this does not claim to repair decompiler text or injected calls.

Corrected physical storage now enters the shared register, stack and composite
location analysis. A fully decoded final delayed return can retain a proven
incoming register prefix; malformed slots, alternate entries and delayed jumps
remain rejected. A folded delayed write ends that prefix conservatively at
the slot address.

The next runtime check exposed a distinct N32 stack-depth defect: `addiu`
updates the low four bytes of the eight-byte stack register and sign-extends
the result. Ghidra's `CallDepthChangeInfo` loses the affine stack value. Its
alternate-register constructor and per-instruction delta API also failed this
reproduction; their output is retained rather than parsed as a guessed depth.

`TruncatedStackDepth` instead proves low-address affine arithmetic from decoded
p-code in a language-declared truncated physical RAM space. It derives widths
and byte order from Ghidra, has no processor/register names, requires the
existing complete straight-line/entry/flow proof, and tracks COPY, extension,
low SUBPIECE and constant ADD/SUB with overlap invalidation. Unknown pointer
writes remove the fact. The low bits are normalized to the actual physical
address width. Delay-slot entries remain unknown because the owner's folded
p-code does not establish the independently observable pre-slot state. This is
not general delayed-control-flow or register/spill lifetime support.

## Current local evidence

**CONFIRMED locally:** candidate ZIP SHA-256
`4f82c63255ab3817171c9eb3024d684f59c6df468777f2a687225debefb8907b`,
production JAR SHA-256
`9cfc158d7ed9fcd0f0699d9fb5bc68fa74368797079bf1ff340ebc0e7e7b100a`.
The installed extension uses the existing packaged native libraries; no native
binding or binary changed. Research commands and raw outputs are retained under
`build/mips-wide-allocation/` in the `mips-wide-allocation` worktree.

- `mipsN32ParameterAllocationSmoke`: 198 checks, both byte orders, positional
  arguments, aggregate order, hidden four-byte pointer, exhaustion/splits,
  named variadic parameters, custom storage and metadata/cancellation controls.
- `delayedReturnPrefixSmoke`: 204 real-decoding and malformed-tail checks across
  O32/N32/N64 in both byte orders.
- `truncatedStackDepthSmoke`: 112 checks, including narrow/wide adjustments,
  unknown COPY/AND/LOAD/ADD pointer writes, ordinary 64-bit-memory rejection,
  missing decoding, offcut entry, override and cancellation controls.
- Existing truncated-store (182), stack control-flow (832), stack-local (376),
  stack-value (332), spill (106), AArch64 allocation (670), and composite-value
  (1,032) checks pass, plus the five-target stack-first-use suite. Earlier
  register/composite prefix regression results are retained in `build-second.log`.
- Eight fresh non-PIE runtime cases: N32 and N64, each big and little endian,
  with both retained ELF symbols and fully stripped originals.
  N32 has 399 instruction observations per order (363 exact values, 36 expected
  gaps); N64 has 469 per order (433 exact values, 36 expected gaps). All 1,736
  observations per stripping form pass (3,472 total). These include mixed
  integer/floating and by-value aggregate
  parameters, exhausted integer slots, and stack arguments after adjustment.
  GDB `stepi` skips the delayed instruction in these runs; separately visible
  slot states are not claimed by this runtime count.
- GNU header/section/note/DWARF inspection, LLVM verification and the repository
  strict libdwarf completion checker pass for all eight artifacts. Strict
  reported errors and corroborated frame errors are both zero. A plain
  `dwarfdump -ka` run is retained but is not the strict completion receipt.
- Repeated exports of all eight cases are byte-identical and preserve
  input/package/program database bytes; only documented filesystem index backup
  files rotate. Receipts are in `four-case-matrix.json` and
  `stripped-four-case-matrix.json`.
- The exact packaged AArch64 ABI non-PIE regression passes at
  `aarch64-regression/exec.zj1whmlk`, including its compiler-reference policy.
- Workflow lint and architecture-neutrality checks pass. All three new model
  tasks are wired into both host task lists; this is not a hosted pass.

The first cancellation test used a monitor with cancellation disabled; the
fixture now enables it and passes. The first v3 headless experiment invoked the
GUI-only entry script and was rejected before writing output. The retry uses
the production `GhidraDwarfForge.java --packaged-natives` headless entry. Both
failed logs remain available. No production exception was suppressed.

## Current follow-up and remaining work

**CONFIRMED CI regression correction:** run `41342751358` stopped at the old
O32 FP32 paired-register smoke expectation, before runtime jobs. The decoded
delayed-return proof now correctly retains both pieces until the first member
write. The revised test checks the exact `[0x1000,0x1004)` available prefix,
unavailable remainder and rejection of an alternate entry, for both member
writes and byte orders. No production behavior changed. The full workflow
Gradle model/build command passes locally (114 tasks); hosted acceptance still
requires a passing run of the corrected head.

The versioned wider runtime/oracle and non-PIE/PIE/rebased/shared tests now
pass locally, including failure/cancellation controls and independent compiler
reference windows. The separate bounded call policy also fixes the suppressed
N32/N64 typed returns. See `MIPS-WIDE-CALL-PROFILE.md` for exact counts, package
receipts and limits. The checkpoint investigation below retains the failures
that led to those fixes; they are no longer the current outcome of the admitted
four-signature fixture.

**PRESENT, UNVERIFIED as a complete ABI/storage profile:** finish the N32 input
allocation audit for opaque, wider/aligned/floating/nested aggregate signatures,
and remaining return/storage cases. General N32 spill/reload and delayed
control-flow tracking still require work. Hosted acceptance, protected
integration and the remaining O32, FPXX/FP64A, ARM32 and i386 requirements in
`TARGET-ABI-COMPLETION-PLAN.md` remain binding. Passing this fixture does not
complete #69 or the combined goal.

## Wider reference and return follow-up

**HISTORICAL investigation, now covered by the passing follow-up above:** complete
GCC instruction sampling shows that the original `wide_pair`/`wide_large`
aggregate homes are never populated. `-fno-tree-sra` does not repair them.
`-O0` and Clang 16 provide later positive aggregate observations but introduce
different unavailable ranges. The original source form and its prior passing
Forge regressions are retained. An additional `FORGE_MIPS_AGGREGATE_HOME`
fixture form explicitly requests aggregate memory operands and supplies positive
compiler observations after each corresponding store.

The candidate versioned oracle decodes the independent compiler instructions,
requires the expected stores at the reported frame offsets, and checks raw ABI
registers/memory against source-known values at every calibrated pre-store PC.
It also identifies the single delayed-return PC where GCC switches two stack
argument locations before the stack adjustment executes. A strict-reference
mode retains those wrong displays as failures. The first N32 big-endian compiler
run passes 412 observations under this precise policy. Every parameter has
positive typed observations outside the calibrated windows. This is not yet a
passing wider compiler/Forge pipeline: the Forge return checks below fail.

The experiment also exposes `DW_AT_GNU_locviews` being incorrectly followed as
a DIE reference by the pinned strict checker. The validation-only correction,
48 positive/negative/previous-tool checks and actual-artifact results are
recorded in `../support/validation/README.md`. The production native pair and
JNA bindings remain unchanged.

**CONFIRMED remaining debugger-call/return work:** the current N32 call policy
marks the functions as non-callable, and GDB's `FinishBreakpoint.return_value`
is unavailable even for `wide_words`. This is retained as a failing Forge
acceptance test, not silently converted into a passing return check. The
compiler's hidden-buffer `wide_large` return also lacks automatic display;
the harness separately checks the captured caller buffer using its return type,
matching the existing AArch64 oracle policy. Independently injected compiler
calls now return exact values for all four signatures on both N32/N64 byte
orders (16/16). That establishes a prerequisite for a carefully bounded wider
call policy; it does not itself authorize every MIPS signature or ABI.


**CONFIRMED follow-up CI regression correction:** run `41343539954` reached
an older dynamic-composite runtime assertion that required the O32 scalar to
be unavailable for its entire body. The delayed-return proof now preserves
its exact unsigned 64-bit value until `lui a0` overwrites the first carrier.
The test independently verifies the first five machine instructions, requires
correct values through the clobber instruction, and requires unavailable values
from the following PC through return. It also decodes the exact two-register
DWARF location-list bytes and end marker; it does not accept an omission report
as its own oracle. Fresh big/little-endian compiler, computed-storage and
converted-custom-storage runs pass with GNU/LLVM/strict validation,
deterministic reruns and protected-input checks. Production code is unchanged.
Receipts: `build/mips-wide-allocation/dynamic-composite-correction-v2.json`.
The required hosted gate must pass again on the updated test commit.

## Truncated-store runtime oracle correction

**CONFIRMED:** hosted run `41346595567` next reached the older truncated-store
fixture and failed both MIPS lanes on its expectation that the O32 wide argument
was unavailable at entry. The emitted value was the source-known
`0x1122334455667788`. This is the same newly supported incoming-register prefix,
not a reason to remove valid locations from the exporter.

The corrected test independently reads the first six original instructions:
frame adjustment, frame-register save/setup, the two argument stores, then
`LUI a0`. It requires a positive location through the LUI instruction and an
unavailable tail starting immediately after it (`0x400148` in this fixture).
It checks the exact endian-aware raw location-list bytes for the two 32-bit
register pieces, the end marker, report bounds and typed value/unavailability
at every visited instruction. It does not infer expected availability from the
exporter's report alone. N32 retains its independently checked scalar path.

Four fresh exact-production-v5 cases pass all compiler/Forge runtime checks,
GNU/LLVM/pinned strict validators, deterministic exports and original/package
preservation. They contribute 194 Forge instruction observations:

- `mips32be.o32.hwXQkRzq`: 49 observations.
- `mips32be.n32.tiHEOyn9`: 48 observations.
- `mips32le.o32.0Xyd0pjB`: 49 observations.
- `mips32le.n32.IqWXjc1a`: 48 observations.

Paths are below `build/test-results/mips-truncated-space`; invocation logs are
`build/mips-wide-allocation/truncated-prefix-v5-mips32{be,le}.log`. The unchanged
v5 JAR is `8c3931eed60e9e06d084e5026747d948f011dda278535e3abf9f524a2d93aadb`.
The later PR129 package also passes the BE O32/N32 pair. This correction changes
only the regression oracle. A new hosted gate remains required; #69 and the
full four-issue goal remain open.
