# Evidence model for synthetic call-frame information (#112)

**PLANNED production behavior; CONFIRMED compiler-reference checkpoint.**
This document proposes how to satisfy #112. The exporter does not yet synthesize
CFI. [ADR-0002](ADR-0002-DEBUG-FRAME.md)'s production prohibition remains in force
until the model, preservation path and runtime tests below are implemented.
Neither this checkpoint nor historical #8 closes #112.

## Separate recovery from encoding

The recovery stage must produce a target-independent, immutable description of
instruction ranges, CFA rules, return-address rules and caller-register rules.
Each emitted rule needs an instruction/ABI evidence record. The serialization
stage may encode those rules; it must not infer register numbers, stack direction,
call effects or missing locations. No native/JNA addition is needed for this
design; any later native addition requires its own pinned-header audit.

The existing `GhidraVariableStorage.StackDepthProfile` proves selected stack
depth intervals for variable locations. It is not a caller-register recovery
model and cannot directly become CFI. The proposed analysis tracks distinct
entry-register identities and entry-SP-relative addresses through actual decoded
instruction effects. It must distinguish a saved caller value from a later value
written to the same register or stack slot.

An isolated target/ABI description supplies entry CFA, return-address origin,
register numbering and widths, call-preserved/clobbered registers, call/return
stack effects and supported instruction semantics. Initial reference targets
are ordinary x86-64 SysV and AArch64 ELF64 little-endian frames. These are test
targets, not a new production-support claim. Other targets, including MIPS,
remain extensible through descriptions rather than generic processor switches.

## Evidence required at each instruction boundary

1. Decode the entire instruction and retain its address, complete bytes,
   processor context and actual control-flow successors. Partial/unreadable
   bytes, conflicting decoding, unsupported mode transitions or unknown
   instruction effects invalidate affected rules. A gap in a function body is
   not implicit fallthrough. Delay-slot effects need their own complete observed
   bytes and execution semantics before a future delay-slot profile is enabled.
2. Symbolically propagate entry-register identities, affine stack addresses and
   exact-width saved values. Every store must invalidate overlapping saved
   locations; an unresolved possible stack alias invalidates affected evidence.
   Track restoration and stack release as carefully as saving and allocation.
   An instruction's effects begin at its successor boundary, not at its own PC.
3. At calls, apply only proven profile/convention effects, including the
   distinction between callee-entry SP and the caller's post-return SP. Opaque
   call conventions and unsupported indirect effects cannot inherit normal-call
   assumptions. A preserved register still needs a traceable caller identity.
4. At each control-flow join, retain a rule only if every reachable predecessor
   proves the same recovery operation. Work to a fixed point; an unvisited
   predecessor is not evidence. Shrink-wrapped saves and split prologues must be
   modeled through this flow, not by scanning a fixed prefix. Incompatible paths
   produce an explicit omission reason. Cancellation and analysis budgets must
   terminate without publishing a partially proved function.
5. Select a CFA only from a proven relation to the entry frame, using a current
   register plus an exact offset or a separately validated expression. Dynamic
   stack adjustment needs a proven surviving anchor; otherwise omit the affected
   function/range. Establish return-address recovery independently of CFA.
6. Do not cover an unknown interval with the previous valid row. Emit separate
   fully proved FDE ranges with complete initial state, or omit the function if
   independent ranges cannot be justified. Report which caller registers are
   unavailable. Never invent `same_value` merely because a register was not
   mentioned by an incomplete decoder.

Ordinary frames do not establish signal trampolines, interrupt frames, exception
entries, alternate stacks or authenticated return addresses. Such frames require
separate recognition, semantics and runtime oracles. The first production
profiles must positively identify supported ABI/mode conditions and document
the exact exclusion/detection policy before enabling synthesis.

## Metadata precedence and ELF packaging

Trusted original unwind information takes precedence. Preserve the original
executable and its `.eh_frame`/`PT_GNU_EH_FRAME`; retain the existing sectionless
unwind discovery rules. Do not overlay synthetic FDEs on trusted original ranges.
If an existing unwind source cannot be interpreted sufficiently to establish
coverage, report that uncertainty rather than assume its covered addresses.

**HISTORICAL source inspection:** `MatchedElfSidecarWriter` previously retired
all `.debug_*` sections, including compiler `.debug_frame`, when it replaces the
debug view. #112 must address original `.debug_frame` preservation explicitly.
**CONFIRMED runtime reproduction:** a real export at `f64a00f` of the x86-64
compiler reference preserves the original bytes under `.forge.stale.debug_frame`
but hides them from GDB. `file <original>` followed by `symbol-file <sidecar>`
then recovers only two valid frames. Renaming that sidecar section back to
`.debug_frame` in a separate diagnostic artifact restores all eight frames and
all six register witnesses. Its payload hash exactly matches the original.
Both sidecars pass GNU/LLVM/pinned strict validation; structural checks alone
miss the loss of unwind behavior. The original remains unchanged. See the
[reproduction receipt](evidence/synthetic-cfi-preservation-probe.json).
**CONFIRMED locally; hosted pending:** the [preservation fix](ORIGINAL-CFI-PRESERVATION.md)
now keeps original linked-image frames active. Thirty real-export/GDB cases
cover both targets, plain/compressed records, retained link relocations,
PIE/shared-object load bias and rebased imports. Generated-frame collisions are
rejected; unlinked frames remain inactive with diagnostics. This fixes the
prerequisite without enabling synthesis or certifying arbitrary original CFI.

Only after that precedence path is validated may absent coverage be synthesized.
Keep frame addresses in the same original-image address domain as emitted DIEs
and line rows. Preserve non-overlapping function ranges and target identity. A
new `.debug_frame` must not add runtime exception tables to the executable.

For the encoder, use DWARF 5's call-frame format: CIE version 4, explicit address
size, section-relative CIE pointers, target byte order and correctly aligned
records. Emit explicit initial register rules rather than rely on undocumented
consumer defaults. Keep register-rule encoding independent of entry CFA and
target instruction alignment. Source: [DWARF 5, §§6.4 and 7.24](https://dwarfstd.org/doc/DWARF5.pdf).

## Independent reference harness

Run from a clean checkout with GCC/binutils for both targets, GDB/GDB-multiarch,
QEMU user emulation, LLVM and the repository's pinned libdwarf checker installed:

```bash
python3 src/test/integration/synthetic-cfi-reference.py x86_64 \
    build/test-results/synthetic-cfi-reference/x86_64 --dwarfdump "$DWARFDUMP"
python3 src/test/integration/synthetic-cfi-reference.py aarch64 \
    build/test-results/synthetic-cfi-reference/aarch64 --dwarfdump "$DWARFDUMP"
```

Output directories must be new; failing runs remain available for inspection.
CI runs these references in the two existing target jobs and retains their logs
with ordinary test results. Hosted execution of this checkpoint is unverified.

The freestanding fixture has nested calls, four recursive activations, omitted
frame pointers and distinct saved-register witnesses. It is compiled with DWARF
but without runtime unwind tables. `objcopy --strip-debug` creates a separate
no-CFI input; the reference and input must have identical allocated sections and
program headers. Independent compiler builds must match byte for byte. Both
files and fixture sources are hash-protected during validation.

Three debugger modes run the same no-CFI executable: compiler symbols/CFI,
no-CFI symbols, and compiler symbols with DWARF unwinders disabled. The harness
checks the *selected* unwinder in GDB's frame diagnostics, not just a sniffer
attempt or a plausible `bt`. Compiler mode requires the exact eight-frame chain
and six caller-register witnesses. It checks `finish`, steps through all four
recursive returns, records each frame/PC/register trace, and requires exit zero.
The other modes characterize fallback behavior rather than assuming it fails.

**CONFIRMED locally:** x86-64 recovers eight frames with compiler CFI and fails
the full-chain check without it or with DWARF unwinders disabled. AArch64 recovers
the same chain in all three modes; only compiler mode selects the DWARF unwinder.
This proves why a passing AArch64 backtrace alone would be weak acceptance evidence.
Compiler mode records 25 x86-64 and 21 AArch64 instruction stops through recursive
returns. GNU, LLVM and pinned strict libdwarf report no DWARF errors. AArch64
QEMU emits one system-DSO string-table warning, identically reproduced in all
three controls; the harness permits only that exact message and records it.
The [local receipt](evidence/synthetic-cfi-reference.json) records tool/source
hashes, debugger observations, validator output and the retained raw archive.

An initial AArch64 reproducibility failure was traced to the assembler's random
temporary object filename in `.strtab`. An explicit `.file` directive in each
owned startup fixture fixes it; independent builds now match.

## Remaining acceptance before enabling production

- Obtain hosted acceptance of original-metadata preservation. Implement trusted
  coverage discovery/merging before any synthesis alongside existing frames.
- ABI sources are [pinned and audited](UNWIND-ABI-AUDIT.md). The
  [explicit rule encoder](CFI-RULE-ENCODER.md) now passes local structural, malformed-input and runtime tests; hosted acceptance
  remains required and its fixture plans are not recovered Ghidra evidence.
- The [caller-identity flow component](UNWIND-FLOW.md) now has local native
  instruction and fixed-point controls. [Profile selection](UNWIND-PROFILES.md)
  and [closed stack-writing call summaries](UNWIND-CALLS.md) have local native
  controls. Extend call proofs to the unchanged global-writing compiler reference and
  complete evidence-to-frame projection before enabling synthesis;
  full exporter failure/cancellation and runtime acceptance remain required.
- Add compiler-reference cases for prologue/body/epilogue boundaries,
  frame-pointer use/omission, split and shrink-wrapped saves, discontiguous
  bodies, PIE/shared objects and rebased imports. The current fixture covers
  recursion and returns, not that complete matrix.
- Run the actual exporter on inputs without unwind metadata; prove GDB selects
  its CFI and matches independent caller values, `bt`, `finish` and stepping at
  each required boundary. Include corrupt/missing generated-CFI controls.
- Validate generated output with GNU, LLVM and pinned strict libdwarf, unchanged
  inputs, deterministic independent exports and real cancellation/failure paths.
  Publish exact supported and omitted cases and update ADR-0002's production
  decision only when that evidence exists.
