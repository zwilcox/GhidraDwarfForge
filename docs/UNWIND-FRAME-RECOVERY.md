# Native evidence to recovered frame rows (#112)

**CONFIRMED locally:** instruction-state projection and native recovered CFI
pass structural validators and GDB comparisons for the bounded recursive
assembler fixture on x86-64/AArch64 non-PIE and PIE. **PLANNED:** integration into
the real exporter, wider memory alias proofs and
original-CFI precedence, plus the full compiler/shared/failure matrix. This
checkpoint does not enable production synthesis or complete #112.

## Projection contract

`UnwindFrameRows` consumes converged identity states and an explicit target
policy. It selects a known affine register relation for CFA, preferring the
current stack register and then deterministic alternative anchors. Caller stack
value is expressed relative to CFA. Return-address identity is separate from
incoming general-register identities; distinct return and program-counter
columns receive independently valid recovery rules.

An unchanged identity in its own register becomes `same_value`; a copy in
another mapped register becomes a register rule; an exact surviving saved slot
becomes a CFA-relative memory rule. Unknown general registers receive explicit
`undefined` rules and diagnostics. Missing CFA or return-address evidence omits
the interval. Overflowing relations are rejected, with another proven anchor or
save considered when available. Collection insertion order cannot choose a
different result. CIE initialization is explicit and derived from the selected
entry state, including used callee-saved registers.

`GhidraUnwindFrames` keeps native `Address` keys while selecting states and
recording observations. It converts addresses into the original ELF domain only
when constructing rows. Every FDE starts with a complete rule set. Gaps in a
function body and unreachable intervals end the preceding FDE; no old row is
extended across them. Byte order comes from the validated original ELF, and
register numbers/widths/entry relations come from the isolated profile. The
component emits instruction-boundary rows, not asynchronous unwind guarantees
for arbitrary instruction interiors or special frames.

## Runtime defect found: caller lookup inside the call instruction

The first recovered AArch64 artifact passed GNU, LLVM and pinned strict libdwarf
validation but lost the outer recursive frames in GDB. At the call instruction,
the pre-instruction state still put the caller return address in X30. After the
call, X30 no longer held that identity. The independent assembler reference
used the surviving stack save at both boundaries.

GDB 15.1's [DWARF frame consumer](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-15.1-release/gdb/dwarf2/frame.c)
uses `get_frame_address_in_block` for caller CFI lookup; its source comments and
call sites at lines 913–977 explain the return-address adjustment. The exact
upstream file is hashed in the receipt. This corroborates the actual failing
native trace; it is not inferred solely from validator success.

Call-site projection now intersects the proved **before** and **after** states
of the verified call. The selected recovery locations therefore work both at a
live stop before executing the call and when GDB looks up a suspended caller's
row inside it. A location proved on only one side is insufficient. This includes
CFA anchors, caller registers and saved memory, not just the link register.
Missing common return/CFA evidence omits the call interval. The pure regression
rejects the old pre-call link assumption, and the same native failing case now
recovers all frames. The original failing artifacts and logs are retained.

## Independent runtime harness

```bash
python3 src/test/integration/unwind-frame-recovery.py build/classes/java \
    build/test-results/unwind-frame-recovery --dwarfdump "$DWARFDUMP"
```

The harness compiles the existing independent assembler CFI fixtures and strips
only their debug data to obtain runnable inputs without frame records. The PIE
linker retains an empty `.eh_frame` section; its zero length and empty GNU frame
dump are recorded, and the input is not changed to hide it.

A test-only ProgramDB importer loads each selected function's actual executable
bytes at its real ELF address. The production profile, native capture, closed
callee verifier, state projection, frame encoder and sidecar writer then run.
A second independent JVM repeats recovery with the database rebased by
`0x400000`; its complete normalized plan must be byte-identical. The encoder
also runs twice independently for plain and compressed sidecars. The test CU
identifies an explicit CFI experiment; it does not claim recovered original C.

GNU header/section/info/abbrev/aranges/line/frame inspection, LLVM verification
and explicit frame decoding, and the pinned strict checker accept all eight
sidecars. The Python frame consumer independently checks decoded ranges. GDB
compares four modes per fixture: independent assembler reference, missing CFI,
recovered plain CFI and recovered compressed CFI. It compares every recorded
caller PC and saved-register witness while stepping, performs `finish`, and
requires normal exit. The generated and reference traces match at 40 x86-64 and
36 AArch64 instruction stops in both non-PIE and PIE cases. At the checkpoint,
all five ordinary frames must select the actual `dwarf2` unwinder; the no-CFI
control must not. The process-entry `_start` is deliberately outside recovered
coverage, and the oracle stops its caller traversal there.

The known AArch64 QEMU system-DSO string-table warning is allowed only in its
exact existing form and only when identical across all four modes. No other
warnings are allowed. Reference/input/source hashes remain unchanged.

The pure projection suite passes 77 checks. The native call/planning suite now
has 24 fixtures and 4020 checks, including actual body gaps/unreachable code and
every observed planning cancellation poll (771 x86-64, 2480 AArch64) plus retry.
Existing call/flow/profile/capture/encoder suites pass 182/102/235/653/158 checks.
Extension build, architecture guard and workflow lint pass. CI includes the new
component suite and runtime harness in both target lanes; current hosted
execution is **PRESENT, UNVERIFIED**. See [the receipt](evidence/unwind-frame-recovery.json).

## Remaining full-goal acceptance

The existing C compiler reference still writes global `cfi_sink`. Neither the
older variable-location memory analysis nor the new closed-call verifier proves
that absolute/image-relative writes cannot alias caller stack storage. This
required case remains open; the fixture is unchanged. The assembler experiment
above is additional evidence, not a replacement acceptance target.

Original-byte agreement is now required and locally validated; see
[its contract and evidence](UNWIND-CODE-AGREEMENT.md). Before production synthesis,
complete the wider memory proof, trusted original coverage/precedence, exporter diagnostics and
atomic publication/cancellation, and the compiler/shrink-wrapped/discontiguous/
shared/rebased runtime matrix in [the full contract](SYNTHETIC-CFI-EVIDENCE.md).
PR166 hosted/workload acceptance still has priority; #112/#110/#109 remain open.
