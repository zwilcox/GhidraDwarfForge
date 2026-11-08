# Explicit call-frame rule encoder (#112)

**CONFIRMED locally:** the pure Java encoder serializes explicit call-frame plans
and the matched ELF writer preserves their alignment through optional compression.
**PLANNED:** Ghidra instruction/ABI evidence recovery and production synthesis.
The ordinary exporter does not invoke this encoder. This checkpoint does not
complete #112 or change ADR-0002's production decision.

## Contract

`CallFramePlan` is immutable serialization input, not a recovered-evidence claim.
Its caller supplies target byte order, four/eight-byte addresses, the return
register, a complete declared register universe, non-overlapping FDE ranges and
explicit CIE initial rules and complete FDE initial rows. Rules express undefined, unchanged, memory at CFA plus a
signed offset, the CFA-derived value itself, or a value held in another register.
CFA is an explicit register plus signed offset. No architecture, ABI, stack
layout, call effect or register number is inferred by the encoder.

The format follows [DWARF 5 §§6.4 and 7.24](https://dwarfstd.org/doc/DWARF5.pdf):
CIE version 4, DWARF32 lengths, explicit address width, section-relative CIE
pointers and entries aligned to address width. Code/data factors are one, so
rule offsets remain exact bytes. The caller supplies every CIE initial rule;
complete FDE entry rows override them where needed. This also permits ABI-specific
initialization obligations without hard-coding an ABI in the serializer. Unchanged rows are
coalesced. Large address advances use `DW_CFA_set_loc`. The writer uses the same
uncompressed alignment in ELF section headers and gABI compression metadata.

Incomplete rows, overlaps, out-of-range addresses, invalid registers and
resource limits fail before a byte array is returned. Cancellation is polled
through validation and emission. Limits are 65,536 FDEs, 65,536 rows per FDE,
one million rows total, 512 declared registers (IDs 0–4095) and 64 MiB of frame
bytes. Range lengths are positive Java longs and must fit the target address
width. A full 4-GiB ELF32 range has representable endpoints but an unrepresentable
FDE length; a failing-before control now proves rejection in both byte orders.
Generic DWARF expressions and segmented addresses are outside this component.

## Validation

```bash
./gradlew callFrameEncoderSmoke debugCompressionSmoke existingDebugSidecarSmoke buildExtension
python3 src/test/integration/cfi-encoder.py build/classes/java \
    build/test-results/cfi-encoder/x86_64 --target x86_64 --dwarfdump "$DWARFDUMP"
python3 src/test/integration/cfi-encoder.py build/classes/java \
    build/test-results/cfi-encoder/aarch64 --target aarch64 --dwarfdump "$DWARFDUMP"
```

Each runtime target needs its GCC/binutils toolchain and GDB; AArch64 also needs
QEMU user emulation and GDB-multiarch. GNU readelf, LLVM and the pinned libdwarf
checker validate artifacts. Output directories must be new. CI wires both target
commands and the component check; hosted execution is **PRESENT, UNVERIFIED**.

The component suite passes 158 checks including cancellation at every observed
poll and successful retry, unsigned high addresses, input immutability and invalid
plans. Compression and original-CFI preservation regressions also pass.

Each target command passes six structural-only cases (four width/byte-order
layouts plus two greater-than-4-GiB row advances) and two runtime cases (non-PIE
and static PIE). These layout containers do not establish runtime support for
other processors. Every case checks plain/zlib packaging, independent JVM
repeatability, unchanged input hashes, an independent frame decoder, GNU frames,
LLVM verification plus its explicit frame reader, and the pinned strict checker.
Corrupted CIE-pointer controls must be rejected by both external readers. The
strict wrapper's rejection must have native exit status zero, so a native crash
cannot count as successful rejection. Its frame summary counter alone is not
used as proof of frame checking.

Runtime fixtures carry independent assembler CFI and distinct saved-register
witnesses through four recursive activations. The actual executable has debug
metadata stripped. Reference, generated plain, generated compressed and absent
CFI each run against that executable. Reference/generated traces match at every
recorded instruction boundary (40 x86-64, 36 AArch64), including entry, saves,
restores and recursive returns. Tests require the exact six-frame checkpoint,
caller witness values, `finish`, exit zero and GDB's selected DWARF unwinder.
PIE traces compare addresses relative to the runtime checkpoint. The absent
control must not select the target DWARF unwinder. Only the exact AArch64
system-DSO warning corroborated by the reference is allowed.

These rules are explicit fixture plans, not Ghidra-recovered information.
AArch64 initially failed even with reference CFI because explicitly declaring
PC undefined prevented recovery despite valid LR. Both reference and plan now
express PC recovery from LR, or its saved slot, at the appropriate boundaries.
This observation requires ABI/profile review before production use; it is not
a claim about every AArch64 frame, SIMD state, PAC or asynchronous context.

The test producer adds a minimal fixture-only DWARF5 CU because the strict
checker requires one. It describes `plan.txt`, with no source rows or recovered
types. Earlier attempts without a CU, with unordered fixture section iteration,
and with undefined AArch64 PC are retained as failed experiments.

See [the initial receipt](evidence/cfi-rule-encoder.json) and
[explicit CIE follow-up](evidence/cfi-explicit-cie.json) for source hashes, commands,
results and retained raw evidence. Remaining work includes pinned ABI audits,
original-unwind coverage decisions, Ghidra instruction/control-flow recovery,
uncertainty diagnostics, joins/aliases/shrink-wrap controls and real-export
PIE/shared/rebase/cancellation acceptance described in
[SYNTHETIC-CFI-EVIDENCE.md](SYNTHETIC-CFI-EVIDENCE.md).

## CIE initialization audit correction

Pinned [AADWARF64 common information entries](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aadwarf64/aadwarf64.rst#common-information-entries)
requires a defined CIE initialization for used callee-saved registers. The first
encoder unconditionally declared all registers undefined and restored their rules
in each FDE. Although the runtime tests passed, that API could not express the
ABI's initial state. Plans now explicitly supply immutable CIE rules; an
independent decoder verifies them. The earlier X19 CIE fails that assertion.
Both complete target harnesses pass again, including all malformed-frame,
compression, determinism and runtime controls. Production ABI recovery remains
planned; the generic encoder does not choose these rules for a caller.
