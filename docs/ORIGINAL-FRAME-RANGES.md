# Original frame range inventory (#112)

**CONFIRMED locally:** the bounded record reader identifies declared FDE address
ranges in plain linked .debug_frame and .eh_frame payloads. Independent
compiler cases agree with GNU and LLVM. **PLANNED:** ELF source discovery and
decompression, relocation/identity qualification, original-range precedence and
production integration. This component neither certifies CFI rules nor enables
synthesis.

## Contract

OriginalFrameRanges.read accepts the uncompressed bytes, byte order, target
address width, frame format and original section address. It reads complete
record boundaries first, then CIE headers and FDE ranges. The returned immutable
inventory retains record/CIE offsets, initial location, byte count and the
signal-frame marker. A zero-length FDE remains recorded but covers no bytes.

Supported record framing includes DWARF32 and DWARF64 offsets independently of
32/64-bit target addresses, both byte orders and CIE versions 1, 3 and 4.
Version-4 address width must agree with the supplied target, with no segment
selector. .debug_frame uses section-relative CIE offsets, including forward
references. .eh_frame uses backwards field-relative CIE offsets, empty or
recognized z augmentations, and absolute or PC-relative code pointers.
Recognized augmentations are L, P, R and S. Personality pointers are
consumed without dereferencing; LSDA data is not used as frame coverage.
Signal-frame metadata remains identified, not promoted to an ordinary-frame
synthesis profile.

Pointer representations include fixed 2/4/8-byte signed/unsigned integers,
target-width absolute pointers, ULEB128 and SLEB128. FDE length uses only the
representation bits, never the relative application bits. Addition, scalar
domain, target width and LEB overflow are checked. The current domain is
nonnegative signed-long addresses and lengths, matching the ELF reader's
bounded address domain; unsupported high-bit 64-bit addresses do not become
absent coverage. A PC-relative unsigned value cannot masquerade as a negative
displacement. The original failing-before control for that error is retained.

Unknown augmentations, unsupported relative bases/indirection, mismatched
widths, bad CIE references, truncated fields, nonzero data after an EH terminator
and arithmetic overflow throw. No partial inventory is published. Callers must
treat this outcome as unknown coverage and diagnose/omit synthesis, not turn it
into an empty range list. The reader bounds input to 64 MiB and 262144 records,
polls cancellation throughout, and retains no file handles or native resources.

The instruction bytes after each CIE/FDE header are deliberately not
interpreted here. An identified range is not proof that its unwind instructions
are valid, usable or appropriate for an ordinary frame. Existing metadata must
retain precedence without making that stronger claim. ELF adapters must also
establish complete source discovery, decompression bounds and relocation/
load-bias interpretation before a missing range can authorize synthesis.

## Sources and independent evidence

The record layout follows [DWARF 5 sections 6.4.1 and 7.24](https://dwarfstd.org/doc/DWARF5.pdf).
EH decoding is checked against the pinned
[GDB 15.1 frame consumer](https://gnu.googlesource.com/binutils-gdb/+/refs/tags/gdb-15.1-release/gdb/dwarf2/frame.c)
(read_encoded_value and decode_frame_entry_1) and actual GCC/binutils output.
The existing pinned AMD64 psABI source supplies augmentation context; its
historical position-independence wording is not substituted for the observed
EH zero CIE marker and field-relative reference. LSB HTML/PDF attempts returned
access-denied pages, so they supplied no implementation evidence. No Ghidra,
Java, native library or ABI baseline changes.

~~~bash
./gradlew originalFrameRangesSmoke callFrameEncoderSmoke buildExtension
python3 src/test/integration/original-frame-ranges.py build/classes/java \
    build/test-results/original-frame-ranges --dwarfdump "$DWARFDUMP"
bash src/test/integration/architecture-neutrality.sh
actionlint .github/workflows/ci.yml
~~~

The component suite passes 4275 checks, covering framing/width/order/version
combinations, all supported scalar encodings, negative relative displacements,
forward CIEs, signal/personality data, empty ranges, truncation, malformed later
records, immutable results, every observed cancellation poll and successful
retry. Existing encoder checks and extension build pass.

The compiler harness uses the unchanged synthetic-cfi.c (including its global
write) to build twelve independent reference cases: x86-64/AArch64, each with
exec/PIE/shared and either frame format. Independent builds are byte-identical;
source and original hashes remain unchanged. The reader's full range lists
match GNU and LLVM inventories, and LLVM verification passes.

The initial strict run rejected known four-byte-aligned EH records. The final
harness uses the existing exact-byte/identity corroboration policy against the
separate byte-identical compiler rebuild; only matching inherited frame
diagnostics are accepted. Exact counts and logs remain in the receipt/archive.
This is not a blanket warning waiver and does not claim a zero-diagnostic EH
run. A subsequent harness metadata-suffix error is retained separately.

No emitted artifact or production export behavior changes in this checkpoint;
GDB runtime behavior is not newly claimed. Existing original-CFI preservation
and recovered-frame runtime receipts retain their own scopes. The new hosted
reader/compiler checks are wired into both target lanes but are
**PRESENT, UNVERIFIED** until their branch is accepted. See
[the receipt](evidence/original-frame-ranges.json).

## Next integration obligations

Inventory every named/compressed frame source and program-header-derived source,
including uncertainty and conflicting-source handling. Bind original bytes and
relocations to that inventory, exclude declared ranges from generated intervals,
and reconcile preserved/generated records without altering the original target.
Then complete the global-write proof, real exporter publication/diagnostics and
the full runtime matrix in [the synthesis contract](SYNTHETIC-CFI-EVIDENCE.md).
PR166 integration still has priority, and #112/#110/#109 remain open.
