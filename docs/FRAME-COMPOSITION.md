# Preserved and generated frame record composition (#112)

**CONFIRMED locally:** the encoder can append generated `.debug_frame` records
to an unchanged, decoded original section. Original CIE/FDE bytes and their
section offsets remain identical. New FDEs point to the appended CIE's actual
section offset, rather than zero. Generated address ranges must not overlap
any original FDE, including nested or overlapping original ranges.

The original prefix must have a complete supported debug-frame inventory and
address-size alignment. Invalid/truncated prefixes, unexplained trailing zero
records, overlapping generated coverage and the combined 64 MiB byte limit
refuse composition. All generation/copy stages honor cancellation. Empty
generated plans preserve the prefix exactly. This follows DWARF 5 §6.4.1:
record extents are address-size multiples and an FDE's CIE pointer is an offset
within the complete `.debug_frame` section.

This is a serialization prerequisite. It does not establish recovery evidence,
validate original CFI instruction semantics, or qualify ELF relocation effects.
The ordinary writer's original-frame collision rejection remains in force.
**CONFIRMED locally:** the [explicit qualified writer API](QUALIFIED-FRAME-WRITER.md)
connects original section decoding and coverage to this composition path,
retaining old compressed-section identity and safe publication.
Production synthesis still requires the full evidence/ADR acceptance.

## Validation

- 362 encoder/composition checks cover both address widths and byte orders,
  exact prefix preservation, independent range parsing, CIE offsets, overlap and
  truncation refusals, deterministic reruns and every observed cancellation poll.
- Four actual compiler-prefix cases cover x86-64/AArch64 non-PIE and PIE. The
  harness copies the compiler's first complete CIE/FDE without changing a byte,
  then adds explicit generated plans only for the other functions. The original
  executable remains unchanged. These are explicit encoder plans, not recovered
  Ghidra evidence.
- Eight plain/compressed sidecars pass GNU, LLVM and pinned strict validation.
  Independent byte inspection proves the compiler prefix and appended CIE
  references; a separate decoder checks generated rows. Eight native/QEMU GDB
  sessions match the independent compiler reference's instruction-by-instruction
  backtrace, caller-register, finish and stepping observations.
- The AArch64 QEMU VDSO warning matches the compiler reference; it is retained
  and is not attributed to the sidecar. No unexplained validator warning passes.

Evidence and pinned DWARF source hashes are in
`docs/evidence/frame-composition.json`. New hosted coverage is **PRESENT,
UNVERIFIED** until its exact head passes. The unchanged global-writing compiler
fixture, production integration and complete #112/#110/#109 remain outstanding.
