# Original unwind records in sectionless ELF

**CONFIRMED locally; full integration acceptance pending (2026-10-31).**
The production reader fixes an observed i386 rebased-PIE `next` failure by
exposing original unwind bytes. It does not generate call-frame instructions.
P1.7/#66 remains open.

## Discovery and publication

For inputs without section headers, `SectionlessUnwind` reads the original
`PT_GNU_EH_FRAME` header and its sorted search table. Every pointer and complete
record extent must resolve to a unique file-backed `PT_LOAD` mapping. The reader
walks ordinary CIE/FDE record boundaries from the encoded frame address through
the last indexed FDE, validates backward CIE references, and requires equality
between the walked and indexed FDE sets.

The sidecar adds an allocated `.eh_frame` view at the original file offset and
virtual address, with alignment one. Its size ends at the last proven record;
termination and padding bytes beyond that point are not guessed. It is appended
after synthetic load sections so existing symbol indices stay stable. Original
bytes, function addresses and call-frame instructions are unchanged. The normal
atomic output-pair publication contract remains in effect.

The supported header profile is version 1 with fixed-width absolute,
PC-relative or header-relative pointers and ordinary DWARF32 record lengths.
CIE versions 1, 3 and 4 are recognized. The reader validates framing and CIE
relationships; it is not a full CFI instruction interpreter. Structural and
debugger validation remain required. See the
[research and format basis](research/SECTIONLESS-UNWIND.md).

## Bounds and explicit omissions

- At most one header, 16 MiB header bytes, 262,144 table entries/records and a
  64 MiB recovered frame extent.
- At most 128 MiB aggregate reads and 16 million mapping comparisons, with
  cancellation checks in loops and 64 KiB read chunks.
- Original file identity checks surround reads. I/O failures and cancellation
  propagate rather than publishing partial output.
- Absent headers produce no invented frame view. Malformed metadata, ambiguous
  mappings, unsupported encodings, extended records and exceeded bounds omit
  the view with a production diagnostic. Primary DWARF export remains available.

Unsupported recovery can still limit debugger unwinding or stepping. This is
not general unwind reconstruction, ARM EHABI recovery or a promise that every
sectionless ELF contains usable unwind information.

## Validation

The model suite passes 896 checks across ELF32/64 and both byte orders, including
pointer encodings, invalid records/mappings, source changes, cancellation and
preservation of prior output. Thirty-four suites pass with the actual Java 21
runtime against installed candidate JAR
`ef027e1b7de3de54ff0b31163aaeadb76b15683f62645b407b29a327404808c9`.
The previously failing sectionless i386 rebased PIE now passes real headless
export, validators and GDB `next`/`step`, values and returns.

Exposing original frames also exposes inherited validator diagnostics. The
strict checker accepts a section-backed fixture reference only when its complete
retained bytes match the sectionless original except for deliberately cleared
section-header fields. `objcopy` may also clear the section-entry size and
remove trailing section metadata; frame bytes must lie wholly within the
remaining original file. Recovered frame bytes must match its original frame
prefix, with only zeros after that extent. The original checker invocation and
exact diagnostic comparison are retained; no warning category is waived.
Altered header, payload and frame references, plus direct/symlink/hardlink log
collisions, are rejected by controls.

The initial x86-64/AArch64 matrix stopped because the old corroboration helper
required section headers. Its failed logs remain under
`build/i386-unwind-review/`. Fresh cross-target, versioned-symbol, omission and
older sectionless-path regressions pass. Independent review, final-checker replay
and captured-evidence controls also pass; see
[the i386 acceptance record](I386-FUNCTION-ALIASES.md) for scope and receipt.
Committed-package and hosted acceptance remain pending.
