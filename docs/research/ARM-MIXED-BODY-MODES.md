# ARM mixed-body mapping reference

**CONFIRMED defect and consumer experiment; production correction PLANNED.**
This is a component of the unchanged #70 requirement, within the complete
#68–#71 goal. The research harness explicitly requires the current exporter to
fail its static decoding check. Its passing research status is not an exporter
support claim and must never become the supported-target CI gate.

## Reference and independent evidence

`src/test/fixtures/arm-mixed-body.S` defines one function that executes four ARM
instructions, four Thumb instructions, then four ARM instructions. A trailing
four-byte literal is outside the function body. The allocation is a separate
44-byte `.forge_mixed` section, so all code/data boundaries are independently
auditable. The caller passes 11, and the function computes
`11 + 3 + 5 + 7 + 0x1234 = 4686`; the caller exits successfully only for that
result. No proprietary input or prebuilt target binary is used.

GNU's assembler emits `$a`, `$t`, `$a`, `$d` at offsets 0, 16, 24 and 40. The
harness checks their raw names, offsets, zero sizes, local/NOTYPE information and
the entire fixed instruction/literal byte sequence. GDB's compiler reference
decodes the two-byte Thumb instructions correctly before attachment. It then
executes all twelve instructions under QEMU, checking the PC, raw instruction
bytes, CPSR mode and source-known r0 value at every stop. The literal bytes and
returned value are checked separately. Automatic debugger mode selection stays
enabled; no forced mode or fallback workaround is used.

Ghidra 12.0.3 independently decodes all twelve instructions and identifies the
literal. Initial analysis bounds the first function at the first indirect
branch. `PrepareArmMixedBody.java` models explicit analyst curation: it verifies
the already decoded lengths/context, joins the 40 code bytes into one function,
and assigns a name/signature. It neither disassembles unknown bytes nor changes
ARM/Thumb context. The complete curated body still loses its Thumb mode in the
sidecar. The current homogeneous-function extractor diagnoses an unsupported
instruction length rather than producing a false cue.

Both the uncurated and curated exports reproduce the static decoding defect.
The curated baseline decodes each pair of Thumb instructions as a four-byte ARM
instruction. Its runtime raw-register/mode checks still pass: the target CPU
executes the original unchanged instructions. Correct runtime execution alone
does not establish correct debugger disassembly.

## Isolated consumer experiment

The [ARM ELF specification, section 5.5.5](https://github.com/ARM-software/abi-aa/blob/353c2f249a16e6d42e9dae15e78ea148dc6e5349/aaelf32/aaelf32.rst#mapping-symbols)
defines local, zero-sized NOTYPE records for ARM, Thumb and data boundaries.
Each boundary applies until the next boundary or the section end. Therefore a
mapping cannot be confined using `st_size`, and an unknown byte gap cannot be
silently treated as data or assigned the preceding instruction mode.

`arm-mixed-mapping-experiment.py` adds precisely those four known records to a
new copy of the sidecar. It checks preservation of every existing symbol and
every other section/header/payload. This fixture-specific mutation is a
consumer experiment, not the production writer or extraction policy. It refuses
existing outputs. An initial GNU objcopy attempt failed because it could not
rewrite this matched non-loadable ELF's PHDR layout; no invalid output from that
attempt is accepted.

The experiment fixes pre-attachment decoding, matching the compiler's
instruction addresses, widths and text after removing symbol-name annotations
only. All twelve actual instruction observations still pass. The baseline and
experiment both pass GNU readelf, LLVM verification and pinned strict libdwarf
with zero errors. All DWARF bytes remain identical: validators alone cannot
detect this debugger-mode defect. GDB's only accepted warning is the exact
compiler-corroborated QEMU synthetic-vDSO warning; the baseline's exact expected
assertion is recorded separately.

## Reproduction and retained results

With the private ARM compiler/sysroot and Java 21 environment:

```bash
python3 src/test/integration/arm-mixed-mode-reference.py <installed-ghidra>
```

The accepted run is `build/test-results/arm-mixed-reference/run.q7yv7bcm` in
the `work/arm-mixed-modes` worktree. The result is
`PASS_RESEARCH_REPRODUCTION`, with `productionSupport: false`:

| Artifact | Static decoding | Runtime observations | Structural validators |
| --- | --- | --- | --- |
| Compiler reference | PASS | 12/12, exit 0 | PASS |
| Curated production sidecar | Expected failure | 12/12, exit 0 | PASS |
| Separate mapping experiment | PASS | 12/12, exit 0 | PASS |

Two read-only exports of the saved curated program have identical sidecar/source
bytes. All 188 protected input/package/harness files and the saved program bytes
remain unchanged. The accepted sidecar SHA-256 is
`4c2b8e5885728dd1313a97ced8478e850380da073e5be918c003f9386ef33f5b`; source SHA-256
is `e3fed0c82c86b01dc553868349b979c9bb1444e84d7bf446ec5051914e1f2827`.
The installed package is PR130's unchanged v1 JAR
`7b22fdbb111df9d4aba25d8c0fcff4684c8564fcfe761fb481f6e3525631bd7c`.
A final exclusive-create guard produces byte-identical experimental output and
rejects overwriting an existing file without modifying it.

The first assembled harness exported during import and compared that artifact
with a later saved-project export. Ghidra's intervening post-analysis changed
the source result. That retained failed attempt is not a determinism pass.
The corrected harness separates import, analyst preparation and two read-only
exports, then checks program hashes. Production code was not changed to mask
the differing states.

## Required production work

1. Extract section-bound mode/data evidence from the actual saved listing,
   retaining complete coverage, original decode context, unambiguous ownership,
   normalized addresses and original-byte binding. Never extend a mapping over
   a hole, uninitialized data, or unknown padding. Investigate the actual Data
   API distinction between explicit data and undefined bytes before using it.
2. Plan standard mapping symbols in an isolated ARM policy. Reconcile inherited
   mapping symbols and function hints, reject conflicts, bound resource usage,
   and preserve existing symbol/index dependencies. Retain honest diagnostics
   when complete evidence is unavailable.
3. Extend the matched writer with explicit zero-sized local NOTYPE support;
   retain the existing strict nonzero function-symbol contract. Do not encode
   mappings as fake DWARF functions or tag DWARF code addresses.
4. Add actual-Ghidra and ELF/writer controls for missing/changed bytes, unknown
   context, gaps, data boundaries, overlaps, existing mappings, rebasing and
   cancellation. Runtime acceptance must use the unmodified production output
   and cover applicable PIE/shared/sectionless compositions, named/address
   breakpoints, source behavior and preserved originals.
5. Require final-package validators, GDB, failure/cancellation compositions,
   exact-head hosted checks and protected integration. This reference does not
   complete mixed-body support, ARM32, or any umbrella issue.
