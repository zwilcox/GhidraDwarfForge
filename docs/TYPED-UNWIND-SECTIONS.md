# Processor-typed runtime unwind sections

**CONFIRMED locally; hosted acceptance unverified:** the original-frame reader now
recognizes the AMD64 processor-defined `.eh_frame` section type in the validated
ELF64 little-endian profile. Standard `PROGBITS` behavior remains available on
all existing layouts. Normal CLI/GUI synthesis remains disabled.

## Defect and selected contract

A source-built GNU assembly fixture using `.section .eh_frame,"a",@unwind`
links to an executable with `SHT_X86_64_UNWIND` (`0x70000001`). Its runtime frame
records have the same meaning as the existing `PROGBITS` representation. The
previous `OriginalFrameSources` reader rejected this valid metadata solely
because it required type1, preventing recovery of uncovered functions.

The [AMD64 psABI 1.0](https://raw.githubusercontent.com/wiki/hjl-tools/x86-psabi/x86-64-psABI-1.0.pdf),
sections 4.2.2 through 4.2.4, defines the processor section type and its frame
format. The exact inspected PDF has SHA-256
`f5c0e21542fc379090252e18ff3d083d2a5f51da8cca62b0fec41cc330a74641`.
A retained before-fix standalone execution reproduces the `not PROGBITS` refusal.

`UnwindSectionProfile` isolates the processor/class/byte-order mapping. Generic
inventory code still checks every record, search-header agreement, bounded
payload, cancellation and source identity. This change does not certify arbitrary
unwind rule semantics. Nonempty processor-typed sources with unexpected names
cause an explicit refusal; they cannot silently become apparent coverage gaps.
Processor-specific types are not accepted on `.debug_frame`/`.zdebug_frame`,
other processors, untested x32 or big-endian layouts. Unknown section types and
unsupported compression continue to fail.

The independent Python corroboration reader also accepts this exact target/type
combination. It retains the existing ELF/address/frame-byte identity contract and
requires every reported alignment diagnostic to match the original. Recognized
`PROGBITS` and processor encodings may corroborate identical runtime records;
actual exporter tests separately require exact original section-type preservation.
No generic diagnostic, summary, stderr or completeness rule is relaxed.

## Validation contract

The final source-inventory suite passes 1,256 checks. Both processor-typed
fixture families pass all three roles: 54 native exports, twelve staged failure
controls, 24 sidecars and 54 GDB sessions. Six ordinary runtime-metadata cases
across x86-64/AArch64 also pass with the changed package, adding 54 exports,
twelve controls, 24 sidecars and 54 GDB sessions. All 48 exported strict reports
pass final retention review. The report-damage suite passes three positive and
ten negative cases. Complete checker controls, the extension build, workflow
lint and architecture-boundary guards pass.

The final installed package has 681 production classes identical to the compiled
output; both changed production sources match its installed source archive.
The initial compile attempted to access package-private section fields; the
profile API now receives their explicit name/type values. The initial runtime
attempt exposed the same PROGBITS-only assumption in the independent validator
identity reader; it was fixed and tested before the complete final-package runs.
No JNA or native-library call changed. A real headless negative control with
an unexpected processor-frame section name produces no recovery plan and
preserves the previous sidecar/source pair and original bytes. Its deliberate
assertion exits headless with status1; the harness requires that exact refusal,
not a successful process or a generic ignored error. The initial negative-test
wrapper incorrectly required exit0 and is retained separately.

See [the evidence receipt](evidence/typed-unwind-sections.json) for package,
source, command and archive bindings.


The existing source inventory suite covers ordinary 32/64-bit and both byte
orders, compressed debug frames and program-header discovery. New controls test
processor-typed named/header sources, cancellation at every observed checkpoint,
unchanged input, named-only sources, wrong machines, unsupported class/byte order,
wrong debug-section names, unknown type values and unexpected runtime-source names.
The checker suite adds target/type and layout controls to its existing corruption,
truncation, alias, diagnostic-multiplicity and sectionless-reference tests.

The real native-export harness builds both independent assembler families with
the processor section type, in executable, PIE and dynamically loaded shared
roles. Both input and complete reference must actually contain that type.
Validators, caller-frame PC/register traces, GDB stepping/finish, original byte
and section metadata preservation, deterministic reruns, rebasing, source lookup,
staged cancellation/exception recovery and retained reports remain mandatory.

Reproduce with a validated recovery-results directory:

```bash
python3 src/test/integration/unwind-export.py "$GHIDRA_INSTALL_DIR" \
    /path/to/recovery-results /path/to/new-results --target x86_64 \
    --original-runtime --runtime-section-type processor --dwarfdump "$DWARFDUMP"
```

Use explicit native-library paths for an installation without bundled libraries.
The workflow runs both fixture families. Ordinary runtime metadata is also
regressed on x86-64 and AArch64 with the changed installed package.

This is a metadata-recognition correction, not expanded synthesis support for
x32, signal/exception frames or other processor profiles. Compiler-C storage
policy, normal-entry-point enablement, evidence reporting, the ADR decision and
hosted stack acceptance remain incomplete under #112. LLDB and build-ID work
remain separate goal items.
