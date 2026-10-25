# Explicit MIPS FP32 validation reference

**CONFIRMED locally; hosted acceptance pending:** explicit `-mfp32` compiler
fixtures provide correct double-argument observations through the installed
QEMU/GDB combination in both byte orders. The existing exporter also handles
analyst-described two-register pieces correctly in that profile. Whole-register
aliases remain unavailable. No production register map, ABI selection or
location-expression implementation changes.

## Why the distinction matters

The ordinary MIPS fixture uses toolchain-default FPXX. Its compiler DWARF
currently reports zero for two double arguments even though the program stores
the correct values. That remains an unverified parameter-location reference,
as recorded in [VALIDATION.md](VALIDATION.md). A compiler ELF that passes
structural validation does not by itself prove usable debugger values.

An otherwise equivalent source-built `-mfp32` fixture records the explicit
hard-float double-precision ABI and 32-bit CPR1 registers in its ELF attributes.
GDB observes `first=21.5` and `second=-9.25` at entry and before/after their
stores, then checks the stored globals, source navigation and normal exit.
The strict FPXX control still fails with `first=0`. These are observed profile
differences, not a general QEMU fix or permission to map every `f12_13` register
as one supported double location.

The raw control records `sr=0x20000010` for FP32 and `sr=0x24000010` for FPXX.
The initial probe used the invalid GDB register name `status`; its four failed
transcripts remain separate. The corrected name `sr` comes from the retained
source corresponding to installed Ubuntu GDB 15.1. The probe never forces GDB's
FPU mode, edits register contents, or modifies a target ELF to fabricate an ABI.

## Harness contract

Set `FORGE_FP_ABI_PROFILE=mips-fp32` on the existing floating-register harness:

```bash
FORGE_FP_ABI_PROFILE=mips-fp32 src/test/integration/floating-registers-export.sh \
    "$GHIDRA_INSTALL_DIR" /path/to/libdwarf.so.2.3.2 \
    /path/to/libdwarfp.so.2.3.2 mips32be mips32le
```

The selected profile accepts only MIPS32 fixture targets and passes `-mfp32` to
the actual cross-compiler. It verifies the resulting ABI attributes before
export. Both required MIPS CI lanes add this profile alongside their default
FPXX coverage. The default profile's existing explicit unverified observation
policy remains unchanged.

For FP32, the compiler reference must return the exact two double values at
all three instruction boundaries. There is no zero/UNVERIFIED exception.
Each byte order covers exec and PIE, each with baseline, explicit Ghidra
rebase and unchanged repeat exports. `FORGE_FP_STORAGE_FORM=register-alias`
(the default) retains the typed but unavailable `f12_13`/`f14_15` aliases.
`FORGE_FP_STORAGE_FORM=explicit-pieces` requires this FP32 profile and curates
actual two-varnode storage: high/low `f13`/`f12`, and `f15`/`f14`, in Ghidra's
MSB-first join order. It never writes the machine registers or invents a
location in the exporter. The existing generic composite path converts those
pieces to object-memory order. GDB must read both Forge doubles correctly at
all three boundaries; scalar floats remain available in both forms.

The independent raw checker requires exactly two 32-bit, zero-offset DWARF
pieces per double, with register numbers 45/44 and 47/46 on big endian, reversed
on little endian. It checks the actual eight-byte floating base type too.
Both forms run in the MIPS CI lanes, retaining the whole-alias omission as a
negative control. This does not teach the exporter to expand a whole alias or
establish correct pairs under FPXX's unverified transport. Independent compiler
and separate-symbol checks, GNU/LLVM/pinned strict validators, source navigation,
input hashes and repeat byte equality remain mandatory. The new profile also
binds the actual loaded storage extractor to the installed JAR and checks all
module, native and harness files before and after the run.

## Local evidence and limits

The bounded initial investigation is retained at
`/home/ziggy/GhidraDwarfForge/build/mips-fp-mode-review/`:

- `run.3rpPGStn`: initial invalid-register-name failure; no pass claimed.
- `run.6D93wpI4`: two strict FP32 passes and two explicit FPXX failures.
- `export-fp32/run.wnHe0aqH`: six baseline/rebase/repeat exports, with original
  system-checker results retained and separate pinned strict replays passing.
- `research-acceptance.json`, SHA-256
  `3be045b307fa2a155cc637f4bf217c6418310b34f5d9612d2e290e8628e32be6`.

The final production-harness profile runs in worktree `mips-fp32-oracle` at
`build/test-results/floating-registers-fp32/run.nynVeBAG`. Twelve exports and
18 debugger sessions pass using unchanged JAR
`4087b89299fe3e55692455c3577cd54aec33360725f0fe76b2c774dff3396642`.
Local headless Java is 25.0.4.1; this is not a hosted Java 21 claim. Raw-review
receipt SHA-256:
`0902357bc054e323275872de461562eead9326c0c1cdfd0130c72362e026a67d`.

An initial audit incorrectly required the entire rebased source and sidecar to
match the original. Ghidra rebasing changes autogenerated names and decompiler
output. The correct contract checks byte identity for unchanged baseline/repeat
programs and correct normalized curated addresses and GDB behavior after rebase.
That failed audit is recorded without weakening either requirement.

The default FPXX regression `run.fACWs71D` also passes twelve exports across
both byte orders and executable roles; its compiler pair zeros remain explicitly
UNVERIFIED. Combined local receipt SHA-256:
`5776f678f63c91994f602d8d4d2c662e1c8dbe34bffe48ec8016fd7b7c9d7f61`.

The final storage-form runs are `run.icaWn8Jy` (whole aliases) and
`run.jOAqLSqT` (explicit pieces), each twelve exports. Their raw-review receipts
are `5a6fa60c9bd64271059966f07e1f3dffe1195abb4d43693250b48c48ae1fda70` and
`46173c0626a3f3cc393d1b14028c215eefff4b3deb753c25bae662095866bf6a`.
The latter proves actual positive Forge double values and exact piece order;
it supersedes the earlier absence-only scope for explicitly curated pieces.
The original whole-alias omission remains required.

A preliminary owned experiment (`build/fp32-review/pieces/`) first supplied an
incorrect producer path, then retained an obsolete whole-alias omission
assertion after explicit pieces became available. Those attempts are not
positive runtime evidence. Corrected experiment `run.6gqJDzLm` passes six
exports. The raw checker initially treated readelf's single-digit byte tokens
as padded hexadecimal; the retained first checker and failure are followed by
corrected token parsing and the passing final runs. No exporter code changes
were needed for any of these corrections.

Final default regression `run.LudccgGa` passes another twelve exports with the
final scripts. Combined final scope is 36 exports: twelve FP32 alias omissions,
twelve FP32 explicit-piece positives, and twelve default-FPXX regressions.
Final receipt SHA-256: `013d09a28cdaa94fa98f0d40fc81730a9fa069191c4c8b6b706da9bf1978065e`.

Full hosted acceptance remains pending. Automatic whole-alias expansion
still needs a separate, defensible ABI/storage policy and negative controls. FP64A, arbitrary FPXX execution modes, N32/N64 floating
arguments and broader MIPS ABI classification remain outside this checkpoint.

## FP64A remains outside the validated profile

**CONFIRMED negative local evidence:** explicit `-mfp64 -mno-odd-spreg`
fixtures identify a 64-bit FPU and the FP64A ABI. Strict untouched compiler-DWARF
checks fail in both byte orders: the first double reads zero instead of 21.5.
A separate observation completes with six explicitly UNVERIFIED parameter
values per case, while strict stored-global checks and normal execution pass.
GDB exposes the relevant floating registers as four-byte carriers. These are
compiler-reference failures before any exporter invocation.

The inspected [QEMU 8.2.2 MIPS stub](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/target/mips/gdbstub.c)
passes FR=1 values through the target-word-width
[register helper](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/include/gdbstub/helpers.h).
**Inference:** truncation in that transport is consistent with the observations;
the Ubuntu-patched executable is not claimed byte-equivalent to upstream source.
A verified full-width transport is needed before promoting this profile.

Evidence remains under `build/mips-fp-mode-review/`: strict failure
`run-fp64a.L8Obhyk4` and corrected observation `observe-fp64a.6DSo22Fc`.
The observation receipt is
`6eb529e68763c7154c60ebc23c41bb9bd61c5c4892440c5200b12a58f2e4e1fc`.
An earlier all-register-value query failed on an unsupported unnamed register;
its source and `observe-fp64a.muJlW0Ea` logs remain separate. The correction
queries register configuration only and does not turn wrong values into passes.

A separate six-ELF metadata probe proves that these FP32, FPXX and FP64A inputs
all have identical `e_flags=0x70001007`. Their ABI records distinguish them and
remain accessible through `PT_MIPS_ABIFLAGS` in owned sectionless copies.
Receipt `b7892819c8c122d1dd55cd2010b184bfb539e79fa34c1404241bf064fd0af453`
is at `build/mips-abi-metadata-review/run.1q0pn2qx/observations.json`.
This is metadata evidence, not sectionless FP64A runtime validation or a
production ABI classifier. No exporter mapping compensates for the failed
compiler reference.
