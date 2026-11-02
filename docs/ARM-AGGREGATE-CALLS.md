# ARM aggregate call classification

**CONFIRMED local packaged call behavior; hosted acceptance pending.** This
component implements the call-classification gap established in
`research/ARM-AGGREGATE-PCS.md`. It does not complete aggregate parameter
locations, the broader ARM ABI work, or any of #68–#71.

## Behavior and limits

`Arm32CallPolicy` now distinguishes ordinary contiguous scalar-member structures
from homogeneous floating aggregates. A mixed integer/float structure uses the
ordinary aggregate transfer in both PCS variants; it is not restricted simply
because it contains a float. HFAs and scalar floating transfers still require
agreement between the selected per-function PCS and the executable's automatic
GDB PCS. Mismatches emit `DW_CC_nocall` for definitions and callback types.

The classifier checks nonempty structures of up to four contiguous, naturally aligned 4/8-byte
signed, unsigned or floating members, including typedef/qualifier resolution.
An HFA requires identical floating member widths. Hidden return carriers must
point to the exact formal aggregate result and must agree with whether the
selected PCS returns that aggregate through memory or VFP registers. Independent
compiler/custom-storage restrictions remain in force. Nested aggregates, explicit
padding, bit fields, unions and vector types are still separately classified
work, not silently accepted through this envelope.

The maintained runtime fixture exercises integer pairs, mixed integer/float
structures, three-float and two-double HFAs, a register/stack split after three
integers, and an exhausted HFA after seven doubles. The preceding independent
compiler reference establishes raw transfers and typed parameter values. The
new exporter test independently checks raw entry carriers, captured arguments,
automatic typed returns, injected name/pointer calls and unchanged-state
rejections. It deliberately does not claim that a parameter's missing location
has been solved merely because its function can now be called.

## Validation and reproduction

```bash
python3 src/test/integration/arm-aggregate-calls.py /path/to/packaged/ghidra \
    --order little --pcs hard \
    --gdb /usr/bin/gdb-multiarch --gdb-data /usr/share/gdb \
    --qemu /path/to/corrected-qemu-arm
```

Repeat for `softfp` and both BE8 PCS values using the pinned GDB 17.1 and corrected
private `qemu-armeb`. The established consumers, Ghidra 12.0.3, Java 21 and
libdwarf 2.3.2 are unchanged. CI invokes these four production-export cases;
each first runs the strict independent compiler reference. The shared GDB
decoders moved to `arm_aggregate_pcs_oracle.py`; reference assertions remain
strict and the four references pass again through the maintained harness.

The local package is `build/arm-aggregate-pcs/call-candidate-v2.zip`, SHA-256
`0a30530f46cccce411b468787bfae4b258a5e4cebec3cc80bda82d15009d1813`.
Its production JAR SHA-256 is
`7ad5779760f94ee0d24985d286a49069dc65902b011883803b7ff4417b8a64fd`.
All four maintained cases pass, recorded in `call-matrix-v2.outcomes.json` and
the per-case `result.json`, `forge-gdb.json` and `call-attributes.json` receipts.
Across those exporter runs: 48 raw entry transfers, 48 captured aggregate
observations, 36 automatic typed returns, 72 successful injected calls and
24 unchanged-state rejections. Raw DIE checks cover 96 function/callback
calling-convention attributes. These counts exclude the independently rerun
compiler observations, which also pass.

Each case uses fresh stripped import, explicit dynamic signature curation,
saved-program reopen, two byte-identical source/sidecar exports, GNU/LLVM/pinned
strict validation, original-image identity checks, installed-JAR origin and
file hashes. Original executables and installed modules remain unchanged;
saved project differences are limited to documented Ghidra backup rotations.
The private QEMU vDSO warning is corroborated against mapped ELF bytes and is
not broadly suppressed.

The extension build and focused model checks pass: ARM PCS 3,880 checks,
compiler-policy 606 checks across 26 specifications, and custom-storage 486
checks. The new model cases cover ordinary/HFA transfers in both result and
argument roles, all three callable forms, typedefs, wrong hidden carriers,
misalignment/padding/union/bit-field/size-budget rejection and idempotence. Existing guarded
scalar/declaration tests pass in LE hard and BE8 softfp, and the previous ARM
integer aggregate return/callback regression passes. Commands and results are
under `build/arm-aggregate-pcs`, including `call-classification-build-v2.log` and
`call-matrix-v2.outcomes.json`. Workflow lint, Python parsing and whitespace
checks pass. No unrelated full-model rerun is claimed for this isolated policy
change.

## Remaining work

The earlier Q-register HFA omissions and lost saved aggregate locations remain
real implementation gaps. Calls/returns passing here do not prove their
lifetimes. Continue audited logical-register decomposition, shared saved-copy
analysis, per-instruction values/clobber gaps, broader aggregate/type shapes,
layout/profile/failure/cancellation composition and exact-head hosted/host
acceptance. The full original completion plan remains binding.
