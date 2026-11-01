# ARM per-function call and return references

**CONFIRMED compiler-reference limitations; Forge implementation incomplete.**
The mixed base/VFP requirement remains part of #70 and the full #68–#71 goal.
Correct parameter displays do not prove debugger-injected calls or automatic
typed return values. The reference below isolates those operations without
loading any Forge sidecar or changing any exporter policy.

`arm-pcs-call-reference.c` has two functions with explicit GCC `pcs("aapcs")`
and `pcs("aapcs-vfp")` attributes. Each saves its received float arguments and
returns their sum. Normal calls pass 1.25/2.5 and 3.25/4.5 respectively; main
checks 3.75 and 7.75. It builds as freestanding ARMv7 EABI5 hard-float ET_EXEC
in both little-endian and BE8 encodings, with unmodified compiler DWARF.

The current harness requires GDB 17.1 and QEMU 8.2.2 so a changed consumer cannot
silently turn the known-failure oracle into a different profile. GNU, LLVM and
strict libdwarf validate both compiler artifacts without reported errors.
Fourteen fresh QEMU processes examine two functions under `auto`, `softvfp` and
`vfp` settings, plus a direct register-write control in each byte order.

| Operation | LE result | BE8 result |
| --- | --- | --- |
| Ordinary program calls | Both sums correct; exit 0 | Both sums correct; exit 0 |
| `finish`, automatic/VFP model | Base incorrectly reports 0; VFP reports 7.75 | Same |
| `finish`, forced softvfp | Base reports 3.75; VFP incorrectly reports 3.75 | Same |
| Inject base call, automatic/VFP | Wrong received arguments and result | Wrong received arguments and result |
| Inject base call, softvfp | Arguments 1.25/2.5, result 3.75 | Same |
| Inject VFP call, automatic/VFP | Arguments 3.25/4.5, result 7.75 | Wrong arguments/result from swapped register writes |
| Inject VFP call, softvfp | Wrong arguments/result | Wrong arguments/result |

All ordinary entry arguments and raw return registers are checked separately.
Changing the global FPU setting fixes one PCS and breaks the other: it is not a
per-function solution. In the pinned unmodified GDB 17.1 `gdb/arm-tdep.c`,
`arm_vfp_abi_for_function` selects the base ABI for variadic functions and otherwise
uses the global ABI/FPU model. It does not inspect a per-function calling
convention. The GCC reference DIEs contain no calling-convention attribute.
Neither changing a function's true signature nor fabricating variadic status is
an acceptable exporter workaround.

## Independent BE8 register-write defect

The direct write control sends the numerical double 1.25 to D0, then invalidates
GDB's register cache and rereads the target. The remote trace proves GDB sends
`P1a=3ff4000000000000` for BE8. QEMU acknowledges it but returns
`000000000000f43f`, which represents approximately `3.0892442637515623e-319` in
big-endian order. The equivalent little-endian round trip retains 1.25.
No DWARF location expression or injected-call classifier participates in this
control. It changes only the private test inferior's register state.

The [QEMU 8.2.2 ARM stub](https://github.com/qemu/qemu/blob/v8.2.2/target/arm/gdbstub.c)
reads VFP registers through the target-order helper but writes D registers with
`ldq_le_p`; its Q-register writes also explicitly use little-endian loads.
The [10.1.0 source](https://github.com/qemu/qemu/blob/v10.1.0/target/arm/gdbstub.c)
still has that write path. This source comparison rules out assuming that a
simple upgrade to that version fixes the failure; 10.1.0 was not built or run.
A private corrected emulator or independent real-target reference remains to
be investigated. Do not modify Forge's valid DWARF to compensate for remote
register writes.

## Reproduction and retained evidence

With the documented private ARM compiler/validator environment:

```bash
python3 src/test/integration/arm-pcs-call-reference.py \
    --gdb /private/gdb17-arm/build/gdb/gdb \
    --gdb-data /private/gdb17-arm/build/gdb/data-directory
```

The maintained receipt is
`build/test-results/arm-pcs-call-reference/run.i1_lf19l/result.json` in the
`arm-be8-profile` worktree. It records fourteen observations, exact commands,
tool versions, strict reports and before/after hashes of inputs, harnesses,
debugger/data files and emulators. Its status is deliberately
`PASS_REFERENCE_LIMITATIONS`, not exporter acceptance. Failed consumer values
are required controls, not granted exceptions to a claimed working call ABI.
The earlier exploratory scripts/logs remain in
`build/arm-be8-profile/pcs-call-reference-{little,big}`.

Next: obtain a trustworthy BE8 injected-call reference, classify selected
per-function PCS/storage against the ELF and actual Ghidra compiler model, and
validate the real exporter with scalar, wider, aggregate and exhausted-register
argument/return cases. Keep ordinary value reading, automatic typed returns and
injected calls separate in the acceptance evidence. The interim blanket BE8
call guard remains incomplete and does not close #70.

## Corrected private emulator reference

**CONFIRMED locally:** both a private unmodified QEMU 8.2.2 build and a private
build with one D-register write correction were executed against identical
compiler fixtures. Changing `ldq_le_p` to the target-order `ldq_p` in
`vfp_gdb_set_reg` restores the BE8 1.25 register round trip and injected VFP
arguments 3.25/4.5 with result 7.75. LE remains correct. Base/VFP global-selection
failures still reproduce, isolating them from the emulator write defect.
This supersedes the earlier open search for a scalar BE8 injected-call reference;
actual Forge call-policy implementation and the wider ABI requirements remain.

The source archive SHA-256 is
`847346c1b82c1a54b2c38f6edbd85549edeb17430b7d4d3da12620e2962bc4f3`.
`support/validation/build-arm-qemu.py` pins that archive and the single patch,
records build commands and executable hashes, and only builds private ARM/BE8
linux-user executables. No system package is installed or replaced. The selected
QEMU source includes one unused firmware symlink to absolute host headers;
safe extraction explicitly skips and records that exact link. Every other
member uses Python's data filter. Locally, development packages were downloaded
and extracted beneath the experiment directory; their names/hashes are recorded.

The correction deliberately does not change Q-register writes. Scalar D/S
call-reference success is not vector/NEON acceptance. The emulator is a
validation tool only; it is not bundled with the extension or native producer.

```bash
python3 support/validation/build-arm-qemu.py /private/qemu-arm-reference \
    --correct-d-register-writes
python3 src/test/integration/arm-pcs-call-reference.py \
    --gdb /private/gdb17-arm/build/gdb/gdb \
    --gdb-data /private/gdb17-arm/build/gdb/data-directory \
    --qemu-arm /private/qemu-arm-reference/build/qemu-arm \
    --qemu-armeb /private/qemu-arm-reference/build/qemu-armeb \
    --expect-corrected-d-register-writes
```

The initial paired receipts are `run.2uow55_4` (unmodified) and `run.d506qehx`
(corrected) under `build/test-results/arm-pcs-call-reference`. They cover 28
fresh reference executions, including all deliberate per-function PCS failures.
Source, dependency, configure and build receipts are under
`build/arm-be8-profile/qemu-write-reference`. The failed first patch application
is retained in `maintained-corrected/patch.log`: its hand-written context missed
a blank line and was correctly rejected with zero fuzz; the canonical patch
uses the exact pinned archive's context.

The private upstream emulator produces a different synthetic-vDSO diagnostic
than Ubuntu's installed build. The harness captures `AT_SYSINFO_EHDR` and its
mapped page. It corroborates that the valid ARM ELF load segment ends before
the declared section table, whose bytes are absent/zero in memory. Only then
does it accept the exact memory-object diagnostic in this compiler-reference
experiment. All other debugger diagnostics still fail. Two actual vDSO pages
pass and fourteen machine/extent/section-content/load-address corruptions
reject (`vdso-corroboration-controls.json`). No original ELF validator check is
weakened, and this corroboration is not a general exporter warning allowance.

The maintained builder subsequently passes in `maintained-corrected-v2/`, and
its complete 14-process reference run passes at `run.fjqqbzqw`. The final current
system-emulator regression passes at `run.vywlp9nz`. These are additional runs,
not replacements for the retained initial failures. The original private
unmodified emulator/source hashes were rechecked unchanged after all experiments.
Maintained corrected executable SHA-256 values are:

- `qemu-arm`: `0a5431ec83113c4d12521e55c8cdb4abb7645d4c52ab87ec5ccedea447f15faf`.
- `qemu-armeb`: `f33d585bc238ea44d33e6606837281840969b6a67ae379f1e829a37b694c5ebc`.
