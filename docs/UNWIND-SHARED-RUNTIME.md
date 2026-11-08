# Recovered frames in loaded shared objects (#112)

**CONFIRMED locally:** native x86-64 and QEMU AArch64 recover the ordinary and
split/shrink-wrapped fixture frames after `dlopen` relocates their shared
libraries. This extends the instruction-recovery harness's default roles from
non-PIE/PIE to non-PIE/PIE/shared. The existing two CI target lanes run all three
roles for both fixture families.

The driver loads the unchanged no-CFI library with `RTLD_NOW | RTLD_LOCAL`.
`dladdr` supplies its actual runtime base; GDB adds the reference or generated
sidecar with that bias. Each session requires a nonzero base and checks the
runtime checkpoint address against its link-time ELF address. `-Bsymbolic`
keeps the fixture's recursive/checkpoint calls local and direct, matching the
closed-callee proof. The recovery path still receives only original instruction
bytes and Ghidra decoding, with original/rebased plans required to agree.

The independent assembler-CFI reference and plain/compressed generated sidecars
must produce identical normalized instruction traces, backtraces and caller
register values. `finish`, instruction stepping, both shrink-wrapped paths and
exit status remain checked. Missing-CFI and disabled-DWARF controls must select
no DWARF unwinder at any recovered function address. Positive modes must select
it at every expected recursive frame level. This address qualification matters:
the first shared no-CFI experiment wandered into libc, whose own CFI triggered
the older level-only oracle. Its failed log is retained.

The shared driver's call into the x86-64 startup fixture pushes a return address;
kernel entry does not. `CFI_SHARED` adjusts that startup stack before its calls.
The oracle now asserts ABI stack alignment at each recursive/checkpoint entry
on both targets. An explicit failing-before alignment run is retained. The
shared driver still defaults to `cfi_main`; separate compiler-reference GDB
regressions exercise its unchanged return, register witness and `dlclose` path
on both targets.

## Local acceptance

- Twelve final cases: two targets, three roles, two fixture families.
- Twenty-four plain/compressed sidecars pass GNU, LLVM and the pinned strict
  checker; sixty GDB sessions include both negative controls in every case.
- Independent fixture rebuilds are byte-identical; repeated sidecars are
  byte-identical; original/rebased recovery plans agree; inputs are unchanged.
- x86-64/AArch64 fixture inventory/reproducibility checks, extension build,
  workflow lint, architecture guard and script syntax checks pass.

See `docs/evidence/unwind-shared-runtime.json` for commands, raw evidence and
counts. Fresh output directories are required. Example:

```bash
python3 src/test/integration/unwind-frame-recovery.py build/classes/java \
    build/test-results/unwind-shared --roles shared --fixture-family shrinkwrap \
    --dwarfdump "$DWARFDUMP"
```

## Remaining scope

These controlled assembly libraries end at the fixture's `_start` root and
terminate the driver process. They test relocated frames within that library;
they do not prove unwinding across arbitrary library boundaries, interposed or
indirect calls, signal/exception frames, or a compiler's general shared-library
output. The separate default-driver compiler regression does not test generated
CFI for the unchanged global-writing C fixture.

Automatic production-exporter integration, that compiler-C acceptance and full
export failure/cancellation coverage remain **PLANNED**. The existing strict
stack/global alias refusal is unchanged. ADR-0002 still prohibits unvalidated
production synthesis. Hosted checks for these additions are **PRESENT,
UNVERIFIED**. PR166 integration keeps first priority; #112, #110 and #109 remain
open.
