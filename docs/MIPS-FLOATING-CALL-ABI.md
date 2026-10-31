# MIPS floating debugger-call ABI

**CONFIRMED defect and initial local fix; acceptance incomplete:** on the tested QEMU/GDB
transport, compiler-generated MIPS O32 FPXX `float` and `double` calls injected
by GDB execute with stale floating arguments and report incorrect returns.
The program's own ordinary calls produce the correct values. Equivalent
explicit FP32 fixtures pass both argument and return checks in both byte orders.
The current packaged Forge exporter reproduces the double-call defect.

This is distinct from unavailable parameter locations. An unavailable location
must not be treated as protection against an unsafe debugger-injected call.

## Evidence

The source-built research is retained under the root checkout's
`build/mips-injected-call-research/`:

- `run2/observations.json`: eight compiler double-call cases, both byte orders,
  FPXX/FP32 and non-PIE/PIE. FPXX leaves the observed arguments at `21.5, -9.25`
  while increasing the call counter; the requested arguments were `19.5, -3.25`.
  FP32 receives those requested arguments and returns `16.25`.
- `float/observations.json`: the same eight compiler cases using scalar float,
  with the same FPXX failure and FP32 positive control.
- `forge/observations.json`: eight double-call exports through the prior packaged
  JAR, reproducing the compiler distinction. SHA-256:
  `3eaba57de71d126e2b0b2ddd236bbf059be3b2f9d762448accbc60faa3e8ba43`.
- `fixed/`: candidate headless exports, immutable rereads, structural validators
  and QEMU/GDB rejection/positive controls. All sixteen float/double, both-endian,
  FPXX/FP32, exec/PIE cases pass, with eight unchanged-state rejections and eight
  positive injected calls. Runtime receipt:
  `3bf5c2f452db41675325b402562d4a61eee59ba577ecc48c1853703bd697c775`.
  Independent raw DIE/value review:
  `da7f6f668face1a9dd1029a0606b3d62039b7eab68adfe533b87b3c368e46c9f`.

The initial research launch used unavailable `qemu-mips`; the corrected run
uses the installed `qemu-mips-static`/`qemu-mipsel-static`. The initial failure is
retained separately. No emulator register state or target metadata is modified
to manufacture the positive FP32 result.

## Initial implementation

`MipsFloatingCallPolicy` runs before native DWARF production, selected through
the target description and original ELF. It preserves return/parameter types,
names, locations and existing convention restrictions. Scalar floating signatures
without the independently observed explicit O32 FP32 profile receive a debugger
call restriction, serialized using the existing `DW_CC_nocall` mechanism.
Unsupported floating widths and unclassifiable cyclic alias chains are also
restricted. Typedefs and qualifiers do not conceal a floating type; pointers to
floating data do not imply floating argument transfer.

Variadic signatures without that profile are restricted because the fixed
signature cannot rule out floating actual arguments. This does not change the
variadic declaration or invent an ABI. Nonfloating, nonvariadic signatures and
unrelated targets retain their previous policy. The positive profile is a
necessary bound for this safeguard, not certification of every FP32 aggregate,
variadic, vendor or custom calling convention.

The 3,456 model checks cover both byte orders, typed section/segment/absent ABI
carriers, FP variants, scalar aliases, pointer controls, existing restrictions,
external declarations, deterministic repetition and cancellation. Initial installed runtime
checks and 32 actual Java 21 suites pass. The candidate has 60 exact production
sources and 247 Java 21 classes. The repository-owned harness is
`src/test/integration/mips-floating-call-export.py`; its GDB driver independently
checks ordinary calls, integer injection, floating argument/return transfer or
unchanged-state rejection, types, source lookup and normal exit. Both MIPS CI
lanes execute FPXX/FP32, float/double and exec/PIE/rebased PIE; Linux and Windows
also run the model suite. Hosted acceptance remains pending.

Run one case with the installed extension and pinned validator available:

```bash
python3 src/test/integration/mips-floating-call-export.py "$GHIDRA_INSTALL_DIR" mips32be \
    --profile fpxx --scalar double --role pie-rebased
```

`--previous-ghidra` optionally runs the same immutable curated project through
an older installed exporter. Compiler/previous FPXX calls are observations:
a future debugger may repair the transport. Fixed FPXX rejection and FP32
positive transfer remain mandatory assertions.

The first maintained harness attempt failed its strict GDB diagnostic gate:
the previous sidecar referenced the candidate's subsequently overwritten source
path, triggering a source-timestamp warning. Separate previous/candidate output
paths preserve each source reference; the complete rebased BE FPXX rerun passes.
The original failed artifact directory and transcript are retained. No warning
filter or timestamp manipulation was added.

## Maintained local checkpoint

All 24 both-endian, FPXX/FP32, float/double, exec/PIE/rebased-PIE cases pass:
72 real exports (previous/fixed/repeat), 72 QEMU/GDB processes, 12 unchanged-state
FPXX rejections, 36 positive FP32 floating calls and 72 integer controls.
The 24 compiler/previous FPXX observations retain the reproduced wrong transfer.
Each fixed export passes GNU/LLVM/pinned strict validation, immutable saved-project
rereads, deterministic output, exact installed-JAR origin and protected input/
module/source hashes. Independent raw review receipt:
`aa123a5457a3859a87982258886cab16910cd7dc285e8f304792dfdbf0a7afe0`.

Five-target baseline export/GDB regressions and fixture reproducibility pass.
Controlled decompilation failure preserves its symbol-only fallback; cancellation
after 16 MiB of copied ELF bytes preserves both the original and previous output
pair. Combined local receipt:
`43ee06d6b6ac524c815d56e3dca42927c3f282ed4c8727f906f174bca66ccd53`.
Final committed package and hosted gates remain pending.

## Completion requirements

- Prove rejection before changes to PC, status, observed arguments or call count;
  retain ordinary execution, typed display and normal process exit.
- Prove explicit FP32 float/double calls still receive and return exact values;
  retain nonfloating call controls in FPXX too.
- Cover both byte orders, non-PIE, PIE and explicit Ghidra rebases, with compiler
  and previous-exporter controls, independent raw DIE review and validators.
- Preserve input and prior output bytes, immutable saved-program rereads and
  cancellation behavior; validate the exact assembled package on Java 21 and
  through both-host required CI gates.
- Keep P1.7/#66 open until the remaining calling ABI and alias requirements are
  independently complete. No release publication is included in this work.
