# Split and shrink-wrapped frame runtime evidence (#112)

**CONFIRMED locally:** the existing instruction/callee proof and frame projection
handle the new x86-64 and AArch64 fixtures without a production algorithm change.
An early conditional return skips all stack allocation and register saves. The
recursive path allocates and saves in separate instructions, restores the frame,
and joins the early path at one return instruction. Both paths execute in each
runtime case; no frame pointer is used.

The x86-64 fixture saves R12 before a separate stack allocation. The AArch64
fixture allocates space, saves X19, changes it, and only then saves the return
register. Each fixture includes nested recursion and calls to the checkpoint.
Assembler CFI directives provide an independent reference for every transition;
the recovery path receives only the stripped executable's actual instruction
bytes and Ghidra decoding. No directives or reference rows enter recovery.

The GDB oracle observes the no-allocation branch exactly once and the allocation
and save labels three times. It compares complete instruction traces, caller
witness values, backtraces, finish and stepping with the independent reference.
The x86-64 trace has 51 stops and AArch64 has 53. Both references and generated
sidecars select the DWARF unwinder; the no-CFI controls do not.

Four non-PIE/PIE cases pass on native x86-64 and QEMU AArch64. Eight
plain/compressed sidecars pass GNU/LLVM/pinned strict checks; sixteen debugger
sessions include reference and absent-CFI controls. Original/rebased extraction
produces identical normalized plans and encoded frames. Reruns are deterministic
and originals remain unchanged. The four original encoder-family recovery cases
also pass after the oracle extension (eight sidecars/sixteen GDB sessions).
All five target fixture inventory/reproducibility checks pass, with fifteen
artifacts per target. See `docs/evidence/unwind-shrinkwrap.json`.

These are controlled assembly layouts with independent assembler CFI, not a
substitute for the unchanged compiler-generated C fixture or a claim that every
compiler's shrink-wrapping strategy works. Conflicting/unknown flows still use
the existing rejection policy. Automatic exporter integration, global-store
storage evidence, shared/compiler cases and the full export failure/cancellation
matrix remain **PLANNED**. New hosted checks are **PRESENT, UNVERIFIED**; PR166
integration retains first priority. No full #112/#110/#109 completion is claimed.
