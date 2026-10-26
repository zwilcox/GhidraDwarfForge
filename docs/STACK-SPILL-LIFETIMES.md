# Bounded parameter stack spills

**CONFIRMED in PR60 and its separate main gate (2026-10-25).** A scalar
parameter can remain visible after its incoming register is overwritten when
Ghidra's decoded instructions prove that the complete value was saved to one
stack location. This extends P1.11a without completing general migration.

PR60 head `2b0666f` passes all twelve jobs in `40244794589` and independent
exact-package, seventeen actual Java 21 suites, raw target, both-GUI and
38 native Windows task reviews. Merge `47ff38e` preserves the tested tree.
Its separate main run `40247374065` also passes the complete gate and review;
receipt SHA-256: `ec1358c3d2b4a99772b659be447497346aa16fe6046d86d142f7a36560dbe3a7`.
Earlier hosted-pending statements describe historical checkpoints.

## Proof and limits

The parameter must be attached to its saved program/function, begin at entry,
and have matching formal, physical and register widths. The existing complete
body and straight-line checks apply. Calls, jumps, delayed instructions,
ambiguous flow, incomplete decoding and overrides do not acquire this proof.
The target stack pointer and register numbering come from the compiler spec
and isolated target register map; generic code contains no ISA register names.

Before the first incoming-register overwrite, one separate instruction must
complete exactly one full-width store to the actual stack pointer plus a
constant. Only ordered, instruction-local COPY and constant ADD/SUB p-code
facts are accepted. Partial unique-space overwrites invalidate overlapping
facts. Facts do not persist between instructions; arbitrary register copies,
loads, pointer arithmetic and overflow do not establish a stack save.

The original register remains the location until its first overwrite completes.
A proved stack save then uses existing DW_OP_bregx serialization. Any later
STORE, direct memory output, listing memory result or stack-pointer write ends
the stack interval after that instruction. The location describes the state
before each instruction executes. There is no alias exemption for apparently
unrelated stores, recovery after stack restoration, or reacquisition after a
possible clobber. A previously supported register backup retains priority.
Unknown tails retain name/type and report UNKNOWN_LIFETIME.

General memory/register joins, calls, later locals, stack-slot reuse, aggregate
pieces and additional target/ABI profiles remain **PLANNED**. These fixtures
establish x86-64 and AArch64 scalar behavior only.

## Reproduction and acceptance

With a packaged extension installed and the documented compiler, GDB, QEMU
and validator tools available:

```bash
./gradlew stackSpillSmoke registerCopySmoke registerPrefixSmoke directLeafCallSmoke mixedParameterPrefixSmoke
python3 src/test/integration/stack-spill-export.py "$GHIDRA_INSTALL_DIR" x86_64 --role exec
python3 src/test/integration/stack-spill-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie
python3 src/test/integration/stack-spill-export.py "$GHIDRA_INSTALL_DIR" aarch64 --role pie-rebased
```

Run all three roles on both targets. Optional `--previous-ghidra PATH` compares
the same saved program and ELF against the preceding packaged exporter. The
six roles are mandatory in the x86-64/AArch64 CI lanes; the model suite is also
required on Windows. Passing local tests do not imply a hosted gate pass.

Acceptance requires exact signed 32/64-bit argument values at instruction
boundaries, independently compiled reference values, a raw stack witness,
correct values after register loss, and unavailable tails even when a later
unrelated store leaves the old stack bytes intact. It also requires exact raw
location-list expressions, source/type lookup, next/step, normal exit, PIE
runtime bias, rebase normalization, unchanged inputs/module/saved program
(except documented project backup rotation), and byte-identical repeat pairs.
GNU/LLVM and pinned strict DWARF validators run on the emitted artifacts.

## Retained local evidence

The `stack-spill-lifetime` worktree retains six passing cases under
`build/test-results/stack-spill`:

- `x86_64.exec.nru1soej`, `aarch64.exec.mdnuuy96`.
- `x86_64.pie.4p8ep4oj`, `aarch64.pie.pgmq5abh`.
- `x86_64.pie-rebased.fk84esga`, `aarch64.pie-rebased.er0zfxck`.

These comprise twelve final exports and six preceding-package comparisons,
with 1,350 GDB instruction observations over compiler/current/previous views.
The previous exporter makes the value unavailable after register loss; the new
one retains it until the first possible stack clobber. LLVM passes and GNU
reports no warnings. Strict-checker frame-length diagnostics are inherited:
independent review matches each raw diagnostic multiset and original .eh_frame
bytes; there are no uncorroborated errors.

The installed JAR SHA-256 is
`f56e89c56d9c5540888286148079caea91fca6bb9e949354f36330ee622699a5`.
Local headless Ghidra uses Java 25.0.4.1. Separately, seventeen exact packaged
suites pass on actual Java 21 in `build/stack-spill-review/packaged.g8yrw1he`,
including 106 stack-spill controls. Independent receipt
`build/stack-spill-review/acceptance.json` SHA-256 is
`34cf4303fabcc9bc771cc84b5349e4eb2c49a86a9d040613ff9fb95c5b86d486`.
Fixture inventory/reproducibility passes all five configured targets; this
alone is not a claim of stack-spill runtime support on all five.

Failed attempts remain retained: initial model controls used p-code object
identity and a cancellation-disabled monitor; initial observer code missed a
direct RAM output; an oracle expected compiler spelling instead of Ghidra's
`longlong`; an early probe script path recursively included a private Ghidra
installation; the independent audit initially looked for the JVM version in
stdout instead of stderr. Corrected runs above pass. The previous architecture
check's false pass is tracked separately and requires the corrected CI gate.
No release has been published for this change.


Additional compatibility regressions pass six dynamic-parameter exports on
x86-64/AArch64/ARM32 and two primary semantic exports on x86-64/AArch64,
including the applicable existing GDB checks. Dynamic saved-program repeats
remain byte-identical. Evidence is retained as `dynamic-regressions.log`,
`semantic-regressions.log`, `semantic-gdb-regressions.log` and
`additional-regressions.json` under `build/stack-spill-review`. The initial
supplemental audit expected `first.dbg`; it was corrected to the actual retained
`first.dynamic.dbg` before writing any acceptance receipt. No production or
oracle changes were necessary for these regressions.

## Protected hosted acceptance

**CONFIRMED integration (2026-10-25):** stack-spill PR60 head
`2b0666ff7cc5b1ff44cd7420522c57737cc72d43` passes all twelve jobs in
`40244794589`, exact-package/seventeen actual Java 21 suites, raw five-target
review, 38 native Windows tasks and both GUI hosts. The new stack cases cover
six roles, twelve exports and 900 hosted compiler/Forge GDB observations.
Normal merge `47ff38ebbfe2ac5eb8e7d2f3d0ec445fdb29dc95` preserves the accepted
tree. Independent receipt SHA-256:
`a84e37a5ccc878f2fcacae2dbf53726db7326585ca5b7dc838d1bb4f21ecf225`.
Separate main-push verification is pending. Earlier pending stack-spill notes
are historical; general migration and other unfinished work remain open.
