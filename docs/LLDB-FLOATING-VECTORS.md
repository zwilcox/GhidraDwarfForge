# LLDB scalar floating-point and AArch64 vector validation (#110)

**CONFIRMED locally:** LLDB 18.1.3 reads the selected scalar floating-point and
128-bit lane fixtures from production Forge sidecars. This checkpoint changes
consumer tests and pipeline wiring, not production Java or native register
mappings. Full hosted acceptance and the remaining #110 discovery/support audit
are still required; #112 retains integration priority and #109 follows #110.

## Scope and acceptance

The scalar harness checks x86-64 on native Linux and AArch64 through QEMU 8.2.2
with an explicit `cortex-a53` CPU. Each compiler/Forge comparison checks the
same actual float/double arguments, exact entry and marker PCs, stored globals,
and normal exit. After the deliberate scalar-register overwrite, Forge must
report the argument unavailable and the physical register must contain zero.
The compiler reference may preserve the old value or report it unavailable.
Each session observes ten stops. Exec/PIE, rebased analysis and repeat exports
are separate cases; no inherited compiler location is substituted for Forge's.

The vector harness checks exec, PIE and rebased PIE on the same AArch64
transport already selected by the existing GDB vector fixture. Each producer
has 119 instruction observations across six functions: signed integer lanes,
floating lanes, register copies, a surviving stack spill, an unproven alias
spill and a ninth vector argument passed on the stack. Forge has 42 unavailable
observations and 43 memory observations in each case. At every stop:

- The actual displayed lane values and their typed bytes agree with the GDB
  trace for that producer. Signed 32-bit values are read at their actual width;
  the test also requires LLDB's displayed sign, rather than only reinterpreting
  a zero-extended integer from `GetValueAsSigned`.
- The independently decoded Forge location interval selects either the actual
  vector register or the current SP-relative memory. Both must contain the
  expected 16 bytes. Missing intervals must produce unavailable child values.
- Register-zeroing really removes every vector-register copy. The surviving
  spill remains readable; the alias case stays unavailable after its evidence
  ends. The stack argument stays at its incoming stack address.
- Raw return lanes agree with the independent GDB result. The stack-spill case
  has returned to register storage before its spill slot is released.

LLDB exposes an inline parent's call-site PC. The test uses frame zero for the
executing machine PC and the owning lexical frame for its parameter, requiring
their CFA/SP to agree. The final trace still has to match every GDB offset;
skipping inline instructions is not permitted. Forge source references must
resolve to the actual companion file from a different working directory.

The driver hashes originals, references, sidecars, source and independent
oracle inputs before/after consumption. Existing production fixture drivers
retain GNU/LLVM/pinned strict validation, GDB behavior and deterministic export
checks. Their status is not inferred from the LLDB pass.

## Explicit transport limitation

**CONFIRMED limitation:** with QEMU 8.2.2's default SVE register description,
LLDB 18.1.3 cannot map DWARF register 64 to Neon. Both the unchanged compiler
reference and Forge fail at the first vector argument with the same missing
register mapping. SVE registers are present while `v0` is absent. The retained
negative control requires that exact error in both producers, then normal
process exit; arbitrary debugger failures do not count as this control.

This matches [LLVM issue 107864](https://github.com/llvm/llvm-project/issues/107864).
[Upstream fix 108365](https://github.com/llvm/llvm-project/pull/108365) adds Neon
subregisters when the remote XML supplies only SVE registers. No newer LLDB
release was validated here. The positive CPU choice preserves the existing
ordinary Neon fixture scope; it does not claim SVE support or change the
exporter's register numbering.

Other processors, Windows-hosted LLDB, Darwin/Mach-O, vector inferior calls,
and arbitrary SIMD/SVE ABI profiles are not established by this checkpoint.
Existing GDB call-refusal checks remain in force; LLDB inferior-call semantics
are not inferred from successful value display.

## Reproduction and pipeline

With the pinned LLDB executable and its runtime dependencies configured:

```bash
export FORGE_LLDB=/path/to/lldb-18
src/test/integration/floating-registers-export.sh "$GHIDRA_INSTALL_DIR" \
    /path/to/libdwarf.so.2.3.2 /path/to/libdwarfp.so.2.3.2 x86_64 aarch64

for role in exec pie pie-rebased; do
    python3 src/test/integration/aarch64-vector.py "$GHIDRA_INSTALL_DIR" \
        --role "$role" --with-controls --lldb "$FORGE_LLDB"
done
```

The scalar production driver invokes LLDB for every baseline/rebased/repeat
export on the two selected targets. Other target lanes retain their GDB checks.
The vector driver invokes LLDB after its existing production/GDB/control
validation. CI enables these hooks in the matching target jobs.

Saved scalar samples can also be consumed with `floating-registers-lldb.py
<case> <new-results-directory> --target <target> --sample rebased --lldb <path>`.
The source path remains the actual recorded `artifacts/floating.dbg.c`, not a
newly invented path beside the saved sidecar. For the known default-SVE control,
run `aarch64-vector-lldb.py <case> <new-results-directory> --lldb <path>
--check-sve-limitation`; this also requires the complete positive Cortex-A53
trace. These are explicit-loading tests, not automatic-discovery evidence.

Raw artifacts, source hashes, commands, limits and test counts are bound by
[the checkpoint receipt](evidence/lldb-floating-vectors.json).
