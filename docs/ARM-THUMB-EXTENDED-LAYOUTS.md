# ARM/Thumb mode cues in extended executable layouts

**CONFIRMED locally; full target acceptance remains open.** This component
addresses the stripped PIE/rebased PIE and dynamic-symbol portion of #70.
The complete #68–#71 requirement table remains in `TARGET-ABI-COMPLETION-PLAN.md`.
Ghidra 12.0.3, Java 21 and libdwarf 2.3.2 are unchanged.

The previous planner rejected every ET_DYN input. The ordinary PIE reproduction
in `build/test-results/arm-thumb-mode/run.aHT0H57Y` passed compiler/QEMU execution
and GNU/LLVM/strict DWARF validation, but the exported Thumb function was decoded
as ARM by GDB before attachment. This is a debugger behavior failure despite a
structurally valid artifact.

The candidate routes extended layouts through the existing original-byte,
complete-body, unique-owner, allocation, name-conflict and original-mode checks
used by ARM aliases. Synthetic names remain local ELF instruction-mode hints;
they do not become analyst aliases or DWARF declarations. The writer's existing
dynamic-symbol mirror preserves original records and names. The sectioned
ET_EXEC path remains unchanged. New model controls reject missing/mismatched
owners, overlap with an uncued function, bad hashes, invalid tags and duplicate
cues; they also exercise cancellation, deterministic writing and sectionless
allocation binding. ARM-only selections retain their existing no-cue behavior.

## Runtime and structural evidence

The final local four-case matrix uses the same assembled production package:

- ZIP SHA-256: `44c692873d8d7b723aa2d2b3bc662716fbbd69bc43f01366f8c20ac86dae789c`.
- Installed JAR SHA-256: `7b22fdbb111df9d4aba25d8c0fcff4684c8564fcfe761fb481f6e3525631bd7c`.
- Private installation: `build/arm-abi-completion/ghidra-v1`.

| Role | Case under `build/test-results/arm-thumb-mode` | Result |
| --- | --- | --- |
| Non-PIE regression | `run.s2Nx8oXs` | PASS |
| Stripped PIE | `run.iyDs7L38` | PASS |
| PIE rebased in Ghidra by `0x200000` | `run.FmPURHev` | PASS |
| PIE with exported dynamic symbols | `run.uUNApqyf` | PASS |

Each case requires compiler and Forge static instruction decoding, default GDB
ARM mode, function-pointer values, named/address breakpoints, direct/indirect
calls, source next/step, positive parameter values and an unavailable clobber
tail, globals and normal process exit. The runtime load bias is measured after
attachment; it is distinct from Ghidra's analysis rebase. Five original function
and data names additionally remain resolvable in the dynamic-symbol case.
Original dynamic records/string offsets remain byte-identical around inserted
locals. Five deliberate inventory corruptions are rejected per case.

Each case exports twice from the same saved program and requires byte-identical
sidecar/source, unchanged inputs/package/test sources, GNU readelf output without
warnings, LLVM verification and zero strict-libdwarf errors. The documented
QEMU synthetic-vDSO warning must match the compiler observation. Ordinary PIE,
rebased PIE and non-PIE additionally reject mutated Thumb tags/entries; PIE
controls reject a synthetic symbol extent extended into a literal pool.

Commands, with the retained ARM compiler/sysroot and Java 21 environment:

```bash
./gradlew arm32ModeSymbolsSmoke arm32FunctionAliasSymbolsSmoke \
    ghidraArm32FunctionModesSmoke aarch64ParameterAllocationSmoke buildExtension
for role in exec pie pie-rebased pie-dynamic; do
    FORGE_THUMB_ROLE="$role" src/test/integration/arm-thumb-mode-export.sh <installed-ghidra>
done
```

The final model counts are 231 mode-symbol, 476 alias/mode-binding, 59 actual
Ghidra mode-extraction and 673 AArch64 allocation checks. The AArch64 addition
confirms that observing its nonempty killed-register list does not change its
fingerprint/allocation; no AArch64 production correction was necessary.

## Literal pools and remaining requirements

GCC's function size can include trailing literal pools. The instruction oracle
uses the compiler's `$d` mapping to identify the executable prefix independently
of Forge, requires the Ghidra instruction sequence to cover that prefix exactly,
and records data-byte disassembly separately. It does not require a debugger's
instruction decoder to interpret data as if it were executable code. Extending
a synthetic symbol over those bytes is still rejected by the raw extent check.
The original dynamic function sizes remain intact, including their literal pools.

The earlier `pie-dynamic-v1.log` failure compared decoding of those data bytes,
not executable instructions. Its retained Ghidra listing inspection identified
147 instructions, 21 defined data items and six unknown bytes in `.text`.
Those unknown bytes must not be relabeled as code/data merely to create a
complete section mapping. General mixed-body mapping symbols remain PLANNED.

**PRESENT, UNVERIFIED:** the extended planner's sectionless production path has
model coverage but no new end-to-end mode test yet. Shared-library loading,
sectionless runtime, mixed mode within one body, per-function base/VFP ABI,
BE8/big-endian runtime, broader storage and failure/cancellation composition
remain required. Exact-head hosted acceptance and protected integration also
remain required. This component does not complete #70 or any umbrella issue.

An independent BE8 compiler/QEMU/GDB reference now passes, and Ghidra selects
the expected mixed-endian instruction language automatically. Production export
still rejects that target before native calls. See
[the BE8 reference](research/ARM-BE8-REFERENCE.md); this does not claim BE8 support.
