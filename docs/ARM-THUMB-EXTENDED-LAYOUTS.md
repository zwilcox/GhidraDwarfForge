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

## Sectionless runtime and failure/cancellation checkpoint

**CONFIRMED locally:** the previously model-only sectionless route now passes
fresh headless imports, production exports and QEMU/GDB runtime on all four
roles. This supersedes the earlier sectionless PRESENT, UNVERIFIED paragraph;
shared/mixed-body/ABI/BE8 and hosted acceptance remain open.

The positive fixture now requests both GNU and SysV hash tables so its dynamic
symbol count remains explicit after removing section headers. Only a copied
input has `e_shoff`, `e_shnum` and `e_shstrndx` zeroed. The sectioned original,
loaded package and test sources remain unchanged. GNU-only empty hash tables do
not provide a complete symbol count; a separate fresh-import control requires
the precise omission diagnostic, no replacement `.symtab`, valid DWARF and
preserved inputs. That control is not counted as successful Thumb mode support.

| Role | Sectioned case | Sectionless case |
| --- | --- | --- |
| exec | `run.k1c8wscC` | `exec.v5thlwyy` |
| pie | `run.iSD5SfIL` | `pie.b3i083kh` |
| pie-rebased | `run.u80JbScD` | `pie-rebased.nlam34xy` |
| pie-dynamic | `run.H4fAhEXG` | `pie-dynamic.qvyym2c1` |

Sectioned paths are below `build/test-results/arm-thumb-mode`; sectionless paths
are below `build/test-results/arm-thumb-sectionless`. The original v1 installed
JAR/ZIP listed above is unchanged. The sectionless test reads instructions from
remote memory before continuing execution, because synthetic NOBITS load
sections cannot supply file-backed bytes. It explicitly selects the fixture's
ARMv7 architecture after `.ARM.attributes` disappears, while retaining automatic
ARM/Thumb mode selection. Runtime load bias, source stepping, direct/indirect
calls, typed values and clobber gaps pass without mode forcing.

The raw inventory oracle verifies all original dynamic records against the
sectioned compiler artifact, their new load-section indices and the exact
added mode symbols. The sectionless loader additionally identifies the PLT
resolver prefix as a function. Its four original machine words and compiler
`$a`/`$d` boundaries are independently checked; no arbitrary extra emitted symbol
is accepted. Six inventory corruption variants are rejected per positive case.
Only the previously corroborated QEMU synthetic-vDSO warning is allowed, and
Forge may emit fewer instances than the compiler, never additional ones.

All eight cases also pass `arm-thumb-mode-controls.py`: two real native
instruction-limit failures followed by a production copy cancellation per case.
The failed `recovered_arm_after` has its symbol/address but no invented formal
children or source declaration line; neighboring Thumb source/values still work.
The shared failure script now carries actual extracted mode cues to
the production exporter, as the installed entry point does. The cancellation
imports a separate padded fixture, stops after bounded copying begins, preserves
the existing artifact pair and leaves no temporary files. Saved program changes
are restricted to Ghidra filesystem index backups. Totals: 16 deterministic
failure exports and eight cancellations, all with validators and GDB checks.

The assembled command now runs these controls and sectionless checks after each
ordinary role. Fresh combined PIE and GNU-empty-hash commands pass under
`combined-pie.log` and `combined-empty-hash.log` in `build/arm-abi-completion`.
The pipeline runs all four positive roles plus the explicit GNU-only omission
control. Exact-head hosted acceptance and protected integration remain pending.

## Shared-library runtime checkpoint

**CONFIRMED locally:** stripped shared objects and rebased shared objects pass
with the same installed v1 production package. The harness builds a small
non-PIE driver whose SONAME dependency resolves to the stripped library. After
stopping at the driver entry, it measures the library's mapped `.text` address,
subtracts the independently read original section address and explicitly loads
the compiler symbols or Forge sidecar with that bias. `auto-solib-add` remains
off. Static decoding runs before attachment; runtime function and stored Thumb
pointer addresses are checked again after relocation. Inherited dynamic names
remain resolvable beside curated names.

PIC code overwrites the second argument's register earlier than the executable
fixture does. The test independently decodes `ldr r1,[r7,#4]`, verifies executed
bytes `79 68`, observes the original argument immediately before it and the new
register value immediately afterward. Compiler DWARF retains its saved-stack
value; Forge correctly marks the register-only value unavailable. The original
`mov r0,r3` boundary is still checked separately. Raw `.debug_loclists` must
contain exactly the corresponding reg0/reg1 prefixes and end markers; report
bounds alone are insufficient evidence.

| Role | Runtime/validator case | Failure/cancellation case |
| --- | --- | --- |
| shared | `run.JJdP94X7` | `run.ry7x9ls5` |
| shared-rebased | `run.FV8vsjrq` | `run.4piv54ta` |
| PIE regression | `run.p6nPedda` | `run.2do21k6n` |

Runtime cases are below `build/test-results/arm-thumb-mode`; controls are below
`build/test-results/arm-thumb-controls`. The regression also passes fresh
sectionless import/export/runtime and its controls at
`build/test-results/arm-thumb-sectionless/pie.xsa921p6`. Each shared role passes
GNU/LLVM/pinned strict validation with zero errors, deterministic repeated
exports, original/package/driver preservation and both GDB phases. Its two real
native failures preserve neighboring Thumb behavior; cancellation preserves the
previous output pair. Early shared attempts are retained: the first exposed the
new honest argument gap; the second showed the compiler named breakpoint lands
exactly on the clobber instruction. The final oracle handles that boundary
without skipping either the before or after observation.

CI runs all six ordinary roles plus the empty-GNU-hash omission control. The
sectionless child remains scoped to the four executable roles; sectionless
shared loading is not claimed. Wrong-function-tag controls are scoped to inputs
without inherited dynamic function symbols, since those can independently
supply the correct mode. Raw symbol-inventory corruption controls still run in
all roles. Mixed-mode bodies, per-function ABI, BE8 and broader storage remain
required, along with exact-head hosted acceptance and protected integration.

The shared failure-script change also passes a fresh AArch64 SIMD exec export,
strict/GNU/LLVM validation, runtime values and its real failure/cancellation
composition at `build/test-results/aarch64-vector/exec.fhtol32k`, using the same
installed package. ARM mode extraction remains empty for that AArch64 target.
