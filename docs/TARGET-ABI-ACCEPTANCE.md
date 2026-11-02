# Combined P2.3–P2.3c acceptance audit

**CONFIRMED candidate scope (2026-11-02):** this audit retains all original
requirements in issues #68–#71 and `TARGET-ABI-COMPLETION-PLAN.md`. It combines
PR125–PR154 with accepted `main`, using normal merge ancestry. Ghidra 12.0.3,
Java 21-compatible bytecode and the pinned libdwarf 2.3.2 producer remain the
baseline. Release publication is not part of this goal.

**PRESENT, UNVERIFIED:** combined hosted target/Windows acceptance, independent
uploaded-artifact review and protected integration. The rows below identify
concrete implementation and local behavioral evidence; they are not closure
claims based on test names or existing section names.

The tracker already marks #68 closed. Its accepted AArch64 component records
remain valid, but the combined candidate must still pass the AArch64 regressions.
The other three umbrella issues remain open. Earlier statements that all four
tracker issues are open are historical; they do not override the full combined
regression requirement.

## Original requirements and evidence

All paths in the test column are beneath `src/test/integration/`. The workflow
runs the listed tests through the same installed production exporter. Model
suites also run against actual Ghidra language/compiler specifications on both
supported hosts.

| Original requirement | Implementation and behavior to verify | Maintained test and component evidence |
| --- | --- | --- |
| 68.1 Selected ELF/language/compiler ABI | `DwarfTarget` and `GhidraCompilerCallPolicy` distinguish LP64/v8A/default from same-width AppleSilicon, Windows, Go/Swift, nonzero flags and unsupported OSABI/version choices. Negative calls preserve registers, stack and counters. | `abi-profile-export.py` AArch64 matrix; [selection](AARCH64-ABI-SELECTION.md) |
| 68.2 Exhaustion, stack and aggregate arguments/returns | `Aarch64ParameterAllocation` corrects register-exhausted structures without changing analyst storage. Fifteen functions cover narrow/128-bit values, alignment, direct/indirect objects, shifted pointers and hidden returns. | `aarch64-abi.py --with-controls`, all five exec/PIE/shared/rebase roles; [allocation](AARCH64-PARAMETER-ALLOCATION.md) |
| 68.3 HFA/vector as distinct profiles | HFA arguments and returns have source-known values. Full SIMD storage has independent lane bytes and destructive-write boundaries; selected non-native vector representations retain call guards. | `aarch64-abi.py`, `aarch64-vector.py --with-controls`; [vector storage](AARCH64-VECTOR-STORAGE.md) |
| 68.4 Multiple PCs and unavailable boundaries | Shared register/stack/indirect lifetime analysis checks live object addresses, shifts, reloads, destructive writes and post-clobber gaps. Every positive ABI argument needs at least two correct typed observations. | `aarch64-abi-gdb.py`, `aarch64-abi-controls.py`, vector corruption controls; [allocation](AARCH64-PARAMETER-ALLOCATION.md) |
| 68.5 Isolated mapping and exact positive/negative contract | Architecture register maps and allocation policy remain isolated. Profile, custom-storage, malformed metadata, changed prototype and cancellation negatives accompany runtime cases. | `architecture-neutrality.sh`, compiler/target/allocation smoke suites and the two runtime matrices above |
| 69.1 MIPS ABI/ISA/FPU classification | `MipsAbiFlags`, `MipsWideCallPolicy`, `MipsWideParameterAllocation` and `TargetRegisterMap.forElf` require typed ABI evidence and matching selected profiles before enabling extra pair/allocation/call semantics. | MIPS ABI/pair/call/allocation smoke suites, `mips-floating-call-export.py`, `mips-wide-abi.py`; [wide profile](MIPS-WIDE-CALL-PROFILE.md) |
| 69.2 Reliable FPXX/FP64A reference | Actual FR=1 O32 execution uses an unmodified 64-bit system-emulator register transport in both byte orders. Compiler float/double values, raw FPRs, stored globals and main's return agree. Wrong FPR and FR controls fail. | `mips-fpr-system.py`; [reference](MIPS-FPR-SYSTEM-REFERENCE.md). This is a reference prerequisite, not production FR=1 pair-location support. |
| 69.3 O32 aggregate/wide/stack/mixed | Separate four-byte slots cover ten wide arguments, mixed integer/FP/aggregate/stack inputs and two hidden-buffer returns. Naturally aligned fixture types, exact clobbers and existing mixed-storage gaps are required. | `mips-wide-arguments.py --abi o32 --with-controls`, both orders and five roles; [O32 evidence](MIPS-O32-ARGUMENTS.md) |
| 69.4 Distinct N32 and N64 | ELF32/four-byte pointer versus ELF64/eight-byte pointer semantics coexist with 64-bit GPR/FPR slots. Scalar, aggregate, nested/array/128-bit/aligned objects and live-session allocation use separate matching sysroots and debuggers. | `mips-wide-abi.py`, `mips-wide-arguments.py`, `mips-layout-arguments.py`, `mips-live-import-export.py`; [scalar](MIPS-WIDE-SCALAR-PROFILE.md), [layout](MIPS-LAYOUT-ALLOCATION.md), [alignment](MIPS-ALIGNED-COMPOSITES.md) |
| 69.5 Runtime layouts and sectionless regression | Both MIPS lanes retain real QEMU/GDB loader and bias checks across exec/PIE/shared/rebases. Baseline big-endian sectionless import/export, FP32 and truncated-space cases remain required. | Five-role N32/N64/O32 matrices, baseline target lane, `floating-registers-export.sh` sectionless case, `mips-truncated-space-export.sh` |
| 70.1 Stripped Thumb/interworking | `Arm32ModeSymbols`, recovered function cues and local symbol planning preserve static decode, untagged DWARF addresses and tagged function pointers. Named/address breaks, mode bits and source steps are checked. | `arm-thumb-mode-export.sh`, `arm-function-aliases.py`; [extended layouts](ARM-THUMB-EXTENDED-LAYOUTS.md) |
| 70.2 PIE/shared/sectionless/mixed bodies | `GhidraArm32SectionModes` and `Arm32SectionModes` bind complete listing/context/bytes to allocation mappings. Contiguous/split and live/saved exports cover all five roles, including sectionless shared loading. Conflicts and missing evidence produce explicit omissions. | `arm-mixed-mode-reference.py --production`, `--split`, `--sectionless`, live/failure/context/omission controls; [mappings](ARM-MIXED-MODE-MAPPINGS.md) |
| 70.3 Per-function base/VFP arguments and returns | `Arm32CallAbi` parses file attributes, while `Arm32CallPolicy` uses each effective convention and preserves its recorded name. Definitions, declarations and callbacks distinguish matching, mixed, unknown/custom and conflicting metadata. | `arm-pcs-profile.py`, `arm-aggregate-calls.py`, LE/BE8 × base/VFP; [PCS](ARM-PCS-CALL-PROFILE.md), [controls](ARM-PCS-CONTROLS.md) |
| 70.4 Separate BE8 runtime profile | `Arm32EndianProfile` distinguishes big-endian data from little-endian instructions and rejects BE32/contradictory language selections. Real scalar, PCS, HFA and aggregate executions use matching tools; native producer lifetimes run on both hosts. | `arm-be8-reference.py`, PCS/aggregate/HFA matrices, `nativeProducerSmoke -PtargetProfile=arm32be8`; [BE8](ARM-BE8-PROFILE.md) |
| 70.5 Additional stack/aggregate/mixed storage and boundaries | Shared slice/stack analysis and isolated HFA/composite allocation preserve proven pieces through spills/reloads. Fourteen-function fixtures cover exhaustion, alignment, packed/three-byte objects and mixed storage, with independent expression evaluation and mandatory unavailable tails. | `arm-stack-aggregates.py --availability-contract audited-prefix --with-controls`, `arm-hfa-lifetimes.py`, PIE/shared corruption controls; [stack](ARM-STACK-AGGREGATES.md), [shared](ARM-SHARED-AGGREGATES.md), [HFA](ARM-HFA-STORAGE.md) |
| 71.1 Preserve accepted shared-library integration | Existing i386 direct/shared loader cases preserve original dynamic symbols, measured relocation, curated lookup and explicit sidecar loading. | `i386-shared-profile-export.py`, four roles with direct/shared children; [integer/shared profile](I386-INTEGER-PROFILE.md) |
| 71.2 Real libc-backed runtime | The selected Linux i386 fixture actually calls malloc/free/memcpy/memset. Scalar and aggregate execution uses the real loader/libc rather than only a freestanding stub. | `i386-extended-return-export.py`, `i386-abi-matrix-export.py`; [matrix](I386-ABI-MATRIX.md) |
| 71.3 x87/SSE/vector/aggregate parameters and returns | `I386ParameterAllocation` and the isolated XMM map preserve stack argument alignment, x87 typed returns, explicit XMM inputs, ordinary aggregate results and raw vector/SSE returns. Correct source-generation storage and analyst overrides are independently exercised. | Four-layout extended-return and eleven-function ABI matrices, instruction-boundary/wrong-location/failure controls; [matrix](I386-ABI-MATRIX.md) |
| 71.4 Additional conventions and target ABI | Selected regparm/stdcall/fastcall/thiscall/SSE conventions preserve explicit analyst knowledge and reject unsupported injected calls. ELF flags/OSABI/version and actual Windows compiler selections are separately classified. Windows host support is not Windows-target ABI support. | `abi-profile-export.py --target i386`, ABI matrix; [selection](I386-ABI-SELECTION.md) |
| 71.5 Stripped/sectionless/PIE/rebase/dynsym/explicit sidecars | Existing integer/shared/alias tests remain required alongside the four new libc layouts. Wrong locations must fail even when structural validators pass. | `i386-profile-export.py`, shared-profile and alias/sectionless helpers, `i386-abi-matrix-negative.py` |

## Explicit limits are part of the tested contract

The goal requires the selected profiles and honest recovered information; it
does not require every possible ABI or debugger extension. These limits are
backed by positive ordinary-execution evidence and explicit negative controls,
rather than being used to close an untested requirement:

- FPXX/FP64A has a positive independent **FR=1 reference**. The saved MIPS32
  whole-pair aliases still do not identify those 64-bit physical registers;
  their double locations and unsupported calls remain unavailable. The reference
  requirement is distinct from a new production floating-storage claim.
- O32 mixed register/stack aggregate lifetimes stop at the first possible write.
  The wider ARM aggregate profile has independently decoded prefix boundaries.
  These tests require correct positive values before the boundary and explicit
  unavailable values afterward; they do not assert whole-function availability.
- GDB globally selects ARM floating PCS. Incompatible per-function injected
  calls remain guarded, while natural arguments/returns are tested. BE8 uses
  pinned unmodified GDB 17.1 and a recorded QEMU 8.2.2 D/Q register-transport
  correction; LE uses GDB 15.1. Compiler-only differential controls establish
  the consumer defects. BE8 shared-library loader support is not advertised.
- Selected i386 native vector/SSE automatic returns have independently measured
  GDB limitations. Forge keeps their call guards and verifies raw returns.
  Ordinary float/double/long-double x87 returns remain strict typed checks.
  The separate `x86:LE:64:compat32` stack-location omission is not a validated
  profile; it must not be described as completed compatibility-mode support.
- Synthetic source remains decompiler output, not original source. No fixture
  repairs registers or memory in the positive exporter comparisons. Explicit
  mutation/reference-control processes are separate from positive acceptance.

## Combined acceptance gates

1. Build the merged source from a clean checkout using Java 21 and Ghidra 12.0.3.
   Run the exact `extension-build` workflow step, including architecture isolation
   and its negative controls. Local merge `d94dbe8` passes all 128 Gradle tasks
   and the wrapper/release-assembly tests. Its rebuilt JAR is byte-identical to
   the component-tested package:
   `30d90f1c3d754ffba93c750a00703e1792df9cdd15f04964d3528153b8b4a929`.
2. Require the combined PR's exact-head native Linux/Windows, release assembly,
   five target lanes, Windows host and `required-validation` checks. A cancelled,
   skipped or failed component run is never a passing gate. A predecessor's green
   result is not a substitute for the combined head.
3. Independently inspect the uploaded release manifests and raw validator/GDB
   evidence for every row above, including negative and failure/cancellation
   receipts. Confirm the executed exporter matches the packaged JAR and source.
4. Integrate normally into current `main`, preserving required checks and merge
   ancestry. Only then reconcile #69–#71 and the TODO completion status; #68's
   existing tracker closure does not waive its regression lane.

Current local audit snapshots are under `build/abi-completion-audit/`:
`original-issues.json`, `required-ci-commands.json`,
`production-source-hashes.json` and `component-receipts.json`. They retain the
original issue wording, executable workflow commands and component evidence.
All 106 production files match the rebuilt package. Old local-only paragraphs
in component documents are historical evidence; the combined gate above controls
final acceptance. No umbrella issue is closed by this document alone.
