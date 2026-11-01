# P2.3 through P2.3c completion plan

**CONFIRMED active scope (2026-11-01):** finish P2.3, P2.3a, P2.3b and
P2.3c together, following the user's expanded goal. Issues #68–#71 remain open.
The shared baseline is Ghidra 12.0.3, Java 21-compatible bytecode and the pinned
libdwarf 2.3.2 producer. This work does not change that baseline or authorize a
release publication. Starting main is `c227cf34b2d386aa146c55b7c6edd68734ea0f98`.

The original remaining issue rows are preserved below. An existing scalar
fixture or accepted processor identifier does not satisfy an additional ABI
profile. Older local-only/pending paragraphs must be checked against their
later acceptance records before treating them as current gaps.

| Issue | Required remaining behavior |
| --- | --- |
| #68 AArch64 | Classify selected ELF/language/compiler combinations; exhausted argument registers and stack arguments; direct and indirect aggregates and returns; separately tested HFA/vector storage; multiple-PC exact values and clobber gaps using shared lifetime analysis; isolated mappings and exact positive/negative contract. |
| #69 MIPS | Classify ABI/ISA/FPU attributes against Ghidra; establish trustworthy FPXX/FP64A compiler/debugger references before location claims; extend O32 aggregate/wide/stack/mixed cases in both byte orders; validate N32 and N64 as distinct pointer/GPR/argument/runtime profiles with matching tools; add applicable PIE/rebase/shared behavior and retain big-endian sectionless coverage. |
| #70 ARM32 | Stripped Thumb/interworking static disassembly, address/named breakpoints, function-pointer mode and stepping; PIE/shared/sectionless/mixed-body mode handling; per-function base/VFP ABI argument and return classification; separately modeled BE8/big-endian runtime profile; additional stack/aggregate/mixed storage and unavailable boundaries without regressing ARM-state coverage. |
| #71 i386 | Preserve accepted shared-library integration; extend libc-backed runtime coverage; compiler-relative x87/SSE and selected vector/aggregate argument/return tests; explicit additional convention and host-specific target ABI classification; preserve stripped/sectionless/PIE/rebase/dynamic-symbol/explicit-sidecar behavior. |

The rows above are requirements, not newly claimed support. N32/N64, BE8 and
the floating/vector rows cannot be closed by merely documenting the current
omission. Where independent evidence exposes a genuinely unusable emulator or
debugger representation, record the exact failed reference, investigate an
alternative and preserve honest omissions rather than inventing values.

## Execution and acceptance

1. Establish compiler and runtime references, retaining raw ELF, DWARF,
   register, instruction and Ghidra storage evidence. Compare source-known
   values too: compiler DWARF can itself be wrong at an instruction boundary.
2. Implement demonstrated gaps through shared storage/lifetime machinery and
   isolated target policies. Do not duplicate the generic analysis per ISA.
3. Add positive and negative model/runtime fixtures for each new profile,
   including all required executable forms, clobber boundaries and failure/
   cancellation controls. Preserve input bytes and saved Ghidra projects.
4. Run GNU, LLVM and pinned strict libdwarf validators and applicable GDB tests;
   require deterministic repeated outputs and no unexplained diagnostics.
5. Validate the exact assembled package and required host/target pipeline,
   review and integrate through normal protected merges, then reconcile each
   original issue row with linked evidence. A component PR does not close an
   umbrella issue or redefine the full objective.

## Current component

The first AArch64 component is tracked in `AARCH64-PROFILE-PLAN.md`.
**CONFIRMED locally:** the baseline omits a dynamically indirect 24-byte
structure argument. The candidate reuses shared pointer-value analysis and
emits the formal object's memory location while its carrier is proven. The
isolated producer, GNU/LLVM/pinned strict validator checks and 34 real-Ghidra
carrier checks pass. Nine-function non-PIE, PIE and rebased-PIE runs pass
270 instruction observations per symbol file and typed return checks. Each run
includes independently decoded raw location expressions, a positive pointer
spill/reload and the conservative unknown-store control. Full component/hosted
acceptance and all remaining original issue rows are still required.

**CONFIRMED reference limitations and independent calibration:** GCC 13.3 and
14.2 prematurely name integer HFA pieces and an unloaded stack-argument pointer
in two specific prologues. The harness recognizes only exact audited instruction
bytes and independently checks raw ABI registers/memory against source-known
values at every affected PC. Wrong compiler displays are recorded explicitly;
Forge receives no such exceptions. All other compiler observations remain
strict, with positive typed observations required for every field. Three
mutation/oracle tests check exact instruction windows and integer/FP decoding.
`FORGE_AARCH64_ABI_STRICT_REFERENCE=1` retains the failing compiler reproduction.
Clang 16's incorrect indirect-stack location and unavailable exhausted HFA are
retained failed alternatives, not accepted references.

The fixture also exposes a GDB 15 consumer limitation: after a callee legally
zeros the hidden-result register, automatic return display is unavailable with
both symbol files. The harness records this omission, independently reads the
actual caller-owned buffer captured at entry, and checks its values using the
exported return type. It does not claim that automatic `finish` display works
for that case. The other scalar, direct aggregate, HFA and ordinary hidden-buffer
returns still require automatic typed results.

Repeated packaged exports are byte-identical and preserve original/program
database bytes. Only Ghidra's documented filesystem index backups rotate on
read-only reopening. The shell uses the existing exact compiler-corroborated
QEMU synthetic-vDSO diagnostic policy. Three real native failure/cancellation compositions also pass, preserving
neighboring values and existing outputs. The new model/native/runtime checks
are wired into candidate CI, but no hosted run of this candidate has passed yet.

GCC 14 was downloaded as Ubuntu packages and extracted below the ignored build
tree, using the existing AArch64 binutils/sysroot. No system package was
installed. Package versions, hashes and commands are retained with the results.

**CONFIRMED environment inventory:** AArch64 and MIPS O32 compilers plus QEMU
ARM big-endian/MIPS64/N32 emulators are on PATH. ARM cross compilers, MIPS64
compilers and an i686 cross compiler are not currently on PATH. This is a
tool-discovery result, not a blocking conclusion; inspect retained toolchains
and obtain isolated dependencies where needed before requesting user action.

## AArch64 selection component

**CONFIRMED locally; integration pending:** the next component distinguishes
actual AArch64 language/compiler pairs and classifies ELF call-profile metadata.
Twelve packaged cases pass validators, ordinary argument/source observations,
positive injected calls and unchanged-state rejection through both names and
callback types. Six existing x86-64/MIPS rebased regressions pass. The contract,
reference CPU bound, diagnostic accounting and receipts are in
`AARCH64-ABI-SELECTION.md`. This is progress on the first and final rows of #68;
it does not close that issue or any related target issue. Required exact-head
hosted validation, protected integration and the full scope audit remain.

## AArch64 SIMD storage component

**CONFIRMED locally; integration pending:** six separate integer/float lane
functions pass non-PIE, PIE and rebased-PIE runs, including real failure and
cancellation controls. Full-width register copies, spills, reloads and incoming
stack storage retain exact values; uncertain aliases and clobbers produce honest
gaps. The representation is an explicit analyst array layout with guarded
debugger calls, not an invented native vector type. See
`AARCH64-VECTOR-STORAGE.md` for the compiler-reference investigation and exact
acceptance. The full original AArch64 scope audit, hosted gates and protected
integration remain required, as do all remaining MIPS, ARM32 and i386 rows.

## AArch64 allocation and shared-library follow-up

**CONFIRMED defect; candidate acceptance in progress:** actual narrow/aligned and
register-exhausted aggregate fixtures exposed a wrong computed split between the
last integer register and stack. The candidate corrects only the audited dynamic
prototype, preserving explicit storage and the saved program. Shared-library
variants explicitly load the sidecar at the real mapped bias. See
`AARCH64-PARAMETER-ALLOCATION.md` for the full positive/negative contract and
reference limitations. No issue is closed before final package, regression,
hosted and protected-integration evidence is reconciled.

## MIPS independent-reference follow-up

**CONFIRMED compiler references; exporter acceptance pending:** N32 and N64
non-PIE scalar floating fixtures execute with correct typed compiler-DWARF
observations. A strict-reader GNU frame-termination defect blocks the original
N64 validator and has a separate validation-only correction. FPXX FR-mode
experiments expose different unresolved consumer failures by byte order. See
`research/MIPS-ABI-COMPLETION.md`; the full #69 row above remains binding.
