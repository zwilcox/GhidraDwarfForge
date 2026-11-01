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

**CONFIRMED local N32/N64 scalar acceptance; integration pending:** the new
ELF64 target descriptions and shared physical register mapping pass all 20
ABI/endian/layout cases, including real failure/cancellation compositions.
See `MIPS-WIDE-SCALAR-PROFILE.md` for exact package receipts, the explicit PIE
load-bias workflow, and separate N32 aggregate/mixed failures uncovered by the
next research fixture. Those failures and all remaining original issue rows
still require correction and acceptance; this component does not close #69.

**CONFIRMED local wider-argument progress; full acceptance pending:** the N32
allocation correction and shared delayed-return/truncated-stack proofs pass
eight fresh endian/ABI/stripping non-PIE cases and 3,472 instruction observations. Compiler
aggregate-reference calibration, versioned wider runtime coverage and remaining
ABI/storage cases are still required. See `MIPS-WIDE-ARGUMENT-ALLOCATION.md`.
The original requirement rows above remain the completion criteria.


**CONFIRMED local wider MIPS call/return progress; full scope remains open:**
The versioned wider argument harness passes all 20 ABI/endian/layout cases,
with 9,500 instruction observations, typed return checks, 320 compiler/Forge
injected name/callback calls and all failure/cancellation compositions.
Separate scalar float/double return calls pass 24 cases. See
`MIPS-WIDE-CALL-PROFILE.md` for the exact admitted metadata/type envelope,
compiler defects, consumer limits and retained natural-source regressions.
This resolves the earlier blanket-call-guard failure, but does not establish
completion of the broader allocation/storage audit or any original issue row.
Hosted gates and protected integration remain pending.

## Wider MIPS layout audit

**CONFIRMED additional defects; candidate acceptance in progress:** nested
aggregate classification and 128-bit alignment produced wrong values in both
ABIs and byte orders. Shared unnamed register-slice handling also needs an
exporter correction; a separate GDB 15 big-endian piece defect has a positive
unmodified GDB 17.1 reference. See `MIPS-LAYOUT-ALLOCATION.md` for exact evidence
and remaining acceptance. This adds evidence to the original #69 row without
closing it or narrowing any of the four issues.

**CONFIRMED component integration update:** the AArch64 indirect-argument
component is integrated through PR121 (`54dc96313ef497df89f59f0a06fe87622e77e7d8`),
with all twelve required hosted jobs and independent raw artifact review.
The older pending statements above are historical for that component. PR122
selection is refreshed onto main and rerunning its exact-head gate. The wider
MIPS layout matrix now passes 20 local ABI/endian/layout combinations and has
versioned GDB 17.1 provisioning plus 20 passing failure/cancellation
compositions; exact-head hosted acceptance remains in progress. All four original requirement rows remain open.

## Aligned aggregate and live-session follow-up

**CONFIRMED aligned-aggregate and live-session MIPS defects; correction under validation:**
Explicit aggregate alignment now skips the required register slot and caps
argument alignment at 16 without changing formal types. A separate fresh-import
failure was traced to Ghidra lazily serializing an empty killed-register list;
the fingerprint correction preserves strict rejection of nonempty changes.
434 model checks, all 20 saved-program layout/control cases and all 20 final
live-session cases pass locally. Exact-head hosted acceptance remains pending. See
`docs/MIPS-ALIGNED-COMPOSITES.md`. The full #68–#71 goal remains open.

## ARM32 extended-layout checkpoint

**CONFIRMED local ARM32 PIE mode progress; full acceptance remains open:**
The original ET_DYN omission now has a reproduced static-decoding failure and a
candidate correction using existing byte/owner/mode checks. Four packaged
exec/PIE/rebased/dynamic-symbol cases pass compiler/Forge runtime, validators,
determinism and original-preservation checks. See `ARM-THUMB-EXTENDED-LAYOUTS.md`
for exact evidence and literal-pool oracle boundaries. Sectionless production
behavior is PRESENT, UNVERIFIED beyond model checks; shared/mixed-body/BE8/ABI
work, failure/cancellation composition and hosted acceptance remain required.
All #68–#71 requirements remain active.

## ARM32 sectionless and failure/cancellation checkpoint

**CONFIRMED local ARM32 sectionless and failure/cancellation acceptance:**
Fresh sectionless imports now pass all four exec/PIE/rebased/dynamic-symbol
roles, with independent raw inventory and real debugger checks. The combined
eight-case matrix passes 16 native decompilation-failure exports and eight
production copy cancellations. A separate empty-GNU-hash control requires an
honest mode-symbol omission where no complete symbol count exists. The pipeline
now runs these checks. See `ARM-THUMB-EXTENDED-LAYOUTS.md`; shared loading,
mixed-body/ABI/BE8 work and exact-head hosted acceptance remain required.
All original #68–#71 completion requirements remain active.

## ARM32 shared-library checkpoint

**CONFIRMED local ARM32 shared-library mode acceptance:**
Stripped shared objects and explicitly rebased shared objects pass static mode
checks, measured runtime relocation, source stepping, direct/indirect calls and
exact register-clobber gaps with the unchanged production package. Both cases
also pass repeated native decompilation failures and production cancellation.
The PIE/sectionless regression passes after the harness extension. CI includes
both shared roles. See `ARM-THUMB-EXTENDED-LAYOUTS.md` for receipts and the
PIC-specific second-argument boundary. Mixed-body modes, per-function ABI/BE8,
broader storage and exact-head hosted acceptance remain open; #68–#71 retain
their full original scope.

## ARM32 mixed-body reference

**CONFIRMED ARM32 mixed-body defect and consumer reference:**
A source-built function switches ARM → Thumb → ARM with twelve independently
checked executed instructions. The current curated production sidecar passes
validators but misdecodes Thumb before attachment. A separate standard mapping
symbol experiment fixes decoding and preserves every DWARF byte; it is not a
production correction. The reproducible research harness passes and records
all input/package/program preservation evidence. See
`docs/research/ARM-MIXED-BODY-MODES.md`. Implementing validated extraction and
writer support, the remaining ABI profiles and exact-head integration remains
required; all #68–#71 requirements stay active.

## ARM32 production mixed-body checkpoint

**CONFIRMED local production ARM32 mixed-body mapping progress:**
The real exporter now emits complete evidence-backed ARM/Thumb/data section
mappings. Non-PIE, PIE and rebased PIE pass raw mapping checks, compiler-relative
static decoding, twelve actual instruction observations, strict validators,
determinism and original/program preservation. Six real decompiler-failure
exports and three cancellations pass; ELF/writer and real-Ghidra models pass
33/84 checks. The final package also passes the AArch64 vector/control regression.
See `docs/ARM-MIXED-MODE-MAPPINGS.md`. Shared/sectionless mixed compositions,
source-step acceptance, broader ABI requirements and exact-head integration
remain open; the complete #68–#71 scope is unchanged.

## ARM32 discontiguous mixed-body checkpoint

**CONFIRMED local discontiguous mixed-body acceptance:** eight additional ARM
layouts pass two-range bodies with an excluded data word, six exact mapping
boundaries, raw DWARF range/line checks and compiler/Forge runtime comparisons.
Saved/live/failure exports total 1,672 debugger observations, 32 injected calls,
16 native failure exports and eight cancellations. CI covers both contiguous
and split bodies. See `ARM-MIXED-MODE-MAPPINGS.md` for source-map limits,
receipts and retained harness failures. Inherited-map runtime acceptance,
sectionless shared composition, the remaining original ABI requirements and
exact-head hosted integration remain open; this does not complete #68–#71.
