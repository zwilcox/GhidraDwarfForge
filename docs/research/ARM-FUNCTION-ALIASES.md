# ARM and Thumb analyst-alias evidence

**CONFIRMED compiler-fixture research (2026-10-31); production alias support
remains PLANNED.** P1.7/#66 remains open. The isolated ARM mode-symbol planner
does not currently authorize analyst aliases.

## Toolchain and observed layouts

The earlier ARM compiler is retained under the `arm-unwind-fixture` worktree's
private `build/arm-toolchain` directory. It is absent from the normal PATH; the
preceding i386 regression therefore used recorded hosted ARM inputs. A fresh
private toolchain is now extracted from those recorded Debian packages plus
GCC 13.3 C++ and development packages. Package identities and hashes are retained;
no system installation or alteration of the older toolchain is required.

Four source-built instances of `retained-function-aliases.cpp` use ARMv7-A,
VFPv3-D16 hard float, DWARF 5 and unwind tables: ARM/Thumb each as exec and PIE.
All four execute successfully under QEMU. ELF symbol, instruction and unwind
inventories are retained independently of Ghidra.

- ARM function symbol values are even; Thumb function values are odd. Code and
  DWARF addresses must remain distinct from the tagged ELF values, consistent
  with the pinned [Arm ELF ABI, symbol values](https://github.com/ARM-software/abi-aa/blob/17f2cc8ee6645c1709088f4e0cb4438ce75a14ff/aaelf32/aaelf32.rst).
- The exec fixture's function bodies end at `bx lr`. PIE symbols additionally
  cover literal-pool words; Thumb PIE includes alignment padding before them.
  Symbol size is therefore not evidence of an entirely executable body.
- The existing homogeneous mode extractor checks saved decoding context,
  current per-byte TMode, instruction tiling and original bytes. Its primary
  mode planner only adds cues for selected section-backed ET_EXEC cases;
  aliases need an explicit policy for retained symbols, PIE and sectionless ELF.

Receipt: `faba119441caf12d7a1d5ad3e3eac63459911fddc4191717cede1a2c7a59cfc7`.
Evidence is under `build/arm-alias-review/`. The initial compiler invocation
failed before fixture creation because private binutils needed a command-scoped
host-library path; the corrected four-case probe passes. This is compiler/QEMU
evidence, not proof of Forge alias correctness.

## Required next proof

Keep ARM encoding decisions outside generic alias planning. Bind instruction
mode evidence to the actual entry-containing code range and its original bytes;
do not infer Thumb state from pointer width, a name or a guessed address bit.
Retain generic ownership, collision, full-body and discontiguous-range checks.
Do not solve the range issue by expanding function bodies across literal pools.

First prove compiler and unchanged-exporter observations with exact code-end
boundaries, static disassembly and native/QEMU debugger behavior. Then test a
separate tagged-symbol packaging experiment before changing production policy.
The implementation must reconcile existing static/dynamic mode information,
preserve original inventory, and diagnose unknown/conflicting mode evidence.

Acceptance needs retained/stripped and sectionless ARM/Thumb cases, exec/PIE/
rebased images, mixed-mode neighbors and indirect calls. GDB must preserve
original and analyst lookup, typed prototypes, mode-correct static disassembly,
breakpoints, source stepping, values and returns. Include malformed, changed-code,
ambiguous-mode and discontiguous/entry-interior controls. Shared-object behavior
must be proven before claiming that scope. General ARM modes and calling ABIs
are not established by these four compiler fixtures.

## Retained baseline and tagged-symbol experiment

**CONFIRMED retained ARM/Thumb baseline and packaging experiment (2026-10-31):**
six ARM/Thumb exec/PIE/rebased cases pass repeated real exports, independent
compiler/Ghidra code boundaries, GNU/LLVM/strict libdwarf validation and QEMU/GDB
lookup, prototypes, owned data, stepping and returns. Static disassembly is checked
before attaching so CPSR cannot hide missing mode information. An isolated writer
experiment preserves every existing symbol/DWARF byte while adding two correctly
tagged local aliases; all six cases pass two deterministic writes and runtime
lookup through the aliases. Automatic ARM alias extraction remains PLANNED;
stripped, sectionless, mixed-mode and conflicting-evidence cases remain open.
Receipt: `94f3e5b759834daa9477773fae4b88b8a822ce6b26c32ada6961805f308f886e`.
See `docs/research/ARM-FUNCTION-ALIASES.md`. P1.7/#66 remains open.

The common integration harness now accepts `arm32 --arm-mode arm|thumb`.
It separates the tagged ELF value and compiler symbol size from the decoded code
extent. Independent objdump instruction boundaries and exact `bx lr` bytes define
the fixture body; Ghidra must agree without expanding it across literals.

The baseline cases are retained under `build/arm-alias-review/baseline.ysz2rova`;
the writer experiment is `tagged-packaging.vt0n2ar6`. Both use packaged JAR
`adacaa6dd7f27fd3990ff58b63c0282962d262902af9901c3dcf8d15361ce699`.
Commands are retained alongside each artifact. The experiment compiles the
existing `LocalSymbolMergeProbe` with `--release 21`, executes it with Java 21,
and compares the full original symbol inventory and all DWARF sections. Its
second invocation of each function uses the newly inserted alternate name.

Two harness failures are retained: GDB Python's inclusive disassembly end
included the next instruction until the test used `end - 1`; the first experiment
copy omitted the executable permission until it used `copy2`. Neither required
an exporter change. Original inputs, packaged runtime and saved programs remain
protected. Passing retained-symbol cases does not prove missing-mode recovery:
existing mapping symbols can still determine decoding. The next experiments
must remove that protection, test conflicting tags, and cover mixed neighbors.

## Stripped mode proof and negative controls

**CONFIRMED stripped Thumb PIE mode gap and isolated repair (2026-10-31):**
four ARM/Thumb baseline cases pass, while stripped Thumb PIE and rebased PIE
fail GDB static disassembly before attach despite valid DWARF. Existing production
mode cues are restricted to ET_EXEC. An isolated tagged-alias writer experiment
repairs both cases; all six stripped roles pass validator and runtime checks.
Six deliberately wrong-tag controls fail static decoding while LLVM still passes;
twelve mode-inventory corruption controls are rejected. Production extraction
and planning remain unchanged. Receipt:
`b79408ac6e9055788d95822a24712bd6307d68eb47a87e89181102261267f6dd`.
Automatic ARM/Thumb alias support, sectionless/mixed/conflicting evidence and
broader P1.7 remain open. See `docs/research/ARM-FUNCTION-ALIASES.md`.

The stripped baseline is `build/arm-alias-review/stripped-baseline.milr6fzy`;
its two Thumb PIE failures are retained, not counted as passes. Both cases
complete deterministic export and structural checks before GDB decodes Thumb
bytes as ARM instructions. The compiler comparison succeeds. The other four
roles pass the complete baseline workflow.

Primary ET_EXEC mode-symbol inventory is checked independently against compiler
mapping intervals. The checker preserves the original dynamic records and
string prefix exactly, checks every added local's type, name, tag, section and
extent, and requires both curated function cues. Repeated mapping markers of
the same mode do not end a homogeneous interval; the initial checker failure
at such redundant ARM markers is retained and corrected. Twelve mutations of
tags, extents, types, bindings, visibility and names are rejected.

The stripped packaging experiment (`stripped-tagged-packaging.fy_34qkv`) adds
exactly two local aliases to the original dynamic inventory using the unchanged
packaged writer and unchanged DWARF sections. It does not reuse the baseline's
primary mode symbols. All six cases pass deterministic writes, validators,
static disassembly, typed alias lookup and actual QEMU/GDB stepping and returns.
The wrong-tag controls (`wrong-tag-controls.n_mwljqq`) change only each added
symbol's mode bit. All twelve function disassemblies across six cases become
incorrect before attach, while LLVM still reports no errors. This establishes
why structural validation alone cannot accept the feature.

## Implementation boundary selected by the experiments

New aliases need separate entry-range mode evidence, rather than relying on
primary mode cues being emitted. Keep byte and DWARF addresses untagged; apply
the mode bit only to an ELF function symbol after original-code, ownership and
mode checks. Derive evidence from both saved decode context and fully known
current TMode, with exact instruction tiling. Preserve generic checks across
every body range; an entry below a later range or inside an entry-containing
range must not be silently excluded.

The target planner must reconcile original function tags and mapping intervals,
reject conflicting/unknown modes with diagnostics, and handle PIE independently
of the ET_EXEC-only primary-cue policy. Sectionless and mixed-neighbor experiments
are still required before general production authorization. No claim is made
for Thumb shared objects, big-endian ARM or an untested calling convention.
