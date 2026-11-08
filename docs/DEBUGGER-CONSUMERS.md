# Debugger consumer contract

**CONFIRMED hosted and protected acceptance for the scoped LLDB profile.**
PR #183 merged normally as `9c3029f97a418eb3c63742213d68392608ff15a2`
after [run 42291314960](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42291314960)
passed all required jobs. The tested and merged trees are identical. The
[final receipt](evidence/lldb-final-acceptance.json) binds all five target
artifacts, Windows results and the package audit. Issues #110 and #112 are closed;
build-ID installation #109 remains separate and incomplete.

This document describes what the #110 tests establish. It does not announce a
release or extend every GDB target/ABI claim to LLDB. Existing GDB requirements
and structural validators remain mandatory and are not replaced by LLDB.

## Selected LLDB profile

The tested consumer is Linux LLDB 18.1.3, with its matching Python bindings;
CI pins Ubuntu packages `lldb-18` and `python3-lldb-18` to
`1:18.1.3-1ubuntu1`. Runtime targets are x86-64 Linux SysV LP64 and little-endian
AArch64 Linux AAPCS64 LP64. x86-64 runs natively; AArch64 uses QEMU user 8.2.2
and the target sysroot. The floating/vector tests explicitly select Cortex-A53.
Ghidra 12.0.3/Java 21 and the same production exporter generate the sidecars.

| Behavior | Local evidence and boundary |
| --- | --- |
| Function lookup, named/address breakpoints, source listing and stepping | Compiler/Forge semantic and shared-library oracles, plus scalar marker and sectionless original-byte checks. Generated C is synthetic and its source lines are not original compiler source. |
| Types, globals and available variables | Recursive structures, arrays, pointers, typedefs/qualifiers, union members, actual globals, register/stack values and unassigned locals in the [semantic checkpoint](LLDB-REGISTER-PIECES.md). |
| Bitfields and split/changing storage | [Memory-piece checkpoint](LLDB-MEMORY-PIECES.md): actual word/packed-byte field values and compiler/GDB/LLDB instruction comparisons across register copies, memory pieces, spills/reloads, aliases, branches, loops, calls and unavailable intervals. Exec/PIE/rebased PIE and selected x86 red-zone/frame-pointer leaves are covered. |
| Floating-point and vector values | [Floating/vector checkpoint](LLDB-FLOATING-VECTORS.md): scalar float/double arguments, globals and clobber gaps on both targets; complete selected 128-bit AArch64 lane traces through copies, spills, stack arguments and returns. |
| PIE, shared objects and rebased analysis | Real runtime load bias in PIE/shared fixtures; rebased database exports normalize back to original link-time addresses. See [ELF layouts](LLDB-ELF-LAYOUTS.md) and the value-flow/floating receipts. |
| Sectionless ET_EXEC | Explicit separate symbol-module loading with independently checked zero slide works. Direct attachment can resolve names yet miss the named breakpoint. Automatic build-ID discovery is unsupported by the pinned consumer; the precise negative and working alternative are both tested. |
| Generated ordinary call-frame rules | [CFI checkpoint](LLDB-CFI-COMPATIBILITY.md): independent compiler references and plain/compressed normal Forge non-PIE exports agree through all observed ordinary recursive boundaries, caller PC/SP/register values and selected DWARF unwinders. The broader GDB unwind matrix does not establish every LLDB frame/layout combination. |
| Automatic association | [Discovery checkpoint](LLDB-DISCOVERY.md): a configured private build-ID tree works for selected exec/PIE/shared pairs. Unconfigured and mismatched exec/PIE trees do not supply recovered symbols. This is independent of explicit loading and does not implement the #109 installer. |

The test histories retain failed pre-fix encodings and independent controls.
Byte pieces replace the earlier problematic equivalent encoding only for the
already audited register/memory slices; this does not create a new variable
location or extend its proven lifetime. Unknown intervals stay unavailable.
Unproven locations must never be synthesized to satisfy a debugger display.

## Known limits

- QEMU's default SVE register XML omits the Neon aliases expected by LLDB 18.
  Both compiler and Forge vector arguments fail the same mapping check there.
  Explicit Cortex-A53 is the validated ordinary Neon transport, not SVE support.
- The compiler reference's union array with an omitted member offset triggers
  one precisely corroborated LLDB parser diagnostic. Forge's explicit zero
  offset preserves the array. That control permits neither unrelated warnings
  nor malformed Forge DWARF.
- The AArch64 compiler CFI fixture produces an assembler-language-plugin warning
  in LLDB. Its register/caller-frame comparisons pass; those tests do not claim
  assembler variable inspection. No such warning occurs in the Forge CFI runs.
- Sectionless automatic discovery cannot obtain the original's UUID even when
  program-header build-ID notes exist. Use the tested explicit module workflow.
- Nonzero register-bit offsets, non-byte-sized register slices, arbitrary ABI
  profiles and untested forms are not established by the byte-piece matrix.
  Their generic DWARF encoding remains explicit; a structural validator pass
  alone is not an LLDB runtime claim.
- No LLDB support claim is made here for MIPS, ARM32/Thumb/BE8, i386,
  Windows-hosted LLDB, Darwin/Mach-O, asynchronous unwind frames, arbitrary
  debugger-injected calls, or vector inferior-call semantics. Existing GDB
  coverage for those targets is independent.
- Automatic debuglink-only discovery, perf symbolization and production
  build-ID installation/refresh/provenance are separate #109 acceptance work.

## Issue #110 requirement audit

| Requirement | Evidence | Final acceptance |
| --- | --- | --- |
| Reproducible x86-64 and AArch64 lanes with debugger/transport versions | Pinned workflow packages, `lldb_consumer.py`, per-session commands/QEMU invocations and versions in all linked receipts. | Required combined run passed; normal protected merge completed. |
| Compiler reference, stripped headless import/export and actual original/sidecar consumption | Native-inclusive installed package, production fixture drivers, package/source hashes and raw exported ELF/DWARF in the linked evidence archives. | Reviewed final artifacts; all 210 packaged source files match the tested head and all release/platform manifest entries match. |
| Lookup, breakpoints, source, types, globals, bitfields, split/changing locations and honest gaps | Executable assertions in semantic, bitfield, value-flow, shared, floating/vector and sectionless consumers. | 47 hosted LLDB result records and raw transcript diagnostics inspected, preserving compiler controls and unavailable intervals. |
| PIE/shared bias, rebase, stripped/sectionless inputs, discovery separate from explicit loading | Layout/value matrices and automatic discovery controls above. Sectionless limitation is independently reproduced in compiler and Forge, with a validated explicit alternative. | Hosted results confirm the same bounded profile and explicit limitations. |
| Retain compiler/Forge transcripts, structural results and failures; unchanged inputs and deterministic exports | SHA-256-bound local archives, original/copy hash assertions, production repeat comparisons and GNU/LLVM/pinned strict logs. | Reparsed 2,844 positive strict records; rejected/mutated controls counted separately. Rehashed 68 retained LLDB inputs/snapshots. Unretained originals remain covered by runtime hash assertions, not independent download rehashing. |
| Document unsupported cases and integrate CI/support contract after passing | This contract, scoped checkpoint documents, explicit negative controls and CI hooks. | CI hooks and bounded support contract integrated by PR #183 after all required checks passed. |

The earlier checkpoint documents describe local milestones and their then-pending
hosted work. This final audit supersedes those pending statements. The remaining
active goal item is the full #109 installer acceptance, including its distinct
consumer discovery/cache and Windows requirements.
