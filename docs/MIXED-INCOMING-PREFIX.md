# Bounded incoming register/stack pieces

**CONFIRMED local current contract (2026-11-02):** the shared incoming-value
analysis now preserves the low field through its exact stack spill and reload.
The fixture is available through offset 20 and unavailable from offset 24.
The updated raw/runtime oracle below replaces the historical first-store cutoff;
production exporter code is unchanged. Hosted acceptance remains pending.

**HISTORICAL initial profile (2026-10-25).** A computed ARM
parameter containing two integers can straddle `r3` and the caller's stack.
Previously the exporter retained its type but omitted its entire location.
The bounded implementation now describes all pieces before the first possible
memory write or first write to any participating register. The whole value is
unavailable afterward. It does not infer that a prologue store copies the value
into a new location, or that an arbitrary store is disjoint from the argument.

## Evidence and scope

An owned ordinary C fixture independently demonstrated Ghidra's effective
`Stack[0x0]:4,r3:4` join. Before the first prologue store, the low field resides
in `r3` and the high field at entry SP. After SP decreases by eight bytes, the
same high field is at current SP plus eight. The first store ends the bounded
location even though this specific fixture's store is disjoint from that high
field. No general memory-alias proof is claimed.

The machine argument observations are `{low=305419896, high=-1234567}` at
entry and after SP moves. GCC's DWARF instead describes an uninitialized stack
home for the low field at those early PCs. Those compiler observations remain
explicitly unvalidated. Compiler fields are checked strictly after its
prologue store and again after the globals are written; the machine arguments
and final globals corroborate the same values. No wrong compiler-entry value
is treated as a successful reference.

The code is independent of ARM register names and register numbers. It uses
the loaded Ghidra language, compiler stack pointer, exact register mappings,
storage pieces, byte order and instruction-level stack depth. Positive runtime
evidence currently covers the specified ARMv7 little-endian hard-float profile.
It does not establish mixed-piece support on every architecture or ABI.

## Proof requirements

- Require a real attached incoming parameter, its owning function and the
  same program architecture. Formal size, storage size and all piece sizes
  must agree; forced-indirect, unassigned and malformed storage is rejected.
- Inspect the pinned Ghidra 12.0.3 `VariableStorage` contract. Compound storage
  permits a non-register carrier at the last big-endian or first little-endian
  position. Require one valid stack piece there, exact language-register
  lookups, nonoverlapping storage and no stack piece spanning offset zero.
- Normalize Ghidra's significance order into DWARF object-memory order. Keep
  each mapped register's original slice semantics.
- Reuse the complete, contiguous, entry-first instruction and incoming-reference
  proof. Calls, branches, delay slots, missing listing bytes, instruction
  overrides, malformed stores and nonterminal opaque operations reject it.
  The ordinary terminal-return boundary from PR57 remains applicable.
- End at the instruction boundary after the first possible memory write or
  register overwrite. Memory outputs and listing memory-result addresses count
  as possible writes, as well as `STORE`. There is no alias-based exemption.
- Require a known zero entry stack depth. Resolve each stack piece against
  analyzed SP depth at each instruction; unknown depths produce unavailable
  intervals. Use the intersection with the proven incoming lifetime.
- Emit a register slice or a resolved byte-aligned register-relative memory
  piece, each followed by `DW_OP_bit_piece`. Raw stack coordinates and partial
  memory-byte pieces remain rejected. No frame-base guess is emitted.

The instruction/reference collection is shared with the previous register-only
proof without changing its policy. Its call, copy, opaque, coverage and
composite model regressions remain mandatory. Existing register-only DWARF
expressions keep their previous encoding.

## Validation

`MixedParameterPrefixSmoke` runs 67 real-Ghidra checks over computed and
analyst-custom joins: SP adjustment, stores before register writes, register
writes, a fully stable body, syscall hazards before/after a write, calls,
listing gaps, invalid parameter ownership/size and cancellation. Neutral
expression checks cover register/memory piece order, offsets and rejection
of unresolved or unaligned memory pieces.

Thirteen freshly compiled suites pass on actual Java 21 against isolated JAR
`abd90f6f1a735fbf87266a284f5f72e79d233b4f94c82e4b7f2d063896212446`.
Receipt SHA-256:
`597bd60566e2ace26e60870870ffacbbf0d082757c51e610d626e0ae876bf0df`.
Local headless Ghidra uses Java 25.0.4.1; hosted Java 21 is a separate gate.

`mixed-incoming-prefix-export.sh` covers computed/custom storage for exec and
PIE with baseline/rebased/repeat imports, twelve exports total. The final local
run is `run.wFuQ3yau`; its receipt SHA-256 is
`232cdec0166eb63c419dbeaec29d77b9006ca87d9bdace2ac6784fe323672c64`.
All twelve artifacts pass GNU/LLVM and pinned strict libdwarf with zero
reported errors. GDB checks exact fields before the conservative boundary,
whole-value unavailability afterward, source lookup, runtime relocation,
unchanged globals and normal exit. The checker independently corroborates
raw register/memory expressions, SP offsets and normalized endpoints.
Original ELF bytes, protected source/JAR/native files and deterministic output
are checked by the harness.

The same package passes six ARM register-only terminal-pair exports
(`run.r3fZC7Vf`) and eighteen floating exports across ARM32/x86-64/AArch64
(`run.tAdP3MdR`). AArch64's inherited frame diagnostics are corroborated against
the original; zero unexplained diagnostics remain. All five fixture source
inventories and deterministic builds pass with the new source included.

Retained development evidence under `build/mixed-review` includes:

- The previous package's typed-unavailable baseline and the first new
  validator-clean/GDB-positive `mixed-export.s6fm73ip` probe.
- `initial-models.log`: a synthetic detached mixed-storage sketch reached the
  new proof. Requiring the same actual attached parameter/function/program
  fixed that inconsistency; the complete related model suite then passed.
- `run.qlqILB4I` and `run.4VCmzi8f`: a generic GDB diagnostic scan mistook
  numbered decompiler source comments for warnings. The final oracle captures
  the source listing, preserves the two exact calling-convention comments,
  and still rejects other warnings/errors. Runtime values and validators had
  passed up to the failed harness assertion; neither failed run is acceptance.

The full exact-head cross-target/native Windows/GUI gate and package review
remain required before integration. General memory migration, overlapping
stores, later-starting locals, surviving pieces, non-stack memory joins,
call-crossing mixed values and broader ABI support remain incomplete.

## PR59 integration accepted (2026-10-25)

**CONFIRMED:** head `28ae3f0c0b2306490932da8841d161b09bb9490e` passes all
twelve jobs in `40241665541`, exact hosted package/provenance review and
sixteen actual Java 21 suites. Raw five-target artifacts, 37 native Windows
tasks and both GUI hosts pass their applicable checks. Independent review
confirms exact Thumb/VFP clobber boundaries, twelve mixed incoming exports,
36 explicit MIPS FP32 exports across whole aliases/pieces/sectionless inputs,
12 default MIPS regressions, and the corrected architecture guard with five
controls. Native Windows GUI lacks the independent strict checker and Linux
ELF runtime GDB; those omissions remain explicit. Linux GUI checks include
strict validation and GDB. Both hosts' chooser/console screenshots were also
inspected.

Acceptance receipt SHA-256:
`4b03ddc3aeb697d002b41f8bc6def3c9fdc427e7a63b3d28a932b49f2270bcfd`.
Normal merge `2fed5c3c6de79b319b3d6aa3d9c82c88e0fc25ea` has the identical
accepted tree; PR57 and PR58 are integrated through its ancestry. Distinct main
run `40244657118` remains pending. Earlier pending and failed component notes
are historical, and the failed architecture guard is not retroactively
accepted. This does not complete broader lifetimes, ABI modes, linkage/scopes
or optional attachment. No release publication.


## Current register/spill/reload oracle

PR136's hosted run `41380112300`, ARM job `125070868433`, failed because the
old oracle required `pair` to be unavailable immediately after `str r3,[sp,#4]`.
The hosted sidecar instead retained a valid copy. A fresh reproduction with
the current unchanged package failed at the same assertion. An independent
instruction-by-instruction GDB observation then confirmed exact values in the
new carriers, without changing the executable, registers or emitted DWARF.

The source-built fixture has ten four-byte instructions. The oracle checks
every opcode, including the executable's MOVW/MOVT global address or the PIE
PC-relative literal-pool address. It requires this exact whole-object location
contract, relative to the function entry:

| PC interval | Low field | High field |
| --- | --- | --- |
| `[0,4)` | `r3` | `[sp]` |
| `[4,12)` | `r3` | `[sp+8]` |
| `[12,20)` | `[sp+4]` | `[sp+8]` |
| `[20,24)` | `r2` | `[sp+8]` |
| `[24,40)` | unavailable | unavailable |

The first store is an exact stack spill. The later store through `r3` occurs
at offset 20 and ends the proven location at offset 24; the test does not assume
that generic analysis can prove this store disjoint from every argument byte.
The physical source-known values remain independently checked even while Forge
correctly reports unavailability. Stack restoration at offset 36 is checked
with the original SP and adjusted physical memory addresses.

The raw checker follows `mixed`'s `pair` formal-parameter DIE to its own location
list and requires all four exact expressions and normalized endpoints. It
requires the precise UNKNOWN_LIFETIME diagnostic at offset 24. It cannot pass
by finding similar expressions belonging to another variable. Every GDB stop
checks raw carriers against `{low=305419896, high=-1234567}`; all six proven
stops must also have correct typed fields. Both fields must be unavailable at
the four remaining stops. Compiler entry/pre-spill displays retain their known
uninitialized-home limitation; the audited instruction prefix and actual raw
arguments corroborate those two points. All eight later compiler displays must
be correct.

`mixed-incoming-prefix-controls.py` runs the actual GDB oracle with three
independent errors for both executable forms. An early gap fails at offset 8,
a late gap fails at offset 24, and substituting r1 for the reloaded low-field
carrier fails at offset 20. Every control requires the exact assertion contents,
nonzero GDB exit, the compiler-corroborated warning, bounded QEMU termination
and private-socket cleanup. Original artifacts and oracle files remain unchanged.
These controls run immediately after the positive fixture in CI.

Local Java 21/Ghidra 12.0.3 validation passes twelve exports covering computed
and explicit custom storage, exec/PIE, ordinary/rebased/repeat imports. GNU,
LLVM and the pinned strict checker report zero errors for all twelve outputs.
There are 140 compiler/Forge instruction observations, 48 required unavailable
pairs, six rejected runtime corruptions, deterministic artifact pairs and
unchanged input/package hashes. Python compilation, shell syntax, workflow lint
and whitespace checks pass. No new production/native code requires rebuilding.

Final case: `build/test-results/mixed-incoming-prefix/run.nK5O9mQM`.
Acceptance receipt SHA-256:
`d94ebca2d97340271380ef50f9f7526e0880d73f765b757e2e018addf2887247`.
Negative receipt SHA-256:
`7ffb20b8811c42ee83d989a2e95a47bd9f99f428086cbe5b03f03c350b432459`.
Separate raw/hash review: `build/arm-mixed-incoming-oracle/review.json`, SHA-256
`0b53ee9f75dbc1331d2cd99f3fd5750ea4306af50984e2b6125a0dcd3b43ac31`.
All 103 production source hashes still match the previously tested JAR
`c3eb4886ebb1d82e1d34131e27d323e80132b6e8c44a50ac4909e83e28650ade`.
The original hosted failure, fresh failed `run.hFPQRvdU`, raw observations and
initial passing `run.q9WrAtyJ` remain retained. Fresh hosted acceptance and
normal protected integration are required; no umbrella issue is closed.
