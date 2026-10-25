# Bounded incoming register/stack pieces

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** A computed ARM
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
