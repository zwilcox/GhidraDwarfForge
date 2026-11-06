# LLDB memory pieces, bitfields and changing storage (#110)

**CONFIRMED locally; hosted integration PRESENT, UNVERIFIED.** This follow-up
to [register pieces](LLDB-REGISTER-PIECES.md) checks actual values through spills,
reloads, aliases, branches, loops and calls. It does not complete #110 or change
the order of #112 protected integration, full #110 acceptance, then #109.

## Memory-piece compatibility

With a general-register byte piece followed by a memory bit piece, LLDB 18.1.3
rejects the latter with `unable to extract DW_OP_bit_piece` from an address
value. Compiler references and GDB can read the expected pair. Both x86-64 and
AArch64 reproduce this with the previous production exporter. The failure is
in value consumption even though structural validation accepts the artifact.

The expression planner now emits `DW_OP_piece` for its existing exact,
byte-aligned memory fragments. [DWARF 5 section 2.6.1.2](https://dwarfstd.org/doc/DWARF5.pdf)
defines the equivalent contiguous bytes at the computed memory address. This
case has no partial-register placement ambiguity. The separately documented
target contract still controls register byte pieces; unknown register layouts,
nonzero register bit offsets and non-byte-sized register slices retain their
explicit bit-piece expressions. No new location or lifetime is inferred.

The [pinned LLDB evaluator](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Expression/DWARFExpression.cpp)
reads memory for `DW_OP_piece` but rejects an address value for `DW_OP_bit_piece`.
The original local probe accidentally treated an empty successful `SBError`
string as failure; the corrected oracle uses `SBError.Success()`. Both versions
are retained. The permanent instruction-level harness rejects the previous
x86-64 production memory expression at its first affected value read.

## Independent consumer and lifetime checks

`composite-value-flow-lldb.py` consumes the source-built compiler reference,
stripped executable and normal packaged Forge sidecar from the existing GDB
integration driver. Every executed ordinary instruction is checked against
the independent compiler/GDB trace: runtime address after load bias, instruction
bytes, stack delta and actual stack-slot contents. Calls additionally check each
executed callee instruction. Compiler scalar arguments establish entry values;
the Forge aggregate deliberately represents the analyst's curated grouping.

At each Forge stop the raw decoded location list determines the declared
interval. LLDB must recover both fields when available, and physical registers
or memory must independently agree. Outside the proved interval, the parent and
both children must report unavailable. The oracle does not permit stale copies
to restore availability after an unknown alias or clobber. Branch visits, loop
iterations and invocation order follow the independent trace. Normal process
exit, protected hashes and byte-identical export reruns are required.

Both targets pass exec, PIE and rebased-PIE cases, including 605 x86-64 and 588
AArch64 ordinary observations per standard case. The x86-64 red-zone and
frame-pointer leaf controls also run in the CI matrix. Local results and exact
tested controls are enumerated in the [receipt](evidence/lldb-memory-pieces.json).

## Bitfield and ARM32 regressions

`bitfield-values-export.sh` optionally runs the pinned LLDB consumer when
`FORGE_LLDB` is set. Both the four-byte and packed one-byte structures must have
fields `a=5`, `b=17`, bit widths 3/5 and offsets 0/3. Independent compiler and
Forge observations agree on x86-64 and AArch64. The real exports, GDB sessions,
GNU/LLVM/pinned strict checks and deterministic repeats all pass. The strict
validator corroborates two x86-64 and five AArch64 inherited frame diagnostics
against each original; these are not silent warning exemptions.

The changed memory expression also passes all twelve ARM32 mixed-incoming
baseline/rebased/repeat cases for exec/PIE and computed/custom storage, including
raw expression checks, strict validators and GDB values. ARM register bit pieces
remain unchanged. The three focused Java smoke suites pass, including 1,032
composite-flow checks. This is not an ARM32 LLDB support claim.

The broader ARM aggregate oracle also checks natural compiler parameters that
split between r3 and the entry stack. Its decoder required the new memory byte
pieces, but a final exact-byte comparison still expected the former bit-piece
encoding. The corrected comparison keeps r3's register bit piece and requires
exact 4/1/8-byte memory tails for pair, packed and three-word aggregates. Ten
fresh little-/big-endian exec/PIE/rebased cases, including little-endian shared
objects, pass compiler/GDB/physical-carrier comparisons, deterministic reruns,
strict validation and failure/cancellation controls. See the
[regression receipt](evidence/arm-memory-piece-regression.json). Hosted acceptance
remains pending; this is not an ARM LLDB claim.

## Reproduction and remaining scope

```bash
FORGE_LLDB=lldb-18 src/test/integration/bitfield-values-export.sh \
    "$GHIDRA_INSTALL_DIR" x86_64 aarch64
python3 src/test/integration/composite-value-flow-export.py \
    "$GHIDRA_INSTALL_DIR" aarch64 --role pie-rebased --lldb lldb-18
```

The debugger is pinned to LLDB 18.1.3. AArch64 uses the recorded QEMU user
transport; x86-64 runs natively on Linux. Shared-library relocation, applicable
sectionless inputs, remaining sliced-storage limits, explicit versus automatic
discovery, hosted acceptance and the final consumer-support contract remain
open. Passing these tests does not establish other LLDB versions, target ABIs
or transports. Build-ID installation remains #109.
