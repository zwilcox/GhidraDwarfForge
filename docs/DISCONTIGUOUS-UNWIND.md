# Discontiguous function-body unwind validation (#112)

**CONFIRMED locally; hosted acceptance pending.** The x86-64 SysV and AArch64
AAPCS64 assembly fixtures now have an explicit branch over sixteen bytes of
unexecuted padding while saved caller state is live. Independent assembler CFI
spans the original function. The recovered sidecar must instead contain separate
FDE ranges for the two curated body ranges, with complete rules at each range's
start and no coverage of the gap.

The fixture is derived deterministically from the existing encoder assembly;
independent debug-reference builds must match byte for byte. Stripping debug
information produces a separate input without original CFI and with identical
allocated sections and program headers. No reference CFI, stack offsets or
register rules are supplied to recovery.

Ghidra may discover the global branch target as a separate function. The setup
script explicitly curates the assembler-declared ownership: it only removes the
expected interior function, verifies that its body belongs to the declared
function, clears padding, restores the actual branch instruction's default flow,
and assigns the two ranges. This models analyst curation; it does not claim that
automatic analysis always identifies the correct function boundary. A saved
analyst comment is retained. All exports use the installed normal wrapper with
strict synthesis and a read-only saved project.

## Runtime and refusal evidence

Both targets pass non-PIE and PIE cases. Each exports plain and compressed CFI
before and after database rebasing, then repeats every generation. The encoded
frame bytes are identical across compression and database rebase. No FDE or
captured recovery observation covers the gap. Saved-project snapshots and
observations remain unchanged through export, as do original/reference bytes.

The GDB oracle executes all four recursive gap crossings and compares complete
instruction traces, caller PCs and register witnesses against the independent
reference. All eight before/after-gap stops select the DWARF unwinder for every
ordinary caller in the observed stack, not just the top frame. Backtraces,
`finish`, recursive return stepping, stack alignment and normal exit also pass.
Missing-CFI and disabled-DWARF controls do not select that unwinder.

A separate copy of each saved project is deliberately given a function body
containing only part of the branch instruction. The normal exporter reports the
root's refusal and emits no CFI covering that function, while preserving valid
leaf-function CFI. The resulting artifact passes structural validators. At the
function's actual runtime PC, GDB selects a fallback unwinder rather than Forge
CFI. Original positive evidence and the explicitly edited saved project remain
unchanged through these deterministic refusal exports.

Together the positive and refusal matrices pass 40 exports, twenty generated
sidecars through GNU/LLVM/pinned strict validation, and 32 GDB sessions. The four
independent assembler references also pass structural validation. Checking all
caller unwinders was added after the initial runs and applied to all twenty
retained reference/positive GDB transcripts, covering 160 gap stops. No
production algorithm or native binding changed.

## Reproduction and retained failures

```bash
python3 src/test/integration/discontiguous-unwind.py build/discontiguous-unwind \
    --ghidra "$GHIDRA_INSTALL_DIR" --dwarfdump "$DWARFDUMP"
python3 src/test/integration/discontiguous-unwind-controls.py build/discontiguous-unwind \
    build/discontiguous-unwind-controls --ghidra "$GHIDRA_INSTALL_DIR" --dwarfdump "$DWARFDUMP"
```

Output directories must be new. `--target` selects a single architecture for CI;
non-PIE and PIE remain the default roles. Both lanes invoke the same production
exporter and retain the test artifacts.

Three setup failures are retained: parsing the readelf column heading as a
symbol, requesting a strict compilation-unit completion from a frame-only
assembly reference, and overlapping Ghidra's separately discovered interior
function. The corrections select named fixture symbols, compile the independent
assembly with normal DWARF debug information, and explicitly curate the known
function ownership. No validator expectation or recovery rule was weakened.

See [the checkpoint receipt](evidence/discontiguous-unwind.json). This establishes
the selected direct branch and saved-frame layouts, not arbitrary branch modes,
interrupts or every discontiguous function. Native Windows, the combined hosted
gate, artifact review and final #112/ADR acceptance remain required. #110 LLDB
and #109 build-ID installation follow #112.
