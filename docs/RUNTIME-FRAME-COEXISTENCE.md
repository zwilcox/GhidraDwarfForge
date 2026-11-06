# Runtime and generated unwind information through native export

**CONFIRMED locally; hosted acceptance unverified:** `unwind-export.py --original-runtime`
extends the native exporter harness with original `.eh_frame` and
`.eh_frame_hdr` alongside generated `.debug_frame`. It does not enable normal
CLI/GUI synthesis, alter exception handling or complete issue112.

## Fixture and evidence contract

The fixture is built from each existing independent assembler source. The owned
input retains leaf and terminal-boundary CFI, removing only the recursive
function's CFI directives. It is assembled into runtime `.eh_frame`, with a
linker-produced header. The independent complete reference emits both runtime
and debug frames. Both are built twice and must be byte-identical on rebuild.
Their function symbols, text and read-only data addresses and payloads must agree.
This avoids changing PC-relative runtime records by hand.

Adding program headers can change code addresses. Reuse of earlier recovered
recursive rows requires byte-identical recursive instructions and sizes, with
the same uniform address translation for every fixture function. Row addresses
are translated by that verified amount. The complete assembler reference and
actual instruction-by-instruction GDB traces remain an independent oracle;
agreement with an earlier generated plan alone is insufficient.

Only the uncovered recursive function may get generated CFI. Each plain or
compressed sidecar must preserve the original `.eh_frame` and `.eh_frame_hdr`
bytes, offsets, sizes, addresses, flags and section types. Generated records
must equal the translated recursive rows; original-covered leaf and startup
ranges must not receive generated FDEs.

The native-export harness retains deterministic reruns, before/after database
rebase snapshots, injected cancellation and exception controls, successful retry,
source mapping checks and unchanged inputs. It runs seven unwind GDB modes plus
two source-level sessions per case. Generated traces and caller-register values
must match the assembler reference. The inherited-only control must select the
original leaf CFI within the inspected group; disabling DWARF must remove that
selection. Fallback unwinding is not assumed to fail universally.

## Validator scope

GNU inspection, LLVM verification and pinned libdwarf checks run on both
source-built inputs and every retained sidecar. Assembler-only controls have no
compilation units, so their summaries use the existing original-input checker
contract. The harness explicitly prints both debug and runtime frame sections.

Some GNU runtime records are four-byte aligned and trigger the pinned checker's
address-size alignment diagnostic. Each such notice is independently rebuilt
from the actual record length, offset, CIE/FDE identity and address size; the
complete notice multiset must match. No other diagnostic is accepted. Sidecars
still use the ordinary nonzero-CU strict checker, with original runtime-frame
identity and bytes independently corroborated. No checker policy is changed.


The complete twelve-case matrix passes: two targets, two fixture families and
executable/PIE/shared roles, with 108 successful native exports, 24 staged
cancellation/exception controls, 48 GNU/LLVM/strict sidecars and 108 GDB sessions.
All 48 passing strict reports remain complete and bound to their receipts. Plain
and compressed outputs are tested before and after database rebasing.

The first matrix passed export/runtime checks but used the exported-receipt
filename suffix for assembler-input summaries. The final retention audit rejected
that schema mismatch. Input summaries now use a distinct filename, and both the
native-export harness and inherited-unavailable control invoke retention checking
before reporting success. The full matrix was rerun after this correction.
The retention checker itself is unchanged; its three positive and ten
report-damage controls still pass. Four existing shared-library cases (both
targets, absent and gABI original debug CFI) pass 36 exports, eight failure
controls, sixteen sidecars and 36 GDB sessions. The inherited-unavailable AArch64
case passes its one export and two independent GDB comparisons, including its
explicitly incomplete chain. All 65 exported-sidecar raw reports across these
suites pass the final retention review. Earlier failures remain retained evidence.
Commands, source hashes and results are recorded in
[evidence/runtime-frame-coexistence.json](evidence/runtime-frame-coexistence.json).

## Reproduction and remaining acceptance

After producing the existing `unwind-frame-recovery.py` results, run:

```bash
python3 src/test/integration/unwind-export.py "$GHIDRA_INSTALL_DIR" \
    /path/to/recovery-results /path/to/new-results \
    --original-runtime --dwarfdump "$DWARFDUMP"
```

Use `--libdwarf` and `--libdwarfp` for a local installation without bundled native
libraries. Both fixture families and both targets must pass executable, PIE and
loaded-shared-library cases. The workflow invokes the same harness on both target
lanes. Hosted acceptance remains unverified until its exact commit passes.

The strict storage-alias policy and the unchanged global-writing compiler-C
fixture remain separate unresolved acceptance. These controlled assembly tests
do not replace compiler-reference acceptance, user-facing provenance/policy,
production enablement or the remaining LLDB/build-ID goal items.
