# Stack transfers and surviving register values

**CONFIRMED locally; hosted acceptance pending:** an ordered
transfer analysis can preserve incoming scalar bits through completed stack
stores and loads. This is one part of P1.11a. Stack-local initialization/reuse
identity, broader calls/flow, mixed pieces and P3.3 remain required.

The analysis derives the stack-pointer register, memory space, address width,
endianness and register mapping from the program. It tracks exact low-bit
register values and affine entry-stack-pointer addresses. Only a full-width
store of the known value establishes a stack fact; only an exact-width load
from that surviving slot establishes a register fact. Known stack writes retire
overlapping bytes. Unknown-address stores retire all memory facts. Register
writes retire overlapping facts before establishing any ordered output facts.
Listing-only effects with no raw ordering retire affected inputs before the
instruction is interpreted. Unique temporaries never cross instruction
boundaries. Slot addresses are not inferred from source variable names.

Stack-pointer changes retire old memory slots, including released-frame
storage. A register already loaded before frame teardown can still retain the
value. Memory locations use the current proven stack-pointer displacement;
unknown offsets never become a DWARF location. No facts are recreated after
all carriers are lost. Closed, fully decoded straight-line bodies are required;
calls, branches, overrides, outside entries, incomplete decoding and opaque
effects remain outside this component. No new native ABI is introduced.

The new proof fills only unavailable intervals in the established parameter
proof. Existing proven register/spill intervals are retained. It is used only
when an actual stack load has recovered the known incoming bits. This does not
establish mutable parameter or inferred local identity.

## Current evidence

**CONFIRMED locally:** 320 real x86-64/AArch64 signed 32/64-bit model checks
cover completed spill/reload, full and partial overwrite before load, unknown
stores, unrelated stack-slot writes, second spill/reload, final register loss,
frame release, cancellation, flow overrides and outside entries. Existing
106 spill, 424 copy-chain, 380 control-flow-local, 248 merged-local, 28 definition
and 108 later-local checks pass. Seventeen suites pass against the packaged
production JAR on actual Java 21.

All six existing exec/PIE/rebased-PIE spill fixtures pass real headless export, exact raw
loclists, GNU/LLVM/pinned strict checks, GDB values/source/types/navigation and
unchanged/deterministic artifacts. The previous AArch64 model assertion
required unavailability after SP restoration despite the earlier completed
reload; it now requires the proven return-register location. The stack proof
still ends there; only the surviving register extends availability. The raw
runtime checker independently verifies the specific compiler reload and
nonclobbering suffix before expecting that interval. Initial failed assertion
and the corrected test logs remain under `build/stack-value-review`.

**CONFIRMED locally:** all six dedicated x86-64/AArch64 exec/PIE/rebased-PIE
roles pass 12 candidate exports, six preceding-package exports and 12,528
compiler/Forge/previous GDB instruction observations. There are 1,044 additional
available observations where the old package loses the incoming value. The
12 signed 32/64-bit functions exercise three input pairs, repeated spills and
reloads, full slot reuse, unknown-address aliasing and final register loss.
The incoming C argument remains immutable; compiler locals separately describe
the physical stack slots and register carriers. This avoids treating a changed
source argument as the original incoming value.

Compiler GDB independently supplies the slots' SP-relative layout. Raw
loclists must match explicit instruction labels and these independently
observed offsets. Every executed instruction checks actual registers and
memory; compiler local values agree while in their scope. Negative cases
remain unavailable after stale/uncertain reloads and after the final carrier
is lost. GNU/LLVM/pinned strict validators, source/types/next/step, return values,
process exits, protected input/program/module hashes and deterministic reruns
pass. PIE/rebased-PIE inputs and normalized instruction/interval evidence agree.
Raw acceptance is retained in `build/stack-value-review/runtime-acceptance.json`.

Controlled decompiler failure and cancellation after 16 MiB pass with the same
package, preserving the original and prior output pair as applicable. Workflow
lint and both fixture inventories pass. CI now includes all six dedicated
runtime roles and the new model suite on Linux/Windows. Exact final packaging
and hosted validation remain required. The parameter evidence description now
includes proven stack stores/reloads and inspected direct-leaf preservation;
it no longer describes every interval as one register copy.

Tested production JAR SHA-256:
`80abdc9c52410be7b2e3be46888e4d76a59e67ec97701508b567626c9485f968`.
The six existing spill regressions were run with the preceding prototype JAR;
the only later production change before the dedicated matrix corrected the
model's evidence description. Their separate 900 observations are retained in
`prototype-regressions.json`, not counted in the dedicated matrix total.

Reproduction:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew stackValueFlowSmoke stackSpillSmoke buildExtension
python3 src/test/integration/stack-value-transitions-export.py /path/to/private-packaged-ghidra x86_64 --role exec
python3 src/test/integration/stack-value-transitions-export.py /path/to/private-packaged-ghidra aarch64 --role pie-rebased
```

Use all three roles for both targets and the pinned `DWARFDUMP` from
`support/validation/README.md`. `--previous-ghidra` compares the preceding
saved-merged-local package. Initial exploratory fixture binaries contained
compiler-inserted stack-protector calls; the documented final fixture disables
that instrumentation to isolate this straight-line proof. No acceptance claim
covers those exploratory binaries, general calls/branches, stack-local identity
or mixed-piece migration. P1.11a and P3.3 remain incomplete.
