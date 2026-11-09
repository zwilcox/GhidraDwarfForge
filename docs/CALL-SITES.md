# Call sites, tail frames and entry values

**CONFIRMED packaged checks; full acceptance pending:** issue #117 is still under
validation. Both selected profiles pass the installed-package call-site step in
[run 42536372353](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42536372353)
at `cd3817ce`, including all 64 runtime cases and structural/preservation checks.
Windows host checks pass, but a MIPS diagnostic-count assertion failed; the
complete hosted gate and final review have not passed. This document describes
the development implementation, not a released support claim. The
[acceptance plan](CALL-SITE-PLAN.md) records the remaining work and historical
failures.

## What the metadata provides

The exporter examines original instruction bytes, Ghidra function bodies and
recorded parameter storage. When those agree with its control-flow and ABI
proofs, it emits DWARF 5 call-site records. GDB can use these to display supported
argument entry values and reconstruct unambiguous virtual tail-call frames.

Tail-call frames represent eliminated calls, not additional physical stack
frames. Ambiguous paths and unresolved indirect transfers cannot establish an
execution history. An unavailable value or missing virtual frame can therefore
be the correct result. Call-site metadata does not replace unwind information.

The normal export script attempts this recovery automatically. No additional
call-site option is required. Diagnostics beginning with `Call-site metadata at
ELF address` explain omissions. Unsupported call-site proofs do not remove the
function's existing name, type or synthetic source.

## Current proof and test bounds

| Target | Ghidra language/compiler | Recovered-plan runtime coverage |
| --- | --- | --- |
| x86-64 System V integer profile | `x86:LE:64:default` / `gcc` | Native Linux, ET_EXEC and PIE, original and rebased analysis |
| AArch64 AAPCS64 integer profile | `AARCH64:LE:64:v8A` / `default` | QEMU Linux, ET_EXEC and PIE, original and rebased analysis |

The recorded local reference environment uses Ghidra 12.0.3, GCC 13.3.0,
GDB/GDB-multiarch 15.1 and QEMU AArch64 8.2.2. Structural checks use GNU binutils
2.42, LLVM 18.1.3 and the pinned libdwarf checker. Exact versions and fixture
identities are retained in the [compiler reference receipt](evidence/call-site-compiler-reference.json);
the [call-origin receipt](evidence/call-site-call-origins.json) records the later
64-case recovered-runtime checkpoint. The later packaged step is identified
above. These component results do not establish the full hosted gate, other
debugger versions or Windows-hosted call-site recovery.

The implementation currently requires little-endian ELF64 and an audited
ordinary calling convention. Call-site argument expressions are limited to
supported integer-like formal types with one recorded register storage piece
and a proven whole-register actual value. Stack arguments, composite storage,
floating-point arguments, pointer formals, forced-indirect arguments and custom
storage do not acquire call-site value expressions through this profile. Existing
variable-location support is a separate feature.

Unsupported instructions, patched bytes, flow overrides, incomplete bodies and
overlapping function ownership can prevent proof. Completeness is asserted only
when the call inventory is proven. Cross-references and analyst CALL_RETURN
annotations alone are insufficient. The process entry is not treated as an
ordinary called frame.

ARM32, MIPS and i386 have no new call-site support claim. Shared objects,
multiple loaded copies of the same image, other ABIs and LLDB call-site consumers
also need separate validation. The selected profiles do not establish general
optimized-code coverage.

## Inspecting an exported program in GDB

Load the original and its sidecar using the existing explicit workflow:

```gdb
file /path/to/program
set auto-solib-add off
symbol-file /path/to/program.dbg
set print entry-values both
```

After stopping inside a callee, use `bt`, select a relevant frame with `frame N`,
then use `info frame` and `info args`. For a named parameter, `print value@entry`
asks for its entry value; substitute the actual parameter name. The fixture
oracle checks both GDB's tail-frame classification and the `info frame` text,
along with positive values and deliberately unavailable cases.

The fixtures include ordinary calls, a direct tail chain, conditional ambiguous
paths, recursion, forwarding functions and unresolved indirect tails. Their
signatures are explicitly curated. On x86-64, the test also joins known split
fragments of the fixture driver into its correct body. Production export does
not silently repair analyst function bodies; an incorrectly split function can
legitimately prevent a call-site proof.

For discontiguous callees, the sidecar may contain private
`forge_call_entry_...` ELF aliases used to resolve exact call origins in GDB.
Canonical recovered function names and body ranges remain intact. These aliases
are exporter support symbols, not recovered original names. The original ELF
is unchanged.
