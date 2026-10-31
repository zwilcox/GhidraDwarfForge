# Aliases for split and interior-entry function bodies

**CONFIRMED locally; acceptance incomplete:** explicit analyst aliases no longer
require a single entry-first body. The candidate preserves the primary DWARF
range set and true entry, proves the complete body against original ELF bytes,
and uses only the entry-containing range's suffix as the local ELF symbol's
positive extent. No gap, lower chunk or intervening function is silently included
in that single extent. Full function coverage remains in the primary DWARF DIE.

## Consumer experiment

The preceding installed exporter produced the existing assembler-defined
x86-64 split-body and below-entry fixtures. All six exec/PIE baseline/rebase/repeat
cases pass their original validators/GDB oracle. An isolated Java 21 invocation
of the packaged ELF writer then inserts two local aliases while retaining the
exact DWARF. Both zero-size and entry-suffix-size variants pass LLVM/pinned strict
validation, GDB alias prototypes/source, true-entry breakpoints, parameter values,
backward execution, exact primary ranges and gap exclusion, and normal exit.

Research evidence is retained in the `mips-floating-call-abi` worktree under
`build/discontiguous-alias-research/v2/`; receipt SHA-256:
`7f2d3a087769ea2f4df06a92b6bae26c62c755ff7c62a2f8da488e4d46124f39`.
The first GNU objcopy experiment failed because it reconstructed invalid load/
program headers for the non-loadable sidecar. That failure is retained. No
original executable or production writer was changed for the experiment.

**CONFIRMED decision:** use a positive entry-range suffix, retaining the writer's
existing nonzero-size contract. This is an ELF entry-fragment extent, not a
claim that every part of a split function has one contiguous address span.

## Evidence and bounds

`ElfFunctionAlias` records an ordered, nonoverlapping list of code ranges and
one SHA-256 per range. Its true entry must belong to that list. The existing
single-range constructor remains available. The size used in ELF serialization
is derived from the entry and containing range, never from total byte count or
maximum address minus entry.

Ghidra extraction checks the exact current body against the exported primary's
normalized range set before hashing initialized executable memory. The ELF
planner checks every evidence range against the same primary, every other
exported owner and one unique file-backed executable section, then compares
original bytes for every range. A changed lower chunk, a missing range or an
overlapping owner rejects the alias. Bytes and independent functions in a gap
are outside the evidence and remain outside the alias extent. Existing naming,
collision, original-symbol preservation, allocation/name/code budgets and
cancellation rules remain in force. The MIPS policy checks alignment of every
range, including chunks below the entry.

## Local checkpoint

373 planner checks, 228 extraction checks over six Ghidra languages (including
immutable reopen), 540 MIPS policy checks, and 32 installed suites
on actual Java 21 pass. The first real candidate matrix passes all six x86-64
exec/PIE baseline/rebase/repeat cases through the production exporter, GNU/LLVM/
pinned strict validators and GDB. The previous installed package fails the alias
oracle because it omits the aliases; that negative result is retained.

The maintained path is `FORGE_ENTRY_ALIASES=1` with
`src/test/integration/function-entry-export.sh`. The independent symbol checker
proves exact entry-fragment extents and complete original dynamic inventory;
the GDB oracle checks both original primary coverage and alias lookup/execution.
The x86-64 CI lane runs this path separately from the existing no-alias fixture.
Model coverage does not establish split-body runtime support for other targets.

The protected six-case rerun proves the exact installed JAR origin, unchanged
module/fixture/harness hashes and inputs, deterministic sidecar/source bytes and
all runtime behavior. Its independent raw review receipt is
`ed134461feba8958826692252c0e99b250badc3d7729b7f977c967eb9b1e5b21`.
The first raw auditor expected GDB's breakpoint text to repeat the alias name;
GDB correctly reports the primary DWARF name. The corrected review checks the
actual entry addresses and parameter values against the protected alias-driven
GDB script. No runtime assertion was removed or weakened.

Twelve stripped base cases and twelve ordinary alias cases across x86-64,
AArch64 and both MIPS byte orders pass exec/PIE/rebased PIE regressions: 144
compiler/Forge runtime calls, complete dynamic inventory preservation, identical
automatic/independent writer artifacts, strict/LLVM checks and protected hashes.
Failure isolation and cancellation preserve their original/output contracts.
Combined local receipt:
`61827be29e754148b01698630f7405b1115240e8fcfdfe5abe46b076115c4616`.

Final committed package and hosted acceptance remain pending. Sectionless inputs
and additional target/mode policies remain separate incomplete P1.7 work.
