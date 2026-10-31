# Analyst-created function aliases

**CONFIRMED locally; hosted acceptance pending:** ordinary export now selects explicit secondary
`USER_DEFINED` labels at exported function entries and supplies supplemental
local ELF function symbols. The model checks and the complete twelve-case packaged runtime
matrix pass; hosted acceptance remains pending. This advances P1.7/#66 and does not complete the umbrella.

## Identity and ownership

The primary curated definition remains the only typed DWARF subprogram and
source owner. Its return/parameter metadata, source rows, ranges and owned
statics do not change. The new spelling is a supplemental ELF name, not original
compiler linkage, a second definition, or a second scope owner. Earlier consumer
experiments show that a distinct `DW_AT_linkage_name` hides the curated spelling
in GDB's C11 lookup; duplicate overlapping subprograms fail validation. Neither
workaround is used.

Only nonprimary LABEL symbols with explicit USER_DEFINED provenance qualify.
Imported/analysis/default labels are not promoted to analyst aliases. Plain
namespace and class paths retain their current display spelling; function-local
and external ownership is unsupported. A name that flattens ambiguously, collides
with another current symbol or primary function, or already occurs in original
static/dynamic symbol bytes is omitted with a diagnostic. Existing original
symbols remain available through the preserved ELF tables.

An alias must point exactly to one exported memory definition's entry. The
initial policy requires a contiguous entry-first body in initialized executable
default-space memory. Interior labels, unexported thunks, discontiguous bodies,
overlays and unsupported ownership are not silently reassigned to a function.
The current program's bytes are hashed once per selected definition. After
rebasing to link-time addresses, the ELF planner checks the primary identity,
exact extent, nonoverlapping recovered bodies, a unique file-backed executable
section, and the original code digest. Patching the original or current program
cannot silently attach the alias to different code.

## Target and packaging policy

The first runtime matrix targets x86-64 and AArch64 direct-address symbols on
ET_EXEC, PIE and rebased PIE. The target description authorizes symbol-value
semantics separately from generic ELF planning. Other processors are diagnosed
until their instruction-mode/ABI binding has a behavioral test; this is not a
restriction on the project's architecture-neutral mission. Sectionless binding,
discontiguous alias extents and broader target profiles remain planned.

If an input lacks a static table but has named defined dynamic symbols, adding a
partial static table could hide those original definitions in GDB. Such additions
are omitted. Undefined dynamic imports and original name bytes still participate
in collision checking. A future solution must preserve the complete consumer
view before enabling that case.

The previously accepted matched writer merges new STB_LOCAL/STT_FUNC entries
without changing any old symbol record or string offset. It preserves original
local/global order and extended indices and rejects unsupported index-bearing
metadata before publication. The original file remains unchanged. Existing
atomic pair publication, cancellation and temporary-file cleanup apply.

Planning is deterministic (address, then full display name) and bounded: 65,536
candidate aliases, 262,144 inventoried symbols, 16 MiB names and comparison
budget, and 256 MiB code comparison per extraction/planning pass. Unsupported or
ambiguous aliases produce diagnostics; malformed merge metadata still fails
before any final artifact is replaced. Empty additions retain the old writer
path. No native/JNA entry points change.

## Validation contract

The ELF model exercises both classes/orders independently of target support.
The Ghidra model uses six languages, including both MIPS byte orders, to prove
provenance, qualified names, collision rejection, rebasing, cancellation and
immutable saved-program reopening. These checks alone do not claim target
runtime support.

The real integration harness first creates twelve ordinary retained/fully
stripped x86-64/AArch64 exec/PIE/rebase cases. It exports each copied program
before aliases, adds and saves two explicit secondary labels, and performs two
ordinary exports with a read-only reopen. It independently invokes the installed
ELF writer using the unchanged baseline DWARF and observed labels. Automatic and
independent artifacts must be byte-identical. The no-alias baseline must fail
alias lookup; primary source and DWARF bytes must stay identical.

GNU, LLVM and pinned libdwarf must validate every result. Native/QEMU GDB must
prove typed alias lookup, single entry breakpoints, actual parameters/returns,
primary-owned statics, primary frame identity, source listing, next and step.
Original ELF names must remain usable when retained and absent when stripped.
Inputs, installed package and saved programs are hash-protected; only documented
Ghidra read-only backup rotations are allowed. Supplementary names do not make
GDB resolve function-owned statics through an alternate owner spelling; the
primary remains the supported scope owner.

## Remaining P1.7 work

Target/mode variants, sectionless and discontiguous binding, preservation of
otherwise hidden dynamic definitions, and unsupported namespace relationships
need explicit decisions and relevant runtime coverage. Calling-convention and
return-ABI safeguards remain a separate P1.7 component. Rich class/lexical scope
semantics are tracked in #73. Do not close #66 from this component alone.

## Local acceptance checkpoint

The final model checks pass 245 ELF controls and 186 Ghidra checks across six
languages, with immutable reopening. All 27 focused suites pass on actual
Java 21 against installed JAR
`612327106360a2d9228d19ebc2b14c467ce5208749b160e583b5b0093858da47`.
Actual-Java-21 receipt SHA-256:
`f777aae2cc04d7cd7b2b1a39bc4caa46259878e52db1deb85a9d5bec16a47775`.

Twelve base cases pass 24 ordinary exports and 96 compiler/Forge runtime calls.
The twelve explicit-alias cases pass 12 no-alias baseline exports, 24 automatic
exports, 24 independent writer executions and 48 additional native/QEMU calls.
Independent automatic-export artifact review receipt SHA-256:
`e9ef5d6579764cc1aaa7268e5b36972169e870164cf05e94262fe645b468bf03`.
Independent base-case review receipt SHA-256:
`60c08a6e211e0c0123c3577432288734bc5d62dd7a015776ce7b789860959eb7`.

The controlled decompiler failure, cancellation during ELF copying and real
mixed ARM/Thumb regression pass. The latter uses unchanged instruction-mode
semantics; aliases remain diagnosed on that target. Existing 1,272 symbol merge,
231 ARM symbol-mode, qualified-name and curated-thunk checks pass. Workflow lint
and seven architecture-guard controls pass. Local headless Ghidra uses Java 25;
the actual Java 21 suite above is separate evidence.

Evidence is retained under `build/curated-alias-review/` in the implementation
worktree. The first cancellation test incorrectly requested cancellation after
40 polls although the planner had already completed. The test now checks actual
early/middle/late polling points; no production behavior was changed for it.
The initial failed log remains retained and is not counted as a passing test.

The previous PR80 exporter is separately exercised against all twelve saved
programs containing these same observed labels: primary typed lookup works and
both secondary names are absent. Its module and the current case artifacts stay
unchanged. Previous-exporter receipt SHA-256:
`f6d8c98e78fb5836294101de5b549ba3ad7811c3efcc86af8bd0bf193a517e20`.
Aggregate local acceptance receipt SHA-256:
`22d31f36e2627d64c86e58da80dcc8a90ee1394b07912aae6bb52f793e4a4daf`.
