# Curated thunk symbols without borrowed source

**CONFIRMED integration (2026-10-29 America/Chicago):** PR77 corrected head
`cb092feefa5005cd469c0f5fca241001c12a9287` passes all twelve jobs in
`40505333973`, independent package/raw artifact review, 23 actual Java 21
suites and both GUI console reviews. Normal merge
`c779c0b93b3f90c8798f9f287cd72ff70002ec0b` preserves the tested tree and includes
PR75/PR76 through normal ancestry. Acceptance receipt SHA-256:
`39b29389e79eea862d9c7ae60fc0c6411a9901e94f2488df1bca522959b6735f`.
Curated thunk symbols and bounded i386 shared-library debugging are accepted;
P1.7 and the broader ABI/alias requirements remain partial. Earlier hosted-pending
notes for these components are historical. The separate main-push run
`40991540433` is pending; it is not replaced by the PR pass. No release is published.


**CONFIRMED locally; hosted acceptance pending:** explicitly analyst-named
memory thunks now retain their own names, body ranges and formal signatures.
This advances [P1.7 (#66)](https://github.com/zwilcox/GhidraDwarfForge/issues/66).
General alias/linkage semantics and other thunk policies remain incomplete.

## Evidence and policy

The preceding exporter skipped every Ghidra thunk. A source-built tail-transfer
fixture confirmed that a saved `USER_DEFINED` name and integer signature were
lost on both x86-64 and AArch64. The AArch64 probe also exposed a source hazard:
Ghidra returned the destination's `return value * 2 + 1` body when asked to
decompile a four-byte thunk. Those statements are not evidence for the thunk's
instructions.

Selection now includes a memory thunk only when its symbol name has
`SourceType.USER_DEFINED`. Existing entry, memory-body, address normalization,
namespace display and range checks still apply. Default, analysis and imported
thunk names retain the `THUNK` omission policy. A curated external declaration
is still addressless; selecting a memory thunk does not invent an external body.

The source pass deliberately avoids decompiling a selected thunk. It writes an
explicit synthetic-source omission comment with no executable rows or
`DW_AT_decl_file`/`DW_AT_decl_line` on the thunk DIE. This disposition is distinct
from an actual decompilation failure. The ordinary Ghidra signature API supplies
types and provenance, including a signature delegated through a thunk to its
destination. No new claim of independent or original compiler provenance is made.

A deliberate omission preserves independently recorded formal types and
function-owned memory objects. Actual decompiler failures retain the existing
symbol-only behavior, including omission of their owned statics. Unproven
variable locations stay absent; the new runtime fixtures retain a typed
`value` parameter without a location on the thunk. Its destination's proven
parameter remains usable. No new native/JNA calls or ABI/register mappings are
introduced.

The JSON report uses existing `unsupportedConstructs` rows with kind
`OMITTED_SOURCE`, names the affected function and reports `PARTIAL`. Such a row
does not increment `functionsFailed` or `functionsDecompiled`. The existing
schema-one report parser accepts and preserves this distinction. The synthetic
source comment also makes the omission visible without the JSON report.

## Local acceptance

`CuratedThunkSmoke` passes 165 checks using five real Ghidra language models:
x86-64, AArch64, ARM32 and both MIPS32 byte orders. Controls cover curated and
uncurated thunk selection, independent qualified names and body addresses,
formal types, unavailable source rows, genuine failures, function-owned statics,
report parsing, cancellation and immutable saved-program reopening.

The packaged production JAR passes 23 focused suites on actual Java 21.
Source/report regression suites also pass, including 429 report-claims rejection
controls and 432 detailed-report checks.

`curated-thunk-export.py` passes exec, PIE and rebased PIE on both x86-64 and
AArch64: twelve deterministic candidate exports, six preceding-package exports
and eighteen compiler/candidate/preceding GDB runs. Each role checks:

- Persistent analyst name, formal signature and exact link-time body addresses.
- GDB name lookup, `ptype`, and a breakpoint at the thunk's own entry.
- No source row at the thunk and an honestly unavailable parameter location.
- Instruction stepping into the destination with argument 19, destination
  source lookup, return value 39, and normal program exit.
- GNU/LLVM/pinned-libdwarf validation, original ELF identity and build ID,
  unchanged inputs/saved programs, and deterministic artifact/source hashes.

Independent raw review parses ELF/DWARF, type references and address ranges,
checks previous-package omission, and rehashes protected fixtures, harnesses and
installed package files. Matrix receipt SHA-256:
`82a758965efec9cb10a6b6d122ff8ee9288ab69211a7578fe91b5fbcbb760b49`.
Aggregate local receipt SHA-256:
`1e49ac6909cde3acd219142efe4c8517971447a24605f00c93d61fc46e80e67e`.
Final tested JAR SHA-256:
`95ec94f73eab760619ce7d4b050b154b5028eb67e011028a6084c844e8c417ba`.

Ten dynamic-parameter regression exports pass native/QEMU GDB in all five
existing target profiles. The controlled decompiler-failure export preserves its
symbol-only/owned-static policy, and cancellation during ELF copying preserves
the original and the prior output pair. Strict libdwarf results use the existing
corroborated-frame policy: inherited frame diagnostics must match the original;
no uncorroborated diagnostic is accepted. Local headless exports use Java 25
with Java 21 bytecode; the actual Java 21 suite is separate evidence.

Both host model lists and the x86-64/AArch64 runtime lanes include these tests.
Hosted validation remains pending; the five-language model checks alone do not
establish real thunk runtime support on ARM32 or MIPS.

## Retained attempts and limitations

Evidence lives under `build/thunk-review` and
`build/test-results/curated-thunk` in the implementation worktree. Initial model
compilation used incorrect range accessor names and a newer Gson collection
method; those were corrected. The first GDB oracle used global-only symbol
lookup, which misses the exporter's CU-local function DIE. The corrected test
checks both global and static lookup, then independently verifies type,
breakpoint and runtime addresses. Fresh runs pass; the failed attempt remains.
A final diagnostic wording change was followed by a new package and full focused
matrix/model/regression reruns. Earlier passing packages remain historical.

This does not recover source for tail transfers, distinguish every compiler
thunk kind, create alias DIE relationships, certify inherited/custom calling
conventions, infer locations from the destination, or complete class/lexical
scope modeling. Those requirements remain in the open tracking issues.

## Combined integration checkpoint

The shared-library follow-up and TODO issue index are included through normal
merge ancestry. A fresh eight-role i386 shared/direct matrix passes sixteen
exports and 3,000 GDB observations with the thunk JAR above. Its 23 actual Java
21 suites and sixteen fresh i386 producer lifetimes pass. Independent shared
review receipt SHA-256:
`71d4daece096658e583dc679ead487f5f8fe8491b112f52e2b58033f694db1d6`.
These are local results; the combined hosted gate remains pending.

## First hosted attempt and transport correction

PR77 run `40448198808` passed four target lanes and the exact packaged 23-suite
Java 21 check, but the MIPS32LE floating-register compiler-reference test failed
before invoking the exporter. The retained emulator log reports a TCP bind
collision on port 35948; GDB then timed out. Windows-host validation was skipped,
so this combined head is not accepted.

The floating harness now uses the existing private UNIX-socket helper and its
readiness, child-exit and cleanup checks. The helper joins FP32 protected-input
snapshots. No production/native/ABI code changes. Fresh default-profile exports
pass all five targets (30 exports); sectionless explicit FP32 pieces add six
MIPS32LE exports. Raw review confirms 43 unique sockets, successful emulator
exits, removed private directories, validators and deterministic outputs.
Startup, missing-executable, timeout and ready-child cleanup controls pass.
The first review mistakenly expected 45 sessions; the corrected review asserts
per-target counts because only MIPS needs a separate-symbol PIE compiler oracle.
Receipt SHA-256:
`6d6a1796c953d4fe4249aa1432bc70bc51fe2442564dff9b1758b1c9a90e8ca9`.
The corrected exact head still requires the full hosted gate.
