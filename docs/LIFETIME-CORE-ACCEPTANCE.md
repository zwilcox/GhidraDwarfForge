# Integrated stack, control-flow and inspected-call core

**CONFIRMED:** PR100 head `53e182e31f5abe38327f43647b30d502a5372395`
passes all twelve jobs in run `41234746854`. The strict, current-base
`required-validation` protection was checked before normal merge
`97a50d1a3c826e639e7754cffed9a98c199616a6`. Its tree is identical to the
reviewed head. No bypass, history rewrite or release publication was used.

The accepted behavior tracks exact scalar register/stack transfers, explicitly
saved local initializing stores and reuse boundaries, predecessor agreement
through branches/loops/body holes, and selected register preservation through
fully inspected direct-call graphs. Unknown aliases, stale copies, missing
pieces, unsupported call effects and contradictory joins remain unavailable.
These bounds are detailed in `STACK-VALUE-TRANSITIONS.md`,
`STACK-LOCAL-DEFINITIONS.md`, `STACK-LOCAL-EFFECTS.md`, `STACK-CONTROL-FLOW.md`
and `INSPECTED-CALL-GRAPHS.md`. Their earlier pending-hosted statements are
superseded by this acceptance; their implementation limits remain unchanged.

## Evidence

The downloaded release package and all five architecture/Windows artifact ZIPs
match GitHub's exact-head digests. Package review verifies 72 production source
files, 273 Java 21 classfiles, current scripts, native source/patch provenance
and all release/platform manifests. The production JAR SHA-256 is
`444d2479c2792c23e057f19768749dccd35bf022058161e1f9a8094c40dee7e2`.
It matches the 22 passing actual Java 21 suites byte-for-byte, and their test
sources match the accepted head.

Independent review of hosted artifacts covers:

- 36 inspected-call cases: 15,318 executed-instruction observations and 11,664
  named compiler/Forge observations, including branch/loop/nested/recursive/
  discontiguous/clobber graphs on x86-64/AArch64 exec/PIE/rebased PIE.
- 42 stack transition/definition/effect/control-flow cases: 18,072 instruction/
  variable observations, raw location decoding, initialization and loss gaps,
  partial/full/unknown alias effects and stale-backup rejection. Explicit-local
  cases cover both 32- and 64-bit values on both runtime targets.
- Six complete/excluded-body cases: 270 observations and 78 available
  complete-body values, with no excluded-body parameter locations. Physical
  carrier evidence is distinguished from compiler inline-assembly limitations.
- Preserved originals, source/module identity, saved programs apart from the
  documented Ghidra backup files, and byte-identical repeated output pairs.
- Fresh LLVM and pinned strict validation of the reviewed stack and host
  artifacts. Native Windows model/producer checks and both GUI host workflows
  pass. The standalone checker is unavailable on Windows; its emitted ELF
  artifacts pass the pinned checker independently on Linux.
- Five baseline target profiles retain GDB breakpoint, source/type and actual
  value checks. This includes ARM32 and both MIPS byte orders; the new lifetime
  runtime claims remain bounded to their tested x86-64/AArch64 profiles.

Acceptance receipt: `build/pr100-cfg-hosted/acceptance.json`, SHA-256
`1c1879493f65c7afe8ffec26cf4ec606a8d4b360033929fb7d634aeb838e6e80`.
It binds separate inspected-call, outside-flow, stack and host review receipts.
Review scripts and raw evidence are retained beside it. Initial review-script
assumptions about backup-file changes, branch choice/parity and transcript
markers were corrected against the fixture source and stored artifacts; no
repository test or producer behavior was weakened.

## Remaining acceptance

The separate main-push run `41245137186` is not this PR gate. Mutable saved
stack assignments and independently migrating pieces retain their own package,
required CI and integration gates. Richer class/lexical/static/alias/origin and
same-name relationships remain under P3.3. The full requirement audit remains
`LIFETIMES-AND-SCOPES-PLAN.md`; neither #67 nor #73 is closed by this component.

## Independent pieces and mutable saved-stack integration (PR101)

**CONFIRMED:** head `c8e48213e339dd845abeb9afaafd58a043fdcad4` passes all twelve
jobs in run `41245301749`. Normal protected merge
`dfb5c2e06822fd40e9ae55928318307976a5aded` has the same tree. This supersedes
pending integration of the mutable-stack and piece components above. It does
not substitute for the separate main-push gate or pending scope integration.

The exact hosted JAR is
`0787a3852a86910f8d87579264853d506ab502f66bfc9b95173528417eac07c4`.
Package review covers 73 production sources, 274 Java 21 classfiles, manifests
and provenance. Twenty-four suites pass on actual Java 21 with 632 checked
class origins. The locally built and hosted JARs differ in 23 classfiles;
normalized instruction text agrees, and acceptance uses the independently
executed hosted JAR rather than assuming those bytes are identical.

Fresh review of uploaded artifacts verifies eighteen x86-64/AArch64 address/
width roles: six independent-piece roles and twelve mutable-stack roles.
There are 10,530 compiler/Forge caller-instruction observations, 3,180 available
candidate values, 66 stale-first-piece controls, twelve unknown-alias gaps,
57 stale-slot controls and 189 conflicting-owner controls. Twenty-four
compiler/Forge callee visits cover 48 callee instructions. Raw location lists
are decoded again from the actual ELF and compared against instruction bytes,
physical carriers, expected mutation/initialization/loss boundaries and GDB
values. PIE and rebased-PIE locations agree after normalization.

The exact head additionally passes reviewed 42 stack roles (18,072 observations),
36 inspected-call roles (15,318 instruction observations), six complete/excluded
body roles (270 observations), register-composite cases and twelve ARM mixed
incoming-piece artifacts. The latter preserve exact piece ordering and stack
adjustments, and keep unavailable gaps after the proven prefix. Original,
project, source and module preservation and deterministic pairs are checked.
Fresh LLVM/pinned strict validation passes. Linux/Windows GUI, Windows native
models/producer/headless export and all five baseline target profiles retain
their documented behavior. The Windows standalone checker remains unavailable;
its emitted artifacts are independently validated on Linux.

Exact-head review receipt: `build/pr101-composite-hosted/acceptance.json`, SHA-256
`26c8a9b2db02402e7e09c19e46facb212d124ec3a79cc80c09f52a122ab3e8bf`.
It binds six review receipts (migration, prefixes, stack, inspected calls,
outside-body flow and hosts) and the hosted package receipt. Review evidence is
recorded on PR101; self-approval is unavailable to the author account. Strict
`required-validation` was preserved, with no admin bypass or history rewrite.
The full P1.11a/P3.3 audit and remaining scope work stay open.
