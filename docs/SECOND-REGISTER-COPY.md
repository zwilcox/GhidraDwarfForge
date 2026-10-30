# A second proven incoming-value register backup

**CONFIRMED through accepted PR78:** a single incoming scalar
parameter can retain its value through two complete register handoffs in a
fully decoded straight-line leaf. This advances [P1.11a (#67)](https://github.com/zwilcox/GhidraDwarfForge/issues/67),
which remains incomplete. General local-variable identity, arbitrary copy
chains, stack migration, branches and broader call shapes remain separate work.

## Contract

The first backup uses the accepted ordered p-code proof. At its handoff, that
backup is already known to contain the incoming parameter's exact bits. A
second invocation of the same proof starts at this boundary and may establish
one additional backup before the first is overwritten. The resulting location
list contains the incoming register, the first backup, the second backup and
an explicit unavailable tail after the second backup is overwritten.

The second proof requires an attached parameter, matching program/storage
ownership, exact formal and storage widths, first-use offset zero, a valid
single-register storage and an exact named low-bit slice of the first backup.
The slice uses the language byte order; it does not assume a register address
is the low-byte address. Missing named slices preserve the original bounded
result. No new register maps, native bindings or DWARF opcodes are introduced.

Every existing complete-decoding, secondary-entry, opaque-effect, ordering,
width and cancellation guard remains active. There must be no calls anywhere
in the function. Copies completed before the first handoff, copies of already
lost values, partial/incomplete copies and arithmetic transformations cannot
establish this second fact. A source-killing instruction cannot establish a
new backup. A physical self-copy/widening can produce different write boundaries
in the two proofs; both proofs must agree on the exact handoff before their
intervals are joined. Only two handoffs are considered, with no reacquisition
or third-copy search.

This preserves the incoming parameter value. A copy of a mutable local is not
sufficient evidence that the old value still belongs to that local after an
assignment, so this change does not extend curated local-variable lifetimes.
A location at an instruction address describes state before execution: each
handoff and kill takes effect only after the whole instruction completes.

## Local acceptance

`SecondRegisterCopySmoke` passes 186 real-decoder checks for signed 32/64-bit
storage on x86-64 and AArch64, including missing/arithmetic/stale copies,
pre-handoff destruction, partial clobbers, physical/semantic boundary
mismatches, interval coverage and cancellation. The preceding packaged exporter
fails the new positive case on actual Java 21 because the second interval is
missing. Existing copy/model suites still pass. Twenty-four packaged suites
pass on actual Java 21 with class-loading origins checked against the tested
production JAR. Local headless Ghidra uses Java 25 with Java 21 production
bytecode; those are separate runtime observations.

`second-register-copy-export.py` runs exec/PIE/rebased-PIE roles on both targets.
Six roles pass twelve candidate exports, six previous-package exports and
eighteen compiler/Forge/previous GDB executions: 1,188 instruction-boundary
observations. Each role verifies:

- Signed 32/64-bit parameter types and positive, negative and wide values.
- Compiler-derived function and instruction addresses; both raw backup values.
- Exact availability at the copy and kill instructions and their fallthroughs.
- The preceding exporter remains unavailable after the first backup is killed,
  while the corrected exporter retains the value in the second register.
- All registers holding the tracked value are eventually killed. Forge reports
  an unavailable tail; compiler entry-value recovery is a separate capability.
- Source listing, types, `next`, `step`, sink values, returns and normal exit.
- Exact raw DWARF location-list expressions, GNU/LLVM validation and strict
  libdwarf checks. Inherited frame diagnostics must match the original under
  the existing corroboration policy; no unexplained diagnostics are accepted.
- Matching ELF identity/build ID, no sidecar program-header table, preserved
  section addresses, unchanged inputs and installed packages, read-only saved
  program reopen, and byte-identical repeated sidecar/source pairs.
- Identical PIE/rebased input bytes and normalized link-time location ranges,
  with nonzero debugger runtime load biases.

Independent retained-artifact review receipt SHA-256:
`858b02bead1d9c6c022d08946dc9d1939b01bcdf1fc9f200d225e71c6b58d713`.
Evidence is retained under `build/second-copy-review/` in the implementation
worktree. Existing six-role register-copy regressions add twelve passing
exports. Ordinary dynamic-parameter regressions add ten passing exports across
x86-64, AArch64, ARM32 and both MIPS32 byte orders. All five fixture
reproducibility lanes, architecture guard controls and workflow lint pass.
These additional lanes preserve existing behavior; they do not establish
second-copy runtime support beyond the two tested targets.

CI adds the decoder suite to both host model lists and all three new runtime
roles to the x86-64/AArch64 lanes. PR78 run `40993878434` passes all twelve jobs and independent downloaded
artifact/24 actual Java 21 suites/raw target/both-GUI review. Normal merge
`2c90da03ee4e4b585d15796e237b000d597b1168` preserves its tested tree.
Receipt SHA-256:
`8d2f77da6ccbf009daf11e1508493950c477f26873682da8aac8bd6b6520ff95`.
The distinct main-push run `41071957971` also passes its full gate and
independent package/raw/both-GUI review; receipt SHA-256:
`24f67e4ffa8287666e0081bba91743c00f6afdab5348114fa875c77f93190536`. This work does not publish a release or
close the broader variable-lifetime issue.

## Retained failed attempts

The first smoke compilation used an incorrect register-number accessor. A
self-copy negative control initially used a 64-bit operation for a 32-bit fact;
that operation correctly ended the narrower proof, so the control was corrected
to use the tracked width. Its first failed Gradle run was followed by an assembly
attempt using the old ZIP; the package source-equality check rejected that
stale archive. Subsequent build/assembly commands stop immediately on failure.

The initial runtime fixture put the post-clobber label inside the same inline
assembly statement. GCC still described the pre-statement parameter register
there, so GDB reported zero instead of the incoming value. The fixture now puts
that label at a separate statement boundary; fresh compiler and exporter runs
pass. The raw failing compiler logs remain retained. No incorrect compiler
value is accepted or hidden by weakening the value assertion.

An initial prior-package model launch used Gradle's Java 25 test classes on
Java 21 and failed class-version loading. The accepted baseline comparison uses
the separately compiled `--release 21` classes and reproduces the semantic
missing-interval assertion. That launch failure is not regression evidence.
