# Register locations require a completely decoded body

**CONFIRMED locally; hosted acceptance pending (2026-10-25):** listing iteration
alone does not prove that a register remains stable. Ghidra returns the
instructions that exist in the listing and skips undefined bytes. A function
can retain those bytes in its declared body, and the decompiler can still
successfully decode the executable bytes without repairing the listing.

## Reproduction and correction

The AArch64 supervisor-call fixture preserves the logical parameter `value=-19`
in another register before a Linux `getpid` call changes the incoming register.
With the syscall decoded, the existing opaque-effect guard correctly omits its
location. Clearing only that instruction's listing entry hid the effect from
the stable-register scan. The previous exporter then emitted a whole-function
incoming-register location: GDB displayed a positive process ID as `value`
after the syscall, although the compiler reference and stored result remained
`-19`. This reproduces on non-PIE, PIE and explicitly rebased PIE inputs.
The ELF and function-body bytes are unchanged. Decompilation succeeds.

`stableRegister` now tracks uncovered addresses in the declared function body.
A stable scalar or composite register location requires complete instruction
coverage, instructions contained in the body, and intact decoded lengths.
Undefined bytes, partial instructions, missing instructions, empty listings and
length overrides produce `UNKNOWN_LIFETIME`, with an incomplete-coverage
diagnostic. The address-set check preserves discontiguous function bodies;
bytes between their ranges are not automatically part of the function.

Existing modeled-write and call diagnostics retain precedence. The existing
prefix proof remains responsible for a `REGISTER_MODIFIED` rejection; it
already rejects gaps. An incomplete-coverage rejection does not fabricate a
prefix. Names and types remain available without a location. No ABI register
mapping, native binding, stack-location policy or decompiler recovery changes.

## Validation

`RegisterBodyCoverageSmoke` passes 421 checks over real x86-64, AArch64,
ARM32, MIPS32 big-endian and MIPS32 little-endian language models. It exercises
scalar/composite parameters and locals, intact/discontiguous positives, deleted
head/middle/tail/entire listings, byte preservation, partial-body instructions,
controlled length metadata negatives and cancellation on an empty listing.
These are model tests, not additional runtime architecture support claims.

The enhanced existing opaque-effect integration harness accepts
`FORGE_OPAQUE_LISTING=complete|gap` (default `complete`). The gap profile clears
the syscall listing entry after analysis, preserves its function body and bytes,
and verifies after export that the gap remains. CI runs both profiles on
AArch64 with all three executable/rebase roles and runs the new model suite on
Linux and native Windows.

Local runtime evidence in worktree `register-body-coverage`:

- Baseline: `build/test-results/opaque-register-effects-listing-gap/run.gx8oBAA9`.
  Three wrong-value reproductions, two deterministic exports per role.
- Fixed gaps: `build/test-results/opaque-register-effects-listing-gap/run.3Y8kRYi8`.
  Three correct unavailable-location cases, two exports per role.
- Intact opaque-effect regression: `build/test-results/opaque-register-effects/run.pYfOB1rI`.
  Three cases, two exports per role; existing diagnostic and omission preserved.

All nine cases pass GNU/LLVM and the pinned strict validator, with zero
unexplained errors. The six inherited frame diagnostics are corroborated
against each original by the existing strict policy and remain in the logs.
Raw DIEs prove the correct addresses and typed parameters, with locations
present only in the intentionally reproduced baseline. Compiler/Forge GDB
values, source lookup, stepping, normal exits, original/module/harness hashes
and deterministic repeats were independently reviewed.

Local headless Java is 25.0.4.1. Nine separate suites pass on actual Java 21
against the assembled production JAR, including the new coverage suite and
existing register-copy, direct-leaf-call, composite-prefix, dynamic-parameter,
opaque-effect, qualified-function, external-inventory and type-graph suites.
JAR SHA-256:
`9912567f2e9b2adcab8c9cb82867703b8c83616955e33ce1d007b0ed30df517b`.
Combined raw-review receipt SHA-256:
`6381425cf9b9c295efbefb2618ad88b51359c702f8b859e3353f7e31f1b65b47`.
Additional prefix, alias, composite-order, truncated-space and stack-first-use
model suites pass. The broader hosted gate remains pending.

The first model run exposed an incomplete instruction proxy in the existing
register-copy test: its four-byte instruction supplied address bounds but no
length accessors. The proxy now supplies matching decoded/listing lengths;
production checks were retained. The original failure log and corrected run
remain under `build/coverage-review/`. An earlier one-role reproduction is
retained separately as `run.TDW4FXqb`. No failed run is counted as acceptance.

This is a conservative correctness fix. It does not infer missing instructions,
repair the analyst's listing, or implement general variable migration.

Additional runtime regression review passes twelve register-copy exports on
native x86-64 and QEMU AArch64 (exec/PIE/rebased PIE) and 24 floating-register
exports across x86-64, AArch64 and both MIPS byte orders (exec/PIE with
baseline/rebase/repeat). Existing supported locations remain present and GDB
checks pass. Default MIPS FPXX double limitations remain explicit. ARM32 runtime
was unavailable locally and requires its hosted lane. Regression receipt:
`ecb8fa0457fe201fb3337d7c18e2468be06cc0978003634e525c2037e8cc679f`.
The first ad hoc completion probe used the wrong final marker string; the
retained runtime log already ended with `floating-registers-export=PASS`.
The subsequent raw review uses the exact marker and inspects each artifact.

## Combined FP32 regression checkpoint

The unchanged coverage-fix JAR also passes 24 exports using PR55's exact FP32
harness: twelve whole-alias omissions and twelve explicit-piece positives,
covering both byte orders, exec/PIE, rebase and unchanged repeats. Receipt:
`5187f942d15815eb8755e579baa162613b0b6af98e6a685cffbde9fa3ade2478`.
The normal integration merge retains both component histories. Its own complete
current-base hosted gate and exact artifact review remain required; component
checks do not substitute for the combined gate.
