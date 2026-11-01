# Runtime call-memory boundaries

**CONFIRMED locally; full lifetime/scope goal remains open.** The existing
call-memory implementation now has executed partial-overlap, adjacent-write,
released-slot, unknown-SP and incompatible-return-SP controls on x86-64 and AArch64. This checkpoint
adds fixtures and acceptance coverage; it changes no production or native code.

## What the fixture proves

`call-memory-boundaries.c` passes a live caller value as the ninth argument to
five inspected helpers. A separate 32-bit tenth argument occupies the adjacent
slot. The caller's original `held` remains live in compiler DWARF. Ghidra records
the outgoing copy as `curated_held`, with the exact completed full-width store
as its definition. This is a saved copy of the caller value, not an assertion
that the callee parameter object and the caller local have the same identity.

The bootstrap obtains `&held` and `&adjacent` from actual compiler DWARF at
callee entry. It correlates these addresses with instruction-by-instruction
caller stores, register values and resulting memory. Ghidra independently
requires one eight-byte raw p-code STORE at that definition, with no call or SP
write. The debugger never changes target memory. Architecture-specific fixture
instruction matching and assembly remain outside generic exporter code.

The helpers exercise five distinct effects:

- A one-byte write inside the eight-byte copy ends its location after return.
  Negative inputs demonstrate changed bytes; the caller's original value and
  returned result remain correct.
- A one-byte write in the adjacent argument preserves the copy through return
  until the caller releases its frame.
- A temporary SP adjustment releases the copy's storage, then restores SP
  without writing memory or calling another function. Actual debugger SP
  observations prove that the slot lies in the released interval. Unchanged
  bytes do not justify retaining this location after the call.
- Two XOR operations cancel at runtime, but fall outside the implemented affine
  SP proof. The resulting unknown SP retires the memory location despite its
  unchanged runtime value. This does not claim a general bitwise SP analysis.
- Two reachable return paths produce different SP adjustments. Positive inputs
  take the ordinary return; negative inputs execute x86 `ret $16` or an AArch64
  allocation before `ret`. The caller immediately restores its saved SP. Both
  paths execute, with actual return/restoration SP observations. Neither gets a
  post-call location. This is a deliberately incompatible default-ABI negative
  control, not support for a new calling convention or debugger-injected calls.

All five cases check caller and callee instructions, compiler/Forge values,
before-definition and after-loss gaps, source lookup, types and actual returns.
The saved program is exported read-only twice; originals, module, harness and
saved data remain unchanged, apart from the documented project backup files.
Both outputs are deterministic. Raw location lists, GNU views, LLVM verification
and the pinned strict libdwarf validator pass.

## Acceptance evidence

The earlier `7d38784` checkpoint covers both targets in non-PIE, PIE and rebased-PIE
roles. They include 72 compiler-derived slot calibrations, 2,808 caller and
1,044 callee instruction observations, 531 available Forge values and 144
checked returns. Four register/stack exec regressions validate the shared
harness on both targets. CI runs the new `--storage outgoing` mode in all six
roles; the source inventory and workflow lint pass locally.

Two baseline comparisons use the preceding register-call package
`d2695509eec0abd11dfdd5c5069e421965a815eddea8cdc23e79bfcb273321c4`.
Its original and compiler-reference binaries match the candidate byte for byte.
The new package gains nine available adjacent-case observations on x86-64 and
twelve on AArch64; no formerly available observation is lost. The three
negative cases remain gaps. `--expect-memory-gap` is a baseline reproduction
option, never the candidate CI expectation.

The unchanged tested production JAR is
`5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`.
All 85 current production sources match its source archive and all 318 classes
are Java 21 bytecode. The existing nine-suite actual-Java-21 receipt still
matches this exact JAR; every new headless runtime also checks actual Java 21
and the loaded class origin. No new producer binding is involved.

Evidence in the `local-call-lifetimes` worktree:
`build/call-memory-boundaries-research/{final-matrix,matrix,checkpoint}.json`
and `review.py`. The final matrix has six candidate and two baseline cases;
four earlier matrix rows supply unchanged register/stack harness regressions.
The earlier outgoing rows precede the final explicit asm condition-code
clobber annotation and are not used for final-source acceptance.
Checkpoint SHA-256:
`9fe418ac0e89577dcebdb1d55c05da5f6dfe420f25899fc5fa6dbc340722895e`.

Reproduce with actual Java 21 and the pinned `DWARFDUMP`:

```bash
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra x86_64 --storage outgoing --role exec
python3 src/test/integration/local-call-lifetimes-export.py /path/to/private-packaged-ghidra aarch64 --storage outgoing --role pie-rebased
```

Run all three address roles on both targets. The x86 fixture disables push-based
argument construction so a standalone completed STORE supplies the saved
definition. Both targets disable stack protection for this fixture and disable
IPA constant propagation to retain the intended ten-argument function contract.

The subsequent return-SP checkpoint reruns all five controls in six target/
address configurations, plus four register/stack harness regressions. There
are 90 calibrations, 3,690 caller and 1,290 callee observations, 648 available
Forge values, 180 returns and 72 observed return/restoration SP values. The
caller restores SP immediately after each call. The compiler-value oracle also
honors the earlier saved-register restoration where it precedes stack release.
Evidence: `build/call-return-boundaries/{matrix,checkpoint}.json` and `review.py`.
Checkpoint SHA-256:
`bdb94aee25404fce67a9b5d4ccba07dc870fa7e6b7c66c3529572ae5c943b753`.
Production code remains unchanged. `MUTABLE-CALL-MEMORY.md` records the additional
saved mutable-identity composition.

**PLANNED:** independently migrating pieces through call effects, lexical intersections,
genuine source failure and cancellation composition, and exact final target,
host and package acceptance with normal integration. PR102's combined scope
gate and the original completion audit remain required. Neither #67 nor #73
is complete.
