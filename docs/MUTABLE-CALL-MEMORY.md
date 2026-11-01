# Mutable saved identities through inspected calls

**CONFIRMED locally; full lifetime/scope goal remains open.** The call-memory
implementation now has executed saved mutable-identity coverage: register
updates, stack saves, real callee clobbers, reloads and stale-slot controls.
This checkpoint changes fixtures and acceptance checks, not production or
native code. It supersedes the original mutable component's no-call limit.

## Identity and checks

The fixture's canonical saved stack local and recorded register assignments
retain their identity across an inspected call. The callee writes its own stack
object and overwrites the former working register with 909. A correctly saved
current value remains available in the caller's stack and migrates back to a
register on reload. The unsaved control retains stale bytes; neither those bytes
nor a later reload may be presented as the current logical value. Conflicting
owners remain unavailable. Both branch outcomes and repeated loop assignments
retain their ownership and must-state checks.

`--calls` enables this variant. The harness records compiler-described slot
coordinates and actual instruction bytes before Ghidra curation. The saved
helper has a complete bounded body, selected default convention and actual
signature. Each caller must have exactly one direct call to this helper; its
return successor must match the independently emitted return marker. Immutable
observations include the helper's complete raw instruction evidence.

The compiler copies a saved value into its argument register before the call.
The first checker attempt incorrectly assumed that the old working register
remained the chosen location until return. This failure remains in
`build/mutable-call-review/x86-exec.log`; it is not a passing case. The corrected
oracle derives the argument load and completed boundary from GDB disassembly,
requires its effective stack offset to match the compiler-described object,
and checks the exact raw DWARF register and interval. The stale-slot control
must not adopt this argument copy of the old value. GDB independently evaluates
every emitted location against the current logical value.

## Acceptance

Twelve configurations cover x86-64/AArch64, signed 32/64-bit values and
exec/PIE/rebased-PIE. Their compiler/Forge runs include 5,964 caller and 672
callee observations, 1,593 available Forge values and 168 checked returns.
There are 240 post-call observations where memory retains the new value while
its former register holds 909, 81 rejected stale-slot observations and 237
rejected conflicting-owner observations.

Four original no-call exec variants pass after the shared-harness changes.
Two 64-bit exec variants also export and execute the preceding
`d2695509eec0abd11dfdd5c5069e421965a815eddea8cdc23e79bfcb273321c4`
package on the same immutable saved programs and inputs. Each target gains
35 correctly available post-call values. Return sequences and callee
observations agree.

Every candidate exports twice with identical `.dbg` and `.dbg.c` bytes. GNU,
LLVM, pinned strict validation, ELF identity/build ID, raw locations, source
lookup, `next`, `step`, normal exit and original/module/harness/project
preservation pass. Each callee instruction's bytes agree with saved Ghidra
evidence. CI runs both widths and all address roles on both primary targets.
Workflow lint, source inventories and whitespace checks pass locally.

All runtime processes report actual Java 21. The unchanged production JAR is
`5eb68820f15051378ca9d3b57af48eeb08eb09ba1a318e66bca6213647295826`;
its 85 sources and 318 Java 21 classes match the current production tree. The
prior nine-suite actual-Java-21 receipt still matches that exact JAR.
Evidence: `build/mutable-call-review/{matrix,checkpoint}.json` and `review.py`.
Checkpoint SHA-256:
`6fab4c59b5cd291752cc3423c94ff16b7561e3c9b78578f7724ab5a49a51e199`.

Reproduce with actual Java 21 and the pinned `DWARFDUMP`:

```bash
python3 src/test/integration/mutable-stack-mappings-export.py /path/to/private-packaged-ghidra x86_64 --width 32 --role exec --calls
python3 src/test/integration/mutable-stack-mappings-export.py /path/to/private-packaged-ghidra aarch64 --width 64 --role pie-rebased --calls
```

**PLANNED:** independent pieces across call effects, lexical intersections,
genuine decompiler failure/cancellation composition, final target/host/package
acceptance, normal integration and the full original completion audit.
P1.11a/#67 and P3.3/#73 remain open.
