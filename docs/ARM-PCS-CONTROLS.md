# ARM PCS declarations, metadata and failure controls

**CONFIRMED local matrix; hosted acceptance pending:** this component
extends the real packaged ARM PCS acceptance path. It changes tests and CI,
not production classification or native bindings. The complete #68–#71 scope
in `TARGET-ABI-COMPLETION-PLAN.md` remains active.

## Contract

Each executable contains the same source-known base and VFP scalar, wide and
exhausted-argument functions. The new cases also curate eight addressless
external signatures, preserving their names, return types, ordered formal
parameters and recorded conventions through save/reopen. Raw DWARF must retain
these prototypes and the corresponding call policy without inventing PCs,
source locations or variable storage. GDB must not resolve them as executable
symbols; this is its established behavior for unlocated declaration DIEs, not
a claim that declarations alone support injected calls.

The explicit, implicit dynamic-default, and custom/unknown-callback modes are
all exercised. In the guarded mode, the external `vfp_double` dynamic signature
can receive a normal convention while its unresolved callback remains nocall.
The external `vfp_float` custom unknown signature must remain restricted.

Three original-image metadata cases are distinct:

| Case | Expected policy and behavior |
| --- | --- |
| Original | Matching base/VFP functions and types permit validated calls; mismatched floating PCS and independent guards remain nocall. |
| Absent attributes | Remove only `.ARM.attributes` from the generated executable. GDB selects base PCS even when the ELF flags still declare VFP. Base floating calls remain usable; VFP floating calls are refused by Forge. |
| Conflicting flags | Change only the ELF32 flags word to contradict the unchanged build attributes. Every tested function, declaration and callback receives nocall plus an explicit contradiction diagnostic. Ordinary calls and source-known argument values remain correct. |

The harness checks that every allocated section retains its address and bytes
across fixture construction, then hashes the finished original before import.
Export preserves the resulting metadata exactly. Missing attributes are not
silently synthesized; contradictory attributes are not repaired. GNU, LLVM
and pinned strict libdwarf validate the emitted artifact. Repeated source and
sidecar bytes match; imported program observations remain unchanged.

The GDB oracle records `maintenance print architecture`'s selected floating
model: base soft-VFP is 3 and VFP is 4 in the validated consumers. The absent
attribute compiler reference initially expected its symbol file's VFP model,
but a double return was incorrectly displayed as 2.5 instead of 3.75. The
executable selects the model even after `symbol-file` supplies compiler DWARF.
The corrected reference checks the actual selected model, then requires exact
returns/calls for the matching base functions. The failed original reference
remains at `build/test-results/arm-pcs-profile/little.hard.rl47ou3v`.

## Failure isolation and cancellation

For guarded cases, a copied saved project undergoes two genuine native
decompilation failures at the compiler-identified `_start`. The existing test
hook sets the real decompiler's instruction limit to one. The failed function
must remain symbol-only, later functions must still decompile, and all tested
PCS/declaration attributes must match the accepted baseline. The repeated
outputs must be byte-identical and pass GNU/LLVM/strict validation. GDB repeats
all natural-value, supported-call and unchanged-state rejection checks on the
failure artifact.

Cancellation uses a separately imported, source-identical fixture with a
128 MiB trailing extent, preserving the original-image SHA-256 check. The real
export entry point is cancelled after bounded copying begins. The previously
published failure artifact and synthetic source must remain byte-identical;
no temporary publication files may survive. Both copied and cancellation
projects remain unchanged except documented Ghidra backup rotations. The
baseline project, original executable, tools and installed module remain
unchanged.

Retained pilot failures are harness errors: `failure-pilot-v1.log` used wide
readelf output with a parser expecting undecorated values; `failure-pilot-v2.log`
correctly hit production's input-hash rejection after padding an executable
without importing that padded image. Neither is counted as a passing control.
`failure-pilot-v3.log` passes the complete sequence with the identity check intact.

## Package and evidence

The unchanged production baseline is PR133 head
`d3a2106071c9352eb5bdbb1485e6954bcce29228`, using the installed v4 candidate in
the sibling `arm-pcs-profile` worktree. Its JAR SHA-256 is
`e414c524ef288e0b8a0d2448759b919f48764fb4763f706b180547a02f9bb27c`;
its assembled ZIP SHA-256 is
`8504e0870ddd57e962912bae024f4e724e4188b8a3795fd8ad75c5c721d8181f`.
Ghidra 12.0.3, Java 21 and libdwarf 2.3.2 are unchanged. LE uses GDB 15.1,
BE8 uses the pinned GDB 17.1 build, and both use the pinned corrected QEMU
D/Q-alias reference described in `ARM-PCS-CALL-PROFILE.md`.

Local evidence is retained in `build/arm-pcs-controls` in this worktree.
The twenty passing cases are explicit/implicit/guarded original metadata plus
guarded absent/conflicting metadata, for each byte order and executable PCS.
Twelve guarded cases also include two genuine failure exports and cancellation.
`matrix-v1.commands.json` and `matrix-v1.outcomes.json` record their exact
invocations and zero exit statuses. `acceptance-v1.json` lists all twenty
accepted result receipts. Across compiler, normal Forge and failure Forge runs,
these contain 416 natural argument observations, 216 typed returns, 428
successful injected calls and 284 unchanged-state rejections. The normal
artifacts explicitly verify 160 declaration DIEs. The failure cases add 24
native failure exports and twelve production-copy cancellations. Workflow lint,
Python parsing and whitespace checks pass. The production Java/native code is
unchanged; no unrelated full build/model rerun is claimed. Hosted execution
of the extended workflow remains **PRESENT, UNVERIFIED**.

Broader aggregate/HFA/mixed transfers, executable layout compositions and final
host/target acceptance remain required. This component closes no umbrella issue
and authorizes no release.

## Inherited fixture inventory repair

The PR132/PR133 corrections register the three reviewed PCS fixture sources
without relaxing the exact source inventory. This branch merges both corrections
through normal merge history. All five local reproducibility lanes pass again
(13 artifacts each), with commands/logs and zero exit statuses retained under
`build/arm-pcs-controls/inventory-correction`. Production, fixture contents,
workflow and runtime assertions are unchanged by this refresh. The initial
hosted run `41370489436` encountered the inherited setup failure; it is not
acceptance evidence. A new run at the refreshed head remains required.
