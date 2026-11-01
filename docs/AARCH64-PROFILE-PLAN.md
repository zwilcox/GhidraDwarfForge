# AArch64 ABI and storage completion plan

**CONFIRMED active component:** P2.3 / issue #68 within the user's expanded
P2.3–P2.3c goal; see `TARGET-ABI-COMPLETION-PLAN.md`. Starting main is
`c227cf34b2d386aa146c55b7c6edd68734ea0f98`. Ghidra 12.0.3 and Java 21-compatible
bytecode remain the baseline. No native/JNA ABI change is proposed.

The existing Linux A64, ELF64, little-endian, LP64/AAPCS64 profile is the
starting point. Big-endian, ILP32, SVE/SME and non-Linux profiles remain separate
as specified in `TARGET-PROFILES.md`; they require explicit negative diagnostic
coverage here, not accidental admission as the baseline.

## Original requirements and acceptance

| Requirement from #68 | Required evidence |
| --- | --- |
| Classify selected ELF/Ghidra ABI/compiler combinations | Inspect actual ELF metadata and pinned language/compiler specifications. Distinguish validated selection, definite contradiction and unvalidated combinations; preserve analyst knowledge and explain restrictions. Same processor/width alone is insufficient. |
| Exhausted argument registers, stack parameters and aggregate argument/return classes | Compiler-DWARF and real stripped-input exports for integer and FP register exhaustion; narrow/wide stack values and alignment; small direct and larger indirect composites; ordinary and hidden-buffer returns. |
| Homogeneous FP aggregates or vector-related storage | Separate positive and negative fixtures for HFA register allocation, exhaustion and return storage. Investigate short-vector representation independently; do not infer its support from scalar FP or HFA results. |
| Multiple PCs, clobber boundaries and shared lifetime integration | Compare exact typed compiler/Forge values before, during and after each supported storage transition. Require honest unavailable gaps; reuse the accepted generic lifetime machinery. |
| Isolated mappings and exact profile contract | Keep target rules outside generic extraction/emission; update the contract with tested positive/negative cases and runtime limits. |

Every row requires applicable GNU/LLVM/pinned-libdwarf structural checks and
GDB behavior, source-built fixtures, unchanged original inputs, immutable saved
program exports, deterministic repeats, genuine failure/cancellation controls,
the required target/host CI gate, normal protected integration and TODO/context/
issue reconciliation. A passing component does not close #68.

## Sequence

1. Audit current code and tests against the original requirements. Historical
   profile notes predate accepted lifetime/call work and are not current gaps.
2. Establish compiler-oracle fixtures and saved Ghidra storage observations for
   exhausted integer/FP registers, direct/indirect aggregates and HFAs.
3. Fix demonstrated classification or storage defects in independently tested
   components. Add failure and unsupported-profile controls with each change.
4. Expand non-PIE proofs to PIE/rebased PIE and relevant shared-library cases;
   validate argument and return semantics independently of display strings.
5. Reconcile the full requirement map against the exact production package and
   protected hosted gate before closing the umbrella.

**CONFIRMED local reproduction:** the accepted exporter omits forced-indirect
parameter storage. The source-built 24-byte argument is available in compiler
GDB and unavailable in the baseline Forge sidecar. The candidate follows the
ABI pointer with the existing shared value-flow proof; exact entry values and
the unavailable tail after pointer overwrite pass locally. Broader carrier
and profile acceptance remains pending.

ABI reference: Arm AAPCS64 release `2025Q4`, commit
`daa7a94ca55973736c0e434a67a6e4bbcd35d7fa`, particularly parameter passing and
result return. Use this fixed reference alongside the actual compiler and
Ghidra behavior; the upstream moving branch is not the experiment baseline.

## Local component evidence and remaining gates

**CONFIRMED:** the candidate follows Ghidra's effective ABI pointer while
retaining the 24-byte formal structure type. A register-held pointer becomes
`DW_OP_bregx`; a pointer held in proven stack memory becomes `DW_OP_bregx`
followed by operand-free `DW_OP_deref`. The existing generic value-flow analysis
continues to decide copies, clobbers, stack ownership, calls and unavailable
intervals. No target register is introduced into generic production code.

`aarch64-abi.py` builds and strips the fixture, saves analyst signatures using
Ghidra's dynamic parameter allocation, reopens the project read-only, exports
twice through the installed production extension and compares bytes. It runs
GNU, LLVM and pinned strict libdwarf validators and compiler/Forge QEMU-GDB
sessions. The driver checks original/module/project hashes and retains the
actual language, compiler specification, formal/effective storage and rebase
metadata. `aarch64-abi-locations.py` decodes emitted location bytes independently
for the runtime carrier oracle.

The nine source functions exercise integer and FP register exhaustion, direct
pairs, indirect structures, a stack-passed ABI pointer, positive pointer spills
and reloads, an unknown-store negative control, HFAs and exhausted HFA registers.
The positive spill case must retain exact fields when all integer carriers
except the frame register have actually been zeroed, then survive a reload.
The negative case must remain unavailable after a store with an unproven relationship to the pointer slot
and its subsequent reload. Every available emitted address must equal the actual
argument object's independently captured address. These requirements prevent
an entry-only pass from masquerading as a spill/lifetime proof.

The compiler-reference and GDB hidden-return limitations are documented in
`TARGET-ABI-COMPLETION-PLAN.md`. They are recorded consumer/reference defects,
not a claim of incorrect ABI values becoming acceptable. Non-PIE, PIE and
rebased-PIE are distinct runs. Existing shared-library coverage does not yet
prove this additional argument fixture in a shared object.

**PRESENT, UNVERIFIED in hosted CI:** both host model-task lists include
`indirectParameterStorageSmoke`; the AArch64 lane adds isolated native pointer
emission and the three full runtime forms. Workflow lint, the unchanged
architecture boundary guard and the oracle mutation tests pass locally.

**CONFIRMED local failure/cancellation composition:** all three address forms
pass two deterministic failure exports and one cancellation each. A real native
instruction-limit rejection of `curated_abi_large_spill` retains the breakpoint
symbol, removes its argument/type/source DIE attributes and every physical
location-list range belonging to that function, and preserves all eight other
functions' typed values. The test requires the saved indirect carrier to exist
in the extracted model before the failed-owner filter runs. Cancellation uses
the installed entry point after ELF copying begins, preserves an existing
validated artifact/source pair byte-for-byte, and leaves no staging residue.
The padded test executable is imported separately, preserving the production
imported-SHA256 check.

Commands use the baseline Ghidra 12.0.3 installation with the assembled candidate
extension and an actual Java 21 runtime:

```bash
python3 src/test/integration/aarch64-abi-oracle-test.py
for role in exec pie pie-rebased; do
    python3 src/test/integration/aarch64-abi.py "$GHIDRA_INSTALL_DIR" \
        --role "$role" --with-controls
done
```

Local receipts are `build/test-results/aarch64-abi/exec.onntauy9`,
`pie.sy3cp28k` and `pie-rebased.751m6nic`: 270 compiler plus 270 Forge
instruction observations and 151 independently decoded indirect-carrier
checks per positive run. Each controls subdirectory holds validators, preserved
hashes, failed-symbol behavior, 213 neighboring-function observations and
cancellation reports. The Java 21 build and new indirect, stack-spill,
direct-leaf-call, inspected-call and call-memory-effect suites also pass.

**CONFIRMED final local package/regressions:** the assembled package
`2f55c90c798657958b85a6c852945f69d5579361d3212de535d185743e94d8ec`
passes its whole-release manifest and the full non-PIE driver with controls
(`exec.mjx9mz0u`). Its production JAR is byte-identical to all three runs above
(`4dc33638dceaa6adfe9b27ee96b8f05b87d8ebad691a1ee73448dfa9897c4d04`).
Both x86-64 and AArch64 rebased-PIE `stack-value-transitions-export.py` and
`local-call-lifetimes-export.py --storage stack` regressions pass through that
installed package, including their raw location, runtime, structural and
preservation checks. Their result directories end in `1c2my35h`, `nuraxtx7`,
`pfd0vald` and `pfp_h5me`, respectively. This package receipt precedes the
final documentation-only update; hosted CI must build and validate the eventual
committed head independently.

**PLANNED before component acceptance:** hosted target/host gate and protected
integration. The umbrella additionally retains ABI selection,
short-vector/narrow/alignment cases and the complete original #68 requirement
map. Issues #69–#71 retain all their distinct architecture work.


**CONFIRMED hosted review correction:** PR121's first run reached an older
`FormalFunctionReturnSmoke` assertion requiring all forced-indirect arguments
to be omitted. Its safety intent is now checked explicitly: the unchanged
AArch64 nop/return fixture must keep the 24-byte formal type and emit the
object's `DW_OP_bregx` address throughout its body, never a `DW_OP_regx` pointer
value. All five target variants, immutable reopen and cancellation checks pass
(348 assertions), as do the 34 new indirect-carrier checks. Production code is
unchanged by this test correction; the full hosted gate must pass the new head.
