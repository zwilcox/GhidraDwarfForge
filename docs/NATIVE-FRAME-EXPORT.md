# Recovered frames through the native exporter (#112)

**CONFIRMED locally; hosted acceptance unverified:** an explicit internal exporter
API now accepts a proved `CallFramePlan`. Standard script/GUI exports do not
enable synthesis. This checkpoint joins real ELF import, decompilation, type
extraction, native DIE production and qualified frame packaging; it does not
close #112 or supersede ADR-0002's production enablement criteria.

## Contract

`MinimalDwarfSidecarExporter.exportWithFrames` requires a non-null plan and
checks its address width and byte order against the original ELF before native
production. It uses the existing pinned producer mappings without adding any
JNA calls. Packaging goes through `MatchedElfSidecarWriter.writeWithFrames`,
which retains original-CFI precedence, overlap checks, identity checks and
bounded serialization. The export result reports the generated frame section.
Ordinary exports retain the same internal path with no supplied frame plan.

The caller remains responsible for binding the plan to original bytes and the
Ghidra program. `ExportRecoveredFrames.java` is an integration-test entry point,
not an installed user command. It captures the export consistency guard before
recovery, runs the real program-wide collector, extracts functions, decompiler
source, types, aliases and target policies, and stages the native artifact and
source through `ArtifactPairPublisher`. It checks consistency after extraction
and immediately before publication. The existing optimistic guard is not a
snapshot or lock. Refused roots retain diagnostics; an unsupported startup
function cannot suppress the independently proved recursive call group.

## Acceptance exercised by the harness

`unwind-export.py` consumes the source-built independent assembler fixtures from
`unwind-frame-recovery.py`. Unlike that earlier byte importer, the new test uses
Ghidra's actual ELF loader and auto-analysis with no function/body hints. Both
ordinary and split/shrink-wrapped families cover x86-64 and AArch64 executable,
PIE and dynamically loaded shared-library roles. Additional executable cases
inject a decompilation failure for `cf_checkpoint`.

Each case requires nine successful native exports and two injected failures:
plain/compressed repeated exports, a database rebase, repeated exports at the
new base, cancellation and an exception during frame serialization, then a
successful retry. Both failure paths must preserve the previous artifact/source
pair and leave no staging files. The original binary remains byte-identical.

All four retained sidecars per case (plain/compressed before/after rebase) pass
GNU, LLVM and the pinned strict checker. Independently decoded frame rows must
match the earlier recovered plan in every case. Runtime traces must match the
independent assembler reference, including recursive depth, caller-register
witnesses and instruction stops. Absent-CFI and disabled-DWARF controls prove
that GDB actually selected the generated DWARF unwinder at fixture addresses.
Shared cases must demonstrate nonzero load bias. Separate source sessions
exercise function lookup, `list`, `ptype`, `next` and `step`, with source-path,
line-range, changed-PC and normal-exit assertions. This does not establish
variable locations that the decompiler cannot justify.

The final fourteen-case matrix passes: 126 successful exports, 28 injected
cancellation/failure controls, 56 validator-clean retained sidecars and 126 GDB
sessions (98 unwind comparisons/controls and 28 source sessions). Both failed
decompilation cases independently retain only name/address attributes on the
failed function DIE, retain its diagnostic source comment, and keep the proved
frames usable. The ordinary exporter consistency regression also passes on
both targets: twelve successful exports, eight failure controls, four sidecars
and six GDB sessions. Extension build, source/package agreement, workflow lint,
syntax, architecture neutrality and diff checks pass. See
`docs/evidence/native-frame-export.json` for commands, hashes and the raw archive.

Rebasing can alter decompiler literals, such as the terminal AArch64
`UndefinedInstructionException` address. The original-image frame rules must
remain identical, but the synthetic source need not be byte-identical across a
changed program. Repeated exports of each unchanged program must match exactly.
The initial harness incorrectly required the entire rebased pair to match and
is retained as a failed test. A separate initial harness assumed that all imports
started with zero rebase delta; real PIE imports exposed that assumption.

The pre-rebase snapshots still reference the final source pathname. Subsequent
exports can therefore produce GDB's exact `Source file is more recent than
executable` warning for those snapshots. It is retained and permitted only for
those two modes. The previously established AArch64 QEMU system-DSO string-table
warning must match the independent reference; other warnings fail. Ghidra may
also report terminal instruction/decompiler or empty GNU-hash markup warnings;
raw logs retain them, and independently checked code/frame identity remains
mandatory.

## Reproduction

Build/install the extension into Ghidra 12.0.3 using Java 21, then build the
reference results as documented in `UNWIND-FRAME-RECOVERY.md` and
`UNWIND-SHRINKWRAP.md`. For each target and fixture family:

```bash
python3 src/test/integration/unwind-export.py "$GHIDRA_INSTALL_DIR" \
    build/test-results/unwind-frame-recovery/x86_64 \
    build/test-results/native-unwind-frame-recovery/x86_64 \
    --target x86_64 --dwarfdump "$DWARFDUMP"
```

The packaged native libraries are used by default. Local isolated installs can
provide both `--libdwarf` and `--libdwarfp`. Use `--roles exec
--failed-source-name cf_checkpoint` for the failed-decompilation case. Output
directories must be new. CI includes both families and that control in each
initial target lane; hosted execution remains **PRESENT, UNVERIFIED**.

## Remaining work

Enablement in the installed script/GUI, user-facing policy and provenance,
unchanged global-writing compiler-C acceptance, broader original-metadata
combinations and hosted acceptance remain open. Original/generated `.debug_frame`
coexistence is now locally validated under the explicit input contract in
`NATIVE-FRAME-COEXISTENCE.md`. The existing
strict storage-alias refusal remains in force. PR166 integration has priority;
this work does not complete the remaining #112, #110 or #109 goal items.
