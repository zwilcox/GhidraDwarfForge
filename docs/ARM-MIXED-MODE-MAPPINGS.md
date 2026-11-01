# Recovered ARM section mappings

**CONFIRMED locally; full acceptance and integration pending.** The production
exporter now preserves ARM/Thumb/data transitions in completely evidenced
allocations containing selected mixed-mode functions. This addresses the
reproduction in [the reference record](research/ARM-MIXED-BODY-MODES.md); it does
not complete #70 or any of the unchanged #68–#71 requirements.

## Contract

`GhidraArm32SectionModes` selects allocations touched by a selected function
whose existing listing has both ARM and Thumb instructions. It never decodes or
repairs the program. For each complete allocation, it requires initialized
memory, exact code-unit coverage, consistent current and original decode context,
ordinary instruction lengths/alignment and matching parsed/current instruction
bytes. Data must be explicitly defined in the listing. Default undefined bytes,
holes, partial units and uninitialized tails cause omission with a diagnostic;
they are never silently classified as data.

Evidence binds normalized allocation identity/extent and a SHA-256 of every
byte to the mapping boundaries. The isolated ELF planner compares those bytes
with the original input, rejects overlaps with any other allocated section,
checks code alignment, reconciles inherited mapping intervals/function tags and
supplemental function tags, and bounds symbols, bytes and comparisons. An
inherited mapping is preserved when it agrees, rather than duplicated. Conflicts
or name collisions produce an explicit omission. Cancellation is polled during
selection, unit/byte inspection, hashing and symbol planning.

The writer has distinct sealed representations for local function symbols and
zero-sized local NOTYPE mapping boundaries. The existing nonzero function-size
contract remains intact. Mapping boundaries must lie inside their executable
allocation. ELF addresses remain untagged for mappings and DWARF; ARM function
tags keep their separate semantics. No native/JNA declaration or producer call
was added.

The four modes in the fixture are emitted by the actual installed exporter.
No test-side symbol mutation is used for production acceptance. The old research
mode remains explicit and requires the old static decoding failure; CI invokes
`--production` to require the real sidecar to pass instead.

## Local evidence

The installed v2 package has JAR SHA-256
`0e62944fdf8a5536181d961c382602332a545e9bf3e1dd153358445a8b209ac4` and ZIP SHA-256
`79d4faa977904d33e87c1dbb754aad98ed1918c6c6501f1c91eab656ae8b63ad`.
It retains Ghidra 12.0.3, Java 21 bytecode and pinned libdwarf 2.3.2.

| Layout | Production case | Native failure/cancellation case |
| --- | --- | --- |
| Non-PIE | `exec.6uggp5sp` | `controls.8dvy_bu2` |
| PIE | `pie.kew3u7f9` | `controls.3p8wcreq` |
| Rebased PIE | `pie-rebased.ebf8p4s3` | `controls.0k9we6dl` |

Cases are below `build/test-results/arm-mixed-reference` in the
`work/arm-mixed-modes` worktree; controls are nested inside their production case.
Each production case verifies the exact four raw mapping records, compiler-
relative static decoding and twelve actual instruction observations per symbol
file. These independently check PC, bytes, CPSR state and source-known register
values, ending with the expected result and exit status. PIE verifies a real
runtime bias; explicit Ghidra rebasing normalizes back to link addresses.
GNU readelf, LLVM and pinned strict libdwarf pass with zero errors. Repeated
read-only exports have identical sidecar/source bytes; original/package/harness
files and saved program data are preserved.

For each layout, two real native decompiler rejections retain the failed
function's name/address and section mode boundaries without fabricated formal
children, return type or declaration line. Runtime decoding and all twelve
instruction observations still pass with its symbol-only DIE. The shared
failure helper's explicit `--symbol-only` reference is used because this
fixture writes its parameter register in its first instruction; existing ABI
fixtures still require their positive saved-parameter reference by default.
A separate padded input is imported and cancelled after production copying
starts. The previous artifact pair remains identical and no partial temporary
artifact remains. These are six failure exports and three cancellations.

The ELF/writer smoke passes 33 checks, including original-byte changes, duplicate
or mismatched evidence, inherited conflicts, nonexecutable allocation overlaps,
exact NOTYPE records, deterministic output, cancellation, callback propagation
and existing-output preservation. The real-Ghidra smoke passes 84 checks,
including explicit `undefined4` versus unknown bytes, instruction holes,
modified data, current/stored context disagreement, rebasing and cancellation
at every observed polling point. The first cancellation test used a point
beyond the fixture's actual polling count; its retained failure was corrected
by measuring the full path and exercising every reached point.

Existing mode-symbol, alias/mode-binding and Ghidra function-mode tests pass
231/476/59 checks. The v1 package passes the complete existing ARM PIE command
including sectionless and failure/cancellation children at `run.9hzKkoYq` and
`pie.azdxu6oj`; the only subsequent production change tightens overlap rejection
to include allocated non-code sections, with its new passing negative control.
The final v2 package passes the AArch64 vector exec/runtime/native-failure/
cancellation regression at `build/test-results/aarch64-vector/exec.htj4xv7z`.

The first PIE harness comparison forgot Ghidra's default `0x10000` import bias.
Its retained failure is a test-coordinate error, not an accepted runtime result.
The corrected oracle subtracts the observed import delta for listing comparisons
and independently checks raw emitted link addresses and runtime relocation.

```bash
./gradlew arm32SectionModesSmoke ghidraArm32SectionModesSmoke
for role in exec pie pie-rebased; do
    python3 src/test/integration/arm-mixed-mode-reference.py <installed-ghidra> \
        --production --role "$role" --with-controls
done
```

The assembled `--production --role pie --with-controls` command also passes
freshly at `pie.96bxfy2x`, exercising the same command used in CI.
Both model tasks and the three production/control roles are wired into CI.
Hosted exact-head acceptance and protected integration remain pending.

## Remaining acceptance

Shared-library and sectionless mixed-body runtime compositions still need
evidence. The generic synthetic-load allocation route is PRESENT, UNVERIFIED for
this new mapping feature. Discontiguous mixed bodies, additional inherited-map
and live-session cases, explicit source `list`/`next`/`step` behavior and broader
named/address/function-pointer workflows also remain to be tested. Machine
stepping in this checkpoint does not claim source-stepping completion.

Unknown gaps intentionally prevent complete section mapping. A successful
homogeneous-function mode hint elsewhere does not establish mixed-body coverage.
The remaining ARM per-function base/VFP ABI, BE8 and storage requirements, MIPS
FPXX/FP64A and wider lifetime work, i386 work, and full integration audit all
remain active in `TARGET-ABI-COMPLETION-PLAN.md`.

## Hosted boundary-audit correction

Run `41354512199` rejected the new isolated ARM extractor/planner because their
exact paths were absent from the architecture-boundary audit inventory. The
review confirms that TMode interpretation and ARM ELF mapping semantics remain
inside those two target modules; the generic writer only serializes explicit
ELF symbol types. The audit now names those exact paths. A separate temporary
generic-source probe containing TMode is still rejected; no broad path or
pattern exception was introduced. This test-inventory correction does not
change the validated production package. Exact-head hosted acceptance is still
required.
