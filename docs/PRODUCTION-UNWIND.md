# Opt-in call-frame recovery through normal export (#112)

**PRESENT, UNVERIFIED as a complete supported feature.** The integration branch
adds normal headless and Script Manager entry points. The original executable
remains unchanged. Existing exports default to off. See the revised
[decision](ADR-0002-DEBUG-FRAME.md) and [evidence model](SYNTHETIC-CFI-EVIDENCE.md).

## Controls

- `--synthesize-unwind=off`: preserve original unwind data, without recovery.
- `--synthesize-unwind=strict`: recover supported ordinary integer frames using
  the existing strict instruction/ABI model. Unresolved stores invalidate saved
  memory; functions that cannot establish rules are reported as omitted.
- `--synthesize-unwind=conditioned --unwind-stack-separation=1000:1007,2000:2007`:
  explicitly assert that these inclusive hexadecimal original-ELF ranges never
  overlap live stack storage of analyzed call groups or their callers. Addresses
  are normalized through Ghidra rebasing. This is an external condition, not
  inferred separation.
- `--unwind-relocated-pointers=fixed`: additionally assert qualified relocated
  pointer slots remain invariant after ordinary loading and all stack-relative
  accesses stay disjoint from those slots. Only conditioned mode permits it.
  Default is off. RELRO/relative-relocation qualification alone is not proof.

The PowerShell parameters are `-SynthesizeUnwind`, `-UnwindStackSeparation` and
`-UnwindRelocatedPointers`. `ExportGhidraDwarfForgeWithUnwind.java` offers Off,
Strict and Explicit memory conditions. Its first choice is Off; conditional
choices request the ranges and a separate pointer choice. Cancelling a chooser
must publish nothing. Normal non-interactive script options are identical on
both hosts. Linux GUI behavior is validated below; native Windows execution
remains pending.

## Artifacts and interaction with existing features

A requested recovery produces `<sidecar>.unwind.json` alongside the existing
sidecar and synthetic source. It identifies original input bytes, generated
artifact/source hashes, captured instructions, rules, omissions and explicit
conditions. Independent validation remains `NOT_RUN` until external validators
run. An all-refused input still gets an ordinary symbol/source export and a
report with no generated plan. This does not claim usable synthetic unwinding.

The optional `.gdb.py` loader and unwind report share one recoverable generation
with sidecar/source. Every destination participates in alias and concurrent-change
checks. A failed write, cancellation or installation restores prior files. Both
wrappers protect the report path from log truncation, including filesystem aliases.
The normal exporter retains annotations, constants, context, types and coverage;
the frame API now accepts those same synthetic constants instead of discarding
that knowledge. Existing attachment preparation does not yet support the extra
artifact transaction and explicitly rejects synthesis.

Ordinary recovery positively selects the audited x86-64 SysV and AArch64 AAPCS64
integer profiles; other profiles are omitted. This does not expand support to
signal, exception, interrupt, pre-loader, authenticated-return or arbitrary
indirect-call frames. Original unwind coverage and instructions affected by
loader writes remain subject to the existing qualification/refusal policy.

## Validation status

**CONFIRMED locally:** option parsing/normalization and three/four-file publication
suites pass, including failure after each installation, preservation of prior
files, fourth-file input aliases and protected-native aliases. Linux wrapper
forwarding and log collision controls pass. A normal AArch64 shared-library export
with fixed-pointer conditions, evidence and GDB loader completes. That initial
export alone is not structural or runtime acceptance.

**CONFIRMED locally:** the normal-wrapper matrix passes on x86-64 and AArch64
executable/PIE/shared compiler fixtures. It checks off/strict/conditioned/compressed
exports, bound reports, deterministic reruns and invalid-option preservation:
30 successful exports, six invalid-option controls, 24 validated sidecars and
30 GDB sessions. GNU/LLVM/pinned strict checks pass; compiler and generated rules
agree at every executed ordinary instruction boundary and through recursive
returns. The explicit strict policy refuses the global-writing compiler groups;
conditional mode retains the stated assumptions.

Two further shared-library cases pass six exports, sixteen real cancellation/
failure controls and eight GDB sessions. Cancellation/failure is injected within
recovery, frame serialization, evidence serialization and loader creation. The
previous four-file generation and curated program remain unchanged, no stages
leak, and retry is deterministic. Rebased exports preserve original-image frame
bytes. Analyst comments remain in their evidence-backed source catalog; typed
constant lookup variants evaluate to three in GDB alongside generated CFI.

An initial test incorrectly requested an unqualified constant name despite the
catalog's `NO_UNAMBIGUOUS_TYPED_VALUE` result and expected an unplaced plate comment
in the function's first ten source lines. The corrected oracle uses every
advertised typed lookup and the actual catalog source line. This respects the
existing annotation policy; product behavior was not changed to invent a type or
source placement. The failed test is retained separately.

**CONFIRMED locally — production journeys:** the installed Script Manager passes
seven actual chooser journeys on each of x86-64 non-PIE and AArch64 shared-library
inputs: four exports and cancellation at each of the three choices. Initial Off
and No choices, output fallback, native package selection, unchanged program/input
and bound evidence are asserted. All eight sidecars pass GNU, LLVM and pinned
strict validation. Generated rules match independent compiler references in GDB
at ordinary instruction boundaries and through recursive returns. These checks
exercise a private Xvfb/Openbox display, without using the user's desktop.

The real `.gdb.py` companion passes all six target/image-role combinations and
18 GDB sessions. The generated symbols are initially absent. The test exercises
automatic load-bias detection (or an explicit refusal when mappings are absent),
unload, rejection of an incorrect explicit bias, then successful loading with
the measured bias. Boundary and return traces match the compiler reference.

Eight rebased saved-project cases pass 32 normal-wrapper exports, 16 validated
sidecars and 24 GDB sessions. Both targets cover plain original `.debug_frame`
in non-PIE, GABI-compressed original frames with shrink-wrapped PIE, GNU-compressed
original frames in shared libraries, and runtime `.eh_frame` with shrink-wrapped
shared libraries. Repeated generations are byte-identical; the saved project
files and observed analyst comments/image base remain unchanged. Combined frame
bytes match the prior independently validated native exports; inherited sections
retain their metadata and bytes. This samples all named dimensions, not every
combination of them. The first test attempt incorrectly expected evidence JSON
in historical fixtures that predated it. That failed attempt is retained; the
corrected test decodes their retained raw frame records and reads the original
image base from the saved program's loader metadata.

CI now invokes these Linux journeys and adds a native Windows chooser run whose
artifacts feed Linux strict validation and GDB. The Windows additions are
**PRESENT, UNVERIFIED** until their hosted execution passes. Complete native
Windows and hosted/ADR acceptance remain required.
These local checks do not complete #112.
See [the checkpoint receipt](evidence/production-unwind-entry.json).
The additional journeys are recorded in
[their receipt](evidence/production-unwind-journeys.json).

**CONFIRMED locally — PowerShell forwarding:** a portable PowerShell runtime
invokes the installed wrapper against real Linux headless Ghidra through an
explicit Linux launcher adapter in an isolated installation. Five exports cover
off, strict, conditioned and compressed modes, including a deterministic repeat
of the four-file sidecar/source/evidence/loader generation. Invalid ranges fail
with code 10 and preserve that generation. Packaged natives are selected and the
input remains unchanged. Independent Linux GNU/LLVM/pinned strict checks pass on
all four sidecars; six GDB sessions compare boundary and return traces with the
compiler reference. This validates PowerShell parsing/forwarding and real export,
not Windows process launching or native DLL behavior.

CI runs the same producer through native Windows PowerShell and its actual
`analyzeHeadless.bat`. The Linux consumer requires a Windows producer receipt,
verifies transported hashes and exercises unchanged generated CFI. It loads
symbols directly after transport: generated companions contain producer-host
paths, so this check does not claim companion relocation between hosts. Existing
Linux companion tests remain separate. See
[the PowerShell checkpoint](evidence/powershell-unwind-journeys.json).
