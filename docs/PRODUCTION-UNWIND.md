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
both hosts. Windows and GUI behavior remain unverified for this change.

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

Actual chooser journeys, Windows execution, saved-project wrapper journeys,
original-CFI coexistence through normal entry points and hosted gates remain
required before acceptance. These local checks do not complete #112.
See [the checkpoint receipt](evidence/production-unwind-entry.json).
