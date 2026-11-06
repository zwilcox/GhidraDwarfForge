# ADR-0002: Opt-in evidence-backed `.debug_frame` recovery

- Status: Revised design; production integration under validation, not release acceptance
- Date: 2026-09-03
- Revision: 2026-11-06

## Revised decision and acceptance boundary

Permit explicit `--synthesize-unwind=strict` recovery for the audited ordinary
integer profiles, with synthesis off by default. No original executable or
runtime exception table is rewritten. The existing qualified coverage and
composition path preserves original frames and refuses overlaps or uncertain
coverage. Instructions, bytes, caller identities, fixed-point joins and target
profiles supply the rules; stack depth or decompiler output alone does not.

`--synthesize-unwind=conditioned` additionally requires user-supplied original-ELF
ranges through `--unwind-stack-separation`. This mode asserts those ranges never
overlap live stack storage of analyzed call groups or their callers. Optional
`--unwind-relocated-pointers=fixed` asserts qualified loader-established pointer
slots retain their values after relocation, and all stack-relative accesses are
disjoint from those slots. Neither condition is inferred from the executable,
RELRO declaration or a passing fixture. The complete normalized conditions remain
labeled `EXTERNAL_CONDITION_NOT_PROVED` in the bound evidence artifact. Strict
analysis cannot consume such conditions or their summaries.

Every requested synthesis export stages `<sidecar>.unwind.json` with the sidecar
and source, including when all roots are refused. This records recovered rules,
omissions, original instruction hashes, target identity, input/output/source
hashes and independent validation status `NOT_RUN`. It is a description of
analysis, not a proof certificate. If requested, the GDB loader joins the same
recoverable generation. Serialization, consistency or publication failure must
restore the preceding generation; no successful artifact may silently outlive a
failed evidence write. Original metadata remains authoritative.

The normal wrapper and Script Manager entry points share this implementation.
The dedicated GUI chooser starts at Off and requests explicit range/pointer
conditions. Existing ordinary exports remain off. Attachment preparation retains
its existing transaction contract and rejects synthesis options; callers may
export a standalone generation. Unknown target/profile/function semantics produce
explicit omissions, not architecture guesses. A successful export with omissions
is not a claim of complete unwinding.

**PRESENT, UNVERIFIED as a supported feature:** the normal-entry-point integration
is being validated. The internal compiler matrix is accepted only in its exact
local scope, documented in [relocated-pointer recovery](RELOCATED-POINTER-UNWIND.md).
The new production path still needs its full wrapper/GUI, cancellation, preserved
annotation, existing-CFI, architecture and hosted gates. This design revision does
not complete #112 or authorize a release. Signal/interrupt/exception frames,
pre-loader execution, mutable pointer slots, arbitrary indirect/interposable calls
and the excluded target extensions remain unsupported.

## Historical decision (2026-09-03)

The following records the earlier production policy, superseded only by the
explicit revised design and its pending validation boundary above.


GhidraDwarfForge will not synthesize `.debug_frame` for the current ELF
milestone. Debuggers continue to use unwind information already present in the
original target, normally `.eh_frame` and `PT_GNU_EH_FRAME`. Absence of target
unwind information is reported as a target limitation rather than filled with
guessed call-frame instructions.

## Rationale

`.debug_frame` describes how the canonical frame address and saved caller
registers change over instruction ranges. A recovered Ghidra stack frame or a
function's entry stack depth is not sufficient evidence for those rules. It
does not, by itself, establish architecture-specific prologue/epilogue state,
shrink wrapping, exception transitions, signal frames, or every saved-register
location.

Incorrect call-frame information is worse than omission: it can corrupt stack
backtraces and cause otherwise defensible variable locations to be evaluated
against the wrong frame. The current variable-location implementation uses
explicit registers and instruction-range stack-pointer depths; it does not
require a synthetic CFA.

The source-built fixtures retain toolchain-generated unwind information in
their ordinary and stripped inputs. Program-header-only inputs also retain the
original loadable bytes and `PT_GNU_EH_FRAME` metadata even though their ELF
section table is absent. The sidecar-loading workflow keeps the original ELF
as GDB's executable, so its runtime/unwind metadata remains authoritative.

## Reconsideration criteria

Reopen this decision only for a concrete target class that lacks usable unwind
metadata and for which Ghidra or a separately validated analysis can produce
instruction-address-varying CFA and saved-register rules. Any implementation
must then pass nested-call, prologue, body, epilogue, and failure-path unwind
tests on every architecture it claims. No generic fallback may assume a frame
pointer, stack direction, return-address register, or calling convention.

## Issue #112 reconsideration (2026-11-05)

**PLANNED:** [the proposed recovery and validation model](SYNTHETIC-CFI-EVIDENCE.md)
now separates instruction-range evidence from frame serialization and requires
original unwind metadata precedence. Independent compiler reference harnesses
exist for x86-64 and AArch64, including no-CFI and disabled-unwinder controls.
They do not validate Forge-generated CFI. At that checkpoint the production prohibition remained active. The revised
design above now governs integration; #112 remains open until acceptance passes. The new requirement supersedes any historical interpretation that closing
#8 also completed synthetic unwinding.

**CONFIRMED locally; hosted pending:** [original compiler-CFI preservation](ORIGINAL-CFI-PRESERVATION.md)
now retains `.debug_frame`/`.zdebug_frame` in linked sidecars. This corrects the
retirement bug; it does not synthesize frame rules and does not change this ADR's
requirement to validate generation before claiming supported behavior. New frame payloads cannot silently replace
original unwind metadata.
