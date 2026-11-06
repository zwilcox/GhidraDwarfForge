# ADR-0002: Do not synthesize `.debug_frame`

- Status: Accepted
- Date: 2026-09-03

## Decision

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
They do not validate Forge-generated CFI. This ADR's production prohibition
remains active until the proposal's full acceptance criteria pass; #112 remains
open. The new requirement supersedes any historical interpretation that closing
#8 also completed synthetic unwinding.

**CONFIRMED locally; hosted pending:** [original compiler-CFI preservation](ORIGINAL-CFI-PRESERVATION.md)
now retains `.debug_frame`/`.zdebug_frame` in linked sidecars. This corrects the
retirement bug; it does not synthesize frame rules and does not change this ADR's
prohibition on unvalidated generation. New frame payloads cannot silently replace
original unwind metadata.
