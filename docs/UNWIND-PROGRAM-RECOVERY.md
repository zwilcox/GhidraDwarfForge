# Collecting recovered frames across a program (#112)

**CONFIRMED locally:** `GhidraUnwindRecovery` collects the existing native
call-group proofs and instruction-range projections across a Ghidra program.
It is an internal prerequisite for production integration, not an exporter
option. ADR-0002's production synthesis gate remains active.

## Collection contract

Functions are visited in address order. A root that cannot be proved receives
an address-keyed refusal reason; later independent functions are still examined.
A failed caller does not poison a valid leaf. A successful closed group marks
its members verified, so later roots already covered by that group are skipped.
When an earlier leaf is reached again from a later caller, repeated frame,
instruction and original-byte evidence must match exactly and is deduplicated.
Conflicting evidence or overlapping frame ranges abort collection.

The result contains the optional combined plan, verified function entries,
instruction-level observations, original byte/file-offset hashes and per-root
refusals. Maps and sets are immutable and sorted. No successful profile means
no plan; verified functions fully covered by original CFI yield a present but
empty plan. Original precedence and instruction-gap omissions retain their
existing semantics. No new register, calling-convention or storage assumptions
are introduced.

Cancellation and I/O failures propagate rather than becoming ordinary refusal
messages. Whole-program limits are 65,536 visited functions, 1,000,000 unique
instruction observations and the encoder's 65,536-frame limit. Exceeding a limit
throws without returning a partial plan. Existing per-call-group limits remain.
The caller must hold a consistent Ghidra program view and protect original input
identity through final publication; this API is not a substitute for that guard.

## Validation

The native suite now includes mixed programs on both initial profiles: an
unknown-writing function, an independent leaf, its valid caller and a caller of
the refused function. Reversed function creation order still yields stable
address order. Only the two proved functions produce frames, the shared leaf is
not duplicated, and both refused roots retain the exact storage diagnostic.
Empty and entirely refused programs produce no inferred plan. Existing direct,
recursive, mutually recursive, gap, unreachable, patched-byte, convention and
original-frame precedence controls exercise collection too.

All 1,992 x86-64 and 3,973 AArch64 observed cancellation checkpoints in the mixed
collection are injected independently. No partial result escapes, and subsequent
recovery matches the successful baseline. Removing the owned fixture ELF causes
an I/O failure; restoring it permits an identical retry. Rebased plans agree and
original inputs remain unchanged. The extended native suite passes 10,491 checks.

The runtime harness now imports the fixture's startup function as well as its
recursive/checkpoint functions. It serializes the program collector's plan and
requires exact agreement with the independently invoked root proof. The startup
function is explicitly refused; it cannot prevent valid recursive frame output.
Twelve ordinary/shrink-wrapped exec/PIE/shared cases pass across twenty-four
GNU/LLVM/pinned-strict sidecars and sixty GDB sessions, including absent and
DWARF-disabled controls. Original/rebased plans, deterministic reruns, complete
proved instruction-byte coverage, runtime stack alignment and unchanged inputs
remain mandatory.

See `docs/evidence/unwind-program-recovery.json` for raw evidence and commands.

## Remaining work

The test-only byte importer and minimal compile unit still do not establish
production-exporter acceptance. The collector must be connected to the real
export operation with consistent-view/input-publication protection, diagnostics
and full export failure/cancellation tests. The unchanged global-writing compiler
fixture still requires a defensible storage policy; the strict alias refusal is
unchanged. Hosted acceptance of these additions is **PRESENT, UNVERIFIED**.
PR166 integration remains first, followed by full #112, #110 and #109.
