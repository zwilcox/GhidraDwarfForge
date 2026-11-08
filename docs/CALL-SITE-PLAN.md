# Call-site and tail-call metadata — issue #117

**PLANNED, not implemented:** this plan preserves all six acceptance items in
[issue #117](https://github.com/zwilcox/GhidraDwarfForge/issues/117). No emitted
call-site records or debugger behavior are claimed yet. #120 follows completion
of #117. Storage controls remain mandatory throughout implementation.

## Verified starting point

**CONFIRMED:** #115 closed after PR189 merged as
`71352a398bc71e4c9bfbae8a53e98d7b16f18636` on 2026-11-08. Its GitHub tree
`bbe18cff2f5cbbfe9ace47608324f7a1c66fb5c4` equals the locally retained
`work/multifile-source` tree. Full run `42446082844` passed all sixteen jobs;
performance run `42446082851` passed all five. The source observations below
refer to that tree, not the older main checkout currently carrying the new
storage-policy edits. Preserve those edits before synchronizing the checkout.

`MinimalDwarfSidecarExporter` currently emits function/parameter DIEs but has no
call-site emission path. `DirectLeafCalls.directCall` already compares listing
and raw p-code evidence and excludes flow/length overrides and delay slots;
it deliberately accepts only ordinary direct returning calls. It cannot be
relabeled as a general tail-call classifier. `GhidraUnwindCalls` and `UnwindCalls`
verify bounded ordinary-call effects and return restoration; their contracts
also cannot silently become tail-call proofs. `GhidraInstructionEvidence`
retains listing starts, but listing enumeration alone is not a proof that a
function's entire executable body has been decoded.

## Semantic constraints

Use [DWARF 5 sections 3.3.1 and 3.4](https://dwarfstd.org/doc/DWARF5.pdf) for
the encoding contract. Call PCs identify transfers; return PCs follow the
target's actual return convention, including delay slots. Origins reference
callee identities. Parameter locations describe argument destinations; value
expressions must avoid call-clobbered dependencies. Completeness flags require
evidence covering the relevant calls. Self-tail recursion and optimized-away
calls are not ordinary call-site entries.

[GDB's tail-frame documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Tail-Call-Frames.html)
describes reconstruction of unambiguous virtual frames, not recovery of execution
history. Ambiguous chains and recursive entry values can remain unavailable.
The plan therefore requires positive and negative debugger observations.

## Acceptance and evidence map

| Issue requirement | Implementation obligation | Required proof |
| --- | --- | --- |
| 1. Classify calls, tails, thunks, internal jumps and unresolved indirect transfers | Capture instruction bytes, default/current flow, p-code, address-space identity, whole instruction coverage, caller body and exact callee entry. Keep unsupported classifications explicit. | Independently inspected fixture disassembly and saved-Ghidra controls for each category; reject conflicting references, overrides, patched bytes and body gaps. |
| 2. Correct attributes and justified parameter expressions | Add an immutable call-site model, a completeness result with reasons, and a later writer pass once callee/formal DIE identities exist. Separate destination storage from recoverable actual values. Normalize addresses once. | Raw DIE forms/targets/expressions and compiler controls; constants and proven incoming-value chains, plus clobbered/unknown omissions. No blanket all-call-sites flag. |
| 3. Preserve uncertainty | Record unresolved targets and ambiguous paths without manufacturing origins, entry values or virtual histories. | GDB must keep unsupported values unavailable and avoid asserting a unique intermediate frame in ambiguous/recursive fixtures. |
| 4. Compiler/Forge fixture comparison | One small source-built fixture family covering normal calls, a direct tail chain, conditional paths, recursion, thunks and an indirect tail. Disable incidental inlining where needed and verify what the compiler actually emitted. | Original compiler DWARF and stripped/curated Forge outputs from the same executable bytes; equivalent semantic probes rather than forced DIE-byte equality. |
| 5. Runtime debugger behavior | Start with selected native x86-64 and QEMU AArch64 profiles; include ET_EXEC, PIE and rebased analysis. Keep target-specific transfer/ABI rules isolated. | `bt`, `info frame`, argument and entry-value probes at meaningful callee stops, plus original source/name/stepping checks. Record exact GDB, compiler, QEMU and Ghidra versions. Other targets retain existing behavior and require separate evidence before a new claim. |
| 6. Validation and lifecycle | Keep the existing DWARF 5 packaging, publication, cancellation, deterministic source and original-preservation contracts. Audit any producer calls against the pinned headers before native execution. | Isolated producer controls, GNU/LLVM/pinned validators, saved-program and input hashes, repeat exports, cancellation/failure preservation and required hosted gates. Update support bounds and all six acceptance rows before closure. |

## Implementation order

1. Preserve the storage-policy changes and synchronize source with the verified
   merged baseline, using the existing checkout rather than another worktree.
2. After storage admission succeeds, build the tiny compiler reference first.
   Record positive and negative tail-frame behavior before relying on GDB output
   as a Forge oracle. Reuse toolchains and promptly retire temporary runs.
3. Implement model/classification and completeness evidence. Keep `Address`
   identities through capture and reserve integer normalization for serialization.
4. Add producer constants and a call-site emission pass. Reuse audited APIs where
   possible; any binding change first runs outside Ghidra. Test forward callee
   references, recursive graphs and missing/unsupported targets explicitly.
5. Add actual-value proofs and the complete runtime/structural fixture matrix.
   Call-site metadata supplements existing unwind information and never replaces it.
6. Complete exact-head validation, review and protected integration before #120.

**CONFIRMED current admission failure:** retained external evidence exceeds the
approved budget. The cleanup plan is prepared and awaits explicit deletion
approval. Read-only analysis and small planning files are proceeding; builds,
artifact downloads and runtime matrices have not been started or bypassed.
