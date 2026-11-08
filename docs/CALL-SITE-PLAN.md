# Call-site and tail-call metadata — issue #117

**CONFIRMED recovered-plan structural validation; full runtime acceptance incomplete:** this plan preserves all six acceptance items in
[issue #117](https://github.com/zwilcox/GhidraDwarfForge/issues/117). The normal
headless/UI script is now connected to call-site recovery and compiles, but its
packaged end-to-end invocation remains **PRESENT, UNVERIFIED**. The saved-program
producer probe establishes recovered plan emission with the debugger gaps below.
#120 follows completion
of #117. Storage controls remain mandatory throughout implementation.

## Verified starting point

**CONFIRMED:** #115 closed after PR189 merged as
`71352a398bc71e4c9bfbae8a53e98d7b16f18636` on 2026-11-08. Its GitHub tree
`bbe18cff2f5cbbfe9ace47608324f7a1c66fb5c4` equals the locally retained
`work/multifile-source` tree. Full run `42446082844` passed all sixteen jobs;
performance run `42446082851` passed all five. The source observations below
refer to that tree. The storage-policy edits were preserved in commit
`e1ccbc6`; the existing working branch now incorporates the merged baseline.
No additional checkout was created for this synchronization.

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
| 1. Classify calls, tails, thunks, internal jumps and unresolved indirect transfers | Capture instruction bytes, default/current flow, p-code, address-space identity, whole instruction coverage, caller body and exact callee entry. Keep unsupported classifications explicit. | Independently inspected fixture disassembly and saved-Ghidra controls for each category; reject conflicting direct references, incompatible overrides, patched bytes and body gaps. Retain CALL_RETURN as an annotation on a separately decoded jump, never as proof of tail semantics. |
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
   Run the isolated producer admission probe below before selecting the native
   compatibility fix; Java constants alone cannot enable these attributes.
3. Implement model/classification and completeness evidence. Keep `Address`
   identities through capture and reserve integer normalization for serialization.
4. Add producer constants and a call-site emission pass. Reuse audited APIs where
   possible; any binding change first runs outside Ghidra. Test forward callee
   references, recursive graphs and missing/unsupported targets explicitly.
5. Add actual-value proofs and the complete runtime/structural fixture matrix.
   Call-site metadata supplements existing unwind information and never replaces it.
6. Complete exact-head validation, review and protected integration before #120.

**CONFIRMED storage admission restored:** the user directed us to skip further
cleanup for this goal after the approved 21-directory cleanup. Six fixed legacy
archives are reported as a scoped exception; all new work retains the original
budgets. The guard admits work and all 16 storage controls pass. See STORAGE.md.
At that starting checkpoint, no artifact download or exporter/runtime matrix had started for #117.

## Producer compatibility audit — 2026-11-08

**CONFIRMED by source inspection, not runtime execution:** the pinned v2.3.2
producer does not admit the standard call-site attributes through the existing
Java-bound APIs. The retained official release archive matches the production
SHA-256 in `native/libdwarf/PROVENANCE.md`; these inspected files are byte-identical
to its members:

| File under `src/lib/libdwarfp` | SHA-256 |
| --- | --- |
| `dwarf_pro_forms.c` | `1e693b054ab78ff71cad3759a6c1065e33464cb2d2c34a2ee03c109e2749f985` |
| `dwarf_pro_expr.c` | `c40c8d8ae6f35898d69902fc44e8a2e27315d343b7c87345c76242c6e95eb485` |
| `libdwarfp.h` | `3fd4cc23c0f9363d1b8875f45c06363d196413475d75fd28e3be915a40d7f7ae` |

- `dwarf_add_AT_targ_address_c` rejects `DW_AT_call_pc` and
  `DW_AT_call_return_pc` through its attribute whitelist.
- The internal reference helper used by `dwarf_add_AT_reference_c` rejects
  `DW_AT_call_origin` and `DW_AT_call_parameter` through a separate whitelist.
- `dwarf_add_AT_location_expr_a` rejects `DW_AT_call_value`. The block API is
  not a ready substitute: its expression-form selection also omits call-value
  attributes, so it would select `DW_FORM_block` rather than `DW_FORM_exprloc`.
- `dwarf_add_expr_gen_a` has no `DW_OP_entry_value` case. The current Java
  expression model also has no nested-expression operation. Do not encode a
  block pointer as a generic numeric operand or silently omit entry-value work.
- The current downstream patch changes relocation width and string ownership;
  it does not change any of these producer attribute/operation checks.

**CONFIRMED stock API reproduction:** `src/test/native/call-site-producer-probe.c` isolates
five attribute admission cases, one per fresh process, plus a control using
existing supported address/reference/location attributes. It uses only public
APIs already declared in the production binding, checks return codes and error
pointers, attempts serialization/section retrieval after successful admission,
and finishes its producer. It compiles with `cc -std=c11 -Wall -Wextra -Werror`
and runs under the storage guard against the retained stock v2.3.2 libraries.
The control serializes successfully; `call-pc`, `return-pc`, `origin`, `parameter`
and `value` each return 1 with `DW_DLE_INPUT_ATTR_BAD (143)`. The
[evidence record](evidence/call-site-producer-stock.json) retains compiler,
commands, native hashes and each process result. It is not wired into CI yet.
Next run every mode against a candidate patched library and require admission
success, then independently validate actual forms, references and nested
expressions. API admission alone is not valid ELF or debugger acceptance.

**PLANNED integration details:** retain formal-parameter DIE identities alongside
`functionDies` and emit call sites after all definitions are allocated, before
adding the CU to the producer. Call/return PCs must be included in the relocation
expectation derived from accepted call-site evidence; the existing validator
currently accepts only function/scope/object addresses. Preserve its rejection
of unexpected relocations. Add call-origin/reference tests through
`Dwarf32InfoRepair`, whose section-offset repair shifts CU-relative references.

## Candidate native patch checkpoint — 2026-11-08

**CONFIRMED local Linux x86-64:** patch 0002 adds the missing address/reference
attribute whitelist entries and selects `DW_FORM_exprloc` for the five call
expression attributes in both public expression APIs. It applies with zero fuzz
after patch 0001 to the checksum-verified v2.3.2 archive and builds with the
production shared/producer/static configuration. No upstream checkout or
previously retained native library was modified.

`src/test/native/check-call-site-producer.py` compiles the standalone C probe
with warnings as errors. Fifteen cases pass API admission and section retrieval,
GNU readelf abbreviation-form checks, and LLVM verification of a tiny ELF
envelope. Five raw-block cases also require LLVM to decode nested entry-value
expressions. The [result and hashes](evidence/call-site-native-forms.json) identify
GCC 13.3.0, binutils 2.42, LLVM 18.1.3, both native libraries, probe source,
harness and both patches. The ABI probe passes, including the newly audited
public block API signature.

The first fixture revision failed LLVM verification because a synthetic caller
with a call-site child lacked a completeness attribute. The fixture now declares
its one artificial call explicitly; this is not a rule for asserting completeness
on recovered programs. GNU readelf does not decode the nested expression for
`DW_AT_call_data_location` here, so the independent nested-expression assertion
uses LLVM. Expected attribute forms are still checked with readelf in every case.

**PLANNED remaining:** integrate and pin the separate patch in production Linux
and Windows builds and corresponding-source packaging; add the standalone JNA
block-expression path; then implement evidence capture and exporter emission.
These native probes do not prove Ghidra call classification, reference repair,
call-point argument recovery, virtual tail frames, PIE/rebase behavior or Windows
support. All original six issue acceptance items remain in scope.

The reusable native install occupies approximately 7 MiB in the shared cache.
The temporary source/build tree was retired after verification; scratch returned
to approximately 23 MiB. Selected receipts and command results are retained,
without a duplicate native/source artifact archive.

## Native pipeline and package wiring — 2026-11-08

**PRESENT, hosted execution unverified:** all four native builds now verify and
apply patch 0002 after patch 0001. Linux runs the 15 form/serialization cases;
Windows compiles and executes all 15 API-admission modes. Both metadata records
identify each patch separately. Release assembly requires both pinned patches,
matches their hashes to both platform metadata files and includes both in the
corresponding-source payload and release manifest.

**CONFIRMED local controls:** workflow lint and the guarded release-package suite
pass. Ten added negative cases independently exercise missing, malformed,
duplicated and mismatched call-site patch records on both platform inputs, and
missing/changed corresponding-source patch files. Existing release ZIPs survive
rejection; positive checks cover deterministic ZIPs, manifests, CRLF/escaped
Windows metadata and executable launcher/supervisor modes. See the
[packaging receipt](evidence/call-site-packaging.json). These are synthetic native
package fixtures, not execution of Windows DLLs.

The assembler and test now honor the guard's temporary parent during cleanup.
The old timestamp assertion incorrectly matched zipinfo's archive-path header
when that path contained the repository name; it now inspects actual ZIP entry
timestamps. No timestamp requirement was relaxed. JNA, hosted integration and
all Ghidra/GDB acceptance work remain incomplete.

## Standalone JNA checkpoint — 2026-11-08

**CONFIRMED local:** the fixed-width block API is mapped in `LibDwarfProducer`
and exercised by `CallSiteProducerSmoke` outside Ghidra. On Linux, five target
profiles (x86-64, AArch64, ARM32, MIPS32 big/little endian) each pass eight native
error/cleanup lifetimes and eight successful lifetimes with byte-identical
sections. The input block is changed after the native call; independent LLVM
decoding still finds the original nested entry-value expression. GNU readelf
checks forms, address width and PCs; LLVM verifies the ELF envelope and actual
origin/formal-parameter reference targets. See the
[receipt](evidence/call-site-jna.json) for source/native hashes and runtime bounds.

The real `callSiteProducerSmoke` Gradle task and extension build pass locally.
The compiled binding is Java 21 bytecode, tested here on OpenJDK 25.0.4.1 with
Ghidra's JNA 5.14.0. The new CI steps run the isolated task and validators in all
five Linux target lanes and on Windows x86-64; **PRESENT, UNVERIFIED** until those
hosted jobs run. Production extraction/emission still does not use the new API.

The extension ZIP check exposed inclusion of the newly added local workspace.
`buildExtension` now excludes `.forge-work/**`; the affected local ZIP was replaced
and the rebuilt ZIP contains no workspace entries. The Gradle smoke's temporary
Java/JNA paths honor the storage launcher. Scratch is approximately 43 MiB and
shared cache approximately 197 MiB after the Gradle download/build. The deferred
legacy archives were not modified or removed.

Next: compiler reference fixtures and Ghidra control-flow/argument evidence,
followed by the exporter pass and debugger acceptance. These isolated ABI and
form checks do not establish runtime tail-call reconstruction or recovered
entry values; none of the original six acceptance items is closed by them alone.

## Compiler reference and debugger oracle — 2026-11-08

**CONFIRMED local compiler reference, not Forge behavior:** the source-built
`call-site-reference.c` family passes 64 GDB sessions across native x86-64 and
QEMU AArch64, each as ET_EXEC and PIE. `call-site-reference.py` builds the fixture
twice with identical bytes, preserves the original image, and compares full
compiler DWARF with a copy stripped of debug information but retaining ordinary
unwind data. GNU disassembly independently checks every selected direct call,
tail transfer, return-PC boundary and callee identity against the DWARF graph.
Readelf, LLVM and the repository's pinned standalone checker pass, with only
byte-identical inherited `.eh_frame` alignment diagnostics corroborated by the
existing strict checker. See the [receipt](evidence/call-site-compiler-reference.json).

GDB 15.1 reconstructs both virtual frames in the direct tail chain, including
entry arguments 20 and 21 and the leaf argument 23. The normal-call control has
only physical frames. Both outcomes of the ambiguous diamond and the unresolved
indirect tail omit intermediate frames and leave the leaf entry value unavailable.
Ordinary recursion retains three physical recursive frames plus the final virtual
recursive frame, while that leaf's entry value remains unavailable. Optimized
self-tail recursion has only one virtual function frame; the test does not invent
four historical invocations. A forwarding function supplies a further positive
tail-frame control, but its code alone is not evidence of a Ghidra thunk.
Removing debug information removes every virtual frame without removing the
ordinary physical callers. PIE tests require a nonzero observed runtime bias.

The exact environment is GCC 13.3.0, GDB 15.1, LLVM 18.1.3, GNU binutils 2.42 and
QEMU 8.2.2. AArch64 produces the known QEMU vDSO string-table warning in both
compiler and absent-debug controls; only that exact diagnostic is admitted,
recorded, and required to match between each paired run. An initial raw checker
run reproduced the already documented GNU location-view reference bug. The final
tests retain normal compiler debug output and use the production CI validation
bundle, including its existing location-view patch; no new suppression or
checker patch was added. This tool is cached once for subsequent work.

**PRESENT, hosted execution unverified:** the compiler harness is wired into the
x86-64 and AArch64 Linux CI lanes for both roles. **PLANNED remaining:** actual
Ghidra evidence capture/classification, recovered argument proofs, call-site DIE
emission, saved-program/rebase controls and compiler/Forge runtime comparison.
These reference oracles establish expectations for acceptance items 4 and 5;
they do not complete those items without the production exporter comparison.

## Immutable Ghidra capture — 2026-11-08

**CONFIRMED local:** `GhidraCallSiteEvidence` preserves address-space-aware
addresses, function/thunk identities, body ranges, raw p-code operands, decoder
context, original-byte matches and transfer classifications in immutable records.
It checks ELF/Program target agreement and uses the existing loader-write and
file-backed executable-byte guards. The current loader-effect admission remains
limited to its audited x86-64/AArch64 profiles; this adds no other architecture
claim. No architecture register numbers or stack convention are embedded in the
capture code. Full tail/argument semantics are deliberately not inferred from
these observations. `captureComplete()` means inventory completeness only and
must never become a DWARF all-call-sites flag on its own.

Ghidra adds CALL_RETURN overrides to most direct tail-shaped jumps in these
fixtures. The capturer retains that annotation while classifying the raw branch;
other incompatible overrides are rejected. It also preserves computed-target
references as hints, never as a callee origin. This matters because Ghidra labels
the volatile indirect fixture as a thunk to its initial pointer value. The
captured indirect transfer remains unresolved even in that case. A direct branch
to another function remains a candidate until return/stack-state proof succeeds.
An x86 get-PC instruction is an internal branch rather than a callee call;
conditional-move p-code branches to the next instruction remain ordinary
instructions, with their conditional effects retained for later value analysis.

The real Sleigh suite passes 457 checks across 48 cases, including both targets,
direct/indirect transfers, thunk annotations, conditional and discontiguous
branches, missing/interior callees, computed hints, incompatible overrides,
conflicting direct references, opaque instructions, changed bytes, incomplete
bodies, rebase, target mismatch, snapshot immutability and cancellation at every
observed poll of the two direct-call controls. The extension builds successfully
and its ZIP still excludes the managed workspace.

`call-site-evidence.py` imports each compiler reference through headless Ghidra,
then reopens its saved program using the current source runtime, without changing
the user's installed extension. Original and temporary rebased captures pass for
ET_EXEC/PIE on x86-64 and AArch64: all 104 selected transfer records agree with
the compiler's independently checked instruction PCs and callee identities.
Rebase preserves normalized addresses and original-byte hashes. Two captures
within each program view are identical, and the original ELF is unchanged.
The x86 driver has an auto-analysis body split at its epilogue, so both original
and rebased captures report an incomplete inventory; that omission is retained.
An exact Ghidra function entry alone still does not prove that an external jump
is a tail call—auto-analysis also creates an entry at the shared epilogue.

See the [capture receipt](evidence/call-site-ghidra-capture.json). CI runs the
Sleigh suite and saved-program comparisons, but **hosted execution is unverified**.
The current production exporter does not invoke this new evidence path yet.
**PLANNED next:** return/stack-state proofs for branch candidates, actual argument
value analysis, justified completeness, and the later DIE emission pass. All
six original issue acceptance items remain open until the real exporter and
debugger comparisons satisfy them.

## Direct-tail boundary-state checkpoint — 2026-11-08

**CONFIRMED locally:** `GhidraTailStateProof` uses the captured raw transfer
graph and original-byte checks to prove an entry-compatible stack pointer,
original return destination and restored callee-saved registers at each direct
external branch. Every external branch in a function must pass before any of
that function's tails are admitted. An unresolved computed jump is not cut out
of the graph to make the other paths pass. Ordinary calls erase state unless
a separate preservation proof is available; this checkpoint does not supply
one. Conditional moves/selects conservatively kill their possible outputs.
The existing unwind lowering and ABI selection behavior remain unchanged.

The initial saved x86-64 run found a real false positive: `cs_driver.cold`
inherits the driver's active stack frame, but Ghidra labels it as a separate
function. Its jump to the separately labeled epilogue initially passed when
seeded with an ordinary entry state. The corrected verifier checks known
external incoming control-flow edges. Non-call entries require admitted tail
boundary proofs from their predecessors; a failed predecessor invalidates
dependent proofs to a fixed point. External interior entries and fallthrough
entries are rejected. Ghidra's pointer-data `INDIRECTION` references and symbol
entry markers are metadata, not executed incoming edges. CALL_RETURN does not
turn a raw branch into an ordinary call. The cold block is now omitted with its
specific unproved incoming jump, and the incomplete driver remains omitted.

This proof is conditional on the selected ordinary function-entry contract;
it does not establish the absence of arbitrary undiscovered computed entries
or reconstruct dynamic caller history. Cycles of individually valid tail
boundaries may retain that same contract, without a termination claim. No
completeness flag follows merely from a successful inventory or boundary proof.

The real-decoder suite passes **570 checks across 47 cases**, covering balanced
and dirty stacks, lost return destinations, changed preserved registers,
unknown stores/calls, conflicting joins, one bad exit among two, argument and
preserved-register conditional selects, raw/annotated incoming jumps, dependent
rejection, an unselected predecessor, external interior entries, ordinary calls,
rebase, ABI mismatch, hidden PAC, repeatability and cancellation at each observed
poll of both direct controls. All four affected unwind regression suites pass.

The saved-project harness additionally proves all **nine** compiler-selected
direct tails for x86-64/AArch64 ET_EXEC and PIE, both original and rebased:
**72 tail proofs** and the previous **104 raw-transfer comparisons**. The
volatile indirect target remains unresolved. Normalized identities and original
instruction hashes are identical across rebasing; repeated in-memory proofs,
original executable hashes and saved `idata` database hashes are unchanged.
`--reuse-project` permits this comparison without repeating the headless import
or accumulating project copies. It creates a fresh bounded report directory.

See [tail-state evidence](evidence/call-site-tail-state.json) for commands,
source/report hashes and scoped results. CI includes the decoder suite and the
expanded saved-project comparison; **hosted execution remains unverified**.
The production exporter still does not invoke this path. **PLANNED next:**
actual argument expressions, defensible call completeness, producer emission
and the original compiler/Forge debugger acceptance requirements. This
checkpoint does not complete issue #117 or start #120.

### Consumer constraints checked before emission

**CONFIRMED by source inspection; emission policy still requires runtime tests:**
[LLVM 18.1.8's `verifyDebugInfoCallSite`](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/lib/DebugInfo/DWARF/DWARFVerifier.cpp#L256)
checks for a parent completeness attribute's existence, not its flag value.
That does not justify claiming completeness. DWARF 5 section 7.5.4 says a zero
flag represents an absent attribute; section 3.3.1.3 defines the distinct
completeness claims. A false flag might represent partial normal-call records
without a false claim, but passing LLVM alone would not establish consumer
behavior or standards acceptance. Test this explicitly before selecting it.

[GDB 15.1's `read_call_site_scope`](https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/gdb-15.1-release/gdb/dwarf2/read.c#L9467)
requires a return-PC attribute (or its legacy low-PC alias), including for tails.
It retains ordinary call-site lookup separately from the complete tail list;
only a true all-calls or all-tail-calls flag enables that list for intermediate
virtual frames. Therefore incomplete initial callers need separate tests from
intermediate tail callees. The compiler references already record GCC's
post-jump keys for tails. The raw capture correctly leaves a tail's actual
return PC absent: any later GDB-compatible post-jump serialization must remain
an explicit consumer convention, tested against GCC, rather than being
misrepresented as a preserved machine return address. Also retain
`DW_AT_call_pc` identifying the actual transfer instruction. These source
observations are not production export acceptance.

## Integer actual-value expressions — 2026-11-08

**CONFIRMED component behavior:** `CallValue` describes constants, function-entry
register values, slices, zero/sign extension, modular integer arithmetic and
conditional selects. Every intermediate retains its machine byte width. The
encoder uses nested entry-value blocks rather than referring to potentially
clobbered live registers, and masks narrower results. Select branches honor
target byte order. Expression limits are 256 nodes, depth 32 and 4,096 emitted
bytes. Nonconstant shifts remain unavailable. These generic encoding checks
do not imply Ghidra extraction support for every target format.

`GhidraCallArgumentFlow` interprets the captured raw p-code under the selected
x86-64/AArch64 ordinary integer profiles. It checks the instruction profile,
requires resolved control-flow boundaries, propagates to a fixed point, and
retains only common values at machine-level joins. Bounded acyclic conditional
p-code within an instruction can instead produce a select expression. Partial
register writes preserve known unaffected bits; subsequent slices simplify
irrelevant upper bits so a constant does not depend on an unavailable entry
register. Unknown loads and unproved ordinary calls forget values. Memory values
are not tracked; a spill/reload therefore remains unavailable even when the
separate tail-state analysis proves stack restoration. Instructions with known
non-flow memory references do not turn rebased address computations into integer
constants. Pointer provenance and production parameter-type/storage matching
remain separate unfinished obligations.

**CONFIRMED local validation:**

- The independent Python DWARF VM evaluates 7,980 generated boundary/random
  vectors against unbounded-arithmetic expectations for 32-/64-bit expression
  stacks and both byte orders. Ten invalid/budget cases are rejected.
- Twenty-five real-decoder cases pass 293 checks and 120 independent emitted
  expression evaluations. They cover wrapping, constants, subregister writes,
  call clobbering, definitions after calls, joins, loads, untracked spill/reload,
  known and unknown conditional selects, rebasing, determinism, original hashes
  and cancellation at every observed poll of both incoming-register controls.
- Eight saved/rebased program views pass 576 numerical expression comparisons
  at eleven selected transfer sites per view. Positive and zero/nonzero recursive
  conditions are covered. Overflow samples check machine arithmetic rather than
  claiming defined signed-overflow semantics for the original C source. Original
  ELF and saved database hashes remain unchanged; rebasing preserves expressions.
- The isolated JNA producer serializes an additional generated conditional
  expression in all five target formats. LLVM/readelf validate the actual bytes,
  the independent VM passes 105 checks extracted from native-produced sections,
  and the existing 8 success/8 error lifetimes, copied-buffer and deterministic
  section checks pass for each format. No native declaration changed.
- The extension builds and workflow lint passes. CI includes both new component
  suites, VM evaluations, native expressions and saved-project comparisons;
  **hosted execution is unverified**.

See [integer-expression evidence](evidence/call-site-argument-values.json) for
commands, source/report hashes and scoped counts. The saved fixture's incomplete
driver, split cold block and unresolved indirect tail remain explicit omissions;
their argument values are not invented. The observer's first two integer
registers are fixture expectations, not a production ABI/parameter mapping.
No call-site DIEs are emitted by the production exporter yet. Next complete
parameter identity/storage matching and caller coverage, choose tested completeness
and consumer-PC handling, and run the full compiler/Forge GDB comparison. All
original issue requirements remain required; this checkpoint does not close #117.

## Production serializer and consumer controls — 2026-11-08

**CONFIRMED locally, explicit provider only:** `CallSitePlan` carries sorted,
immutable function inventories with partial/all-tail/all-call completeness,
normalized transfer PCs and callee/formal identities. It rejects duplicate keys,
self-tail recursion records, missing owners/origins, out-of-body call PCs and
stale parameter names/types/ordinals before native production. The exporter
accepts this plan through an explicit constructor; existing callers receive an
empty plan. The ordinary Ghidra script is not connected to it yet.

The serializer emits call-site/parameter DIEs after function declarations exist,
checks its address relocations alongside existing function/object relocations,
and omits call-site children for a failed decompilation. Callee source failure
also suppresses argument children whose formal DIE was not emitted. Actual
argument expressions use the audited block API; no native declaration changed.

The new runtime control caught an interoperability failure that LLVM verification
did not detect: emitting both `DW_AT_location` and `DW_AT_call_parameter` made
GDB report that no matching parameter existed. The
[GDB 15.1 reader](https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/gdb-15.1-release/gdb/dwarf2/read.c#L9673)
rejects their simultaneous presence. Register arguments now emit only location
and call-value attributes; formal identity is checked in the model and against
the actually emitted declarations. Formal-reference-only transport is not claimed.

**CONFIRMED consumer behavior in these controls:** partial inventories emit a
false `DW_AT_call_all_calls` flag, preserving DWARF's absent-flag semantics while
satisfying LLVM's presence check. GDB resolves ordinary-call entry values from
them but does not fabricate intermediate tail frames. Complete inventories use
true all-calls or all-tail-calls flags and recover the two expected tail frames.
Tail `call_return_pc` is the compiler/GDB post-transfer lookup key, explicitly
not a saved return destination; `call_pc` identifies the transfer instruction.
This validates the chosen encoding, not a Ghidra completeness inference.

`call-site-serialization.py` exercises native x86-64 and QEMU AArch64 ET_EXEC/PIE
with compiler-derived call PCs, source-controlled expressions and parameter ABI
locations. Seven variants cover complete, partial, all-tail, failed-source,
empty, missing-value and cancelled exports. There are 56 debugger sessions.
Positive chain entry values are 23/21/20, and normal-call values are 11/10.
Unknown current values remain unavailable: the control supplies entry-only
locations plus explicit unavailable body ranges. Partial/failed/empty cases do
not invent tail history; missing actual values do not prevent justified frames.
PIE sessions require a nonzero runtime load bias.

Each artifact passes readelf and LLVM verification, plus the pinned strict
checker. The latter reports inherited `.eh_frame` alignment diagnostics; the
existing strict harness requires exact corroboration against the unchanged
original and matching frame bytes. No blanket warning suppression was added.
Repeated sidecars and companion sources are byte-identical; original ELF and
compiler-reference hashes are preserved. Cancellation is injected at every
observed poll, preserves a sentinel output, leaves no temporary files and permits
a subsequent successful producer lifecycle. Plan admission controls, extension
build and workflow lint pass. The new tests are wired into both hosted target
lanes; **hosted execution remains unverified**.

See [serialization evidence](evidence/call-site-serialization.json) for exact
hashes, commands and per-profile cancellation counts. The compiler-derived
provider is intentionally a test control, not a fallback for missing Ghidra
evidence. Next bind the recovered integer expressions to actual callee entry
storage, prove completeness/caller coverage, and connect the normal export path.
The full ambiguity/recursion/indirect/thunk, saved/rebased Ghidra, host and target
acceptance matrix remains required. No #117 acceptance item is closed here.

## Callee entry storage and integer binding — 2026-11-08

**CONFIRMED component behavior:** an optional `GhidraTypeGraph.extract` observer
now snapshots entry storage in the same loop that reserves each exported formal
type. It reuses the selected allocation policy's result, including corrected
storage and omitted automatic parameters. The snapshot uses the exported ordinal
after omissions and retains the exact canonical formal identity. Existing callers
do not request snapshots and retain their previous model behavior.

`GhidraCallParameters.bind` checks the callee identity, selected ordinary ABI,
canonical formal identity, scalar integer/enum type, direct single-register
storage, low-bit placement and physical/DWARF register agreement. Typedef and
qualified chains are followed with bounds. It reads the whole destination
register from the earlier actual-value proof; known low bits do not justify
inventing upper bits. Missing or decompiler-only storage, pointers, floating
types, indirect/composite/stack storage, stale formal identities and unavailable
whole-register values produce omissions. This is the initial integer component,
not a claim of support for those other argument representations.

**CONFIRMED local checks:**

- The existing 25 real-decoder cases now include actual Ghidra parameter
  allocation, extraction and binding. They pass 469 checks and 240 independent
  DWARF VM evaluations, including upper-bit preservation and zero extension.
  Additional controls cover typedefs/enums, unsupported types, narrow-only facts,
  stale identities, indirect/high-slice omissions, allocation correction reuse,
  hidden-return-parameter omission/reindexing and every observed binding
  cancellation poll. An observer/no-observer comparison verifies unchanged
  type/storage models on both selected targets.
- Eight saved/rebased x86-64/AArch64 ET_EXEC/PIE views pass 712 independent
  whole-register evaluations and retain the earlier 104 transfer comparisons,
  72 tail proofs and 576 low-word evaluations. Source-known integer signatures
  are applied only inside a rolled-back fixture transaction to model analyst
  curation. The input ELF and saved database hashes remain unchanged.
- AArch64's driver already had proven constant values in the preceding flow
  checkpoint. Its eight ordinary calls now have explicit parameter/constant
  checks, including two-argument recursion. The incomplete driver/split-cold-block
  omissions concern x86; the unresolved indirect tail remains omitted on both.
  Do not generalize the x86 coverage limitation to AArch64.
- The five-target recovered-parameter regression passes 610 checks. The extension
  build and workflow lint pass. CI reuses each existing reference project for the
  curated binding checks; no duplicate import or extra installation is needed.
  **Hosted execution remains unverified.**

See [binding evidence](evidence/call-site-parameter-binding.json). This step does
not emit these bound expressions through the normal Ghidra script. Next compose
the verified captures/tails/arguments and parameter entries into a serialization
plan with justified completeness, address x86 caller coverage and run the full
Forge debugger comparison. Before integration, audit ordinary-call entry
assumptions too: the current tail verifier checks incoming-edge dependencies for
functions containing admitted tails, not every function used by argument flow.
All six original acceptance items remain open until their full evidence is in.

## Ordinary-entry regression and original incoming instructions — 2026-11-08

**CONFIRMED reproduced and fixed on the work branch:** a split-frame function
with an ordinary outgoing call could acquire incoming-register facts despite a
known dirty incoming jump. The entry-dependency pass previously visited only
functions with admitted outgoing tails. The new `CallEntryContractSmoke` first
failed on the x86 dirty-jump case, showing the invalid entry facts in the
ordinary call's argument state. This path is not enabled in the normal exporter.

The pass now checks known incoming edges for every captured function that has
not already failed its boundary proof. Rejection still propagates through
dependent tail proofs. Original direct incoming calls must pass the same
instruction-byte, loader-write, decoded-flow, override and return-PC checks as
outgoing call capture. A patched Ghidra instruction cannot establish an original
ELF call. An incoming jump still needs an admitted tail-boundary proof; a
CALL_RETURN annotation or an unselected predecessor is not sufficient.

**CONFIRMED locally:** 16 decoder cases across both selected architectures pass
340 checks, including every observed cancellation poll of the ordinary incoming
call path. Positive cases retain ordinary calls and proven clean tails; negative
cases cover dirty/annotated/unselected jumps, interior entries, original-byte
disagreement and actual external fallthrough. Every input ELF remains unchanged.
The tail-state regression passes 611 checks and integer flow/binding still passes
469 checks with 240 VM vectors. Eight saved/rebased fixture views retain 104
capture comparisons, 72 selected tail proofs, 576 low-word evaluations and 712
whole-register binding evaluations, with original/database hashes preserved.
Raw capture checks, extension build and workflow lint also pass.

The saved fixture now records one additional entry/argument omission for
`cs_leaf`: Ghidra has a computed incoming reference from the unresolved
`cs_indirect` tail. That edge cannot establish an ordinary entry contract, so
the leaf's outgoing argument state is unavailable. Its checkpoint call has no
parameters; the selected direct-tail and integer-binding comparisons are
unchanged. The harness explicitly requires this extra omission rather than
claiming the entire old observation is identical.

This checks known incoming edges under the selected ordinary-entry ABI contract;
it does not prove the absence of undiscovered computed entries or reconstruct
actual execution history. The normal-script connection and justified call-site
completeness remain pending, as do x86 driver coverage and the full Forge/hosted
acceptance matrix. See [entry-contract evidence](evidence/call-site-entry-contract.json).

## Recovered plan composition and first runtime gaps — 2026-11-08

**CONFIRMED locally:** `GhidraCallSitePlan` composes immutable instruction captures,
tail-boundary proofs, integer actual-value analysis and captured formal entry
bindings into the production writer's plan. Profile selection precedes the
64-bit loader analysis; unsupported ABIs/loader extensions return explicit
omissions. Shared caller bodies are rejected before instruction-keyed value
states can overwrite one another. Direct calls can survive a partial caller
inventory, while unproved tails do not become call sites. An unexported target
gets no origin or invented parameter bindings.

`ALL_CALLS` requires complete original-instruction coverage, accepted known entry
dependencies, a closed decoded value-flow graph, audited instruction semantics
and representation of every admitted call/tail. Failure of any of those checks
leaves `PARTIAL` with reasons. Missing argument expressions do not invalidate an
otherwise complete call inventory. These claims describe the curated Ghidra
function body under the selected ABI, not proof that undiscovered execution
paths cannot exist. No computed reference is promoted to a direct origin.

Eight saved/rebased x86-64/AArch64 ET_EXEC/PIE views retain 104 capture
comparisons, 72 tail proofs, 576 low-word and 712 whole-register value checks.
The plan compares 96 direct call/tail records to independent compiler PCs,
return keys and origins. Actual decompiler source and recovered type models now
feed the production native writer; all eight resulting sidecars pass GNU,
LLVM and strict pinned libdwarf checks, with deterministic repeated sidecar and
source bytes and unchanged original/saved-program hashes. Inherited frame
alignment diagnostics remain accepted only with exact original corroboration.

The first AArch64 native artifact exposed a conditional-expression join past
the final operation. LLVM accepted it, but the strict consumer incremented its
error count in `check_skip_branch_offsets` (confirmed by a native GDB watchpoint).
`CallValue.Select` now ends with `DW_OP_nop`, giving every join an in-expression
operation target. The independent VM enforces that bound and accepts all 7,980
encoder vectors plus 240 decoded/binding vectors. The strict consumer passes
the corrected artifact; the validator was not weakened.

**CONFIRMED runtime observations, not full acceptance:** 64 native/QEMU debugger
sessions cover four target/layout profiles, original/rebased views and all eight
scenarios. Sixty frame-structure comparisons match compiler references. Four
fail: x86-64 recursion (scenario 4) lacks the expected `cs_recursive` virtual
frame in both layouts and both views. AArch64 frame comparisons all match.
The positive `value@entry` acceptance also fails: recovered formal parameters
have no entry location, so GDB cannot use them for entry-value lookup. These are
open implementation gaps, not permitted omissions used to close the issue.

The normal script collects the same entry snapshots and passes the recovered
plan to the production writer. It compiles against the selected Ghidra API.
**PRESENT, UNVERIFIED:** packaged headless/UI invocation, broader existing export
regressions and hosted execution. CI now emits and structurally checks recovered
plans in the existing saved-project step; no second import is added.

Next resolve the x86 recursion lookup and evidence-backed formal entry locations,
then x86 driver coverage, complete debugger comparisons and the full protected
acceptance matrix. No original acceptance item is closed by this checkpoint.
See [composition evidence](evidence/call-site-composition.json).
