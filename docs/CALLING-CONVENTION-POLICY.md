# Calling conventions and debugger-injected calls

**CONFIRMED locally; hosted acceptance pending (2026-10-25):** the candidate
preserves the selected Ghidra convention and marks a resolved nondefault
prototype as `DW_CC_nocall`. All three local runtime roles pass.
This is a conservative correctness policy, not a new alternate-ABI mapping.

## Confirmed defect and decision

The preceding exporter classified every nonempty, non-unknown convention as
`DW_CC_normal`. With an x86-64 GCC compiler specification, Ghidra's default
`__stdcall` model uses SysV argument registers; its explicitly selected `MSABI`
model uses different registers. The same name cannot be classified using a
universal x86 convention-name whitelist.

A local real-export probe confirmed that GDB 15.1 injected a call into an
explicit `MSABI` function using the ordinary SysV argument convention. For
four integer arguments `(1,2,3,4)`, a weighted result should be 1234. With
controlled otherwise-unused registers, the old export returns 4389. Ordinary
calls compiled into the program still work. GCC 13.3's original debug info
also lacks this distinction; Clang 16.0.6 emits LLVM's Win64 convention code,
but the tested GDB still injected the wrong call. A compiler reference alone
therefore does not certify debugger-injected callability.

Extraction compares the selected resolved `PrototypeModel` name with the
program compiler specification's resolved default. When both exist and differ,
the function signature or curated external declaration records that fact and
produces a diagnostic. Serialization emits standard `DW_CC_nocall` (`0x03`)
instead of `DW_CC_normal`. The constant was checked against `dwarf.h` in the
pinned libdwarf 2.3.2 source archive recorded in
`native/libdwarf/PROVENANCE.md`; no native/JNA entry point changes.

The original convention string, formal types, signature provenance and
independently defensible parameter locations remain intact. Ordinary entry
breakpoints, parameter values, source listing and execution remain usable.
GDB rejects the unsupported injected call before executing target code.
It also declines automatic return-value presentation after `finish`; the
regression requires exactly that warning and records it without altering the
original log. The fixture separately verifies the known integer return
register and the program's normal exit. This does not claim that GDB can infer
an arbitrary alternate return ABI.

Unknown conventions retain the previous omission policy. The raw `default`
alias resolves through the compiler specification. Default conventions and
custom storage are not newly certified by this change: mismatched compiler
specifications, arbitrary custom storage, return classification, aggregate/
vector ABI rules and function-pointer/subroutine-type distinctions remain
separate work. A future supported alternate convention needs an explicit
mapping and behavior tests before removing this conservative restriction.

## Acceptance harness

`CallingConventionPolicySmoke` uses real ProgramDB instances across x86-64,
AArch64, ARM32 and both MIPS32 byte orders. Its 202 checks cover all available
named prototypes, default/unknown aliases, curated external declarations,
provenance, deterministic repeated extraction and immutable saved reopening.
Twenty-two isolated packaged suites pass on actual Java 21; package source,
class-loading origins and Java 21 bytecode are checked separately.

`calling-convention-export.py` uses a source-built x86-64 executable containing
both conventions. Exec, PIE and rebased PIE must each:

- Import and curate the function conventions using actual Ghidra APIs.
- Reopen read-only and export twice with identical sidecar/source hashes.
- Preserve target metadata, link-time function addresses and original bytes.
- Pass GNU, LLVM and pinned strict libdwarf validation.
- Retain four signed integer parameters and the corresponding normal/nocall
  attributes; list synthetic source from an absolute sidecar path.
- Return 1234 from an injected SysV call. Reject the Microsoft call without
  incrementing its counter. With the optional preceding package, reproduce
  4389 and the unwanted counter increment.
- Read `(1,2,3,4)` at both ordinary function entries, observe the known integer
  return register as 1234, and exit normally.

Both host smoke lists include the model suite. The x86-64 hosted runtime lane
includes all three roles; the other five-language model checks establish
selection policy, not alternate ABI runtime support on those targets.

The final three-role matrix passes six deterministic corrected exports and
three preceding-package reproductions, with eighteen ordinary GDB calls across
compiler/corrected/preceding variants. Independent review checks raw artifact
identity, exact function addresses, signed parameter types and convention
attributes, validator results, GDB observations and protected-file hashes.
Raw acceptance SHA-256:
`4c314b0cbff76b7c4d20caa77d71d62c1b1fdcdfbdf46c546b9ffbe08fb13d9b`.
Five ordinary dynamic-parameter profiles and the ARM mixed base/VFP profile
add twelve passing regression exports with native/QEMU GDB checks. All five
fixture reproducibility checks, architecture guard controls and workflow lint
pass. Candidate JAR SHA-256:
`9d541a593e67a66be9e5f95fd2fb5ea5b4b8da34544ca0e42d95cc3a9f5d3a07`.
Aggregate local receipt SHA-256:
`25a5c14de64448ea9ad97e260392176e7f97c14c070ed32479456989726d89ba`.
Headless local exports used Java 25 with Java 21 bytecode; actual Java 21 model
runs are separate evidence. Hosted target/Windows acceptance is still pending.

## Retained research and failed attempts

Local evidence is retained under `build/convention-review/` and
`build/test-results/calling-convention/` in the `calling-convention-policy`
worktree. Earlier GCC/Clang/one-byte owned-copy probes remain under the main
worktree's `build/calling-convention-research/`; patched copies were research,
not production exports.

The first harness attempt incorrectly passed an `env` keyword to a helper
without that argument. The second correctly caught GDB's previously
unaccounted return-display warning. Neither is accepted as a complete run.
The first PIE compiler reference triggered libdwarf's
`DW_DLE_DIE_ABBREV_LIST_NULL` while inspecting GCC's GNU location-view metadata;
LLVM accepted that reference. The fixture now uses
`-gno-variable-location-views`, keeping optimization, DWARF 5 and parameter
locations while omitting that optional GNU extension. The retained failure is
not suppressed or counted as a strict pass. All new outputs must still pass
the existing strict gate, including independently corroborated inherited
frame warnings where applicable.
