# Variadic and no-return function types

**CONFIRMED locally; hosted acceptance pending:** saved Ghidra function types
retain variadic behavior. Their no-return property is now explicitly diagnosed
when it cannot be represented by the validated DWARF mapping. This addresses
P1.7's requirement to represent or diagnose variadic and no-return cases; it
does not complete P1.7 or establish additional target ABI support.

## Encoding decision

Ghidra 12.0.3 `FunctionDefinition` exposes both `hasVarArgs()` and
`hasNoReturn()`. The type extractor already emitted variadic function types
with `DW_TAG_unspecified_parameters`, but silently discarded the no-return
property. Direct subprograms already use `DW_AT_noreturn`.

DWARF 5 section 3.3.1.1 describes `DW_AT_noreturn` on subprogram entries.
Appendix A does not list it for `DW_TAG_subroutine_type`; the pinned libdwarf
tag/attribute table agrees. No validated function-type extension is established
here. The exporter therefore retains the type and emits one omission diagnostic
per canonical no-return function type:

```text
Function type /noreturn_type no-return property omitted: DW_AT_noreturn describes subprograms; no validated subroutine-type mapping
```

The diagnostic contributes to the existing PARTIAL export report. It does not
invent a type attribute, change calling-convention policy, or modify the saved
Ghidra program. Direct subprogram no-return metadata and variadic type metadata
remain intact.

## Local evidence

- `FunctionPointerCallPolicySmoke` passes 1,994 checks across five target
  languages, covering all four variadic/no-return flag combinations for each
  tested compiler convention, deterministic extraction and saved-program reopen.
- All 39 standalone suites pass on the actual Java 21 runtime against the
  installed candidate JAR.
- `function-type-flags-export.py` passes x86-64 exec, PIE and rebased PIE with
  compiler controls, the preceding package and two current exports. Each case
  requires the new diagnostic exactly once, unchanged saved metadata and
  byte-identical sidecar/source files across previous/current/repeat exports.
- `readelf`, `llvm-dwarfdump --verify` and the strict pinned `dwarfdump` checker
  pass. Independent raw review follows each variable-to-pointer-to-subroutine
  type reference and checks direct no-return and variadic attributes.
- GDB executes twelve variadic calls with compiler DWARF and twelve with Forge
  DWARF, returning 60 or 29 as specified. Six ordinary no-return pointer paths
  reach the intended entry and exit with status zero.
- The current lifetime policy omits the no-return function's register-modified
  `code` parameter. The test requires that exact omission and an unavailable
  GDB value, then independently checks the entry argument register. It does not
  claim a recovered variable location.
- Seven additional installed-package regressions pass: aggregate returns on
  all five maintained targets, big-endian MIPS FPXX double calls and a rebased
  x86-64 Windows-compiler-profile pointer case.

Raw local receipt:
`2e2c148ab2c88df065e70c67249d18630be80a9cee2749d01f3803f1f675fc8f`.
Actual Java 21 receipt:
`8dfbd1cf11546e7d29a23f336baf5719b141185b0a44d05e575969f3f9f599d9`.

Run the focused installed-package integration with:

```bash
for role in exec pie pie-rebased; do
    python3 src/test/integration/function-type-flags-export.py \
        "$GHIDRA_INSTALL_DIR" --role "$role"
done
```

Add `--previous-ghidra /path/to/previous/private/install` for the explicit
diagnostic-delta and artifact-identity comparison. CI runs the current package
in the x86-64 target lane. Final package and hosted acceptance remain required.
