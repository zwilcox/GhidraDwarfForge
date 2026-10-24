# Unsupported stack-local first-use metadata

**CONFIRMED:** a stored Ghidra stack local can have a nonzero first-use offset
even though Ghidra 12.0.3 does not support that field for stack symbol mapping.
The exporter previously retained the offset in its declaration model but
assigned the stack location throughout the function. In the reproduced case,
two disjoint compiler scopes reuse a slot: GDB displayed the earlier object's
value `11` as the later variable `second`, whose own value is `22`.

The bounded correction preserves the analyst's name, type and recorded offset,
but omits the entire location for a stack local with any nonzero first-use
offset. The report gives `UNKNOWN_LIFETIME` and identifies the unsupported
offset. This includes negative, off-instruction, outside-body and extreme
offsets. The ordinary zero-offset path and stack parameters retain their
existing proof. No native declaration, producer call or DWARF encoding changes.

This does not recover general stack lifetimes or solve slot reuse. Clipping a
location at the supplied offset would still assume an unsupported start and
invent an end. Ghidra's listing and mapped-symbol evidence does not establish
the object's identity throughout that interval. A variable may therefore be
typed but unavailable even at an instruction where compiler DWARF can describe
it precisely. That is the deliberate fallback when Forge lacks enough evidence.

## Pinned API evidence

The inspected Ghidra 12.0.3 `SoftwareModeling-src.zip` has SHA-256
`ae94f7ede157d57b865eaa7caefd72c9f98bfed04e122db6909dface0bd22748`.
`Variable` documents an entry-relative first-use offset. `LocalVariableImpl`
rejects nonzero offsets for stack storage, and ordinary function insertion
does not accept the unsupported state. Calling the public setter on an
already inserted `LocalVariableDB` does persist it; listing rendering exposes
the field. Tests save and reopen the actual program database to verify this.

The decompiler's `LocalSymbolMap` supplies no definition address for stack/RAM
storage, and `MappedVarKey` explicitly discards stack first-use. The DWARF
importer's `DWARFVariable` also normalizes stack lexical offsets to zero.
`HighSymbol`/`SymbolEntry` alone do not provide a complete scope end or prove
which source object owns a reused slot. These observations justify omission,
not a guessed location range. They must be revisited for another Ghidra baseline.

An uninitialized value is a separate issue: compiler DWARF can expose a stack
address before its initializing store. Raw indeterminate bytes are not a
known-value oracle and are not treated as a demonstrated exporter defect here.

## Acceptance

**CONFIRMED in exact hosted run `40081385807`:** PR #30 head `fb2fa406` passes
all twelve jobs, package/source audit and independent x86-64/AArch64 runtime
and both-host GUI reviews. Normal merge `74a7466` preserves that tested tree.
Local final run `run.zHNit33c` also passes six roles/twelve exports; unchanged
previous-exporter run `run.R6pJS512` reproduces the wrong location in all six
roles. Five-profile extraction and actual Java 21 checks pass, including the
native Windows stack smoke. This does not complete broader lifetime work.

`StackFirstUseSmoke` exercises actual Ghidra languages for x86-64, AArch64,
ARM32 and MIPS32 in both byte orders. It checks insertion restrictions,
persisted setters, names/types/offsets, diagnostics, cancellation, zero-offset
and parameter positives, and database save/reopen. A guard-absent negative
control must fail the new assertion. These are extraction tests, not five
runtime architecture claims.

`stack-first-use.c` provides disjoint compiler scopes with shared storage and
an ordinary zero-offset local. The x86-64/AArch64 GDB oracle measures both
stack coordinates relative to the entry stack pointer, verifies compiler
scope boundaries and raw slot values, then supplies those measured coordinates
to a curated, fully stripped Ghidra import. The test explicitly records the
later instruction as analyst first-use metadata; it does not call that offset
the compiler's lexical-block start.

The fixed export must retain a signed four-byte `second` with no location at
all four observations, including the compiler's live interval, and report its
omission. The ordinary `zero` must remain `37`. A baseline-reproducer mode
requires the old wrong `11` before the later object's lifetime, then `22`; it
never labels that result a passing fix. Raw storage, source lookup, stepping,
global address formatting and normal exit are checked separately.

Each target runs non-PIE, PIE and explicit Ghidra rebase roles, two fresh imports
per role, GNU/LLVM/strict libdwarf validators, exact code-address index checks,
unchanged input hashes and byte-identical output pairs. The independent DIE
and report oracle checks both exports. Existing stack-depth, register-copy,
opaque-effect and other architecture tests remain required.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew stackFirstUseSmoke
src/test/integration/stack-first-use-export.sh /path/to/private-packaged-ghidra
```

Neither published alpha includes this correction. Broader P1.11a lifetime and
storage migration work remains partial.
