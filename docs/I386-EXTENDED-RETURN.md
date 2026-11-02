# i386 extended floating-return allocation

**CONFIRMED locally; hosted acceptance pending:** computed SysV i386
`long double` returns incorrectly acquire a hidden return pointer in the pinned
Ghidra 12.0.3 model. The exporter now removes that automatic parameter from its
DWARF view and uses the correct stack allocation for the explicit parameters.
This is one component of P2.3c/#71; P2.3–P2.3c remain incomplete.

## Defect and correction

Ghidra's `x86gcc.cspec` gives `long double` a logical size of 10 and aligned size
of 12. `ParamListStandard.assignAddressFallback()` passes the aligned length to
`ParamEntry.getAddrBySlot()`. The default output entry accepts at most ten bytes
in ST0. Allocation therefore fails and `ParamListStandardOut.assignMap()` falls
back to a hidden result pointer. For `long double f(long double a, long double b)`
the saved model is EAX pointer return, automatic pointer at stack offset 4,
`a` at 8 and `b` at 20. The actual executable returns in ST0 and takes `a` at 4,
`b` at 16. The original export displayed both arguments as zero instead of
1.25 and 2.5. GNU/LLVM/strict validation accepted that incorrect artifact.

The ABI's floating return table specifies ST0 for float, double and long double:
[Intel386 psABI](https://raw.githubusercontent.com/wiki/hjl-tools/x86-psabi/intel386-psABI-draft.pdf),
Table 2.4. The source-built executable and compiler DWARF independently confirm
this allocation. The pinned Ghidra implementation was inspected from its
`SoftwareModeling-src.zip`, not inferred solely from debugger output.

`targets/I386ParameterAllocation.java` confines the correction to ELF32/i386,
`x86:LE:32:default`, compiler `gcc`, ET_EXEC/ET_DYN, zero ABI version and flags,
and System V/Linux OS ABI identifiers. It fingerprints the exact default
prototype and verifies the saved dynamic storage against a fresh allocation.
Only ten-byte floating returns with twelve-byte alignment qualify. Explicit
analyst storage and nondefault conventions remain authoritative.

The isolated allocation query substitutes the already audited scalar x87
`double` return class **only while calculating input storage**. Formal return
and argument types remain unchanged. This removes the nonexistent automatic
pointer and lets Ghidra's input allocator assign the explicit arguments.
Neither the program nor compiler specification is modified. Generic extraction
receives a resolved storage map plus explicit automatic-parameter omissions;
it rejects attempts to omit an explicit parameter. Other target declaration
paths retain their previous behavior.

## Local evidence

Worktree: `GhidraDwarfForge-worktrees/i386-abi-reference`.
Evidence root: `build/i386-abi-reference/`.
Ghidra 12.0.3, Java 21.0.13+9 and shipped libdwarf 2.3.2 remain selected.

Candidate `ghidra-call-extended-v2` was assembled through the release assembly
script using the existing pinned Linux/Windows native inputs. Its JAR SHA-256 is
`fc21789b60c94b190b6dc8e3cba4035845088a977eb5950423144d2ed0210c4b`.
Package and production-source receipts are `call-package-extended-v2.json` and
`production-sources-extended-v2.json`.

- `allocation-tests-v3.log`: extension build and nine actual Ghidra-model suites
  pass. Counts: i386 allocation 926, AArch64 allocation 673, MIPS N32 allocation
  434, dynamic parameter storage 232, indirect storage 34, formal return 348,
  calling-convention policy 330, custom storage 486 and compiler policy 606.
- `src/test/integration/i386-extended-return-export.py`: four fresh cases pass
  eight deterministic exports, twelve compiler and twelve Forge function-entry
  observations, and the corresponding typed returns. Each executable links and
  runs against real libc. GNU views, LLVM verification and the pinned strict
  checker pass on compiler and Forge DWARF. Inputs, package and persistent
  program data remain identical; exact journal/index backup housekeeping is
  recorded separately.
- Accepted local case directories below `build/test-results/i386-extended-return/`
  are recorded in `build/i386-abi-reference/portable-review.json`. Each contains
  commands, models, before/after project hashes, validators and debugger results.
- Existing integer/stack rebased-PIE regression passes at
  `build/test-results/i386-profile/pie-rebased.q_e_slj6`.
- Python compilation, architecture-boundary checks, workflow actionlint and
  `git diff --check` pass.

Run the new fixture with a multilib C development toolchain, native i386 Linux
execution, GDB, GNU readelf, LLVM and the repository's strict validator:

```bash
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role exec
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role sectionless
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role pie
python3 src/test/integration/i386-extended-return-export.py "$GHIDRA_INSTALL_DIR" --role pie-rebased
```

`I386_CC` optionally selects a compiler command. Locally it selects a private
sysroot containing checksum-recorded Ubuntu multilib development packages;
no system package was replaced. CI installs gcc-multilib/libc6-dev-i386, runs all
four cases in the x86-64 lane, and adds the allocation model suite on both hosts.
Hosted results have not yet established acceptance.

Retained setup failures are not passes: the first model compile used an invalid
typedef constructor; the first portable validator command aliased its original;
`-g3` compiler macro records triggered conservative strict-output rejection; and
the first project comparison included Ghidra's removable backup files. The
fixture now requests ordinary `-g` DWARF without irrelevant macro records and
records narrowly bounded housekeeping. Checker rules were not relaxed.

## Required follow-up

**HISTORICAL at PR144:** the recovered type reports `sizeof(long double)`
as 10, whereas compiler DWARF reports 12. `extended-size.json` and the two
`*-extended-size.log` files reproduce this. The correction deliberately retains
the Ghidra formal type. The current [floating-layout follow-up](FLOATING-TYPE-LAYOUT.md)
validates object size, array indexing and structure fields. The remaining
synthetic signature defect at that checkpoint is now addressed locally by the
[read-only decompiler correction](I386-DECOMPILER-ALLOCATION.md), including
analyst call overrides. Hosted acceptance and integration remain pending.

The wider eleven-function research fixture remains under
`build/i386-abi-reference/abi-reference.c`. Both exec and PIE run natively and
under qemu-i386-static with real libc. Compiler DWARF under GDB 15 and an isolated,
unmodified GDB 17.1 exposes separate consumer limits: vector and sseregparm typed
returns are wrong despite correct raw XMM0 contents, and GCC marks a mutated
mixed-aggregate parameter unavailable at entry. Those failures remain retained
as REFERENCE_MISMATCH; they were not converted to successful reference results.
The selected regparm Forge entry values are correct, while the existing
nondefault-convention policy deliberately prevents typed automatic return display.
Additional convention, vector, aggregate, instruction-lifetime and call coverage
remains required by the original completion plan.

The native GDB17 builder now accepts `--target-profile i386` on Linux x86-64,
using the host-native target so it can execute 32-bit processes. Its pinned
archive is unchanged; the native build receipt is `gdb17-native/receipt.json`.
This validation-only executable does not replace the system debugger or enter
the extension package.
