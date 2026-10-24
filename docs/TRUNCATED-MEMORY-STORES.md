# Register locations across explicitly truncated memory stores

**CONFIRMED locally; hosted acceptance pending:** Ghidra 12.0.3's
MIPS64 languages with 32-bit addresses use a full-width SLEIGH instruction
model and explicitly truncate the RAM address space. Actual decoded STORE
operations have eight-byte address operands while that RAM space reports a
four-byte pointer size. The previous register-lifetime proof treats this
mismatch as an unknown instruction effect, so defensible incoming parameters
can retain names/types but lose their locations.

This finding does not show an incorrect DWARF register map or justify an ABI
classifier change. The intended correction concerns the memory destination of
a modeled STORE. It does not establish the validity of its particular address,
a stack/memory variable location, or a lifetime across a call or register write.

## Pinned semantics and proof boundary

The supplied Ghidra 12.0.3 source archives establish these contracts:

- `SleighLanguageDescription` exposes the names and narrowed sizes of explicitly
  truncated spaces. `SleighLanguage.parseSpaces` accepts truncation only for RAM
  and requires a positive size smaller than the original SLEIGH space. The
  constructed `AddressSpace` no longer exposes that original size.
- `PcodeExecutor.executeStore` obtains the destination space from input zero,
  reads the address from input one and the value from input two, then writes
  through the destination space. The address operand's register is read; it is
  not the destination of the STORE.
- The byte-state implementation converts an offset to a Java `long` and retains
  the selected space when checking/quantizing the address. A wider offset cannot
  redirect a RAM STORE into a different space. Invalid high-bit addresses may
  fail range checks; this is not a claim that every such offset executes.

RAM can also contain memory-mapped registers. The separate, unchanged
`writesRegister` check conservatively rejects any STORE whose selected space
contains the tracked register, including RAM-backed registers. Register
preservation relies on that check as well as the destination-space proof;
classifying a destination as RAM alone is insufficient.

The bounded follow-up must preserve the ordinary equal-width rule and every
existing STORE framing check. A wider offset requires an actual SLEIGH language,
explicit truncation metadata, and agreement between the program's destination
and the language's nonoverlay RAM space. The widened operand is bounded by
`Long.BYTES`; processor names, ELF class, compiler pointer size and processor
size alone do not authorize it. This bound does not reconstruct the discarded
original SLEIGH address width.

Unknown/nonmemory destinations, malformed selectors or operands, inconsistent
space metadata, nontruncated width mismatches and unsupported widths remain
unproven. Calls, modeled register writes, opaque user operations, cancellation,
local-variable assignment checks and diagnostic precedence remain unchanged.

## Bounded compiler and debugger comparison

The retained investigation compiles the same ordinary C for O32 and N32 in both
byte orders. Minimal startup code uses each ABI's actual Linux exit syscall;
there is no libc or matching N32 startup-library assumption. O32 uses MIPS32R2
and N32 uses MIPS64R2, so the ISA is not held constant. The programs run under
QEMU and use Ghidra's naturally selected language/compiler specifications.
Analyst parameter signatures request dynamic storage without hand-assigning
registers or changing instruction flow.

The compiler oracle observes an unsigned 64-bit argument in an O32 register
pair versus one N32 register. Fifth/sixth integer arguments arrive at O32
entry stack offsets 16/20, versus N32 physical argument registers eight/nine.
Compiler named stack-home values are checked after the prologue; raw incoming
carriers are checked at the exact entry.

With the preceding exporter, all four programs export deterministically and
pass GNU, LLVM and strict libdwarf validation with zero unexplained errors.
O32's six integers, including the two stack arguments, have correct Forge GDB
values. Its wide argument remains unavailable with `REGISTER_MODIFIED`. All
seven N32 parameters are honestly unavailable with `UNKNOWN_LIFETIME`, first
reported at a normal prologue STORE with the eight/four width mismatch.

A corrected regression must prove typed N32 values at the actual entry and
subsequent observed instructions, retain all independently justified omissions,
preserve original bytes/ELF flags, pass validators and deterministic repeats,
and exit normally with the expected results. The O32 controls remain mandatory.
Focused checks must exercise actual decoded stores in both truncated languages
and malformed/nontruncated negatives, including unchanged opaque effects and
register-write precedence. The full five-target/two-host pipeline remains
required before integration.

**CONFIRMED local validation scope:** all four source-built cases pass through
the packaged exporter and compiler/Forge GDB. At 194 actually visited Forge
instruction addresses, 864 typed parameter observations have correct values and
30 are explicitly unavailable. Both N32 cases have seven positive entry values;
both O32 cases have six, including stack arguments five/six. O32's modified wide
pair stays unavailable throughout its body. All four strict validators report
zero errors, and all eight exports produce deterministic sidecar/source/report
pairs. The original inputs and observed module/test files remain unchanged.

Actual Java 21 passes 182 focused checks using the packaged production JAR,
including actual decoded stores in both truncated languages, malformed-space
negatives, memory-mapped register clobber rejection and cancellation. Existing
dynamic-parameter and lifetime regression tasks also pass. Local headless
execution uses Java 25; hosted two-host/five-target acceptance remains pending.
These small freestanding QEMU cases are not broad N32 support. They do not cover libc startup, floating/aggregate ABIs, PIE/shared
objects, O64/N64, native MIPS hardware or debugger-injected calls.

## Retained evidence

The investigation is retained under
`dynamic-parameter-storage/build/next-mips-abi-review/`. Its four-case receipt
has SHA-256 `ab7d366be8cff587617cd86e4fd6f9dcce1a9ea327af2be231a7be760370640b`;
the final research/source/acceptance binding has SHA-256
`553230cba62e2f1487991b65a45274966f4f15a7381886b2289f198a6454f1d3`.
Root independently rehashed 459 referenced evidence files. Those records concern
the earlier `2fb0d5e4...` runtime and its omissions, not a passing correction.

The corrected runtime receipt is `build/truncated-store-review/runtime-acceptance.json`,
SHA-256 `7f8bab70170b2f9fcc90ff4f741919838bd1d65ee8c92491a5c8249c9ee573c5`.
Independent raw runtime review has SHA-256
`34252ee04fbf5113786bfc2a70fe6e82941b251a6ab3de1b072e20f761426337`.
All four stripped executables and both fixture sources equal the preceding
contrast byte-for-byte. The old packaged exporter therefore supplies an exact
input comparison; it also fails the new actual-decoded focused positive check.
No old runtime execution was repeated just to rename its fixture files.
