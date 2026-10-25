# Register locations across explicitly truncated memory stores

**CONFIRMED in PR #46 run `40148228012`:** Ghidra 12.0.3's
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
execution uses Java 25. The later PR gate below establishes hosted
two-host/five-target acceptance for the combined correction.
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

## Combined with the register join correction

**CONFIRMED local checkpoint (2026-10-25):** normal merge
`70ba319` combines the STORE change with corrected register-join parent
`5e2ea7d`. The shared join normalization is byte-identical to that parent, and
the STORE predicate is byte-identical to the earlier `18c0d0f` follow-up. No
fixture source, compiler choice, signature preparation or debugger expectation
changed. The earlier `325926ee...` evidence remains a separate component result.

The combined source and installed `2d787e33...` JAR each pass actual Java 21
checks 182/1480/154 at 256 MiB. The shared parent `8303348f...` JAR fails the
actual truncated-RAM positive control, as expected. An audit footer compared
`file:/` and `file:///` spellings literally; its failure is retained. A parsed-
URI evidence check closes the audit without repeating successful JVM runs.

Fresh O32/N32 tests in both byte orders pass eight deterministic exports, eight
compiler/Forge GDB sessions and four plain QEMU exits. At 194 visited PCs,
864 values are correct and 30 are honestly unavailable. N32 has 14 positive
entry values across its two cases; O32 has 12 positive integer entries, including
stack arguments, while the modified wide pair stays unavailable. All four
strict validators report zero errors. Forty distinct per-case protected paths
and eleven global records remain unchanged.

Focused receipt SHA-256 is
`3c29840980910059724534b3136bf6c60cdd67c1cfb9f1471d6f2e9efdea0d46`;
runtime receipt SHA-256 is
`66b5d82365138116807ff54b2800691c777719b0391b6280557cb12e2438b4c3`.
Installed headless/GDB execution uses Java 25.0.4.1; the actual Java 21 checks are
separate. Independent final runtime and focused reviews pass. At this checkpoint
final packaging and the full hosted gate remained pending; the later gate below
closes those requirements.

Independent focused review SHA-256 is
`03aa07a318c2174589ab98453ce238cee43e4643d96bb3be80c08641001b54be`;
independent raw four-case review is
`125f134d13a016df39e94c64ca52107b2913fd882ffa2ceef167fb04e3ff7e0f`.

## Hosted acceptance and normal merge

**CONFIRMED:** exact PR #46 head `ea4f9c0` passes all twelve jobs in run
`40148228012`. The downloaded package passes fresh actual Java 21 checks
231/38/154/1480/182. Independent review accepts all five target artifact chains,
both GUI paths and 28 native Windows suites, including the actual decoded
truncated-space checks. The four new MIPS cases retain 194 visited PCs,
864 correct typed observations, 30 unavailable observations and 26 positive
entry values, with strict-zero validation.

All 214 selected target steps and 22 Windows steps succeed. The 111 excluded
platform conditions remain recorded as skips. Acceptance receipt SHA-256 is
`948b3d183f174cbb068e3a55bd2488df037059a056ae33d6e0fa85b9f890c8a7`;
final artifact bindings are
`d2b6b9d393afc8fd2aac7ecafc7f2453acd591f1dc2d93e89f38ed71e3aba8cb`.
Root rehashed all 30 final witnesses and rechecked the exact CI identity and
enforced branch protection before merging.

Normal merge `800081f7d8dd22280e9d360c2c2a0e5e7ffc343c` at
`2026-10-25T01:23:22Z` preserves the tested tree. Distinct main-push run
`40150436365` also passes all twelve jobs and independent fresh target,
28-suite native Windows and both-GUI artifact review. Only the package-focused
Java 21 observations are inherited after exact runtime/test-source equality.
No broad N32 or
additional lifetime/ABI support is inferred from these freestanding cases.
