# Ghidra register joins and object order

**CONFIRMED defect; correction and full acceptance in progress:** admitting Ghidra's valid
computed parameter storage exposes an ordering error for parameters split across
registers. An ordinary two-int structure passed as `{-19, 37}` appears in GDB
as `{37, -19}` on ARM32 and MIPS32 little endian. The compiler reference, raw
incoming registers and structure member offsets establish the intended values.
The first scalar-only PR #45 head passes its existing full CI matrix but remains
blocked for integration because those tests did not cover this case.

## The pinned API conflict

Ghidra 12.0.3's `VariableStorage` class documentation describes memory order:
least-significant first for little endian and most-significant first for big
endian. However, `ParameterPieces.assignAddressFromPieces` normalizes computed
joins to most-significant first, independently of target endianness.
`getVariableStorage` passes those pieces into `DynamicVariableStorage`, whose
constructor preserves them; `getVarnodes` returns a clone without reordering.

`FunctionDB` computes these locations through the selected prototype when custom
storage is disabled, then assigns the result to the attached parameter cache.
`ParameterDB.setDynamicStorage` and `VariableDB.getVariableStorage` preserve that
order. Actual saved/reopened programs exhibit it: ARM's two pieces are r1/r0,
and MIPS little endian's are a1/a0. The big-endian MIPS order is a0/a1.

DWARF 5 section 2.6.1.2 concatenates composite locations in the object's memory
order. The offset inside a register's `DW_OP_bit_piece` remains LSB-relative;
it is a separate concept. Reversing an object's pieces must not change any
piece's register number, bit size or register bit offset.

The same rule applies to custom parameters and locals. `MappedEntry.encode`
passes the storage varnodes unchanged to `AddressXML.encode`, which writes the
join pieces in their supplied order. The native decompiler's `JoinSpace` and
`JoinRecord` interpret that sequence as most-significant first. This actual
serialization contract conflicts with the general `VariableStorage` class
comment; the comment is not a basis for emitting a different value.

A real ARM conversion probe confirms the distinction. Switching the recovered
function to custom storage changes the storage class and persisted-assignment
flag but preserves its pieces, signature, fields and decompiled member uses.
Saving and reopening also preserves those semantics. The first attempted fix
normalized only computed joins: GDB then showed `{-19, 37}` before conversion
and `{37, -19}` afterwards. All structural validators accepted both artifacts.

The original custom/local test did not catch this error. It injected an unused
64-bit local across two separately supplied 32-bit arguments in memory order.
Its passing GDB value proved the exporter's byte assembly, not Ghidra's meaning
for that joined variable. The test's Ghidra storage must instead use significance
order; its executable, raw register values and expected numeric result stay the
same. Direct uses of Forge's neutral piece model already use object order and
must stay unchanged.

## Extraction correction

**CONFIRMED local focused, package and computed/custom runtime checks; hosted
acceptance pending:** perform every
existing exact-width, register-only, validity, mapping, cancellation and
whole-function lifetime check in the original piece order. If a piece is
unavailable, preserve that first reason and diagnostic. Only after the entire
join is proven, reverse the completed piece list for little endian and retain
it for big endian. Apply this at the shared Ghidra extraction boundary for
computed parameters, custom parameters and locals.

Each piece retains its register number, size and LSB-relative bit offset.
Single-register/stack behavior, the neutral storage model, location-expression
encoder, native producer and lifetime limits are unchanged. A dynamic-storage
class or computed-origin marker does not define a different ordering contract.
Mixed register/memory pieces and forced-indirect parameters remain unavailable
under the existing policy.

## Regression contract

Focused tests use actual Ghidra programs before and after saving/reopening,
including two-/three-piece structures, unequal piece sizes, scalar 64-bit
parameters, computed-to-custom conversions, explicit custom/local controls, malformed or
unsupported storage, cancellation and omission precedence. They must execute
on actual Java 21 with the packaged production JAR and preserve the old JAR's
failure as a negative control.

The five-target runtime fixture keeps the complete failing aggregate C source
unchanged, compiled at O0 with only its main symbol renamed. A separate ordinary
caller invokes it and an O1 scalar leaf that stores an unsigned 64-bit argument.
These choices are fixed before execution. No manually reassigned register map, injected call, instruction patch or
return-flow repair makes a result pass. The test intentionally converts the
computed storage to custom without changing its pieces, then saves/reopens it.
Computed and custom outputs must separately validate and expose identical
values and unavailable intervals; decompiled field uses must retain their meaning.

Compiler raw entry carriers and named values are independent of the computed
Ghidra piece ordering. Forge must show the correct typed structure members and
scalar value wherever it emits a location, including five positive aggregate entries and three positive scalar entries.
The two MIPS scalar cases instead require whole-body `REGISTER_MODIFIED`
omissions with no location: their actual compiler-generated LUI overwrites a0.
That instruction is independently decoded from the original executable bytes.
Every later unavailable interval must agree with the diagnostic report. Exact emitted piece order,
member offsets, saved/reopened origin observations, deterministic repeats,
original/module/test preservation and GNU/LLVM/strict validation are required.
Corrected explicit custom/local storage must agree with Ghidra semantics and
retain the expected GDB values. Full hosted
five-target/two-host acceptance is required before PR integration.

## Retained failure evidence

The original five-case comparison is in
`truncated-space-stores/build/next-aggregate-review/`. Its binding receipt has
SHA-256 `90bf63bf113755d583428c1500dbf939e209efc8f25035a02d7d80dce58b14bd`.
Independent raw ordering review SHA-256 is
`d9f80cb6f8bdcbd809b62dacb311d68424c1e60195a8dbd2848522498452000d`.
The failed ARM and MIPSLE GDB runs remain failed; x86, AArch64 and MIPSBE outcomes
and retained warnings are documented separately in `docs/VALIDATION.md`.

PR run `40141054093` at `f46712f` is component evidence only. Its all-twelve-job
success does not cover this defect and cannot authorize integration. A corrected
head requires a fresh full gate and independent artifact review.

## Historical computed-only correction

**HISTORICAL component evidence, not acceptance:** actual Java 21 at 256 MiB passes 603 focused checks across the five real language
models, including saved/reopened programs. The previous `2fb0d5e4...` JAR fails
the actual ARM ordering assertion. The corrected packaged `97018b02...` JAR
passes the same checks with its production class origins independently verified.

The final all-five compiler/Forge run observes 105 instruction PCs: 76 parameter
observations are correctly available and 29 are explicitly unavailable. All
five aggregate entries and the three non-MIPS scalar entries have correct
values. MIPS scalar omissions remain exact; no fixture body, optimization choice
or lifetime rule was changed to make them positive. Ten exports and ten GDB
sessions pass, with deterministic source/sidecar/report pairs and preserved
inputs. Strict validation records only two/four corroborated inherited frame
errors for x86/AArch64 and none for the other targets; unexplained errors are
zero. AArch64 and ARM retain one matching VDSO warning in each compiler/Forge
session; this is not a quiet-GDB claim.

Three additional fresh primary controls preserve the established ARM and both
MIPS custom/local behavior using unchanged existing export/GDB scripts. Stack
and shifted-stack values remain 42; both MIPS explicit composite values remain
`0x1122334455667788`. Their validators, normal exits and independent raw review
pass. This does not resolve arbitrary dynamic-to-custom conversion histories.

The final author evidence receipt has SHA-256
`585cbd82da6318fbb63306e016b0563b3caad85029aeff6a6077782f804b0b7c`.
Independent all-five raw review is
`3492a51b42ba6294ab48ff9c0bb1e1ea9dd8ae1c3e2f843d723e8e916cb6e431`;
independent primary-controls review is
`4c2d82e4347b6dab486f64e2731f53068da3128e2d01ddf62f270f9f67afab68`.
Local headless runs use Java 25; the Java 21 focused controls are separate.
These results do not accept the computed-only fix: the subsequent custom
conversion fails. The shared correction requires new focused, packaged,
runtime and hosted evidence before integration.

## Confirmed custom-conversion failure

The owned ARM probe uses the same `97018b02...` package and an isolated clone
of the passing aggregate program. Its before/convert/reopen observations retain
`r1:4,r0:4`, the same two field offsets and the same decompiled member uses.
The raw register values remain r0=-19 and r1=37. GDB shows the fields reversed
only after custom conversion and reopen. This is an exporter semantic defect,
not a difference in the input or the analyst's declared meaning.

The source, decompiler, raw DIE, validator and actual GDB evidence receipt is
`build/dynamic-composite-review/custom-history.exrqsykm/observation-result.json`,
SHA-256 `820442806d7a87cc60b7d3c65104f85200f173ebef845454ca8a5fee8374e269`.
The original program, inputs and installed module remain unchanged. An audit
footer's incorrect equality assertion across differently named output files is
retained separately; the three successful headless calls were not rerun.

## Shared extraction correction: current checkpoint

The shared correction passes 1,480 focused checks on actual Java 21 at 256 MiB,
including computed-to-custom conversion and immutable reopen across all five
language models. Explicit custom parameters and locals cover two/three pieces
and unequal widths. Actual `AddressXML` serialization and the direct neutral
model are checked separately. The previous computed-only `97018b02...` JAR
fails the new ARM converted-custom assertion with unchanged signature/pieces.

Production source SHA-256 is
`39eb0a1d4d76554187102e78f2c0c7504438d80918e7b602698388c96e01cdcb`.
The focused receipt is
`dbda0b6242c82ad40623199bf911b5beeef8c840ef6b7cab3a021091804095cd`.
The eight Gradle storage/lifetime tasks and extension build pass. The assembled
`8303348f...` JAR independently passes the same 1,480 checks on actual Java 21;
its production class origins, source bytes, native provenance, manifests and
installed payloads are verified. Package audit receipt SHA-256 is
`892c63c3ca89b70c28ad4591c9ed3ddfc09e5bf16a780a307976f2781acb36fc`.
The revised computed/custom runtime matrix passes on all five targets: twenty
exports and fifteen compiler/Forge/custom GDB sessions. Each Forge variant
observes 105 instruction PCs, with 76 correct available values and 29 honest
unavailable observations. Each has five positive aggregate entries and three
positive scalar entries; the two MIPS scalar functions retain their exact
whole-body overwrite omissions. Before/after conversion and saved reopening,
the signatures, pieces, fields, decompiled member uses and high-symbol storage
stay consistent. Both outputs repeat deterministically and validate with the
same corroborated inherited frame-error totals and no unexplained errors.

A test-only direct-assignment assumption failed on x86's valid adjacent
field-to-temporary-to-global assignments. The failure is retained; the assertion
now checks that bounded dataflow with one field read, one global write and no
intervening temporary write. The C, compiler choices and production code were
unchanged.

All five corrected primary controls also pass fresh exports and GDB checks.
Stack and shifted-stack values remain 42 on every target. The custom composite
remains `0x1122334455667788` on x86-64, AArch64 and both MIPS byte orders; ARM's
modified-register omission stays explicit. Those manually injected unused
locals are assembly regressions, not evidence of recovered original locals.
Their strict inherited totals are 3/5/0/0/0, with zero unexplained errors.
Independent raw runtime and primary-control reviews pass. Final committed
packaging and fresh CI remain required before integration.

The shared correction's installed headless/GDB corpus uses Java 25.0.4.1;
the actual Java21 checks above are separate source/packaged focused tests.
Final local evidence receipt SHA-256 is
`07c73b0f85d28ddb830ffab91f364c6de20c814178b5329a879dc5cc3a5cc86d`.
Independent computed/custom runtime review SHA-256 is
`4939adbb7367d73ab6777698a00745d9c503995faf5b538320f947a486bec14d`;
independent five-primary review is
`4a803df13f60a9418ca10732f8731112ec579af2eab895bdd824dcd039667229`.
