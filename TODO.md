# TODO.md — GhidraDwarfForge

**CONFIRMED integration plan (2026-10-31); final acceptance pending:** the
remaining P1.7 commits from PR88 through PR94 are combined on a normal-history
integration branch based on current main. This preserves every component commit,
the private-socket correction and the explicit fixture inventory correction.
The entire combined head must pass the unchanged, up-to-date
`required-validation` gate, exact-package/raw review, actual Java 21 suites and
both GUI reviews before normal integration. No component pass substitutes for
that combined gate. P1.7/#66 remains open; no release publication.
See `docs/P17-ACCEPTANCE.md` for the complete closure checklist. Earlier plans
to integrate each dependent PR separately are superseded by this combined gate;
the implementation scope and acceptance requirements are unchanged.

**CONFIRMED component evidence:** PR92 head
`78f13571a0270d42d2f67a7db822d7b4be944335` passes all twelve jobs in
`41189959971`, package/raw review and both GUI consoles. Receipt:
`ca433be694deba875bea124539f71a918c37aa0c96a6ec174c17d6a393d1e902`.
Independent recovered-signature provenance review also passes; receipt:
`2a830c53f2ee63ef29f962429fff2620a72dcd8b87cdd04e04386980b1899dda`.
These are component results; combined-head acceptance remains outstanding.

**CONFIRMED locally; function-type flag acceptance incomplete:** saved
variadic/no-return function types pass 1,994 extraction checks and 39 actual
Java 21 suites. The previously silent no-return type omission now produces an
explicit diagnostic; direct no-return and variadic behavior are preserved.
Three saved-program exec/PIE/rebase cases pass validators, 24 compiler/Forge
variadic calls and six ordinary no-return pointer exits. Prior/current/repeat
artifacts are byte-identical. Seven cross-target ABI regressions also pass.
See `docs/FUNCTION-TYPE-FLAGS.md`; final package/hosted review and P1.7/#66
completion remain pending.

**CONFIRMED failed hosted gate; fixture inventory corrected locally:** PR93 run
`41192386664` stopped all five target lanes during fixture setup because
`function-pointer-conventions.c` was absent from the approved source inventory.
The fixture is now explicitly inventoried and documented. All five target
`fixture-reproducibility.sh` runs pass byte-identical rebuilds, partial-strip
symbol checks and source-only inventory checks. Production code is unchanged.
Fresh hosted validation is required; the failed run is not acceptance evidence.
P1.7/#66 remains open.


**CONFIRMED locally; hosted acceptance pending:** function-pointer types now
retain calling-convention and compiler/MIPS call restrictions, closing a bypass
that returned 4389 instead of 1234 through a Microsoft-ABI pointer. All 51 local
saved-program cases pass (six x86 compiler-profile, 24 MIPS floating and 21
five-target aggregate cases), with 240 correct and 90 refused fixed-package
calls, deterministic outputs and protected inputs. All 39 actual Java 21 suites,
five isolated packaged native profiles, 32 validator metadata controls and 97
evidence controls pass. The separately pinned checker recognizes the established
LLVM/GDB function-type convention extension; it suppresses no diagnostics and
changes no shipped native source. Raw receipt:
`6a441bb81bc6607d36e3d9d6b580d1438867f9ef0709444502750bbee18ca44e`.
See `docs/FUNCTION-POINTER-CALL-ABI.md`. Final package/hosted acceptance remains
pending; P1.7/#66 remains open.

**CONFIRMED committed-package checkpoint (2026-10-31):** the merged overload/
aggregate-return candidate builds and its package audit verifies 67 exact source
files, 261 Java 21 classes, native provenance and every release manifest. Its
production JAR is byte-identical to the 21-case aggregate matrix. Six fresh
stripped/rebased overload cases, including ARM and Thumb, and all five merged
fixture inventories pass. Hosted acceptance remains pending; P1.7 stays open.

**CONFIRMED locally; aggregate-return acceptance incomplete (2026-10-31):**
return carriers now retain their names/types/locations as artificial variables
without adding formal arguments. A bounded MIPS policy preserves verified word
arguments and rejects reproduced unsafe wide aggregate calls. All 21 target/
profile/role cases pass 42 exports, 162 positive calls and 24 unchanged-state
rejections, with 24 compiler failures retained as negative controls. Independent
raw receipt: `335f0050b3d608df4b3e63a62b2bd0dfba2a03b759bb4ab023d5d61e03a4eee2`.
Model, fixture, declaration, failure/cancellation and initial Java 21 checks pass;
final committed package/hosted acceptance remains pending. See
`docs/AGGREGATE-RETURN-CALLS.md`. P1.7 remains open.

**CONFIRMED locally; hosted acceptance pending (2026-10-31):** all 36 overload
cases pass across x86-64, AArch64, ARM, Thumb and both MIPS32 byte orders,
including retained/stripped exec/PIE/rebased PIE. The matrix includes 72 exports,
72 compiler/Forge GDB processes and 288 ordinary runtime calls. Independent raw
review, all five fixture inventories and workflow lint pass. Receipt:
`1318930de47d80a26767bfdc67725f09b83046d5ab27abb360bab566714fce26`.
See `docs/OVERLOADED-SIGNATURES.md`. P1.7 remains open; the separate hidden
aggregate-return fix has the local evidence recorded above and awaits hosted acceptance.

**CONFIRMED original ARM mode conflict controls locally (2026-10-31):**
source-built ELF mutations now exercise both contradictory function tags and
mapping symbols through real imports and repeated production exports. Both omit
the new alias and preserve original symbols. Curated debugging still passes for
the function-tag conflict. The wrong mapping is preserved and rejects stopped
GDB decoding before execution; that negative control is not a passing Forge
runtime case. The unmodified sectionless boundary case also passes again.
All three references run correctly, all artifacts validate, and inputs/programs
remain unchanged. Receipt:
`d9cefc626cda90996b52554d0cde7ccfbe254524d6828fc465483e2819b27693`.
Final combined ARM package/matrix and hosted review remain pending; P1.7 stays open.

**CONFIRMED Thumb dynamic-symbol boundary fix locally (2026-10-31):** an
isolated ARM EABI5 policy uses the untagged function address for load containment
while retaining the original ELF value. The previous build omits a valid alias;
the fixed package preserves it and passes source-built sectionless ET_DYN
GNU/LLVM/strict validation, raw inventory/corruption checks, deterministic exports
and QEMU/GDB argument, instruction and return checks. 452 ARM alias checks,
1,730 dynamic-symbol checks, 36 actual Java 21 suites and four fresh non-ARM
sectionless runtime regressions pass. The standalone >2 GiB writer check and
all five fixture reproducibility lanes pass. CI regression wiring is present;
hosted acceptance and contradictory-mode integration remain pending. Receipt:
`490f33b5ed076977ce7fa8d5990e5cebd9b34e92af0fa3cf4ea788a75bc8495e`.
See `docs/ARM-FUNCTION-ALIASES.md`. P1.7/#66 remains open.

**CONFIRMED ARM integration checkpoint locally (2026-10-31):** repository
harnesses now cover 18 ordinary ARM/Thumb/mixed-mode automatic alias cases and
nine sectionless cases, including indirect interworking calls. Automatic ordinary
outputs equal an isolated installed writer byte-for-byte. Twelve wrong-tag
runtime controls reject; 36 actual Java 21 suites and all five fixture
reproducibility lanes pass. CI wiring is present, not yet hosted-validated.
Receipt: `2c794c6336ad054184237c56ce40281d207ae2d4afb09606cd83f2ec62bb1588`.
The boundary defect observed at this checkpoint is fixed locally as recorded
above. Contradictory-mode evidence and final package/hosted validation remain
required before accepting the ARM change. P1.7 remains open.

**CONFIRMED bounded sectionless ARM/Thumb runtime checkpoint (2026-10-31):**
Six fresh sectionless exec/PIE/rebased imports and repeated automatic alias exports
pass raw inventory, structural validation and QEMU/GDB. The debugger explicitly
selects compiler-backed ARMv7 and decodes stopped remote memory before continuing;
this does not establish automatic ISA detection without `.ARM.attributes`.
Six wrong-mode runtime controls and twelve raw inventory corruptions reject;
fifteen retained non-ARM oracle replays pass. Receipt:
`3444e8de979b9baf9fba159474cad2df377f608ab9a26cf2f42df5a106c6370b`.
The initial ARM candidate JAR supplies this checkpoint; final merged package,
mixed/conflicting mode cases and pipeline expansion remain pending. P1.7 stays open.

**CONFIRMED initial ARM/Thumb alias implementation locally (2026-10-31):**
separate saved/current instruction-mode evidence now tags only ELF alias values.
The isolated planner reconciles original mapping/function tags and retains generic
full-body ownership, collision and byte checks. Twelve retained/stripped ARM/Thumb
exec/PIE/rebase cases pass repeated automatic export, unchanged DWARF/source,
GNU/LLVM/strict validation and QEMU/GDB static decode, lookup, stepping and returns.
304 target-policy checks, 59 extraction checks and seven actual Java 21 suites pass.
Receipt: `aea3c3e28605ae12cb56c244261341ba5b702ae60208236a2bf9cef027280ad3`.
Sectionless/mixed/conflicting-mode runtime proof, pipeline expansion and final
acceptance remain pending. P1.7/#66 stays open; see `docs/ARM-FUNCTION-ALIASES.md`.

**CONFIRMED stripped Thumb PIE mode gap and isolated repair (2026-10-31):**
four ARM/Thumb baseline cases pass, while stripped Thumb PIE and rebased PIE
fail GDB static disassembly before attach despite valid DWARF. Existing production
mode cues are restricted to ET_EXEC. An isolated tagged-alias writer experiment
repairs both cases; all six stripped roles pass validator and runtime checks.
Six deliberately wrong-tag controls fail static decoding while LLVM still passes;
twelve mode-inventory corruption controls are rejected. Production extraction
and planning remain unchanged. Receipt:
`b79408ac6e9055788d95822a24712bd6307d68eb47a87e89181102261267f6dd`.
Automatic ARM/Thumb alias support, sectionless/mixed/conflicting evidence and
broader P1.7 remain open. See `docs/research/ARM-FUNCTION-ALIASES.md`.

**CONFIRMED retained ARM/Thumb baseline and packaging experiment (2026-10-31):**
six ARM/Thumb exec/PIE/rebased cases pass repeated real exports, independent
compiler/Ghidra code boundaries, GNU/LLVM/strict libdwarf validation and QEMU/GDB
lookup, prototypes, owned data, stepping and returns. Static disassembly is checked
before attaching so CPSR cannot hide missing mode information. An isolated writer
experiment preserves every existing symbol/DWARF byte while adding two correctly
tagged local aliases; all six cases pass two deterministic writes and runtime
lookup through the aliases. Automatic ARM alias extraction remains PLANNED;
stripped, sectionless, mixed-mode and conflicting-evidence cases remain open.
Receipt: `94f3e5b759834daa9477773fae4b88b8a822ce6b26c32ada6961805f308f886e`.
See `docs/research/ARM-FUNCTION-ALIASES.md`. P1.7/#66 remains open.

**CONFIRMED ARM/Thumb compiler-fixture research (2026-10-31):** four fresh
ARM/Thumb exec/PIE references run under QEMU. The retained isolated toolchain
supplies fresh compilation despite no ARM compiler on PATH. Thumb ELF values
are tagged, and PIE symbol extents include literal-pool data; alias mode and
code-range proof must account for both. Production aliases remain PLANNED;
see `docs/research/ARM-FUNCTION-ALIASES.md`. P1.7/#66 remains open.

**CONFIRMED failed hosted gate; correction locally validated (2026-10-31):**
PR89 run `41180225439` fails the x86-64/AArch64 allocation-observer checks.
The writer exposes original sectionless unwind records before reconstructed
notes, but both metadata observers still expected notes immediately after loads.
The Java helper now accounts for the bounded original unwind view; the independent
Python oracle decodes the fixture search table and record framing itself.
944 unwind checks, 532 allocation checks, 34 actual Java 21 suites, twelve retained
pairs, twenty unwind-field mutations, the sparse >2 GiB metadata control and a
fresh sectionless i386 rebased-PIE export/validator/GDB case pass. Full hosted
acceptance remains pending. See `docs/I386-FUNCTION-ALIASES.md`. P1.7 stays open.

**CONFIRMED second failed gate and local correction (2026-10-31):** PR89
run `41179501376` rejects the new `i386-alias-entry.cpp` because it was missing
from the explicit fixture source inventory. The reviewed entry is now included;
the inventory check remains strict. All five fixture reproducibility lanes pass
with byte-identical rebuilds (including a private ARM cross compiler now located
outside the normal PATH). Production code and the tested JAR are unchanged.
Receipt: `cebe59b1e8f522ed79023627961e0f04855e6d83c90cc8f25bdf32a7a732f905`. Fresh hosted acceptance remains pending; P1.7 stays open.

**CONFIRMED failed hosted gate and local correction (2026-10-31):** PR89
run `41178632812` stops before compilation because the architecture scan matches
the generic unwind local variable `pc`. Renaming it to `initialLocation` passes
the unchanged scan. All executable bytecode and other JAR entries match the
runtime-tested candidate; only the local-variable debug name differs. The 896
unwind checks, 34 actual Java 21 suites and a fresh sectionless i386 rebased-PIE
export/validator/GDB case pass. Correction receipt: `9b988bde18f43a0162fe45c25b9ae31b430b987a4d6bde09aafc68015337e7ec`.
The failed run is retained; fresh hosted acceptance remains pending.

**CONFIRMED new sectionless unwind gap (2026-10-31):** the i386 alias
candidate passes six base and six automatic-alias exec/PIE/rebase cases, but
sectionless rebased PIE fails `next` because the original unwind bytes have no
`.eh_frame` section view. A PT_GNU_EH_FRAME-only discovery experiment matches
16 header-bearing fixtures across five targets, declines two absent headers,
and repairs the failing GDB case with unchanged original frame bytes. GNU,
LLVM and strict libdwarf checks pass. Production bounded/cancellable recovery
is still PLANNED; i386 alias acceptance is held on that work. See
`docs/research/SECTIONLESS-UNWIND.md`; P1.7/#66 remains open.

**CONFIRMED failed hosted gate; scope harness corrected locally:** PR88 run
`41189899075` failed before export when the big-endian MIPS compiler-reference
scope test tried to bind occupied TCP port 33410. The scope harness now uses
its existing private UNIX-socket helper, including readiness and bounded child
cleanup, and protects that helper in its input snapshot. Fifteen five-target
local-candidate roles plus three exact failed-hosted-package MIPS roles pass
with the former TCP port deliberately occupied: 36 exports and 54 GDB runs,
validators, deterministic artifacts and preserved inputs. Existing real-QEMU
startup/failure/timeout/cleanup checks pass. Local receipt:
`ad4c83475641c72e999f2890cfe42af0103b9413dc63e654edefe613fb324242`.
Production code is unchanged; a fresh hosted gate is required. P1.7 stays open.

**CONFIRMED main87 validation:** the separate main push `41189858903` passes
all twelve jobs, exact package/raw review and both personally viewed GUI
consoles. Receipt:
`a190b2f76e12822a1f3eee78ee1142cccdfde42566349ea2d3c8c50c08f7b5bb`.

**CONFIRMED integration (2026-10-31):** PR87 final main-based head
`4414691b020971e3bd8037fc99563087d09d0ad9` passes all twelve jobs in
`41185868818`, independent package/raw review and both actual GUI consoles.
It merged normally as `020bbe46c5517bd99f09af308fec9927f5e1afe8`. Receipt:
`a757e26c63946418f937fc66c168cf4dad87383c228c772331ef2aa61526c3f0`.
The separate main86 push also passes its complete gate; receipt:
`7586804fd005552a17957fadca8e87309ac1dccbca196d1ce2b97b8101db3734`.
PR88 component `d5bbd89519e9f96b0a175d33119bca72184040b5` is accepted
through run `41176178715` and receipt
`2b7bbbec0da6cd726848129b05edce0ce6d280cea8eba753c6ef0fe0fac0fb50`.
It is now based on main; this normal merge changes handoff notes only. Fresh
final-head validation remains required. Earlier pending notes are historical;
P1.7 remains open.

**CONFIRMED locally; sectionless alias acceptance incomplete (2026-10-31):**
bounded PT_DYNAMIC inventories now preserve original symbols before analyst
alias insertion. Twelve four-target exec/PIE/rebase cases, four incomplete-count
omission controls and two GNU-versioned DSOs pass fresh headless export,
validators and GDB/native checks. The new suite passes 1,730 checks; 33 actual
Java 21 suites, independent raw/corruption controls, large-ELF, failure and
cancellation checks pass. Receipt:
`c303b520d316b0cf620564684832b1dc5284783ee1c3061375eafa087f17d526`.
Final committed-package and hosted acceptance remain pending. See
`docs/SECTIONLESS-FUNCTION-ALIASES.md`. Earlier research-only/sectionless-disabled
statements are historical. P1.7/#66 remains open, including other target modes
and broader ABI/scope work; no release publication.

**CONFIRMED research checkpoint; production implementation PLANNED (2026-10-31):**
sectionless alias insertion without a dynamic mirror loses original names in
four MIPS PIE/rebase controls. An independent PT_DYNAMIC mirror passes eight
runtime cases (32 calls), two GNU-versioned DSOs and strict validators. A
32-fixture count matrix matches 29 full inventories and diagnoses three
empty-GNU-only ambiguities; no count is guessed. Production aliases remain
disabled for sectionless inputs. See
`docs/research/SECTIONLESS-FUNCTION-ALIASES.md`; P1.7/#66 remains open.

**CONFIRMED integration (2026-10-31):** PR86 final main-based head
`284da1c70b7aa936ca11069827fcb3f1e986044e` passes all twelve jobs in
`41182122046`, exact package/32 actual Java 21 suites, raw target/ABI review and
both actual GUI console reviews. It merged normally as `ec15669`. Receipt:
`e8ab4c28b78df565632069e7a032396abe0cf5e2994ae684e2da604f73c7671a`.
Its separate main push `41185820092` is running. The preceding main85 push
`41182072765` is independently accepted, including both GUI reviews; receipt
`c7aa6783390a1888b60d8906cd130772aa079b75fb9612e4ae8cb12262118bf8`.
PR87 is now based on main; this merge resolves handoff documentation only.
Fresh final-head validation is required before integration. P1.7 remains open.

**CONFIRMED locally; acceptance incomplete:** range-aware analyst aliases retain
split/interior-entry primary bodies. Per-range original-code/ownership checks
pass 373 planner and 228 six-language extraction checks; 32 installed actual Java
21 suites and six x86-64 exec/PIE/rebase/repeat runtime cases pass. The prior
package omits those aliases. Protected reruns, independent raw review, twelve
base/twelve alias cases across four targets, and failure/cancellation checks pass.
Local receipt: `61827be29e754148b01698630f7405b1115240e8fcfdfe5abe46b076115c4616`.
Final package and hosted acceptance remain pending. See `docs/DISCONTIGUOUS-FUNCTION-ALIASES.md`.
P1.7/#66 remains open.

**CONFIRMED integration (2026-10-31):** PR85 final main-based head
`bd522b85d5e7d375479c4c4ec54665c22c2406cb` passes all twelve jobs in
`41178871807`, exact package/raw review and both GUI console reviews, and
merged normally as `7eeef48`. Receipt:
`affa498fdccd633b95223d05d1b31e22e3ea2acf5fc19bb972d816e2d8932085`.
PR86 component head `32c480fedfd35ab59d3b26dc4fbbb3aca0b2ba10` passes its
complete component gate (`41172382223`, receipt
`59ee737783ddbc24f4ed902fe8cb36172d274cf8f7e8c5d8f9c80e9002fd7d81`).
It now has main as its base; production content is unchanged by the normal
merge. Fresh final-head validation is required before integration. Earlier
pending component notes are historical. P1.7 remains open.

**CONFIRMED integration (2026-10-31):** PR84 final main-based head
`5211c59047141162d38d9c33c91c3e4cc3ab7e59` passes all twelve jobs in
`41174858655`, exact-package/raw runtime review and both GUI console reviews.
Normal merge `0f305b30bb33604b047d12da7680dbd134c89c0b` preserves its tested tree.
Final receipt: `ba4927801dda7dbd29cc685f671544b1a52863b2bc0b138f48991b01f4d3358e`.
The separate main84 push remains pending. Main83's separate push `41174759972`
passes its full gate and both GUI reviews; receipt
`2eec10a18b6e814589a96537f2be994630af36d9b9667fcdb0bbf7f9f43e1d42`.

**CONFIRMED component acceptance; final main-based gate pending:** PR85 corrected
head `24276e62aa01e9a9b0d4e12f70a4df6aa0baa284` passes all twelve jobs in
`41172356200`, exact package, raw runtime, 31 actual Java 21 suites and both GUI
reviews. Receipt: `43c6ac2eded66abe6d92645a1fdf0795cb682d56462ffa2c3323fc2f8ae09b66`.
The normal main merge changes handoff documentation only. Fresh final-head
validation is required before integration. Earlier pending component/main83/PR84
wording below is historical; P1.7/#66 remains open.

**CONFIRMED failed hosted gate; corrected locally:** PR85 run `41170001875`
fails the standalone large-ELF source compile because its dependency list omitted
`DynamicSymbolMirror`, and the ARM/Thumb oracle because it still expected an
all-local symbol table. The compile list is repaired. The oracle now proves the
complete original dynamic inventory survives around inserted local mode symbols,
with exact string offsets, bindings, original dynamic bytes and a correct local/
global boundary. Five corruption controls reject missing/changed imports and
incorrect boundaries. Fresh large-ELF and full ARM/Thumb exporter/GDB checks pass;
production is unchanged. Receipt:
`c00c0dad986876ef14bbed896e8c53209c26df531e71ffacef6fe367d71bd3bb`.
Fresh hosted acceptance is pending; P1.7/#66 remains open.

**CONFIRMED locally; hosted acceptance pending (2026-10-31):** the MIPS floating
call safeguard passes all 24 maintained both-endian FPXX/FP32, float/double,
exec/PIE/rebased-PIE cases: 72 real exports, 72 GDB processes, 12 unchanged-state
rejections, 36 positive FP32 floating calls and 72 integer controls. Independent
raw review, five-target export/GDB regressions, fixture reproducibility,
failure isolation and copy cancellation pass. Local receipt:
`43ee06d6b6ac524c815d56e3dca42927c3f282ed4c8727f906f174bca66ccd53`.
See `docs/MIPS-FLOATING-CALL-ABI.md`. Final package and hosted gates remain
pending; P1.7/#66 stays open.

**CONFIRMED integration (2026-10-31):** PR83 final head
`ba4fbd6cf2d7780478220a4fc33c43564bdf6f49` passes all twelve jobs in
`41171064361`, exact-package/raw review, 29 actual Java 21 suites, 51 native
Windows model tasks and both GUI console reviews. Normal merge
`cb60980b5964e591c14ca003f461d377e7b1c471` has the identical tested tree.
Receipt: `8275983b14fac9e8624fe7e0c19e9683bb45aef71614da113e0ed67fb2d25db4`.
The compiler-spec safeguard is accepted; broader ABI/P1.7 scope remains open.
Separate main push `41174759972` remains pending.

**CONFIRMED component acceptance; final main-base gate pending:** PR84 head
`dd9ed7ba94662728a9117c5e01c061e63a4ae665` passes all twelve jobs in
`41168155944`, exact package/raw review and both GUI consoles. Its component
receipt is `b104384650ca1f3541533b92f1ec41cb94e9b96adbbcd7c41e091a3c8f7615eb`.
The PR is now based on main after a normal merge; production content is unchanged.
Fresh final-head validation is required before integration. Earlier pending
component notes below are historical, not final-main acceptance.

**CONFIRMED defect and initial local fix; acceptance incomplete:** selecting a
Windows compiler specification for an ELF can make custom Microsoft storage
match the program default while GDB still injects SysV calls incorrectly.
A new target-specific compiler-profile restriction preserves curated knowledge
and blocks unverified injected calls. The initial installed reproduction and
381 model checks across six languages/23 compiler specifications pass. Six
Windows/GCC roles, 29 actual Java 21 suites, five-target regressions and independent
raw review pass; committed package and hosted acceptance remain pending. See
`docs/COMPILER-CALL-ABI.md`. P1.7/#66 remains open.

**CONFIRMED integration:** PR81 head
`f00932e50b4a2901a41e4a51f43d9bb4d77c0a72` passes all twelve jobs in
`41162050189`, independent exact-package/raw alias review, 27 actual Java 21
suites, 49 native Windows model tasks and both GUI checks. Normal merge
`bfec9f008c62076f99c038e8a805349d89896ac1` preserves its tested tree.
Receipt: `bb5bbe66c5f4564fbfb9cccd1a197ae0db6bef6dd428e7cda8bee13d368daeee`.
Automatic analyst-created aliases are accepted for the documented
x86-64/AArch64 profile; broader P1.7 scope remains open. The distinct main81
run `41165205316` is pending. Main80 run `41160800685` passes its full
package/raw/both-GUI gate; receipt
`15d0cb0f35e729f396f1ae9910cacad99b8c8f11436df0cda0a32bf974eaed81`.
Earlier pending notes for accepted components below are historical.

**CONFIRMED locally; hosted acceptance pending:** the custom-storage fix and
accepted aliases pass combined package/raw/runtime checks and 28 actual Java 21
suites. The original and prior output pair survive failure/cancellation tests;
all five fixture reproducibility lanes pass. Receipt:
`f1f34cd01e5a8cbf9e61f3ffd2b7b1bc7e192f762c59f5c1dd11241998ada24f`.
See `docs/CUSTOM-CALL-STORAGE.md`, including the separate reproduced
compiler-default/ELF ABI gap. No release publication is included.

**CONFIRMED defect and local fix; acceptance incomplete:** a default-named custom
parameter/return layout could be incorrectly advertised as normally callable.
GDB injected a Microsoft layout through SysV registers (4389 instead of 1234).
A separate custom-storage restriction now preserves exact default equivalence
and emits DW_CC_nocall for unproved layouts. Six-language models and three real
x86-64 exec/PIE/rebase roles pass, including a real custom EDX return and
previous-package controls. Five-target runtime regressions, controlled failure/
cancellation, 26 actual Java 21 suites and independent local artifact review
pass. Final committed package and hosted review remain pending. See `docs/CUSTOM-CALL-STORAGE.md`; P1.7/#66 remains open.

**CONFIRMED integration:** PR80 head
`71ddb39840b65b8d5cd9833054bd37552592bd87` passes all twelve jobs in
`41144394175`, independent exact-package/raw review, 25 actual Java 21 suites,
47 native Windows tasks and both GUI console reviews. Normal merge
`8b6471bb8209c3374e13c3c1d81108a53d736fe3` preserves the tested tree.
Receipt SHA-256:
`adc82421f9ca89cab128399f9cb2b27da03e184b38c128c2f1e1df43725e1e4e`.
The backend prerequisite is accepted. Its distinct main-push run `41160800685`
is pending. Main79 run `41141403157` also passes full package/raw/both-GUI
review; receipt `2c602112e884dcdc239822a1fa45ca79c1fe3f8370a9bbedddcc9b680ae65621`.
Earlier pending wording below is historical.

**CONFIRMED locally; hosted acceptance pending:** ordinary export extracts explicit
analyst function aliases with original-code/ownership/collision checks. Twelve
x86-64/AArch64 retained/stripped exec/PIE/rebase cases pass 24 automatic exports
and 48 runtime calls; automatic output equals the independent writer exactly.
245 ELF and 186 six-language extraction checks, 27 actual Java 21 suites,
failure/cancellation and live ARM/Thumb regressions pass. See
`docs/CURATED-FUNCTION-ALIASES.md`. P1.7/#66 remains open; no release publication.

**HISTORICAL local checkpoint (2026-10-30):** the matched
ELF writer can insert explicit local function symbols into an existing static
symbol table while preserving all original records and string offsets. Both
classes/orders pass 1,272 model checks. Twelve real x86-64/AArch64 exec/PIE/rebase
retained/stripped cases pass 24 backend writes and 48 runtime calls, plus the
ordinary exporter regression matrix. This is a backend prerequisite for curated
aliases, not automatic alias extraction. See `docs/LOCAL-SYMBOL-TABLE-MERGE.md`.
P1.7/#66 remains open.

**CONFIRMED integration (2026-10-30):** PR79 head
`d4d04a805d5bcd1daf7a6c8efd8c3b6a0b21ad9b` passes all twelve jobs in
`41075538032`, independent exact-package/raw alias review, 24 actual Java 21
suites and both GUI console reviews. Normal merge
`1bda5cf382812251c0d42ba9ad33ff54105e9afd` preserves its tested tree.
Acceptance receipt SHA-256:
`a8bfe99353d2d38d6a35d9999fb027eb9e7f45fd5d91193dfa865fc50b229d62`.
Retained-original ELF alias coverage is accepted; arbitrary curated aliases and
broader ABI/scope behavior remain incomplete. The separate main-push run
`41141403157` also passes all twelve jobs and independent package/raw/both-GUI
review, as recorded above. No release publication is included.

**CONFIRMED integration (2026-10-30):** PR78 head
`0c5dd575676329b9194b747e55251d9d8d8dd35d` passes all twelve jobs in
`40993878434`, independent package/raw review, 24 actual Java 21 suites and
both GUI console reviews. Normal merge
`2c90da03ee4e4b585d15796e237b000d597b1168` preserves the tested tree.
Acceptance receipt SHA-256:
`8d2f77da6ccbf009daf11e1508493950c477f26873682da8aac8bd6b6520ff95`.
The second proven incoming-register backup is accepted; broader lifetime
recovery remains partial. The distinct main-push run `41071957971` also passes
all twelve jobs and independent package/raw/both-GUI review; receipt SHA-256:
`24f67e4ffa8287666e0081bba91743c00f6afdab5348114fa875c77f93190536`.
No release publication is included.

**CONFIRMED integration (2026-10-29 America/Chicago):** PR77 corrected head
`cb092feefa5005cd469c0f5fca241001c12a9287` passes all twelve jobs in
`40505333973`, independent package/raw artifact review, 23 actual Java 21
suites and both GUI console reviews. Normal merge
`c779c0b93b3f90c8798f9f287cd72ff70002ec0b` preserves the tested tree and includes
PR75/PR76 through normal ancestry. Acceptance receipt SHA-256:
`39b29389e79eea862d9c7ae60fc0c6411a9901e94f2488df1bca522959b6735f`.
Curated thunk symbols and bounded i386 shared-library debugging are accepted;
P1.7 and the broader ABI/alias requirements remain partial. Earlier hosted-pending
notes for these components are historical. The separate main-push run
`40991540433` also passes all twelve jobs and independent exact-package/raw/
both-GUI review; receipt SHA-256:
`fb6bfc87bb47f0acb48d50929d48fcaf4468f99a746b7c8f7530152f21256459`.
No release is published.


**CONFIRMED failed combined gate (2026-10-27):** PR77 run `40448198808`
failed in the MIPS32 little-endian floating-register compiler-reference check.
QEMU reported `bind: Address already in use` on the legacy TCP port; GDB then
timed out before the Forge export ran. The other four target lanes and exact
package/23 actual Java 21 suites passed, but native Windows was skipped and the
combined head is not accepted. The floating-register harness now uses the
existing private UNIX-socket readiness/cleanup helper. Local validation passes
36 exports across all five profiles plus sectionless MIPS32LE FP32 pieces, with
43 distinct successful/reaped emulator sessions and startup/failure controls.
Receipt SHA-256:
`6d6a1796c953d4fe4249aa1432bc70bc51fe2442564dff9b1758b1c9a90e8ca9`.
Production code is unchanged. A fresh full hosted gate remains required; failed
artifacts remain retained.

## GitHub issue tracking

Each unfinished top-level TODO has one open tracking issue. Its remaining
subtasks and acceptance criteria are checklists in that issue. Completed
milestones and historical issues #1–#9 stay closed; partial component PRs do
not close an umbrella issue automatically.

| TODO | Tracking issue |
|---|---|
| P1.7 | [#66 — Complete function signatures, calling conventions, thunks and aliases](https://github.com/zwilcox/GhidraDwarfForge/issues/66) |
| P1.11a | [#67 — Extend proven variable lifetimes and storage migration](https://github.com/zwilcox/GhidraDwarfForge/issues/67) |
| P2.3 | [#68 — Extend the validated AArch64 ABI and storage profile](https://github.com/zwilcox/GhidraDwarfForge/issues/68) |
| P2.3a | [#69 — Extend the validated MIPS ABI and floating-point profiles](https://github.com/zwilcox/GhidraDwarfForge/issues/69) |
| P2.3b | [#70 — Extend ARM32 Thumb, ABI and endian coverage](https://github.com/zwilcox/GhidraDwarfForge/issues/70) |
| P2.3c | [#71 — Extend i386 shared-library, floating-point and ABI coverage](https://github.com/zwilcox/GhidraDwarfForge/issues/71) |
| P2.8 | [#72 — Implement opt-in debuglink attachment with backup and recovery](https://github.com/zwilcox/GhidraDwarfForge/issues/72) |
| P3.3 | [#73 — Add evidence-backed lexical scopes, classes and declaration relationships](https://github.com/zwilcox/GhidraDwarfForge/issues/73) |
| P3.5 | [#74 — Profile broader workloads and evaluate optional export optimizations](https://github.com/zwilcox/GhidraDwarfForge/issues/74) |

**CONFIRMED local integration (2026-10-26):** the combined thunk/shared/issue
tracking branch retains the tested thunk JAR. A fresh i386 shared/direct matrix
passes eight roles, sixteen exports and 3,000 GDB observations with that JAR;
23 actual Java 21 model suites and sixteen fresh native producer lifetimes also
pass. Independent shared review receipt SHA-256:
`71d4daece096658e583dc679ead487f5f8fe8491b112f52e2b58033f694db1d6`.
The issue index preserves all nine open umbrella trackers. Full combined hosted
acceptance remains pending; component PRs #75/#76 remain open until integration.

**CONFIRMED locally; hosted acceptance pending (2026-10-26):** explicitly
analyst-named memory thunks preserve their own names/ranges and formal types,
with deliberate source omission instead of borrowed destination decompilation.
The six x86-64/AArch64 exec/PIE/rebase roles pass twelve candidate exports,
six previous-package comparisons and eighteen GDB runs. Five-language models
pass 165 checks; 23 actual Java 21 packaged suites, ten cross-profile parameter
exports, genuine decompiler-failure and cancellation regressions pass. See
`docs/CURATED-THUNKS.md`. This advances issue #66; general thunk/alias and ABI
semantics remain partial. No hosted or release acceptance is claimed yet.

**CONFIRMED integration (2026-10-26 America/Chicago):** PR65 head
`fecf6247c8a82f56cb39b71e947775b68ac83775` passes all twelve jobs in
`40266976465`, independent exact-package/twenty-two actual Java 21 suites,
raw target/runtime review, 44 native Windows model tasks and both GUI hosts.
Normal merge `e2320e0b71b3f7258748f3ac6f3c3ca11b866e46` preserves the tested
tree. Acceptance receipt SHA-256:
`cbb30f4a6d8bec15b8a79bcabebe42c1848383838da5d5eb162ef574bb81fa58`.
Nondefault conventions safely reject unsupported debugger-injected calls;
ordinary execution remains tested. This is part of issue #66, not complete
alternate-ABI support. The distinct main-push run `40445798908` passes all twelve jobs and
independent exact-package/raw/both-GUI review; receipt SHA-256:
`c45ca5127556fcf9eae19b917ebbbe707ead3504b1dbde2d02e62bf6c12529b9`.
No release publication is included.

**CONFIRMED locally on the calling-convention candidate; hosted acceptance pending:**
fresh shared/direct revalidation passes eight roles, sixteen deterministic
exports and 3,000 GDB observations with the new producer JAR. Independent raw
review verifies identity, exact locations/types/names and byte-identical shared
inputs. Twenty-two actual Java 21 suites apply to the identical production JAR;
sixteen fresh packaged i386 producer lifetimes also pass. Receipt SHA-256
`9d5a8efaf99b9aa84176c41e84005a9372686bea62fa686eaa81e1a23794b900`.
Submission remains held until PR65's correctness fix completes its hosted gate.

**HISTORICAL shared checkpoint on the PR64 exporter:**
the shared-library follow-up now includes PR64's control-flow correction.
Fresh eight-role validation passes sixteen exports and 3,000 GDB observations,
with independent raw identity/location/type/name review, twenty-one actual
Java 21 suites and sixteen fresh packaged i386 producer lifetimes. Receipt
SHA-256 `b33566ade02c64de6d80034e5bb39c6e6d2c1a82693572ca5fa70fa16ea1822d`.
The calling-convention fix changes the producer JAR again; its fresh acceptance
is recorded above.

**HISTORICAL local shared-library checkpoint (2026-10-25):** the preceding
i386 exporter now has shared-library exec/PIE/rebase evidence. Four shared and
four original direct roles pass sixteen exports and 3,000 instruction-boundary
GDB observations, strict-zero checking and independent raw location/type/name
review. Shared inputs are byte-identical across roles; curated names require
explicit sidecar loading while original dynamic symbols remain usable. No
production code changes. See `docs/I386-SHARED-PROFILE.md`; broader libc/ABI,
linkage and host claims remain incomplete.

**CONFIRMED integration (2026-10-25):** PR64 head
`23d9c57d5e8fc339650428d7252d9b5381adb49e` passes all twelve jobs in
`40263198239`, independent exact-package/twenty-one actual Java 21 suites,
raw five-target review, 43 native Windows model tasks and both GUI hosts.
The six hosted control-flow roles pass 24 exports and 72 GDB observations.
Normal merge `db66cd5f1832238fa32392d568d0369d48efb9a0` preserves the tested
tree. Hosted receipt SHA-256:
`4d6ab95d2a4fa6ced53f5bae017ff50343c4beeffdbd0f558efa34b517cd7106`.
The distinct main-push run `40266883548` also passes all twelve jobs and
independent package/raw/both-GUI review; receipt SHA-256:
`327f0abd832667c1ab971217219f71688455c60f96bedf4a2f5e15b5c08abfed`.
Earlier pending status is historical; broader lifetime recovery remains partial.

**HISTORICAL local checkpoint, accepted through PR65 above:** explicitly
selected nondefault Ghidra calling conventions now emit `DW_CC_nocall` instead
of an unjustified normal-call assertion. Three x86-64 exec/PIE/rebase roles
pass six corrected exports, three preceding-package comparisons and eighteen
ordinary GDB calls. The previous artifact injects a Microsoft-ABI call with
wrong arguments; the candidate refuses it before target execution. Entry
values/types/source remain usable; GDB also honestly declines automatic return
value presentation for that unclassified convention. Five-language model checks
and twenty-two actual Java 21 suites pass, plus twelve cross-profile regression
exports. See `docs/CALLING-CONVENTION-POLICY.md`; broader ABI classification
and default/custom convention callability remain partial.

**HISTORICAL local checkpoint, accepted through PR64 above:** stable register
locations now require contained control flow, not only complete body decoding.
Six x86-64/AArch64 exec/PIE/rebase roles pass 24 corrected exports, six
preceding-package reproductions and 96 compiler/Forge GDB observations.
Twenty-one actual Java 21 suites pass. Names/types remain available when an
excluded block makes the register lifetime unprovable. See
`docs/REGISTER-BODY-CONTROL-FLOW.md`. Another 66 cross-profile exports pass,
for 90 corrected exports total. Hosted acceptance is recorded above; broader
lifetimes remain incomplete.

**CONFIRMED integration (2026-10-25):** PR63 head
`f87f15566a0b9bbbc826de0ea0a51dd70f42a472` passes all twelve jobs in
`40256429124`, independent package/twenty actual Java 21 suites, raw target
review, 42 native Windows tasks and both GUI hosts. The bounded i386
integer/stack profile passes four roles/eight exports and 1,440 instruction
observations; packaged i386 production passes sixteen lifetimes on each host.
Normal merge `6507ffbc6e52156ba2776151dff8711069ef7108` preserves the tested
tree. Receipt SHA-256:
`745e68b0a2151b3e834b246d6d800072c6fb21f77e0ceae9c0609a7beaa4794b`.
The distinct main run `40260399867` passes all twelve jobs and independent
package/raw/both-GUI review; receipt SHA-256
`18dece7092f5d816cd7c36f4f32cf04a9bf2d02e616d468baa76f3218e9caf41`.
Libc/shared, floating/vector
and broader ABI/host claims remain outside that checkpoint. No release is
published by this integration.

**CONFIRMED integration (2026-10-25):** PR62 head
`b5771e30711ff1825c6416b75f2a19eae778877b` passes all twelve jobs in
`40252798774`, independent exact-package/nineteen actual Java 21 suites,
raw five-target review, 40 native Windows tasks and both GUI hosts. Six
hosted definition-start roles/twelve exports provide 504 compiler/Forge GDB
observations; read-start (396) and stack-spill (900) regressions also pass.
Normal merge `fd0a5bac8ad3b97483253f9f6723d229edb777b9` preserves the tested
tree. Hosted receipt SHA-256:
`066960b5571e8e10cae4983dd8d97913b80c7c6d49ff9517efc7ab18ce4c8ad9`.
The distinct main run `40256250143` passes all twelve jobs and independent
package/raw/GUI review; receipt SHA-256:
`54266d3efdd0adea744a3855dc5bd0d9814148acf55d3de0c82c8ae320b84fc4`. Earlier pending
notes for this PR are historical; general lifetimes and lexical scopes remain
incomplete. No release publication is included.

**CONFIRMED integration (2026-10-25):** PR61 head
`56ead2ffc19f0161e79a28683c91e3dac8a2d43f` passes all twelve jobs in
`40249151143`, independent exact-package/eighteen actual Java 21 suites,
raw five-target review, 39 native Windows tasks and both GUI hosts. Six
hosted read-start roles/twelve exports provide 396 compiler/Forge GDB
observations with exact locations and honest unavailable intervals. Normal
merge `b58839468db8511c0814e9e50f766b60ef90f65f` preserves the tested tree.
Receipt SHA-256:
`04b499dfa37bf32da8916db2b8a41a81cd27642f8d11c7b9ac27a0302aa96f54`.
The initial fixture-inventory failure remains rejected. Earlier PR61-pending
notes are historical. Distinct main run `40252662854` at that merge passes
all twelve jobs and independent package/raw/GUI/native Windows review; receipt
SHA-256 `222d313dd226f84572ef03c370059dffc5811920fefad2b79b777b1b99d37e2c`.
The definition-start extension is accepted separately through PR62 above.

**CONFIRMED integration (2026-10-25):** PR59 head
`28ae3f0c0b2306490932da8841d161b09bb9490e` passes all twelve jobs in
`40241665541` and independent exact-package, sixteen actual Java 21 suites,
raw five-target, 37 native Windows tasks and both-GUI review. Normal merge
`2fed5c3c6de79b319b3d6aa3d9c82c88e0fc25ea` preserves that tested tree and
includes the PR57/PR58 components through normal ancestry. Exact ARM
Thumb/VFP prefixes, mixed incoming pieces and explicit MIPS FP32 whole pairs
(including sectionless inputs) pass their documented scopes. The corrected
architecture guard and five controls also pass. Acceptance receipt SHA-256:
`4b03ddc3aeb697d002b41f8bc6def3c9fdc427e7a63b3d28a932b49f2270bcfd`.
Distinct main run `40244657118` passes all twelve jobs and independent exact
package/raw review; receipt SHA-256:
`0e97ba1c742b3e7755c9e0c66b2ef667379c3b75a3b837b90dfe98dd1433756f`.
Earlier failed-head evidence remains
historical; no false architecture-check pass or partial gate is accepted.

**HISTORICAL local checkpoint, accepted through PR60 below:** one
completed scalar stack save passes six x86-64/AArch64 exec/PIE/rebase roles,
twelve exports, six preceding-package comparisons and 1,350 GDB stops.
Seventeen actual Java 21 suites and eight additional compatibility exports
pass. Any later memory or stack-pointer write ends this bounded location.
See `docs/STACK-SPILL-LIFETIMES.md`. General migration, broader ABI modes,
linkage/scopes and optional debuglink attachment remain incomplete. Separate
negative linkage experiments are documented in `docs/research/LINKAGE-LOOKUP.md`.
No release publication is included.

**CONFIRMED (2026-10-25):** PR56 head `2944b0f` passes all twelve jobs in
`40231232266` and exact package/Java 21/raw target/GUI/native Windows review.
Normal merge `fa68fb11c6e0967341fa13ca628a263138953ec9` preserves the tested
tree and includes the accepted PR55 FP32 component through normal ancestry.
Combined receipt SHA-256:
`4c96466a2812c5e10f1b75eb7b6ad6b9d041afcc4c2ff854d69ffd20f0bb057b`.
The separate main run `40234477662` passes all twelve jobs and independent
package/Java 21/raw five-target/Windows/GUI review; receipt SHA-256 is
`766063585ec2764edc21f63f2063bb4637f2207bcc66884b9b816a19598805d4`.
Earlier pending-component notes are historical. Register coverage now rejects missing listing bytes;
MIPS FP32 explicit pieces validate in both byte orders. Whole FP aliases
were incomplete at that checkpoint; the local follow-up above remains pending
hosted acceptance. FP64A transport and general variable migration remain incomplete. No release
is published by this integration.

**HISTORICAL checkpoint:** PR54 is merged as `c0148c7` after all twelve PR
checks and independent artifact review passed. Its separate main run
`40228194534` also passes all twelve jobs and independent artifact review.
PR56 combines the coverage correction and PR55's
FP32 tests through normal history; 24 combined FP32 exports pass locally and
the final combined hosted gate is pending. Remaining broad TODOs stay open.

**CONFIRMED (2026-10-25):** combined PR #53 head `47970c8` passes all twelve
jobs in `40218743315`, exact package/source/native-provenance review, actual
Java 21 focused checks and fresh raw return/parameter/declaration/stack GDB
review. Normal merge `5eeefb76cfcefa2ed501bdd59676048081b5e9bc` integrates
PR50/51/52 and deferred stack analysis without rewriting their history. Its
distinct main run `40221601223` passes all twelve jobs and separate exact
package/raw signature, stack and GUI/native Windows artifact review. Earlier pending-component notes
are historical; no release is published. The direct-leaf call follow-up below
has local evidence and requires its own full hosted acceptance.

This plan began at prototype commit `7a39a186538c7aec3f7dbdc4a6e396125b5d63ea`.
Published corrective release
[v0.1.0-alpha.2](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.2)
identifies main commit `2f88c4a1a7dd90dfedbd8d578b27242dfb8a73b7`, including
PRs #16–#19 and strict-validation PR #22. Exact-main push run `40064204515`
passed all twelve jobs; the final package audit and downloaded public assets
passed verification before and after publication on 2026-10-24 UTC. Section
0.2 records the resolved validator incident without treating earlier green
runs as clean libdwarf evidence. Alpha.1 remains unchanged and affected.

**CONFIRMED:** combined head `9612655` passed all twelve jobs in hosted run
`40068401197`, including the five target lanes and Linux/native Windows Script
Manager journeys. PR #25 merged normally as `befce2c` at
`2026-10-24T06:23:24Z`; its tree equals the tested head. The separate main-push
run `40070016394` subsequently passed all twelve jobs. Component results and the failed GUI attempts
`run.yI7ooUik`/`run.3HcGrt32` remain historical evidence, followed by the
readiness fix and passing local/hosted regressions.

Main now includes the reviewed semantic, GUI, target-language agreement and
line-table/performance changes plus inline/debuglink research. This is no new
release: published alpha.2 remains unchanged and excludes these subsequent
features. Optional attachment and inline emission remain unimplemented. See
[combined acceptance](docs/VALIDATION.md#combined-hosted-acceptance-and-main-integration-2026-10-24).
Use Sections 1.1 and 4 for the next work; do not restart prototype bring-up.

**CONFIRMED:** qualified-function head `d5f2521` passed all twelve jobs in
`40071594248`, including 15 real exporter/compiler/GDB cases across all five
target profiles and both GUI hosts. PR #26 merged normally as `89c07ce` with
the tested tree. It preserves ordinary
Ghidra namespace paths without changing the C11 CU or inventing linkage/aliases.
See `docs/FUNCTION-NAMING.md` and `docs/VALIDATION.md`; this does not complete
P1.7/P3.3 or belong to either published alpha.

**CONFIRMED:** PR #27 head `e7a289c` passed all twelve hosted jobs in
`40073884397` and merged normally as `ce0c3a4`. Opaque instruction effects now
invalidate otherwise-stable register locations. A real AArch64 supervisor call
reproduced an old parameter changing from `-19` to the process ID; the fix
retains names/types without locations and reports `UNKNOWN_LIFETIME`. Exec,
PIE and rebased PIE pass real export, deterministic repeats, validators and
GDB. Existing x86/AArch64 prefix and ARM scalar-register regressions also pass.
This is a correctness guard, not register migration or syscall ABI support.
The separate main-push run `40075761646` also passed all twelve jobs, with
independently verified Linux and Windows GUI artifacts.

**CONFIRMED:** PR #28 head `a5f7910` passed all twelve jobs in `40076025207`
and merged normally as `b4d7869`, with the tested tree. An exact code-only `.debug_aranges`
index resolves the global-address formatting warning in GDB. The warning
reproduced both before and after the opaque-effect guard; omitting that
parameter location only avoided an automatic formatting trigger. The
production implementation, format checks, all 15 five-profile qualified cases,
three AArch64 supervisor-call roles, six x86 advanced-entry exports and the
MIPS32 big-endian sectionless regression pass locally. Independent hosted
reviews additionally verify all five target artifacts, both GUI hosts and nine
native Windows smoke checks. Exact-main push `40077843290` subsequently passed
all twelve jobs and both GUI artifact reviews; this does not change either
published alpha.
Do not suppress the warning. See `docs/ADDRESS-INDEX.md`.
Evidence and exact scope are recorded in `docs/VALIDATION.md`.

**CONFIRMED current main:** PRs #29–#41 are merged through normal history.
They add bounded direct-register-copy lifetimes, conservative omission of
unsupported stack-local starts, filesystem traversal/alias handling, and
read-only digest/build-ID/report/prefix/allocation/selected-hash and candidate
content foundations. Each exact PR gate passed all twelve jobs with independent
reviews.
PR #38 merged as `2bd6739` after exact run `40110565271`; all five target
artifacts, both GUI hosts and twenty native Windows checks pass. Main-push
gates through PR #37 also pass, including `40110261306`; PR #38 push
`40113254401` attempt 1 lost its Windows runner; attempt 2 now passes all twelve
effective jobs, with three earlier successful jobs reused explicitly. Both GUI
hosts and twenty native Windows checks were independently reviewed. PR #39 corrected head
`a190026` passes all twelve jobs in `40116314882`, independent exact package,
all-five-target and both-GUI reviews, and merged as `4e050609`. Native Windows
passes 21 focused checks with 1,140 owned-writer assertions. Its distinct main
push `40118899783` also passes all twelve jobs and independent both-GUI/native
Windows review. PR #40 detailed report binding/private preparation at `13e706e5`
passes all twelve jobs in `40119714272`, exact package/all-five-target/both-GUI
reviews and 22 native Windows checks, and merged as `25845418`. Its separate
main push `40121995458` passes all twelve jobs and independent both-GUI/native
Windows review. PR #41 captures and consumes existing validator evidence before
private preparation: exact head `f52361a` passes all twelve jobs in `40123518106`,
exact package, all-five-target and both-GUI/native Windows 22 reviews, and merged
normally as `fdebe181`. Its distinct main push `40126173922` passes all twelve
jobs and separate both-GUI/native Windows 22 review. See
`docs/VALIDATION-EVIDENCE-HANDOFF.md`. External-function inventory head `296395e`
passes all twelve jobs in `40126794530`, exact package/all-five-target/both-GUI
review and 23 native Windows suites; PR #42 merged normally as `0d2cbc5`.
Its separate main push `40129499500` passes all twelve jobs and independent
both-GUI/native Windows 23 review. Host identity/metadata inspection research
passes its two-host manual trial and PR #43's exact run `40130322553`; normal
merge `0f1abdc` preserves the tested tree. Its distinct main push `40132729633`
passes all twelve jobs and independent both-GUI/native Windows 23 review.
The optional attachment transaction remains planned.
These changes do not complete general variable migration, the optional
attachment transaction or a new release.

Status vocabulary:

- `[ ]` — not complete.
- `[~]` — implementation is present or work has started, but acceptance criteria are not met.
- `[x]` — complete and backed by recorded tests.
- **BLOCKED** — cannot be completed safely until the named dependency/decision is resolved.
- **UNCERTAIN** — scope or design requires investigation; do not guess.

## 0. Global completion criteria

No project-level milestone is complete unless all applicable conditions hold:

**CONFIRMED:** combined head `9612655` passed the complete supported-profile
matrix with strict independent-validator enforcement in run `40068401197`.
All twelve jobs passed, including the actual Linux/native Windows GUI journeys;
the normal main merge `befce2c` preserves that exact tree. This acceptance is
also confirmed by the separate main-push run recorded above.
The separate corrective release gate in Section 0.2 is complete: exact-main
CI, the final package audit and public-asset verification passed for alpha.2.
That release does not include these subsequent features.
Neither a passing job nor acceptance of one profile proves every ELF/ABI is
supported. Detailed scope and intentional omissions are recorded in
`docs/VALIDATION.md`, "Combined hosted acceptance and main integration".

- [x] Builds from a clean checkout using documented commands.
- [x] Uses a pinned Ghidra compatibility baseline.
- [x] Uses a pinned, provenance-recorded libdwarf revision.
- [x] Does not crash or corrupt the Ghidra JVM.
- [x] Preserves the original target byte-for-byte in default mode.
- [x] Produces deterministic `.dbg.c` for an unchanged Ghidra program.
- [x] Produces structurally valid ELF and DWARF accepted by independent validators
  within the documented profiles and bounds: strict combined CI passes, and
  exact-main release CI/package validation passed under Section 0.2. Precisely
  corroborated inherited frame diagnostics remain visible in the reports.
- [x] Passes scripted GDB behavior checks, not only `readelf -S`.
- [x] Is honest about unavailable types, variables, locations, and source mappings.
- [x] Has tests for every claimed architecture/host combination.
- [x] Runs mandatory end-to-end integration lanes for x86-64 and AArch64
  targets in the pipeline.
- [x] Keeps target handling extensible beyond x86/ARM and adds a QEMU-backed
  MIPS behavior lane before claiming MIPS support.
- [x] Updates `PROJECT_CONTEXT.md`, this file, and user-facing documentation when decisions or support claims change.

## 0.1 Published-alpha correctness review (2026-10-23)

**CONFIRMED:** the six findings against `f4a0199` are reproducible. Fixes
are merged into `main`; the published alpha.1 remains affected.

- [x] Reject explicit log aliases before launch/truncation, including direct,
  normalized, symlink and hardlink input/output paths; preserve hashes and
  prove the fake launcher was not invoked on rejection.
- [x] Match Ghidra's minimum PT_LOAD VA image-base convention; real headless
  export and GDB must retain function/global addresses, with and without an
  explicit Ghidra rebase.
- [x] Emit mutually exclusive byte/bit member location attributes and retain
  component storage width; compiler-oracle and Forge GDB values must agree
  for four-byte integer bit fields stored in one byte, including MIPS32 BE.
- [x] Retire inherited `.gdb_index` with replaced debug data (post-alpha PR #16).
- [x] Resolve synthetic source from an unrelated GDB CWD without `directory`
  commands, including output paths with spaces and deterministic reruns.
- [x] Pass the strengthened complete hosted matrix, including ARM32 bit-field
  values and native Windows log identity checks. **CONFIRMED:** all twelve
  jobs passed in run `40041110549` for implementation commit `cd906de`.
- [x] Integrate reviewed PRs #16/#17/#18 under the standing authorization and
  enforced checks. Their merge reached `1f2a46b`; PR #18's final head passed all twelve
  jobs in run `40051501201`.
- [x] Publish a separately validated corrective release after exact-commit CI
  and package checks, preserving alpha.1. **CONFIRMED:** alpha.2 was published
  from `2f88c4a` after all twelve jobs in `40064204515`, the final package/source/
  provenance audit and 20 packaged Linux producer lifetimes passed. Draft and
  public downloads match the audited ZIP; the public tag identifies that exact
  commit and alpha.1's tag/assets remain unchanged. See `docs/VALIDATION.md`,
  "Corrective alpha.2 official publication", for exact hashes and evidence.
- [x] **CONFIRMED locally:** fix the default pair-publication timestamp ordering
  exposed by main run `40053041949`. Staged sidecar mtime is never below its
  paired source; original ELF metadata and later source-edit warnings remain
  intact. Deterministic publisher/cancellation and GDB regressions pass;
  exact-main CI subsequently passed in `40064204515`.
- [x] **CONFIRMED locally:** force canonical LF native patch checkouts, verify
  their pinned hash before all host/comparison builds, and reject inconsistent
  patch metadata during release assembly. Candidate audit exposed Windows CRLF
  metadata; equivalent patched source does not excuse mismatched provenance.
  Checkout-conversion and malformed-metadata regressions pass; exact-main CI,
  including native Windows, and the final provenance audit subsequently passed.

## 0.2 Validator summary enforcement — resolved release blocker

**CONFIRMED (closed 2026-10-24):** exact-main run `40064204515`, the final
package audit and public-asset verification complete this gate for alpha.2
within the documented profiles. The incident and failed-run history follow.

**CONFIRMED:** `dwarfdump -ka -ks` can exit zero while reporting nonzero
checker counts. A digest-verified audit of all five target artifacts from
`40057428382` found affected logs in every lane. Ordinary x86-64/AArch64 cases,
unnamed sections, and section-header-free inputs need separate explanations.
GNU/LLVM and GDB results remain recorded; they do not erase another tool's
reported errors. Historical claims of zero libdwarf errors are withdrawn for
these affected artifacts; the analysis and corrected validation follow.

- [x] Make check summaries and completion evidence mandatory; reject nonzero
  counters even when process status is zero, and reject incomplete logs.
- [x] Establish the exact cause of each diagnostic against emitted ranges,
  executable mappings and inherited original sections. Compare the pinned
  consumer implementation; do not change correct output to satisfy a checker
  assumption or suppress unexplained diagnostics.
- [x] Prove the chosen validation policy with deliberately invalid artifacts
  and strict positive controls, retaining original hashes and all raw logs.
- [x] Preserve original load extents as inert metadata for sectionless inputs;
  verify exact `PT_LOAD` correspondence and reject out-of-image mutations.
- [x] Correct the standalone consumer's rejection of valid `PN_XNUM` originals
  before using them to corroborate inherited frame diagnostics; retain rejecting
  malformed-count/table controls in both ELF widths and byte orders.
- [x] Update integration callers and documentation, rerun the full target/host
  matrix, and audit the exact final main package before publishing alpha.2.

**CONFIRMED locally:** complete-report enforcement and malformed-report,
line-sequence and CU/function-range controls pass with the independently built
2.3.2 checker. Its narrow line-sequence correction does not alter shipped
native libraries. Exact original/frame identity is required for inherited
frame diagnostics; they are reported, not called absent. Twenty-five fresh
non-sectionless target/role cases pass strict validation and GDB. The five
corrected sectionless cases also pass, including exact original-load metadata,
all emitted location intervals, corrupted-artifact rejection and byte-identical
repeats. At that local checkpoint, hosted validation and the final package
audit were still pending. The later exact-main release evidence above closes
the gate; local results alone did not.

PR #22 at `bf7f2b1` passed native builds, extension/release assembly, ARM32 and
both MIPS32 lanes in run `40061424810`. The x86-64 and AArch64 lanes failed
because standalone libdwarf rejected the original extended program-header
encoding before frame corroboration. Windows-hosted validation was skipped;
the aggregate gate failed. The exact candidate package precheck passed, but
neither that audit nor the three passing target lanes permits publication.
The separate validation-only reader patch now passes 16 local positives,
60 malformed-input controls and fresh x86-64/AArch64 full ELF-layout suites.
Corrected PR #22 head `99845c7` passed all twelve jobs in `40062747733` and
merged normally as `2f88c4a`. Its exact-main push run `40064204515` then passed
all twelve jobs, followed by the final package audit and publication checks.
Separately, semantic head `b14e810` passed all twelve jobs in `40063017269`,
including extended-program cases; those additional features are not in alpha.2.

## 1. Milestone ordering

Do not bypass this dependency order:

```text
M0: reproducible build and repository hygiene
  ↓
M1: pinned libdwarf + ABI-safe producer smoke test
  ↓
M2: valid minimal ELF/DWARF sidecar + explicit GDB loading
  ↓
M3: deterministic synthetic source + .debug_line
  ↓
M4: type graph + signatures
  ↓
M5: variables + accurate locations
  ↓
M6: PIE/shared objects + mandatory AArch64 pipeline lane + Windows host
  ↓
M7: headless/release productization
```

Feature work that calls new libdwarfp functions is blocked until M1.

**CONFIRMED:** M1 is complete; every new native declaration still requires its
own pinned-header audit and isolated-process test.

## 1.1 Current remaining work

The baseline exporter, source/type/location machinery, five target lanes,
Windows headless host, and release packaging already exist. The remaining
items are these bounded workstreams:

The semantic component evidence in the table is also exercised by the accepted
combined run `40068401197`; its conditional-step scope is recorded in
`docs/VALIDATION.md`. Passing that matrix does not complete the partial items.

| Workstream | Status and acceptance needed |
|---|---|
| Corrective release (§0.1/0.2) | **CONFIRMED complete within the documented profiles:** alpha.2 is published from `2f88c4a` after exact-main CI `40064204515`, the final package audit and public-asset verification. Alpha.1 remains unchanged and affected; subsequent semantic/GUI/target/performance work is excluded. |
| ELF robustness (P0.9) | **CONFIRMED complete within the documented bounds:** PR #18 implements extended counts, unnamed tables, bounded file-backed I/O, correct recorded-load-base translation and cancellation. Local checks and all twelve hosted jobs pass; direct PN_XNUM execution limits are documented. |
| Function identity and scopes (P1.7, P3.3) | **CONFIRMED in hosted run `40063017269`:** explicit function-owned statics preserve duplicate-name lookup across all five targets, and the controlled failure check omits failed owners under the symbol-only contract. These workstreams remain partial. Curated addressless external declarations and recovered signature metadata are accepted through PR #53. Class-owned display paths and bounded direct-leaf-call backups are accepted through PR54 and its separate main gate. **PLANNED:** distinct linkage names, broader thunks/aliases, full class/lexical semantics, inferred static locals and remaining same-named type/variable cases. Existing namespace globals and external-data declarations must remain working. |
| Additional range/location cases (P1.8, P1.11a) | **CONFIRMED:** bounded entry/ranges, code-only address indexing and incoming-register prefixes pass. PR #29 adds one proven direct-register backup; PR #30 omits unsupported nonzero stack-local starts. Their exact hosted gates pass. The bounded direct-leaf-call backup and additional x86-64/AArch64 exec/PIE/rebased-PIE cases are accepted through PR54. PR59 accepts terminal-return and mixed incoming prefixes through its complete hosted gate; its failed component heads remain historical. PR60 accepts one complete incoming scalar stack save; PR61 accepts explicit curated read-start register locals. PR62 accepts explicit curated definition-start locals. P1.11a remains partial: general register/memory migration, broader call/flow shapes, stack-slot reuse and additional composite storage still require instruction-specific GDB values and honest unavailable gaps. |
| Target-profile coverage (P2.3/3a/3b) | **CONFIRMED in hosted runs `40063017269` and `40068401197`:** five baseline profiles and scalar FP aliases pass, with exact float/double values on x86-64/AArch64/ARM32 and scalar floats on both MIPS orders. The combined run also proves rejection of definite ELF/Ghidra processor, width or byte-order contradictions; nondefault variants/compiler specifications alone are not rejected. PR59 accepts bounded ARM/Thumb terminal prefixes and explicit MIPS FP32 whole pairs in both byte orders; FP64A transport remains unproven. The bounded i386 integer/stack profile is accepted through PR63 above. Target expansion and ABI classification remain partial; this is not blanket CPU/ABI support. |
| GUI and output paths (P2.7) | **CONFIRMED:** both hosts' real Script Manager/chooser journeys pass. PR #31 adds actual parent traversal, complete publisher alias preflight and native Windows short-parent/trailing-dot controls; its exact PR/main gates and artifact reviews pass. Geometry/GDB run on Linux; Windows uses native GNU/LLVM, with independent libdwarf unavailable and Linux-ELF runtime GDB not run. |
| Optional debuglink (P2.8) | **PLANNED transaction:** opt-in attachment, identity/receipt chain and backup/rollback remain unimplemented. PRs #32/#33's digests, typed build-ID observations and report reader pass the full matrix. PRs #34/#35's prefix and indexed allocation observers also pass the full matrix. PR #36 selected-file SHA binding also passes the full matrix. PR #37 program-byte preservation passes the full matrix. PR #38 candidate-content checks also pass the full matrix. PR #39 owned append-only preparation also passes the full matrix. PR #40 detailed report binding/private preparation also passes the full matrix. PR #41 captured validator evidence passes its exact PR and main gates. Default export leaves the original unchanged. |
| Inline reconstruction (P3.4) | **CONFIRMED investigation complete:** ADR 0003 and a reproducible compiler/Ghidra probe distinguish real inline instances from Ghidra's decompiler flag and record surviving locals/source information. Inline emission remains deferred until explicit instance/origin/range evidence and GDB acceptance exist. |
| Performance (P3.5) | **CONFIRMED:** the indexed planner and configured-checker gates pass component run `40065823442` and combined run `40068401197`. Historical local paired 10,000-function exports reduce median process time by 15.5% with byte-identical artifacts; a fresh strict/GDB replay validates the retained result without rerunning timing. Hosted CI is not a new timing measurement. The pinned SQLite complex-application harness and a bounded JFR profile pass locally; broader workloads and further profiling remain **PLANNED**. No blanket speed or memory claim. See `docs/PERFORMANCE.md`. |

The optional/research items need an explicit recorded outcome; they are not
silently complete merely because they are outside the current alpha scope.
Do not fabricate source, scope, or location evidence to satisfy a checkbox.

---

# P0 — Safety, reproducibility, and a buildable product

## P0.1 Restore a clean, reproducible Ghidra extension build

**Status:** `[x]` — build, installation, packaged native selection, and hosted
clean-install validation are enforced by the release pipeline.
**Blocks:** all release milestones.

### Work

- [x] Select and document Ghidra 12.0.3 as the first supported version.
- [x] Compile Java 21-compatible bytecode as required by Ghidra 12.0.3.
- [x] Create the normal Ghidra extension Gradle layout.
- [x] Add a Gradle 9.3.1 wrapper to the repository.
- [x] Add native-free production Java under a conventional package/source tree.
- [x] Package required JAR/native resources into the extension ZIP.
- [x] Add extension metadata and installation documentation.
- [x] Ensure the extension build does not depend on files already present under
  `src/`, `src/temp/`, or `jna-wrapper/target/`.

### Known historical command

An old README contained:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3_PUBLIC
./gradlew :DwarfForge:buildExtension && \
  cp DwarfForge/build/dist/DwarfForge.zip "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

This command is **HISTORICAL, UNVERIFIED** and cannot be treated as current until the missing build structure is restored or replaced.

### Completion criteria

- [x] `./gradlew clean buildExtension` succeeds with `GHIDRA_INSTALL_DIR` set.
- [x] The generated extension ZIP installs in Ghidra 12.0.3.
- [x] Ghidra loads the native-free extension without classloader/native-loader errors.
- [x] The entry point runs on a trivial x86-64 ELF through `analyzeHeadless`.
- [x] Ghidra 12.0.3 and Java 21 bytecode are documented.
- [x] CI workflow builds the extension successfully on a hosted runner.
- [x] No build output is required to be committed for the build to succeed.

## P0.2 Clean generated artifacts and establish repository hygiene

**Status:** `[x]` — generated/shaded artifacts were removed; the pinned CI
native build and deterministic release assembler are the source of truth.
**Dependency:** coordinate with P0.1 so required resources are not accidentally removed.

### Work

- [x] Add a real `.gitignore` covering Gradle, Maven, IDE, temporary,
  native-build, crash-dump, and generated test output.
- [x] Remove committed `jna-wrapper/target/` and the obsolete Maven wrapper tree.
- [x] Remove committed `src/temp/` extracted/generated content after preserving
  its historical role in `PROJECT_CONTEXT.md`.
- [x] Remove the obsolete `src/libdwarf.jar`; production uses Ghidra's JNA and
  CI-built pinned native libraries.
- [x] Avoid duplicate copies of the same native library under generated directories.
- [x] Add reproducible artifact/provenance manifests rather than relying on
  opaque committed binaries.

### Completion criteria

- [x] `git status --short` remains clean after a normal build/test run.
- [x] Clean checkout plus documented tools reproduces all required generated files.
- [x] No crash logs, cores, temporary JNA extraction files, or unpacked JAR contents are tracked.
- [x] Native/JAR artifacts have one documented source of truth.
- [x] Removal does not break extension packaging.

## P0.3 Add repository and dependency licensing

**Status:** `[x]` — the project is MIT licensed. The hosted native-inclusive
bundle carries the third-party inventory, upstream notices, exact LGPL
corresponding source, local patch, reconstruction instructions, and enforced
checksums.

### Work

- [x] Add the project’s chosen MIT `LICENSE`.
- [x] Record licenses for Ghidra APIs, JNA, libdwarf/libdwarfp, and current
  Windows native dependencies.
- [x] Include required notices in the extension/release bundle.
- [x] Document how corresponding source and build scripts for bundled LGPL
  components are made available.
- [x] Ensure the chosen packaging approach includes the technically reviewed
  dependency-distribution materials and replacement mechanism.

### Completion criteria

- [x] Repository has an explicit project license.
- [x] Release artifact contains all required notices.
- [x] Third-party dependency versions and licenses are documented.
- [x] Bundled native distribution obligations have been technically reviewed
  and enforced by release assembly and hosted CI.

## P0.4 Pin libdwarf and record native provenance

**Status:** `[x]` — pinned source, checksums, native provenance, and
Linux/Windows functional-rebuild comparison gates pass in hosted CI run
33778570507.
**Blocks:** P0.5 and all producer feature work.

### Work

- [x] Replace workflow `LIBDWARF_VERSION: main` with an exact release tag or commit SHA.
- [x] Record the resolved commit, configure flags, compiler/toolchain versions, target triple, checksums, and dependent DLL/SO names.
- [x] Fetch the pinned, checksummed official source archive at build time.
- [x] Make Linux and Windows native builds functionally reproducible.
- [x] Add exported-symbol and dependency checks.
- [x] Do not automatically commit opaque rebuilt binaries directly to `main` without review; choose a safer release/update flow.

Current configure flags that must be preserved or deliberately changed:

```bash
sh autogen.sh
./configure --enable-shared \
  --enable-dwarfgen --disable-static --prefix="$PWD/install"
make -j"$(nproc)"
```

Linux currently also runs:

```bash
make install
```

and patches `libdwarfp.so*` RUNPATH to `$ORIGIN`.

### Completion criteria

- [x] No production build references moving upstream `main`.
- [x] A provenance file identifies libdwarf v2.3.2, source commit
  `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`, and the official archive hash.
- [x] Linux x86-64 native build succeeds and dependency/RUNPATH checks pass.
- [x] Windows x86-64 native build succeeds and DLL dependency checks pass.
- [x] SHA-256 checksums are recorded for release natives.
- [x] Rebuilding the same revision with the documented environment produces
  functionally equivalent artifacts on Linux and Windows.
- [x] CI fails when expected symbols or dependency names are missing.

## P0.5 Audit and repair the complete JNA ABI

**Status:** `[x]` — the complete production producer/consumer surface is
audited against pinned headers; the C ABI probe and expanded Java smoke pass
on Linux and Windows in hosted CI run 33778570507.
**Dependency:** P0.4.

### Work

Audit every production declaration against the exact pinned headers. The
superseded top-level prototype bindings were removed so their known unsafe
declarations cannot be compiled, packaged, or mistaken for supported APIs.

Known high-risk mismatches observed against the inspected upstream header include:

1. `Dwarf_Unsigned`/`Dwarf_Addr` are 64-bit `unsigned long long`, but the callback uses `NativeLong`/`NativeLongByReference`.
2. `Dwarf_Handler` should receive opaque `Dwarf_Error`, not an `int`.
3. `dwarf_transform_to_disk_form_a` is missing `Dwarf_Unsigned *nbufs_out`.
4. `dwarf_add_AT_targ_address_c` is missing `Dwarf_P_Attribute *outattr`.
5. `dwarf_add_AT_flag_a` is missing `Dwarf_P_Debug` and `Dwarf_P_Attribute *outattr`.
6. Section callback return value and `sect_name_index` have different semantics.

Additional required work:

- [x] Add opaque JNA types for every handle used by the audited subset.
- [x] Use fixed-width Java mappings in the new production subset.
- [x] Verify signedness and pointer indirection.
- [x] Verify calling convention on Windows.
- [x] Keep strong references to callbacks for the producer lifetime.
- [x] Check every enabled-subset return status and decode producer
  `Dwarf_Error` through its compatible error number; document and verify
  producer-owned error cleanup through producer finish.
- [x] Add a native ABI probe that checks C signatures, widths, structure size,
  and offsets against the pinned headers.

### Completion criteria

- [x] Every function in the new enabled subset has a reference to the pinned
  header declaration.
- [x] A mapping test proves 64-bit `Dwarf_Unsigned` behavior on Linux and
  Windows.
- [x] Error callbacks receive valid opaque error objects and produce readable
  messages on Linux and Windows.
- [x] No known wrong-arity declaration remains in the production binding.
- [x] Callback objects remain reachable until producer finish in the smoke path.
- [x] A standalone smoke test initializes the producer, creates a CU/DIE,
  transforms it, retrieves sections/relocations, and finishes cleanly.
- [x] The expanded smoke test passes under Linux and Windows processes without
  JVM crash/access violation.
- [x] Equivalent calls have passed the standalone test before the production
  exporter path uses them.

## P0.6 Create an isolated native producer smoke-test executable

**Status:** `[x]` — explicit-native isolated JVM coverage passes for every
target profile. Packaged-native resolution and bounded repetition coverage pass
on hosted Linux and Windows. The repetition test exposed and now guards a
patched upstream cross-export string-table state leak. GitHub Actions run
33824105805 passed the complete matrix.
**Dependency:** P0.4 and P0.5.

### Work

Create a small Java command-line test that does not depend on Ghidra and that:

1. `[x]` Loads explicit pinned native libraries and the checksummed native pair
   from an installed extension.
2. `[x]` Calls `dwarf_producer_init`.
3. `[x]` Creates a compile-unit DIE and one subprogram DIE.
4. `[x]` Transforms to disk form.
5. `[x]` Retrieves all generated section buffers.
6. `[x]` Retrieves and checks symbolic relocation data using the pinned API.
7. `[x]` Finishes/deallocates cleanly on the passing path.
8. `[x]` Writes native revision, platform, target mode, and SHA-256 diagnostics.

Run it in a separate process so a native fault produces a test failure rather than killing the test orchestrator or Ghidra.

### Completion criteria

- [x] Exit code is zero on supported Linux/Windows hosts.
- [x] A crash or signal is surfaced as a failed test.
- [x] A 64-lifetime process test samples Linux RSS and enforces a bounded-growth
  threshold; Linux and Windows both repeat the complete producer lifecycle.
- [x] Section callback indices and relocation data are internally consistent.
- [x] Test output records the pinned libdwarf revision and native checksum.

## P0.7 Add source-built ELF fixtures and a test harness

**Status:** `[x]` — a redistributable semantic source builds ET_EXEC, PIE,
shared-object, partially stripped, and program-header-only variants for all
five target profiles. Reproducibility/metadata capture and the real partial
export role passed across the hosted matrix in GitHub Actions run 33824105805.
**Blocks:** meaningful validation of all exporter work.

### Work

Create small redistributable C/C++ fixtures covering:

- [x] One global and one static function.
- [x] Source constructs for parameters and locals; the supported storage cases
  have value-based GDB assertions under P1.11.
- [x] Struct, union, enum, array, typedef, qualifier, recursive pointer type, and function pointer.
- [x] Contiguous and intentionally discontiguous/partitioned function ranges.
- [x] Non-PIE `ET_EXEC`.
- [x] Source-built PIE reference/stripped fixtures with real headless symbol
  export and runtime assertions.
- [x] Shared object built from a dedicated source without `main`.
- [x] x86-64, AArch64, ARM32, MIPS32 big-endian, and MIPS32 little-endian builds
  from the same semantic fixture source.
- [x] Stripped and partially stripped variants.
- [x] Program-header-only variants with no ELF section-header table.
- [x] A fixture/function that the decompiler cannot complete or a controlled mock failure.

Retain original compiler DWARF in a reference build for expected addresses/types, then create stripped inputs for Ghidra. Do not claim Ghidra should reproduce every compiler detail exactly; use reference data to detect gross address/type errors.

### Completion criteria

- [x] Current non-PIE fixtures build through one documented command.
- [x] Stripped, partially stripped, and reference variants are rebuilt twice
  and compared byte for byte.
- [x] Original, stripped, and partially stripped hashes plus ELF metadata are
  recorded as CI diagnostics.
- [x] Test harness imports/analyzes/exports every current fixture using Ghidra
  12.0.3 and validates the resulting symbol sidecar.
- [x] No proprietary firmware is needed for CI.
- [x] Each fixture documents what behavior it exercises.

### No-section-header regression

`cesena/ghidra2dwarf` issue 29 demonstrates an ELF32 big-endian MIPS input with
`e_shoff=0`, `e_shentsize=0`, `e_shnum=0`, and `e_shstrndx=0` crashing an
exporter that indexes the absent section-name table. GhidraDwarfForge must:

- treat this as a valid program-header-only input;
- derive target identity/load information from the ELF/program headers;
- create a fresh output section table and `.shstrtab`;
- pass the normal validators and GDB behavior tests; and
- never crash Ghidra or publish a partial `.dbg`/`.dbg.c` pair.

**Current evidence:** the real headless function/source exporter completes without a
crash for all five no-section-table fixtures, creates a fresh section table
and correctly typed `SHT_STRTAB` `.shstrtab`, and leaves every input hash
unchanged. `.dbg.c`, DWARF 5 line tables, all structural validators, and
native/QEMU GDB source-level behavior pass. Future type/variable paths must
retain this regression before the full product requirement is complete.

## P0.8 Decide and document the ELF sidecar/association strategy

**Status:** `[x]` — matched non-loadable sidecar selected and proven across
ELF32/ELF64, both byte orders, ET_EXEC/PIE, and no-section-table inputs.
**Blocks:** P0.9 and all GDB acceptance tests.

### Questions to resolve

- Should the output be a debug-only ELF derived from the original ELF’s identity/section metadata?
- Should it be an `ET_REL` object loaded explicitly with `add-symbol-file`/`symbol-file`?
- Which approach works correctly for non-PIE, PIE, and shared objects?
- How are build IDs handled?
- Is automatic discovery required in the first milestone or is explicit loading acceptable?
- Which ELF implementation should be used: a tested library, Ghidra ELF classes, or a corrected custom emitter?

### Required experiment

For at least one x86-64 non-PIE fixture, construct candidate sidecars and prove:

- GDB associates or loads the file.
- Function addresses resolve exactly.
- No invalid relocation/symbol-table assumptions remain.
- `readelf` and DWARF validators accept the artifact.

### Completion criteria

- [x] A short architecture decision record documents the selected format and alternatives rejected.
- [x] Exact GDB loading/association commands are documented.
- [x] Build-ID and `.gnu_debuglink` behavior are specified.
- [x] Original-file modification remains optional.
- [x] The chosen design is proven for PIE and ELF32/ELF64; shared-object load
  timing is validated under P2.2.
- [x] Test harness encodes the selected behavior.

## P0.9 Replace or correct the ELF writer for the minimal path

**Status:** `[x]` — the matched sidecar reader/writer implements the scoped
layout/size cases with explicit resource limits and cancellation. Local tests
and all twelve hosted jobs pass for implementation `3e47589` in run
`40047390539`, including all five target profiles and Windows-hosted export.
**Dependency:** P0.8.

**Completed implementation:** PR #18 (`work/elf-robustness-completion`) continues the preserved
`f2884e6` checkpoint on top of PR #17's corrected exporter. The large-output
pipefail is fixed; real extended-section export/GDB passes. Source bytes are
streamed, metadata bounds are documented in ADR 0001, and a >2 GiB input passes
real headless export plus GDB and deterministic reruns. The discovered Ghidra
bounded image-base scan is handled using its recorded original import base.
See `docs/VALIDATION.md` for exact evidence and external loader restrictions.

Additional acceptance criteria:

- [x] Read/write extended section counts and section-name indexes with valid
  section-zero metadata; test boundary cases across ELF32/64 and both byte orders.
- [x] Handle a present section table without a section-name table, separately
  from the already tested completely absent section table.
- [x] Decode extended program-header counts and test address/build-ID metadata
  from entries beyond the ordinary count limit.
- [x] Define supported input/output size and resource bounds. Replace whole-file
  buffering where needed, test large inputs, and reject unsupported sizes
  without changing the original or publishing a partial artifact pair.
- [x] Pass real headless export, structural validators, GDB behavior,
  deterministic reruns and input-hash checks for the added layouts.

### Work

Remove these prototype assumptions from the supported path:

- Always `ELFCLASS64`.
- Always 64-byte ELF/section headers.
- Always `ET_REL` regardless of the selected design.
- `x86` always means `EM_X86_64`.
- Relocation sections with `sh_link = 0` and no symbol table.
- Arbitrary section callback/symbol indices.
- Zero section addresses when the chosen GDB model requires matched addresses.

Implement:

- ELF32/ELF64-aware headers.
- Correct byte order.
- Correct machine and architecture flags.
- Correct section types, alignment, links, and info fields.
- Build identity/association metadata selected in P0.8.
- Correct atomic file writing.

### Completion criteria

- [x] Compiler-DWARF container oracle passes `readelf -h -S -n` and GDB for
  x86-64, AArch64, and MIPS32 big/little endian across ET_EXEC, PIE, and
  no-section-table variants.
- [x] Minimal x86-64 non-PIE sidecar passes `readelf -h -S -n`.
- [x] Producer symbolic relocations are validated and resolved values are
  emitted without an incomplete debug relocation section.
- [x] No unresolved `SHT_REL`/`SHT_RELA` section is emitted; inherited
  relocation headers are neutralized because producer relocations are resolved
  before publication.
- [x] GDB loads the sidecar using the documented path.
- [x] Function symbols/DIE addresses match the original executable for the
  current contiguous-function fixture coverage.
- [x] Original target hash is unchanged.
- [x] Invalid/unsupported ELF machine/class/byte-order combinations fail before
  output is published.
- [x] Reject definite ELF/Ghidra processor, pointer-width and byte-order
  disagreements before extraction/native production. **CONFIRMED:** component
  run `40064731597` and combined run `40068401197` pass metadata controls,
  same-width wrong-processor imports with prior-pair preservation, five-profile
  ET_EXEC exporter/validator/GDB checks and the native Windows metadata smoke.
  Compiler specifications, language variants and further
  ELF ABI-flag policy remain separate; agreement alone does not prove a new ABI.
- [x] Existing compiler DWARF is replaced, not merged. Stale compressed DWARF,
  indexes, debug links, and mini-debug data are retired in the sidecar while
  the original remains unchanged; see ADR 0001 and the validation record.
- [x] Accept valid section tables with `e_shstrndx == SHN_UNDEF`; preserve
  unknown names and physical indexes. Actual nameless MIPS inputs pass dynamic
  loading and GDB value/source tests locally.
- [x] Decode `PN_XNUM` from section zero's `sh_info`, including load and note
  metadata beyond the ordinary count limit. Direct native/QEMU execution of
  the large-program-table fixture is an external loader limitation, recorded
  separately from import/export and runtime checks on its unchanged load image.

## P0.10 Deliver the first validated symbol-only milestone

**Status:** `[x]` — the Linux x86-64 symbol-only milestone passes all local and
hosted validators and GDB behavior tests.
**Dependencies:** P0.1, P0.4–P0.9.

### Scope

Narrow first target:

```text
Host: Linux
Target: x86-64 ELF, non-PIE ET_EXEC
DWARF: one CU + named subprogram DIEs + valid ranges/aranges as needed
Source stepping/types/variables: not yet required
Loading: exact strategy selected in P0.8
```

### Completion criteria

- [x] Exporter runs from installed Ghidra extension.
- [x] Sidecar output name is `<binary>.dbg` by default.
- [x] Sidecar is written atomically beside the binary or to an explicitly selected output path.
- [x] `llvm-dwarfdump --verify` passes.
- [x] `readelf --debug-dump=info` shows valid CU/subprogram DIEs.
- [x] GDB `info functions` includes expected recovered names.
- [x] GDB `break <function>` resolves to the correct link-time/runtime address.
- [x] The initial symbol-only milestone rejected discontiguous functions with
  a diagnostic; P1.8 subsequently added range-list support without flattening gaps.
- [x] Automated test records all commands/results.

---

# P1 — Deterministic synthetic source and line debugging

## P1.1 Refactor extraction away from the monolithic script

**Status:** `[x]` — Ghidra extraction, immutable project-owned models,
synthetic-source generation, native DWARF production, and ELF packaging are
separate. Native-independent model smokes and the supported-profile hosted
GDB matrix pass under P2.12.
**Dependency:** P0 minimal path should remain working throughout refactor.

### Work

Create project-owned immutable models for:

- Program/ELF identity.
- Address spaces and image base.
- Functions and address ranges.
- Symbols/signatures/variables/types.
- Decompiled source tokens and address sets.
- Diagnostics and confidence/omission reasons.

Separate Ghidra extraction, source generation, DWARF production, ELF packaging, and validation reporting.

### Completion criteria

- [x] Unit tests can construct exporter models without opening Ghidra.
- [x] Native producer code does not query mutable Ghidra objects during serialization.
- [x] Existing P0 GDB tests continue to pass.
- [x] No single class owns decompilation, DIE construction, and ELF writing.

## P1.2 Generate deterministic `.dbg.c`

**Status:** `[x]` — deterministic production source, controlled function
failure/cancellation, staged pair publication, and Linux/Windows cross-host
byte identity pass in hosted CI.

### Work

- Define stable function ordering.
- Define stable newlines/encoding.
- Add a deterministic header explaining that source is reconstructed.
- Define stable synthetic declarations and identifiers.
- Record function start/end line numbers.
- Isolate one function’s decompiler failure.
- Write a deterministic diagnostic placeholder for failed functions.
- Avoid leaving a final `.dbg.c` unless its matching `.dbg` succeeds.
- Write to temporary files and atomically rename the pair after complete success.

### Completion criteria

- [x] Repeated export produces byte-identical `.dbg.c` for unchanged input/Ghidra version.
- [x] Function ordering, UTF-8, LF formatting, and honesty header are enforced.
- [x] One controlled decompiler failure does not suppress other functions.
- [x] Failed function still has a symbol-only DIE and source diagnostic.
- [x] Cancellation leaves neither final artifact partially updated.
- [x] UTF-8/newline behavior is tested on Linux and Windows.

## P1.3 Build a structured address-to-source map

**Status:** `[x]` — Ghidra line/token evidence is represented
independently of native production. Focused overlap/discontiguous-range tests
and the supported-profile exporter/validator/GDB matrix pass under P2.12.

### Work

- Extract address sets from decompiler tokens or another validated Ghidra source.
- Use `ghidra2dwarf` and `dwarfexport` token/expression mapping approaches as
  references, while preserving all defensible ranges instead of collapsing a
  line to one minimum address.
- Associate source statements/lines with one or more address ranges.
- Preserve discontiguous mappings.
- [x] Resolve overlapping token address sets deterministically to the earliest
  generated source line for the shared instruction address.
- Do not assign addresses to comments, blank lines, type declarations, or formatting-only lines.
- Preserve mapping evidence/confidence for diagnostics.

### Completion criteria

- [x] Source map is independently constructible/testable without native code.
- [x] Every emitted executable source row has at least one defensible address.
- [x] Comments, blanks, and formatting-only lines have no accidental token row.
- [x] Multiple addresses per line are supported.
- [x] Mapping is deterministic.
- [x] Tests cover overlapping/discontiguous token address sets.

## P1.4 Emit a valid DWARF 5 `.debug_line`

**Status:** `[x]` — valid DWARF 5 line programs, including independent
sequences for discontiguous function ranges and source lookup from another
working directory, pass the hosted target/input matrix under P2.12.
**Corresponds to:** issue #7.

### Work

- Add pinned libdwarfp line-table bindings, or another documented DWARF-producing path.
- Emit a source file table containing `<binary>.dbg.c`.
- Set CU `DW_AT_stmt_list`.
- Emit address/line rows from P1.3.
- End sequences correctly for each function/range as required.
- Add `DW_AT_decl_file` and `DW_AT_decl_line` to functions.
- Validate DWARF 5 line-table forms and support sections.

### Completion criteria

- [x] `readelf --debug-dump=decodedline <binary>.dbg` shows expected rows.
- [x] `llvm-dwarfdump --verify` passes.
- [x] GDB `list <function>` displays the generated function body.
- [x] GDB source breakpoint by file/line resolves to expected addresses.
- [x] GDB `next` advances through sensible source rows.
- [x] Discontiguous function ranges do not merge into unrelated code.
- [x] No rows point at synthetic comments/blank lines.

## P1.5 Complete source-level GDB milestone

**Status:** `[x]` for the required x86-64 non-PIE fixture, with hosted
source/line debugger behavior across the P2.12 target matrix.
**Dependencies:** P1.2–P1.4.

### Completion criteria

For x86-64 non-PIE fixture:

- [x] `list <function>` displays `.dbg.c`.
- [x] `break <function>` resolves correctly.
- [x] `break <file>:<line>` resolves correctly for mapped lines.
- [x] `next`/`step` behavior is documented and sensible.
- [x] `ni` continues to operate normally alongside source stepping.
- [x] GDB reports no malformed line-table/DWARF warnings.
- [x] Automated test stores a transcript or machine-checkable assertions.

---

# P1 — Types, signatures, variables, and ranges

## P1.6 Implement a canonical, cycle-safe type graph

**Status:** `[x]` — native-independent qualifier/reference modeling and
emission pass focused tests; real Ghidra extraction and DIE emission pass hosted
validators and `ptype` on all five targets. The new bit-field regressions also
verify actual values against compiler DWARF. Ghidra 12.0.3's public listing
`DataType` model has no qualifier or
C++ reference datatype to extract, so those are not fabricated.

### Work

Support and cache, at minimum:

- Base types with byte size and encoding.
- Void/unspecified type policy.
- Pointers and references where applicable.
- `const`, `volatile`, and other qualifiers available from Ghidra.
- Arrays and bounds.
- Typedefs.
- Enumerations and values.
- Structures/unions and member offsets.
- Recursive/self-referential types.
- Subroutine/function types and function pointers.

Define precedence among analyst-applied listing/signature types and decompiler guesses.

### Completion criteria

- [x] Repeated references share canonical DIEs.
- [x] Recursive types terminate without stack overflow/duplicate explosion.
- [x] Signedness, size, member offset, array bound, and enum values validate.
- [x] `ptype` in GDB matches expected fixture shape.
- [x] Unsupported types produce a documented fallback/diagnostic.
- [x] Type output is deterministic for the validated unchanged-program paths.
  The generic `DefaultDataType` singleton now uses a stable built-in key instead
  of its process-local ID. Initial export, save, and two fresh read-only reopen
  exports have byte-identical DWARF/source and raw extraction models; persisted
  analyst/imported IDs remain authoritative. See the saved-program regression
  in `docs/VALIDATION.md`. This does not promise equality for independently
  imported or subsequently changed programs.

## P1.7 Emit complete function signatures

**CONFIRMED locally; i386 alias/unwind acceptance incomplete (2026-10-31):**
six retained/stripped base cases, six automatic-alias cases and three sectionless
roles pass after exposing original table-proven unwind bytes. Cross-target,
omission, versioned-symbol, failure and cancellation checks pass; 896 new model
checks and 34 actual Java 21 suites pass. Final strict-reference regressions,
independent raw review, 44 final-checker replays and 97 captured-evidence controls
pass. Committed-package review and hosted gates remain pending. See
`docs/I386-FUNCTION-ALIASES.md` and `docs/SECTIONLESS-UNWIND.md`.
This does not complete P1.7 or ARM/Thumb aliases, broader ABI/return classification
and class/linkage scope work.

**CONFIRMED locally; sectionless alias acceptance incomplete (2026-10-31):**
bounded PT_DYNAMIC inventories now preserve original symbols before analyst
alias insertion. Twelve four-target exec/PIE/rebase cases, four incomplete-count
omission controls and two GNU-versioned DSOs pass fresh headless export,
validators and GDB/native checks. The new suite passes 1,730 checks; 33 actual
Java 21 suites, independent raw/corruption controls, large-ELF, failure and
cancellation checks pass. Receipt:
`c303b520d316b0cf620564684832b1dc5284783ee1c3061375eafa087f17d526`.
Final committed-package and hosted acceptance remain pending. See
`docs/SECTIONLESS-FUNCTION-ALIASES.md`. Earlier research-only/sectionless-disabled
statements are historical. P1.7/#66 remains open, including other target modes
and broader ABI/scope work; no release publication.


**CONFIRMED defect; fix under validation:** MIPS FPXX floating injected calls
can execute with stale arguments and incorrect returns. Compiler and current
Forge reproductions are retained; explicit FP32 controls pass. The isolated ABI
safeguard passes model tests, 32 actual Java 21 suites and sixteen initial
installed runtime cases. Rebased/integer controls and pipeline acceptance remain
pending.
See `docs/MIPS-FLOATING-CALL-ABI.md`.

**CONFIRMED locally; acceptance incomplete:** dynamic-only symbol mirroring
preserves original lookup while adding analyst aliases. Both GNU qualified
versions pass headless DSO fixtures; twelve stripped base/alias roles across
four targets, independent raw review and 31 actual Java 21 suites pass. Final
package/hosted review is pending.
See `docs/DYNAMIC-FUNCTION-ALIASES.md`. This supersedes the earlier blanket
dynamic-symbol omission below; it does not complete P1.7/#66.

**CONFIRMED locally; hosted acceptance pending:** isolated classic O32 MIPS32r2
alias planning passes FPXX runtime cases in both byte orders across exec/PIE/
rebase. 492 model checks, 30 actual Java 21 suites and independent four-target
raw review pass. Six explicit FP32 base/alias roles also pass locally. Defined dynamic
symbols without a static table still prevent new alias insertion; sectionless,
discontiguous and other target-mode relationships remain open. See
`docs/MIPS-FUNCTION-ALIASES.md`.

**CONFIRMED integration:** PR82's corrected custom-storage safeguard passes
all twelve jobs in `41167035160`, package/raw/Java 21/both-GUI review and merges
normally as `f87384c9b9437f28f9088add9f1601b5f981a0dd` with identical tree.
Earlier pending custom-storage notes are historical. Compiler-profile, alias
and broader ABI work retain their own acceptance gates; P1.7/#66 remains open.

**CONFIRMED local fixture correction; hosted acceptance pending:** PR82's first
gate (`41165251340`) fails the two-copy fixture's automatic return-value check
after the custom-storage guard correctly rejects an unresolved convention.
The source-built fixture now records and verifies its known default ABI.
All twelve x86-64/AArch64 first/second-copy roles pass locally, and a separate
unknown-convention control still rejects calls without changing program state.
See `docs/CUSTOM-CALL-STORAGE.md`. This is not full P1.7 acceptance.

Tracking: [#66](https://github.com/zwilcox/GhidraDwarfForge/issues/66).

**CONFIRMED locally; hosted acceptance pending (2026-10-25):** recorded class
ancestors now retain their qualified display path, preventing same-named methods
from collapsing onto an unrelated global. Five-language model checks, actual
Java 21 packaged checks and x86-64/AArch64/MIPS BE/LE exec/PIE/rebase GDB tests
pass. This is display preservation only; class DIEs, method/object relationships,
linkage, aliases and lexical blocks remain partial. See `docs/FUNCTION-NAMING.md`.

**CONFIRMED in PR #52 run `40215680796` (all twelve jobs, exact package,
actual Java 21 and raw GDB/Windows review):** ordered decompiler parameter
names/types now fill DEFAULT noncustom signatures with zero listing parameters.
Only complete supported scalar/pointer lists qualify; uncertain lists are
omitted as a whole. Stronger metadata stays intact and inferred parameters have
explicit UNKNOWN_LIFETIME omissions, never invented locations. 550 five-profile
ProgramDB checks and a real x86-64 compiler/previous-package/GDB regression pass.
GDB displays the inferred types and unavailable arguments. See
`docs/RECOVERED-PARAMETER-TYPES.md`; broader P1.7/P1.11 scope remains partial.

**CONFIRMED in PR #50 run `40214441924` (all twelve jobs, exact package,
actual Java 21 and raw GDB/Windows review):** concrete decompiler
scalar returns now fill only DEFAULT undefined, noncustom listing returns.
Stronger signature/return provenance remains authoritative. DEFAULT signatures
also omit the prototype flag so unknown arguments are not asserted as a known
no-argument list; curated prototype flags remain intact. 645 model checks
cover five profiles and immutable reopen; a real x86-64 installed regression
proves GDB types and ordinary returned values against the previous package and
compiler DWARF. The unsigned-width inference discrepancy is explicit, not
claimed as original type recovery. See `docs/RECOVERED-DEFAULT-RETURNS.md`.

**CONFIRMED in PR #48 run `40205151874` (all twelve jobs):** the earlier prototype acceptance did not
cover forced-indirect aggregate returns. A real x86-64 probe emitted an 8-byte
pointer for a curated 24-byte structure. Extraction now selects the formal
return type; 312 Java 21 ProgramDB checks cover five languages, immutable reopen,
custom conversion and hidden parameters. The x86-64 installed exporter/GDB regression passes: correct structure return,
hidden pointer, actual returned bytes, deterministic exports and unchanged inputs.
The downloaded hosted package and native Windows pass the same 312 model checks;
the hosted x86 runtime agrees. Separate main push `40208082901` also passes all twelve jobs and root package/runtime review.
This bounded fix does
not complete external declarations, linkage names, aliases or class scopes.

**Status:** `[~]` — return/parameter DIEs, names,
prototype/no-return/variadic flags, a user-defined signature, and
standards-backed `DW_CC_normal` pass locally. Unrepresentable vendor ABI
distinctions retain their model string without invented DWARF codes.
**CONFIRMED through accepted PR77:** explicitly analyst-named memory thunks
emit typed definitions with deliberate source omission; uncurated thunks remain
diagnosed and omitted. See `docs/CURATED-THUNKS.md`. **HISTORICAL correction:** the earlier claim
that genuine external functions were also inventoried was not established:
Ghidra's ordinary function iterator excludes them, and the integration assertion
accepted a thunk diagnostic alone. **CONFIRMED:** the dedicated external
inventory passes five real Ghidra language models, five fresh primary exports
with native/QEMU GDB checks, and identical old/fixed/repeat saved-program sidecar
and source bytes. PR #42's exact run `40126794530` and distinct main push
`40129499500` both pass all twelve jobs and independent reviews. Curated addressless declarations pass PR #49 run `40210826397` and distinct
main run `40214033937`, all twelve jobs with exact package/raw GDB/Windows
reviews, in addition to the five-language model and compiler regression.
Default signatures stay omitted. GDB ignores unlocated prototypes even in
compiler DWARF, so this adds metadata without claiming external-code lookup. Distinct
linkage-name emission remains because GDB must retain the analyst-facing
breakpoint name.

### Work

- Add function return-type references.
- Add `DW_TAG_formal_parameter` DIEs.
- Preserve parameter names.
- Preserve variadic signatures when known.
- [x] Preserve plain/nested analyst function namespace identity as a qualified
  display name while retaining lexical source/signature keys. PR #26 head
  `d5f2521` / run `40071594248` passes fifteen exec/PIE/rebased-PIE cases across
  all five targets, with distinct owned statics and a same-named global.
  This bounded display-name acceptance is not full namespace, class, linkage
  or alias semantics; the broader signature task remains partial.
- [~] Preserve calling-convention information where DWARF/GDB can use it:
  defaults retain `DW_CC_normal`; unknown convention state stays absent.
  **CONFIRMED through accepted PR65:** resolved nondefault
  prototypes emit `DW_CC_nocall` with a diagnostic, preventing unclassified
  injected calls. Original model strings remain intact; no vendor mapping is
  invented. See `docs/CALLING-CONVENTION-POLICY.md`. Broader default/custom/
  return ABI classification remains partial. **CONFIRMED locally; hosted
  acceptance pending:** custom-storage equivalence and default compiler-profile
  restrictions reject independently reproduced unsafe calls while preserving
  formal signatures and ordinary debugging. See `docs/CUSTOM-CALL-STORAGE.md`
  and `docs/COMPILER-CALL-ABI.md`; this is not arbitrary ABI certification.
- [~] Add linkage names where meaningful. A distinct imported-name experiment
  was rejected because GDB 16.3 used `DW_AT_linkage_name` instead of the
  analyst-facing `DW_AT_name` in the honest C11 CU, breaking
  `break recovered_add`. **CONFIRMED through accepted PR79:**
  retained original ELF symbols preserve typed original-name/alias lookup beside
  curated DWARF identity in twelve x86-64/AArch64 cases, including fully stripped
  absence controls. No distinct linkage attributes or fabricated aliases are
  added. See `docs/RETAINED-FUNCTION-ALIASES.md`; general alias modeling remains.
  **CONFIRMED through accepted PR80:** lossless static-symbol-table insertion
  passes format, packaged-writer and GDB checks; see
  `docs/LOCAL-SYMBOL-TABLE-MERGE.md`. **CONFIRMED locally; hosted acceptance
  pending:** explicit analyst secondary labels now pass automatic ordinary
  export and runtime checks on x86-64/AArch64. Collision/code/ownership checks
  and scope limits are documented in `docs/CURATED-FUNCTION-ALIASES.md`. Other
  target/mode, sectionless and dynamic-table cases remain planned.
- [~] Distinguish definitions, declarations, imports, thunks, and aliases under
  a documented policy: real definitions and curated addressless declarations
  emit. Analyst-named memory thunks preserve typed symbols without borrowed source
  through accepted PR77; uncurated thunks remain diagnosed and omitted. The
  separate external-function inventory passes PR #42
  (`296395e` / `40126794530`) across all five targets and both hosts.
  Non-default declarations have an addressless model and producer path accepted
  in PR #49 and its separate main gate. Linkage and alias modeling
  remain separate work.

### Completion criteria

- [x] GDB displays expected function prototypes.
- [x] `ptype <function>` or equivalent output reflects return/parameter types.
- [x] Analyst-applied signature overrides are preserved.
- [x] Variadic and no-return cases are represented correctly or diagnosed.
- [~] External/import policy has independent inventory tests. Exact external
  rows/counts, qualified diagnostic names, unreferenced imports, duplicate names,
  separate memory-thunk multiplicity and cancellation pass locally. The former
  external-or-thunk log assertion did not establish external enumeration.
  The corrected shared fixture and both host smoke lists pass PR #42's exact
  hosted and main-push gates recorded above. Declaration emission remains
  separate. See `docs/FUNCTION-NAMING.md`.

## P1.8 Represent discontiguous program/function ranges correctly

**Status:** `[x]` within the documented acceptance: discontiguous and
below-entry bodies preserve exact coverage, true entry, explicit
`DW_AT_entry_pc` and entry-first range lists. Hosted run `40063017269` passes
the isolated producer/structural checks on all five current targets and six
real x86-64 ET_EXEC/PIE, rebase and deterministic-repeat cases with GDB.
Entry-first serialization also supports GDB 15.1, which ignores the explicit
entry attribute. The advanced runtime fixture is x86-64; this is not a claim
of that same runtime coverage on every target. See `docs/VALIDATION.md`.

### Work

- Retain `AddressSetView` ranges during extraction.
- Replace `[entry, max+1)` spans with explicit range sets.
- Emit `DW_AT_ranges`/`.debug_rnglists` where needed.
- Ensure CU ranges describe all relevant executable code without accidental gaps.
- Decide whether `.debug_aranges` is retained and how CU offsets are supplied.

### Completion criteria

- [x] A discontiguous function fixture has no false coverage over the gap.
- [x] GDB associates both real ranges with one function.
- [x] `llvm-dwarfdump --verify` passes.
- [x] `readelf --debug-dump=ranges` or equivalent shows expected entries.
- [x] Emit an exact code-only `.debug_aranges` index with the correct CU header
  offset, both widths/orders and no invented coverage. This supersedes the
  historical absence policy after a direct GDB global-address warning exposed
  a missing lookup path. PR #28 head `a5f7910` / run `40076025207` passes the
  format and five-profile real-export/GDB checks; normal merge `b4d7869` and
  main push `40077843290` are accepted. CU/subprogram ranges remain authoritative.
- [x] Export a function whose body includes addresses below its entry point;
  verify the true entry breakpoint, all ranges, source lookup and gap behavior
  including contiguous/interior entries and PIE/Ghidra rebasing on x86-64.
- [x] Pass the added function-entry tests in the hosted integration pipeline:
  run `40063017269`, with five-target structural and x86-64 runtime acceptance.

## P1.9 Export global variables

**Status:** `[x]` — primary non-default labels backed by defined memory data
emit typed `DW_TAG_variable` DIEs and tested `DW_OP_addr` locations across
ET_EXEC, PIE, and shared objects in all five hosted target lanes. A real typed
Ghidra external declaration emits without a fabricated location, and a
curated namespace is retained as `DW_TAG_namespace` parentage.

### Work

- Export named global/static data objects with type references.
- [x] Distinguish declarations from definitions.
- Handle absolute/address expressions and PIE/shared relocation semantics.
- [x] Preserve Ghidra namespace scope when meaningful. Library/class/function
  scopes remain out of this initial namespace-only policy.

### Completion criteria

- [x] GDB resolves and prints fixture globals at correct addresses.
- [x] Types and sizes match expected fixture data.
- [x] PIE and shared-object behavior pass under ASLR.
- [x] No memory object is exported with a guessed address.

## P1.10 Build an architecture-neutral variable storage model

**Status:** `[x]` — native-independent storage/live-range types and isolated
Ghidra 12.0.3 x86-64, AArch64, and MIPS register maps pass focused tests.
Production register, stack and register-composite extraction plus DWARF
emission are implemented under P1.11. General lifetime and migration work is
tracked separately under P1.11a.
**Blocks:** P1.11.

### Work

Represent, independently of DWARF encoding:

- Stack locations.
- Register locations.
- Register-relative locations.
- Pieces/composite storage.
- Changing locations over live ranges.
- Unavailable/optimized-away locations.
- Confidence and omission reason.

Map Ghidra registers to target DWARF register numbers using isolated architecture tables/adapters.

### Completion criteria

- [x] No generic code hard-codes `RBP` or x86 DWARF register numbers.
- [x] Storage model unit tests cover stack/register/piece/changing/unavailable cases.
- [x] Register mappings are tied to target architecture and tested.
- [x] Unknown storage cannot silently become a numeric DWARF expression.

## P1.11 Emit parameters/locals with accurate locations

**CONFIRMED resolved in PR #45:** corrected head `5e2ea7d` passes all twelve
jobs in run `40145554731`, independent exact-package/all-five-target/both-GUI
reviews and native Windows 27 suites. Normal merge `96fa0a8` retains the tested
tree. Distinct main-push run `40147478153` also passes all twelve jobs and
independent fresh target/native Windows/both-GUI artifact review. Earlier scalar-
only and computed-only candidates remain historical, unaccepted evidence.
Shared register join normalization preserves computed/custom/reopened values;
see `docs/DYNAMIC-COMPOSITE-ORDER.md`.

**CONFIRMED in PR #45 run `40145554731`:** computed dynamic
parameter storage now survives a false persisted `hasAssignedStorage()` flag.
Actual Java 21 five-language saved/reopened checks and a real ARM base/VFP
float oracle pass, with existing lifetime/omission rules unchanged. The new
generic integer fixture passes locally on all five targets and is wired to
their pipeline lanes. This does not
complete general lifetimes or ABI classification; see
`docs/DYNAMIC-PARAMETER-STORAGE.md`.

**CONFIRMED locally (2026-10-23):** mapped logical FP aliases preserve scalar
float/double arguments on x86-64/AArch64 and scalar floats on both MIPS O32
byte orders through stores, PIE and explicit rebases. First-overwrite prefix
checks still make later values unavailable. ARM32 uses canonical D-register
numbering and upper/lower scalar slices; the subsequent hosted semantic run
`40063017269` passes its scalar float/double and upper-slice runtime oracles.
Its opaque-return prefix case was explicitly unavailable in that gate; the
bounded local follow-up is recorded in `docs/TERMINAL-RETURN-PREFIX.md`.
MIPS paired doubles remain explicitly unavailable; compiler-GDB pair values
are also unverified on the tested emulator/debugger. These cases do not prove
vector, aggregate-passing, call-crossing or new ABI support. See
`docs/VALIDATION.md` for exact evidence and the independent compiler limitation.

**Status:** `[x]` within the documented baseline locations, including PR #45
register join ordering; broader lifetimes remain in P1.11a. Parameters and
recovered locals have canonical name/type DIEs. A curated locationless local is
proven in all ET_EXEC/PIE lanes and GDB
reports it optimized out. A native-independent planner and audited libdwarf
producer path now emit exact-width stable register/register-relative locations.
Production extraction admits explicit Ghidra register parameters only after an
instruction/p-code scan proves the register is never written and the function
contains no calls. GDB reads 19/23 on x86-64 and both MIPS byte orders;
AArch64's overwritten input registers are honestly omitted, while ARM32
retains only `r1` in executable/PIE roles. Exact Ghidra stack slots
are translated with instruction-level stack-pointer depths and emitted through
DWARF 5 `.debug_loclists`; GDB reads the curated local as 42 on x86-64,
AArch64, ARM32, and both MIPS byte orders for ET_EXEC and PIE. Exact entry-live
register locals use the same whole-function overwrite/call-clobber proof;
GDB reads the curated register local as 31 on x86-64, AArch64, and both MIPS
profiles for ET_EXEC and PIE; ARM32's `r3` is overwritten and omitted.
**HISTORICAL:** explicit register composite tests supplied memory-order pieces
and emitted `DW_OP_bit_piece` sequences. Those injected, unused locals did not
prove Ghidra join semantics. PR #45 corrects their significance-order storage
and verifies the unchanged expected values.
GDB reconstructs the curated 64-bit value
on the same four profiles, while ARM32's overwritten piece remains
locationless. A controlled stack-depth change proves the stack local resolves
as 42 in two different location-list ranges on all five targets. Unsupported
or uncertain storage remains locationless with a diagnostic.
**Dependency:** P1.10.

### Work

- Emit parameters and local variables with type references.
- Emit simple `DW_AT_location` expressions when storage is stable.
- Emit `.debug_loclists` when storage changes over address ranges.
- Add `DW_AT_frame_base` only when a defensible model exists.
- Handle piecewise storage when supported.
- Omit location while retaining name/type when evidence is insufficient.

### Completion criteria

- [x] GDB prints a stack parameter/local correctly at a breakpoint.
- [x] GDB prints production Ghidra register parameters correctly on x86-64 and
  both MIPS byte orders; overwritten AArch64 input registers are omitted.
- [x] A changing-location fixture resolves correctly in each tested live range.
- [x] Unavailable variable produces an honest unavailable/optimized-out result rather than an incorrect value.
- [x] `llvm-dwarfdump --verify` passes for every production stable-register and
  stack-location-list lane.
- [x] x86-64 register-number mapping has explicit tests.

## P1.11a Extend proven variable lifetimes and storage migration

Tracking: [#67](https://github.com/zwilcox/GhidraDwarfForge/issues/67).

**CONFIRMED through accepted PR78:** a second completed incoming
scalar register backup preserves the value after the first backup is killed.
Six x86-64/AArch64 exec/PIE/rebase roles pass twelve candidate exports, six
previous-package comparisons and 1,188 compiler/Forge/previous GDB observations.
The 186 decoder checks, 24 actual Java 21 packaged suites, twelve existing copy
regression exports and ten five-profile parameter exports pass. Both proofs
must agree on the exact handoff; no calls, arbitrary chains or mutable-local
identity are inferred. See `docs/SECOND-REGISTER-COPY.md`. P1.11a remains partial.

**HISTORICAL local checkpoint, accepted through PR62 above:** a curated local's
recorded full-width register definition now starts availability only after that
instruction completes. A stale-value sentinel proves the earlier interval is
unavailable. Twelve definition/read regression roles pass 24 candidate exports,
six preceding-package comparisons and 1,152 GDB observations. Nineteen actual
Java 21 suites pass. See `docs/LOCAL-DEFINITION-BOUNDARIES.md` for exact evidence,
retained failed attempts and limits; general lifetime and lexical-scope recovery
remain incomplete.

**CONFIRMED integration (2026-10-25):** stack-spill PR60 head
`2b0666ff7cc5b1ff44cd7420522c57737cc72d43` passes all twelve jobs in
`40244794589`, exact-package/seventeen actual Java 21 suites, raw five-target
review, 38 native Windows tasks and both GUI hosts. The new stack cases cover
six roles, twelve exports and 900 hosted compiler/Forge GDB observations.
Normal merge `47ff38ebbfe2ac5eb8e7d2f3d0ec445fdb29dc95` preserves the accepted
tree. Independent receipt SHA-256:
`a84e37a5ccc878f2fcacae2dbf53726db7326585ca5b7dc838d1bb4f21ecf225`.
Separate main-push run `40247374065` at that merge also passes all twelve
jobs and independent exact-package, raw target, GUI and native Windows review.
Main receipt SHA-256:
`ec1358c3d2b4a99772b659be447497346aa16fe6046d86d142f7a36560dbe3a7`.
Earlier pending stack-spill notes are historical; general migration and other unfinished work remain open.

**HISTORICAL local checkpoint, accepted through PR61 above:** explicit
function-owned register locals with positive first-use offsets now have a
bounded proof: one exact read after a completed definition, no overlapping
variable storage, and a fully decoded straight-line leaf. Six exec/PIE/rebase
roles pass twelve exports, six preceding-package comparisons, 594 GDB stops
and eighteen actual Java 21 suites. Earlier/later intervals remain unavailable.
Original lexical scopes, inferred locals and general migration remain planned;
see `docs/LATER-REGISTER-LOCALS.md` for exact evidence and retained failures.

**HISTORICAL local checkpoint, accepted through PR60 above:** one complete
incoming scalar stack save now preserves the value after register loss, ending
at any later memory or stack-pointer write. Six x86-64/AArch64 exec/PIE/rebase
roles pass twelve exports, six previous-package comparisons and 1,350 GDB
observations; 106 model controls and seventeen actual Java 21 suites pass.
See `docs/STACK-SPILL-LIFETIMES.md`. Broader migration remains incomplete.

**HISTORICAL local checkpoint, accepted through PR59 above:** ordinary terminal
return handling now preserves proven ARM incoming scalar/composite prefixes.
The complete value becomes unavailable after its first piece overwrite.
Models, actual Java 21 packaged suites and QEMU compiler/GDB regressions pass;
see `docs/TERMINAL-RETURN-PREFIX.md`. This does not complete mixed pieces,
register/memory migration, later-starting locals or broader call/flow support.

**HISTORICAL local checkpoint, accepted through PR54:** one already
proven scalar register backup now survives a direct, fully decoded leaf call
only when the selected callee ABI and all caller/callee writes prove it remains
intact. x86-64/AArch64 compiler and preceding-package GDB comparisons retain
values across the call and expose an unavailable restore tail. 140 model checks,
actual Java 21 packaged suites and structural validators pass. General calls,
memory migration and mixed pieces remain **PLANNED**. See
`docs/DIRECT-LEAF-CALL-BACKUPS.md`; the broader checklist remains partial.

**CONFIRMED in PR #47 run `40200733276` and distinct main run `40204254359`
(all twelve jobs and reviewed artifacts):** retain a complete incoming register composite
before its earliest physical-register overwrite, then make the whole value
unavailable. An independently reviewed x86-64/AArch64 ET_EXEC probe establishes
the omitted incoming values and exact partial-register clobber boundaries.
Actual Java 21 source checks 469 and packaged checks 469/1480/154/182 pass; ten
relevant Gradle regressions and the extension build pass. Fresh x86-64/AArch64
computed/custom/reopened exports pass validators and GDB with unchanged inputs
and deterministic output. Independent source/package/raw reviews pass. Final committed packaging and both hosted gates pass; normal merge
`ffc16713cc1be34924519544356b5d6f57e851f1` preserves the accepted tree. See
`docs/COMPOSITE-REGISTER-PREFIX.md`. This adds no call-crossing, surviving-piece,
backup, mixed-memory or later-local inference.

**CONFIRMED in PR #46 run `40148228012`:** the truncated-RAM STORE
proof composes with the shared register join correction. All twelve jobs,
independent exact-package/all-target/both-GUI reviews and 28 native Windows
suites pass. Fresh downloaded-package actual Java 21 checks pass
231/38/154/1480/182. The four O32/N32 cases pass compiler/GDB and strict-zero
validation. Normal merge `800081f` preserves the tested `ea4f9c0` tree; distinct
main-push run `40150436365` also passes all twelve jobs and independent fresh
target/native Windows/both-GUI review. This does not prove
call-crossing lifetimes or general ABI support; see
`docs/TRUNCATED-MEMORY-STORES.md`.

**CONFIRMED in hosted run `40081385807`:** a nonzero first-use field on an
already stored stack local is diagnosed and its location omitted, retaining
name/type/offset. Five-profile extraction and actual Java 21 tests pass.
All twelve jobs, exact package and independent x86-64/AArch64 twelve-export
and both-host reviews pass for PR #30 head `fb2fa406`; normal merge `74a7466`
preserves the tested tree. The prior exporter reproduces the wrong earlier
value in all six roles; zero-offset locals remain correct. See
`docs/STACK-FIRST-USE.md`; no general slot-reuse boundary is inferred.

**CONFIRMED in hosted run `40079317009`:** exact PR #29 head `698e939` passes
all twelve jobs. The bounded register-copy fixture passes x86-64/AArch64
exec/PIE/rebase exports, validators and 72 calls per debugger mode, with
independent package and targeted runtime/host-artifact reviews. Normal merge
`25f9830` preserves the tested tree.
It tracks one direct saved
register through the original overwrite, then stops at an unproved backup
write. The whole-function flow/opaque guards remain mandatory. No call,
memory, arbitrary-chain or later-local recovery is implemented. See
`docs/REGISTER-COPY-LIFETIMES.md`; the broader criteria below remain partial.

**CONFIRMED locally:** the opaque-effect guard rejects `CALLOTHER` and
`UNIMPLEMENTED` in the whole-function register proof, shared by parameters,
locals and composites. A narrowly checked ordinary terminal-return boundary
preserves proven ARM scalar storage. No pre-syscall prefix, syscall whitelist
or copied-register tracking is inferred. The new AArch64 runtime regression
and Linux/native Windows real-Ghidra smoke are required CI gates; exact hosted
acceptance passed in `40073884397`; normal merge `ce0c3a4` preserves that tested
tree. This does not complete the broader lifetime/migration tasks below.

**Status:** `[~]` — **CONFIRMED in hosted run `40063017269`:** a simple incoming
register parameter now retains its location through the first overwriting instruction in a fully
decoded straight-line leaf function, then becomes explicitly unavailable. The
new x86-64/AArch64 compiler/GDB oracle covers ET_EXEC/PIE, rebases and repeated
exports. Both target-specific hosted lifetime gates pass.
Later first-use, calls, branches, discontiguous bodies, delay slots, storage
migration and mixed pieces remain outside this bounded proof. The existing
changing-stack test proves SP-relative adjustment, not value migration.

- [~] Establish evidence-backed machine-address live ranges for register
  variables that begin after entry or whose registers are later overwritten.
  Incoming single-register parameters before a proven first overwrite pass
  in the hosted x86-64/AArch64 gates. Curated read-start locals pass PR61's
  complete hosted gate; definition-start locals pass PR62's separate gate. General later variables and other control-flow shapes remain planned.
- [~] Track supported register-to-register and register-to-stack moves across
  calls using the selected ABI and recovered instruction evidence. The bounded
  direct-leaf register-backup case passes PR54's complete hosted gate. PR60
  separately accepts one direct scalar stack spill in a straight-line leaf;
  broader call-crossing and register/memory cases remain pending.
- [~] Test stack-local first-use and slot-reuse boundaries; record unavailable
  intervals where identity or lifetime cannot be established. The bounded
  nonzero-stack-first-use omission passes exact hosted compiler/GDB tests in
  `40081385807`; general identity/lifetime recovery remains pending.
- [~] Support mixed register/memory composite pieces when every piece has
  defensible size, order and lifetime information. **CONFIRMED through PR59's
  complete hosted gate:** attached incoming register/stack joins retain a bounded
  prefix before any possible memory/register write, with analyzed SP adjustment
  and whole-value unavailable tails. ARM computed/custom exec/PIE/rebase/repeat
  passes; other memory joins and migration remain planned. See
  `docs/MIXED-INCOMING-PREFIX.md`.
- [~] Compare GDB values with compiler-oracle fixtures at multiple PCs on each
  claimed profile, including intentionally unavailable gaps. The bounded
  x86-64/AArch64 prefix cases pass; broader lifetimes/storage remain planned.
  Retain validators, deterministic output, input preservation and cancellation tests.

Ghidra high-variable/symbol evidence is a possible input, not proof of original
compiler lifetimes. Analyst-defined listing information retains precedence.

## P1.12 Complete semantic GDB milestone

**Status:** `[x]` for the required x86-64 non-PIE fixture and its documented
semantic checks; hosted evidence is recorded under P2.12.
**Dependencies:** P1.6–P1.11.

### Completion criteria

For the initial x86-64 non-PIE fixture:

- [x] `info functions` shows recovered names.
- [x] `list` shows synthetic source.
- [x] `ptype` shows expected struct/enum/typedef/function-pointer shapes.
- [x] `print` reads supported globals, parameters, and locals correctly.
- [x] Unsupported variable locations are honest.
- [x] Discontiguous ranges are correct.
- [x] All structural validators pass.
- [x] Default export leaves original target unchanged.

---

# P2 — Address relocation, architecture, and host portability

## P2.1 Implement and validate PIE address/load-bias behavior

**Status:** `[x]` — symbol addresses are normalized from Ghidra's image
base to ELF link-time VAs. Runtime breakpoints, source/type behavior, globals,
stable registers, and stack location lists pass under ASLR. A Ghidra project
rebased by `0x2000000` produces link-time DWARF that passes validators and the
full x86-64 GDB behavior oracle; checked conversion tests cover both rebase
directions and overflow.
**Dependency:** P0.8/P0.9 address model.

### Work

- Distinguish Ghidra image-base addresses, ELF link-time virtual addresses, and runtime relocated addresses.
- Determine how GDB applies load bias for the selected sidecar format.
- [x] Handle a Ghidra program that has been rebased.
- [x] Add a PIE fixture and runtime GDB test.

### Completion criteria

- [x] Symbol breakpoints resolve at correct runtime addresses under ASLR.
- [x] Source rows, types, and current supported variables remain aligned after
  relocation.
- [x] Rebased Ghidra input is normalized to original ELF link-time addresses.
- [x] Address conversions are unit tested, including checked overflow.

## P2.2 Support shared objects

**Status:** `[x]` — real stripped `ET_DYN` libraries export through headless
Ghidra and pass hosted structural plus runtime GDB validation on x86-64,
AArch64, ARM32, and MIPS32 big/little endian.

### Work

- [x] Add `ET_DYN` shared-library fixtures.
- [x] Build the library from a dedicated source that does not define `main`.
- [x] Test loading before and after the library is mapped.
- [x] Verify exported function/global addresses and load bias.
- [x] Document exact GDB commands for shared-library sidecars.

### Completion criteria

- [x] GDB loads link-time symbols before mapping and reloads them with the
  observed runtime load bias after mapping.
- [x] The recovered function breakpoint and global address/value resolve after
  load.
- [x] The runtime function address is checked against the main executable.
- [x] The shared-library ELF has no defined `main` symbol.
- [x] Structural and behavior tests pass in all five hosted target lanes.

## P2.3 Add AArch64 target support

Tracking: [#68](https://github.com/zwilcox/GhidraDwarfForge/issues/68).

The shared [target-profile contract](docs/TARGET-PROFILES.md) records the
existing five profiles and a finite follow-up order for P2.3/3a/3b. The
read-only audit is **CONFIRMED**; ABI classification/diagnostics, scalar FP,
stack-passed parameters and real aggregates remain **PLANNED** until their
specific runtime gates pass. Accepted machine/class metadata is not proof of
all calling conventions for that processor.

**Status:** `[~]` — the symbol/source-line/type/signature milestone passes in
hosted CI for ET_EXEC, PIE, shared objects, and no-section inputs. Stack-local
locations pass. Hosted run `40063017269` additionally proves scalar float/double
aliases and bounded incoming-register prefixes; values after the proven
prefix remain unavailable. Additional storage and ABI cases remain beyond
this documented profile.

### Work

- Add AArch64 ELF fixtures.
- Verify `e_machine`, ABI flags, endianness, pointer/address size.
- Implement/test AArch64 DWARF register mapping.
- Validate parameter/local locations under AAPCS64.
- Test non-PIE first, then PIE/shared object.

### Completion criteria

- [x] Symbol/source-line milestone passes for AArch64 non-PIE and PIE.
- [~] Type/signature and stack-local milestones pass; additional variable
  storage classes remain.
- [x] AArch64 PIE/shared cases pass in hosted CI, including the fresh alpha
  release validation run recorded under P2.13.
- [x] A repository guard confines architecture identifiers/register spellings
  to target-description boundaries.

## P2.3a Add MIPS target support

Tracking: [#69](https://github.com/zwilcox/GhidraDwarfForge/issues/69).

**Status:** `[~]` — hosted real headless symbol export, structural validation,
and QEMU/GDB runtime breakpoints pass for MIPS32 big/little endian ET_EXEC,
PIE, shared-object, and no-section-table inputs; `ptype`, stable register
parameters, and stack locals pass. The alpha release validation includes both
MIPS lanes. Hosted run `40063017269` also proves function-owned statics and
scalar float locations in both byte orders. Paired doubles remain unavailable;
the independent compiler-pair observation is explicitly unverified under the
tested QEMU/GDB transport. Additional storage and ABI cases remain.

**CONFIRMED in PR #46 run `40148228012`:** four owned O32/N32
freestanding cases in both byte orders identify an honest N32 omission caused
by eight-byte STORE address operands targeting an explicitly truncated
four-byte RAM space. O32 dynamic stack arguments have correct observed values;
its wide pair remains modified. The selected follow-up proves only that a
well-framed STORE into matching declared RAM cannot redirect its wider offset
to a different space; the separate tracked-register clobber check also protects
memory-mapped registers. No ABI classifier, register map or broad N32 support change
is selected. Actual Java 21 decoded/malformed-space controls and four packaged compiler/
Forge runtime comparisons pass locally, including N32 entry values, O32 stack
arguments and the retained wide-pair omission. Validators, repeats and independent
raw review pass. The complete twelve-job PR gate, 28 native Windows suites,
all-five-target/both-GUI reviews and exact package audit pass; normal merge
`800081f` preserves the tested tree. Separate main-push run `40150436365` also
passes all twelve jobs and independent fresh artifact review.
See [the bounded contract](docs/TRUNCATED-MEMORY-STORES.md).

**CONFIRMED locally; hosted acceptance pending:** an explicit FP32 profile now
provides a strict positive compiler double-argument reference in both byte
orders. Twelve Forge exports across exec/PIE and baseline/rebase/repeat retain
correct scalar floats and honest paired-double omissions. FPXX still fails the
strict compiler control with zero. This establishes a testing prerequisite;
paired-location emission and broader ABI classification remain incomplete.
A second form now proves positive Forge doubles for explicitly curated FPR
pieces through the existing generic composite path, with exact raw order and
runtime values on both byte orders and exec/PIE/rebase. The whole-alias negative
control remains unavailable. Automatic alias expansion and broader ABI
classification remain incomplete. Both forms await their hosted gate.
See `docs/MIPS-FP32-ORACLE.md`.

### Work

- Add source-built MIPS ELF32 big-endian fixtures from the shared semantic
  fixture source.
- Derive MIPS ABI, ELF flags, endianness, address size, and relocation choices
  from the original ELF rather than processor-name guesses.
- Isolate and test MIPS DWARF register mappings for the selected ABI.
- Add a documented QEMU user-mode or system-mode test environment with a
  matching cross-GDB/toolchain.
- Run the real headless exporter, structural validators, and scripted GDB
  behavior checks under that environment.
- Add PIE/shared-object coverage before claiming broad MIPS support.

### Completion criteria

- [x] Producer ABI smoke test emits 32-bit big-endian MIPS DWARF buffers with
  correctly sized symbolic target relocations.
- [x] Headless Ghidra imports and exports the source-built MIPS fixtures.
- [x] QEMU plus `gdb-multiarch` executes both MIPS byte orders and proves the
  compiler-DWARF oracle breakpoint/arguments/source-step/local-value workflow.
- [x] `readelf`, `llvm-dwarfdump --verify`, independent `dwarfdump`, and GDB
  source/type behavior checks pass for the current artifacts.
- [x] QEMU runtime addresses/load bias agree with emitted DWARF for non-PIE,
  PIE, and shared objects.
- [x] A repository guard confines MIPS-specific code to target descriptions and
  register maps.

## P2.3b Add ARM32/AArch32 target support

Tracking: [#70](https://github.com/zwilcox/GhidraDwarfForge/issues/70).

**Status:** `[~]` — the ARMv7 hard-float, little-endian ARM-state profile passes
the hosted producer, real headless exporter, structural-validator, and
QEMU/GDB behavior matrix for ET_EXEC, PIE, shared objects, no-build-ID inputs,
and program-header-only inputs. Thumb, big-endian ARM, and additional ABI or
storage profiles are not claimed.

**CONFIRMED old-exporter reproduction:** a mixed ARM/Thumb ET_EXEC fixture imports and
exports with correct Ghidra instruction context and clean validators, but GDB
15.1 disassembles the stripped input's recovered Thumb function as ARM before
execution. Runtime success can depend on the current CPSR and does not establish
static mode support. A separate saved-project repeat is deterministic.
**CONFIRMED in hosted run `40138005382`:** PR #44's bounded correction restores
defensible ELF mode cues and passes all twelve jobs plus independent package,
ARM/shared and both-GUI/native-Windows reviews. It merged normally as `f359d18`
with the tested tree. Synthesis is restricted to ET_EXEC without named defined
dynamic symbols; the shared-object regression found by the second gate is
corrected without weakening its GDB oracle. Distinct main-push run `40140510117`
also passes all twelve jobs and independent fresh both-GUI/native Windows 25,
ARM and strict-validation reviews.
This does not complete Thumb profile support; see
[the scope](docs/research/ARM-THUMB-MODE.md).

**CONFIRMED in hosted run `40063017269`:** six scalar-FP
exec/PIE/rebase/repeat cases pass stable float/double and upper-`s1` value
checks with strict validation. Function-owned static scopes also pass with
the native EHABI fixture precondition. The clobbered mode-switching-return
case required explicit unavailability in that gate. The bounded terminal-return
follow-up passes locally; general ARM prefix lifetimes remain incomplete.
See `docs/TERMINAL-RETURN-PREFIX.md` and `docs/VALIDATION.md`.

### Work

- Add a source-built `arm-linux-gnueabihf` fixture using the shared semantic
  source.
- Derive ELF32 target identity and isolate the ARM DWARF register map.
- Exercise the same production exporter path used by the other target lanes.
- Validate source/type/global behavior, PIE/shared load bias, stack location
  lists, and honest omission of overwritten registers under QEMU/GDB.

### Completion criteria

- [x] The isolated producer emits 32-bit little-endian ARM DWARF buffers.
- [x] Ghidra imports and exports ARM32 ET_EXEC, PIE, shared-object,
  no-build-ID, and no-section-table fixtures.
- [x] `readelf`, `llvm-dwarfdump --verify`, and independent `dwarfdump`
  accept every current ARM32 Forge artifact.
- [x] QEMU plus `gdb-multiarch` proves function/source/type/global behavior,
  PIE/shared load bias, and the changing stack location.
- [x] ARM register mappings are isolated and covered by native-independent
  storage tests.
- [ ] Thumb, big-endian ARM, and additional ARM ABI/storage profiles are
  separately modeled and validated before any broader support claim.

## P2.3c Add bounded i386 target coverage

Tracking: [#71](https://github.com/zwilcox/GhidraDwarfForge/issues/71).

**Status:** `[~]` — a bounded Linux
i386 integer/stack profile now uses isolated ELF and GPR tables. Fully stripped
exec, sectionless ELF, PIE and rebased PIE pass eight exports, 1,440 debugger
observations at every fixture instruction, strict-zero validation, twenty actual
Java 21 suites and sixteen isolated packaged producer lifetimes. Later stack
locals remain unavailable. See `docs/I386-INTEGER-PROFILE.md`; libc/shared,
floating/vector and broader ABI/host claims remain outside this checkpoint.

- [x] Local isolated target/GPR model and producer baseline.
- [x] Local real export/validator/GDB exec, sectionless, PIE and rebase profile.
- [x] PR63 exact-head full hosted gate and independent package/runtime review.
- [~] Shared-library exec/PIE drivers with Ghidra rebases: prior local review
  passes; corrected-exporter rerun passes; exact-head hosted acceptance is pending.
- [ ] Broader libc, floating/vector and host-specific profiles before expanding
  the documented support claim.

## P2.4 Validate Windows-hosted Ghidra

**Status:** `[x]` — the Windows CI lane builds and audits pinned MinGW DLLs,
runs isolated native/publisher/source smoke tests, performs real Ghidra 12.0.3
headless exports with explicit and packaged natives, and validates source bytes
plus ELF/DWARF. GitHub Actions run 33778570507 passed the complete lane,
including explicit Windows file-lock contention and rollback.
**Dependencies:** pinned Windows natives and corrected JNA ABI.

### Work

- [x] Install/test selected Ghidra baseline on Windows.
- [x] Verify JNA finds both the explicitly supplied and packaged
  `libdwarf`/`libdwarfp` DLL pairs.
- [x] Audit and bundle non-system MinGW runtime dependencies.
- [x] Output paths, atomic replacement, UTF-8/LF, and explicit Windows
  file-lock contention rollback pass.
- [x] Run a real ELF target export with Windows `readelf` and LLVM validation;
  executable GDB behavior remains in the Linux native/QEMU lanes.

### Completion criteria

- [x] Extension loads and exports without access violation.
- [x] Native CI artifacts include documented non-system runtime dependencies.
- [x] Generated source and artifact semantics match the Linux reference.
- [x] Windows-hosted export passes structural validators; executable ELF/GDB
  behavior passes in the supported Linux lanes.
- [x] Host validation is included in CI.

## P2.5 Add ELF32 support

**Status:** `[x]` — ELF32 container, DWARF, line mapping, locations, validators,
and GDB source/type behavior pass for ARM32 and MIPS32 big/little endian. The
table-driven target-profile regression passed in GitHub Actions run 33824105805.

### Work

- Implement ELF32 headers/section headers and target metadata.
- Add at least one 32-bit fixture.
- Verify 32-bit DWARF address size independently of DWARF offset size.
- Add 32-bit architecture register mapping and locations for the selected target.

### Completion criteria

- [x] No ELF64 header/layout code is used for the 32-bit artifact.
- [x] Validators and GDB pass for the selected 32-bit targets.
- [x] Current 32-bit pointer/address and DWARF32 offset combination is tested.

## P2.6 Add big-endian support

**Status:** `[x]` — MIPS32 big-endian container, DWARF 5 line/type/location
serialization, validators, and QEMU/GDB pass. Fail-closed rejection for
unsupported big-endian target profiles passed in GitHub Actions run 33824105805.

### Work

- Select a practical big-endian test architecture/toolchain.
- Verify target ELF metadata, DWARF byte order, and libdwarfp flags.
- Test all integer/section serialization paths.

### Completion criteria

- [x] Big-endian fixture artifact passes validators.
- [x] GDB resolves expected symbols/source mappings under QEMU.
- [x] Unsupported big-endian targets fail explicitly rather than producing
  little-endian output.

---

# P2 — Product behavior and integration

## P2.7 Add output selection, fallback, and atomic pair commit

**CONFIRMED:** PR #31 at `3632f2b` passed all twelve jobs in exact hosted run
`40087258846` and merged normally as `00aaba1`. The follow-up corrects actual parent
traversal through directory links without renaming input-link defaults or
following replaceable output leaves. Public pair publication now rejects all
stage/final aliases and non-file final entries before mutation, preserves
dangling links during rollback, and keeps stale-input guidance accurate.
Eight final packaged exports and three rejection cases pass independent
review, validators, GDB and original/program-database preservation. Native
Windows Java 21 passes all twelve focused checks, actual short-parent lookup,
the real trailing-dot alias control, both publisher APIs in both target orders,
and the GUI journey. Linux GUI and exact package audits also pass. See
`docs/FILESYSTEM-PATHS.md` and the final acceptance record in `docs/VALIDATION.md`.
Earlier missing-helper and short-parent test-oracle failures remain historical
evidence, superseded by this exact gate. This does not implement the separate
P2.8 attachment transaction or guarantee arbitrary filesystem alias handling.

**Status:** `[x]` for the validated paths — deterministic default and explicit paths, stale-path input
override with imported-file hash verification, preflight collision/write
checks, staged pair rollback, and final hashes pass locally. Automated Linux
GUI fallback selection/cancellation passes locally and in hosted run
`39896787460`, in a genuine non-headless Ghidra 12.0.3 process under Xvfb,
including validators and GDB source stepping.
The installed Export launcher now passes actual Linux Script Manager discovery,
double-click Run, Console reporting and chooser selection/cancellation in
`gui-script-manager.sh`. Run `40054563515` at `83b74a6` also passed the full
native Windows journey; this component evidence does not substitute for the
combined-head gate. That gate subsequently passed in run `40068401197` at
`9612655`, including both hosts' real Script Manager/chooser journeys and the
shared pending-filter control. The independent 100-window/Openbox geometry
control is Linux-only. See the combined acceptance record in `docs/VALIDATION.md`.

Additional user-journey coverage:

- [x] Verify Script Manager discovery, launch and report presentation using
  the documented installed-extension workflow on Linux. The native-free
  metadata script and the explicit Export launcher are distinct installed
  entries; this test does not directly construct either production script.
  The first hosted Script Manager run exposed a covering-window focus race;
  foreground/Name-cell targeting passes locally. Later Windows activation
  intentionally focused Ghidra's filter, exposing a separate harness pre-click
  assertion race. The correction verifies real double-click delivery instead
  of requiring table keyboard focus; controlled and full Linux checks pass.
  Run `40062946718` then exposed delayed observation while Ghidra's mouse
  handler compiled scripts in a modal loop. Pre-dispatch event observation
  passes a controlled reproduction and full Java 21 Linux journey
  `run.O3SsqvwH`; no launch retries or timeouts changed. These were local
  results pending the subsequently completed combined gate above.
  Run `40064976588` then demonstrated inconsistent native/Java window
  coordinates under bare Xvfb. An owned Openbox session and independent native
  geometry control pass 100 cases and the full Java 21 Linux journey
  `run.KPdcV6p3`; hosted acceptance was still pending at that checkpoint.
  A subsequent combined-product run exposed a pending Ghidra table-filter
  update that cleared selection during the double-click. Buffered event and
  selection-stack evidence reproduces the null selected script; the harness
  now waits for the actual refresh/filter/sort work and queued selection repair.
  A real Ghidra filter control covers that readiness boundary without launch
  retries; final combined-product Linux run `run.LFXUdxrq` passes all controls,
  chooser outcomes, validators and GDB. Run `40068401197` then passed the
  combined Linux/native Windows hosted gate without retrying the launch action.
- [x] Exercise native Windows output selection and cancellation; verify
  chosen paths, original preservation and no final artifacts after cancellation.
  A real desktop-click/ACL-denial probe precedes the full Windows Script Manager
  harness in CI. The latter uses packaged Windows natives, selected paths with
  spaces, input hashes, Console reports, and native GNU/LLVM validators. Both
  passed in `40054563515`; independent `dwarfdump` was unavailable and Linux
  ELF runtime GDB checks were not run on Windows. The final readiness correction
  also passed the full native Windows journey in run `40068401197`, with the
  same explicit validator/runtime limitations.

### Work

- [x] Default to the executable directory when valid/writable.
- [x] Detect missing, stale, or unwritable `Program.getExecutablePath()`;
  inaccessible remote paths follow the same explicit-input/output failure
  policy rather than receiving guessed behavior.
- [x] Offer/select an output directory in GUI mode; the production chooser is
  exercised automatically with real Swing controls and mouse clicks.
- [x] Accept explicit input/output paths in headless mode.
- [x] Write `.dbg` and `.dbg.c` to temporary files.
- [x] Commit the pair atomically as far as the host filesystem permits.
- [x] Report final paths and SHA-256 hashes.

### Completion criteria

- [x] Default path behavior satisfies issues #1–#3 for a normal local file.
- [x] Unwritable-path policy fails before writing in headless mode; GUI
  selection publishes to the chosen directory and cancellation publishes nothing.
- [x] Headless path is deterministic and non-interactive.
- [x] Cancellation/failure leaves no mismatched final pair.

## P2.8 Add optional `.gnu_debuglink` attachment

Tracking: [#72](https://github.com/zwilcox/GhidraDwarfForge/issues/72).

**CONFIRMED:** PR #32 head `c94158b` passes all twelve jobs in exact hosted run
`40091937766` and merged normally as `7f9c0d2`. The read-only foundations
combine streamed SHA-256/GNU CRC32/byte count (`FileDigests`) with bounded typed
GNU build-ID observations (`ElfBuildId`). Existing SHA callers share the digest
helper; ordinary export does not call the build-ID observer. Actual Java 21
focused checks and both installed-JAR independent oracles pass. The combined
package passes seventeen fresh exports: nine x86-64/AArch64/MIPS32 big-endian
semantic cases and eight saved-program path exports, plus three rejection
cases, validators and GDB. The digest oracle also passes a file above 2 GiB
under a 64 MiB heap. See `docs/FILE-DIGESTS.md`,
`docs/ELF-BUILD-ID-OBSERVATIONS.md` and the combined local validation record.
Both helper oracles pass all five target lanes, including independent artifact
review, x86's large-file case, fourteen native Windows focused checks and both
GUI hosts. Observed
hashes or matching IDs do not establish file identity, parse receipts or expose
attachment; the full transaction remains planned.

The first combined hosted run `40089908416` failed its x86 digest report binding:
a later default-output test reused the primary log filename for a different
output pair. Java/Python digests agreed; the path/hash assertion correctly
rejected the mismatched report. Both helper oracles now run directly after the
primary export/GDB step, with exact consumed transcripts retained. Three local
profile replays and a stale-report negative pass; the corrected full gate above
subsequently passed. The failed initial run did not reach x86's large-file/
build-ID checks or native Windows and remains historical failure evidence.

**CONFIRMED:** PR #33 head `67785a4` passes exact hosted run `40094712284`,
all twelve jobs and independent package/target/GUI reviews, and merged as
`464caf7`. `ExportReportClaims` adds a separate bounded reader for the current report shape. It preserves opaque path/hash/count
claims and opens only the report. Actual Java 21 focused checks, 429 malformed
controls, default resource boundaries and an installed-JAR oracle on nine
retained x86-64/AArch64/MIPS32 big-endian reports pass with independent review.
Valid terminal reports and unsupported historical shapes are distinguished;
no file identity or independent validator result is inferred. See
`docs/EXPORT-REPORT-CLAIMS.md`. All five hosted reader artifacts, fifteen native
Windows focused checks and both GUI hosts pass. This does not add attachment or
its receipt chain.

**CONFIRMED:** PR #34 head `888406e` passes exact hosted run `40097366322`,
all twelve jobs with independent package, all-five-target and both-GUI artifact
reviews, and merged normally as `837cec8`. `MatchedElfPrefix` checks
the bytes retained by the current matched writer through original EOF, with
exactly the documented header exceptions and a required appended-table layout.
Actual Java 21 focused tests cover both classes/orders and an input above 2 GiB
with a 64 MiB heap. The installed independent oracle passes eighteen fresh
x86-64/AArch64/MIPS32 big-endian pairs, with validators and GDB; independent
artifact review is clear. Matching prefixes do not prove the active appended
section addresses, DWARF, identity or attachment readiness. Thirty real pairs and repeated comparisons, the x86 large-file case and sixteen
native Windows focused checks pass the hosted gate. See `docs/MATCHED-ELF-PREFIX.md`.

**CONFIRMED:** PR #35 head `d5bd9fe` passes exact hosted run `40099934709`,
all twelve jobs and independent package, all-five-target and both-GUI artifact
reviews, and merged normally as `0f05ec8`. `MatchedElfAllocations` complements
the copied-prefix check with indexed active-metadata correspondence. Target
fields, retained sections, inert relocation placeholders and sectionless
LOAD/note reconstruction are checked; ambiguous note mappings, allocated debug
transformations and non-round-tripping allocated names stay explicitly unsupported.
Actual Java 21 focused/default-limit checks and an installed oracle on eighteen
retained real-export pairs pass, with independent source/runtime review. These
are metadata observations, not proof of copied code, a snapshot or attachment
readiness. Thirty hosted pairs, 63 metadata mutations and seventeen native
Windows focused checks pass, including 532 allocation assertions. See
`docs/MATCHED-ELF-ALLOCATIONS.md`.

**CONFIRMED:** PR #36 head `c526102` passes all twelve jobs in exact hosted
run `40102754052` and merged normally as `18b3e2e`. The separate
`ExportArtifactHashBinding` composes strict report-first parsing with observed
digests of three explicitly selected regular files. Actual Java 21/64 MiB
focused checks and independent source/runtime reviews pass, including files
above 2 GiB. Installed oracles pass nine retained real reports across three
targets. Opaque reported paths remain inert; per-role SHA agreement is not provenance,
ELF/DWARF validation, a snapshot or attachment readiness. Local package review
is clear. All five target artifacts pass independent review: fifteen reports,
45 retained copies, 35 mismatch subsets and forty typed failures. Native Windows
passes eighteen focused checks, including 551 platform-applicable binder
assertions; both GUI hosts and the x86 large-file case pass.
See `docs/EXPORT-ARTIFACT-HASH-BINDING.md`.

**CONFIRMED:** PR #37 head `89fa8b7` passes all twelve jobs in corrected exact
run `40107222339` and merged normally as `29055f6`. `ExecutableProgramBytes`
checks the complete declared ELF header, raw program table, resolved extended
counts and all non-NULL file payloads with exact section-table-field exceptions.
Callback corrections `c38cd98`/`791631f` preserve supplier exception identity
in the program/prefix readers; program checks now pass 434/446 on actual
Java 21 under 64 MiB, including both widths/orders above 2 GiB. Independent
source review is clear. Nine private
backend candidates from retained x86-64/AArch64/MIPS32 big-endian exports pass
the installed independent oracle and all 27 existing GDB association checks.
The corrected installed run also passes; original fixtures remain unchanged.
The research probe now rejects the known
out-of-LOAD NOTE mutation. This is scoped byte correspondence; active section
metadata and debuglink CRC remain separate checks. All five target artifact
audits and both GUI reviews pass; native Windows passes nineteen focused
checks, including 431 program assertions applicable to that host. See
`docs/EXECUTABLE-PROGRAM-BYTES.md`.

**CONFIRMED:** PR #38 head `b269ec5` passes all twelve jobs in exact run
`40110565271` and merged normally as `2bd6739`. `DebuglinkCandidateContent`
adds separate indexed executable-allocation and exact new-link observations
alongside the program-byte result and streamed selected-sidecar digest. It is
used in the existing private-copy integration/research consumers; no aggregate
attachment approval is exposed. Source `e30fae3` passes 970/972 actual-Java-21
checks under 64 MiB. The corrected parent is incorporated, and nine new private
candidates pass both installed oracles and all 27 GDB association checks.
Independent source/runtime review verifies 72 controls, 27 input copies, 135
parent evidence files and a full sparse sidecar digest above 2 GiB. Independent
exact package, all-five-target and both-GUI reviews are clear. Native Windows
passes twenty focused checks with 965 content assertions actually observed;
Linux has 970. See
`docs/DEBUGLINK-CANDIDATE-CONTENT.md`.

**CONFIRMED:** PR #39 corrected head `a190026` passes all twelve jobs in exact
run `40116314882` and merged normally as `4e050609`. ADR-0005 selects separate
native-free `OwnedDebuglinkCandidate` after a reviewed layout experiment. Source
`1763ebd` passes 1,142 actual-Java-21 checks and 1,148 with one large ELF32
big-endian case under 64 MiB. The installed writer passes twelve retained-fixture
cases across x86-64/AArch64/MIPS32 big-endian: exec/PIE/no-ID plus shared lookup.
Independent reviews reconstruct 24 deterministic outputs and three plaintext
counterexamples, with candidate GNU/LLVM checks, eighteen GDB transcripts and
eighteen native/QEMU process executions. Original fixtures remain unchanged.
Exact package and all-five-target artifact reviews pass: thirty ordinary
deterministic candidates plus five plaintext controls, 75 copies, 330 parent
records, fifteen mutations, forty typed failures, 25 writer GDB checks and
fifteen original/candidate execution pairs. Native Windows passes 21 focused
checks, with 1,140 owned-writer assertions actually observed; both GUI hosts
pass. Private candidate creation does not complete attachment or its transaction.

The first hosted head `6f1a220` / run `40114403014` is **not accepted**: ARM32's
extended-section PIE compiler oracle could not bind TCP port 33168 and never
reached writer checks. The shared oracle now uses the existing private-socket
helper with readiness/cleanup. Existing startup controls and ten real compiler
exec/PIE checks across all five targets pass with unchanged input hashes/mtimes;
the corrected head subsequently passed the full gate above. The failed artifact is retained,
and its port owner remains **UNCERTAIN**.

**CONFIRMED at PR #40's complete hosted gate:** the existing private candidate workflow
now connects explicitly selected report/producer evidence and all three selected artifacts.
Opt-in same-parse detailed reader/binder methods preserve all five diagnostic
inventories with combined limits of 16,384 entries and 1,048,576 UTF-16 string units.
The lightweight APIs retain their existing behavior. Keep `PARTIAL`/`NOT_RUN` and
full diagnostics visible without assigning severity, and require separate hash,
prefix, allocation, build-ID and reported-target observations before construction.
Acceptance includes retained real reports, malformed/mismatched evidence before
scratch creation, and counterexamples showing that rewritten claims, invalid
DWARF or an unresolved source path remain outside these observations. No public
attachment, validator receipt, host-metadata preservation or backup transaction is
introduced by this step.

Source `1d80348` passes 432 actual-Java-21/64 MiB detailed checks and unchanged
lightweight reader/binder suites. The installed retained-export replay passes
nine cases across x86-64/AArch64/MIPS32 big-endian. Independent review reconstructs
30 candidates (18 ordinary repeats and 12 positive controls), verifies 78 controls,
complete diagnostics and selected provenance, and confirms all 44 globally
protected files unchanged. Ordinary GDB/runtime checks and explicit invalid-DWARF
and missing-source counterexamples pass. Final head `13e706e5` passes all twelve
jobs in `40119714272`, exact package/source review and all five target artifact
audits: fifteen fresh cases, thirty ordinary plus twenty positive-control candidate
reconstructions, 130 controls, 45 report sets, 135 earlier and 75 current byte
copies. Both GUI hosts and 22 native Windows checks pass, including 432 detailed
assertions and both retention caps reached together. Normal merge `25845418`
preserves that tree; separate main push `40121995458` passes all twelve jobs
and independent both-GUI/native Windows review. The archive
omits empty negative workspace directories; runtime assertions and absence of
unexpected files are distinguished from fully reconstructed positive outputs.
P2.8's transaction remains incomplete.

**CONFIRMED in PR #41 run `40123518106`:** capture the existing primary LLVM/strict
checks once and consume their full selected-file/tool/output evidence through
the explicit report handoff before normal preparation. Preserve NOT_RUN and the
existing inherited-frame exception; legacy absence is NOT_CAPTURED, with no
automatic fallback. The raw Java-probe limitation controls remain ungated and
separate. Source `9390565` passes 100 focused checks and nine fresh validator pairs;
nine installed cases, eighteen entry-point rejections and independent byte/GDB/
runtime reviews pass. Final head `f52361a` passes all twelve jobs, exact package
and independent all-five-target/both-GUI/native Windows 22 review: hosted97
focused checks, fifteen fresh captured pairs and thirty entry-point rejections.
The separate raw130 controls remain intact. Normal merge `fdebe181` preserves
that tree; distinct main push `40126173922` passes all twelve jobs and separate
both-GUI/native Windows review. See
`docs/VALIDATION-EVIDENCE-HANDOFF.md`.

**Status:** `[ ]` — optional product operation **PLANNED**. The bounded backend
and backup-based re-export investigation is complete; the explicit transaction
design and remaining acceptance tests are in
[`ADR-0004`](docs/ADR-0004-DEBUGLINK-ATTACHMENT.md). No attachment option exists.

**CONFIRMED inspection scope:** manual run `40129632540` and independent
Linux/native Windows artifact reviews pass on actual Java 21/64 MiB. Linux covers
ten entries, four pairs and eight malformed manifests; Windows covers twelve
entries, six pairs and nine retained byte copies. Retained FIFO and PowerShell
failures remain separate from the corrected runs. ACL inheritance, access times,
stream identity and sharing-lock observations expose host limits without claiming
preservation, durability or a transaction. See the
[host research record](docs/research/ATTACHMENT-HOST-OBSERVATIONS.md). Both native
host contracts and ADR-0004's remaining transaction gates stay incomplete.

**CONFIRMED at the compatibility layer:** automatic debuglink lookup and CRC
mismatch rejection now have strict local tests on private copies made with
target `objcopy`. No-build-ID negative controls prevent fallback from masking
a bad CRC. This does not implement the optional product attachment operation;
the full original/backup/rollback contract below remains required.

### Work

- Keep default export non-mutating.
- Add an explicit user option to attach `.gnu_debuglink` only after sidecar success.
- Compute/store the required CRC correctly.
- Retain a verified independent original backup and atomically replace the
  modified target; test rollback without overwriting an existing backup.
- Preflight receipt, temporary receipt, log and backend-output paths against
  every input, pair and backup before writes; test identity aliases and
  preservation even when rejection reporting fails.
- For refresh, export directly to a fresh final sidecar/source basename;
  retain the previous pair/receipt and back up the prior attached image.
  Test changed-CRC refresh and full prior-association rollback, not merely
  byte-identical re-export. Reject a lost or overwritten prior pair.
- Verify automatic GDB discovery.

### Completion criteria

- [ ] Option is disabled by default.
- [ ] User receives an explicit warning that the target will change.
- [ ] Original backup/rollback policy is documented and tested.
- [ ] GDB automatically discovers the sidecar.
- [ ] CRC mismatch test fails as expected.
- [ ] Default-mode original hash test remains unchanged.

The Linux research probes cover GNU 2.42 tools for x86-64, AArch64 and MIPS32
both byte orders, including backend rejection of unsupported layouts. These
results do not claim a product transaction, Windows attachment, or narrower
ordinary-export input support. Their historical bare-libdwarf result predates
strict summary enforcement and is not current validator acceptance. A separate
save/reopen investigation found
generic `undefined` used a transient Ghidra UID that changed type DIE ordering;
the normalized model and source remained identical. The separate bounded fix
and fresh-process saved-program regression now pass the combined matrix,
without weakening imported-input SHA checks; this does not implement attachment.
See [reproduction/evidence](docs/research/DEBUGLINK-EVIDENCE.md).

## P2.9 Add build-ID association where applicable

**Status:** `[x]` within the documented profiles — matched sidecars preserve
the original build ID. The prior hosted x86-64 discovery test did not reject
section-association warnings.
Allocated relocation metadata is now preserved as inert sections, and strict
ET_EXEC/PIE discovery plus mismatch rejection passes locally on x86-64,
AArch64, and both MIPS32 byte orders. All five target CI lanes now run these
checks, and exact-main run `40064204515` passes all five before alpha.2
publication. No-build-ID sidecars retain that absence and the existing explicit
GDB workflow remains covered.

### Work

- [x] Copy the original build ID into the matched sidecar.
- [x] Handle and test binaries without build IDs without inventing identity.
- [x] Test standard `.build-id` directory lookup.

### Completion criteria

- [x] Build-ID behavior is documented.
- [x] GDB discovery works in the selected layout.
- [x] A sidecar with another fixture's build ID is rejected by GDB.

## P2.10 Add exporter diagnostics/reporting

**Status:** `[x]` — schema-versioned deterministic JSON reports distinguish
success, partial semantic coverage, cancellation, and fatal failure. Real headless
success, controlled decompiler failure, fatal preflight and Windows-hosted
assertions pass under P2.12. Current evidence is run `40047390539`.

### Work

Produce a structured final report with:

- [x] Target identity and architecture.
- [x] Output paths/hashes.
- [x] Counts of functions/types/variables exported.
- [x] Counts and names of failed/skipped functions.
- [x] Omitted variable locations and reasons.
- [x] Unsupported constructs.
- [x] Validator/test status; the exporter honestly records `NOT_RUN`, while
  development harnesses run and retain validator results after publication.
- [x] Native/libdwarf revision.

### Completion criteria

- [x] User can distinguish success, partial semantic coverage, cancellation, and
  fatal failure.
- [x] Diagnostics are deterministic and machine-readable JSON.
- [x] Native errors include libdwarf messages without unsafe pointer use.
- [x] No unsupported feature is silently presented as supported.

---

# P2 — Headless, CI, and releases

## P2.11 Add a headless exporter entry point

**Status:** `[x]` — packaged Bash and PowerShell wrappers drive the same
production exporter in temporary-import or read-only existing-project mode.
The Bash contract, real Ghidra completion/fatal behavior, deterministic rerun,
validators and native Windows PowerShell checks pass in hosted CI. Run
`40047390539` also passes the expanded log-alias safety suite.
**Dependency:** exporter core separated from GUI/script state.

### Work

- [x] Expose the same core exporter through Ghidra headless analysis.
- [x] Define stable command-line arguments for project/program/output/options.
- [x] Return meaningful exit codes.
- [x] Avoid GUI prompts.
- [x] Support CI fixtures.

### Completion criteria

- [x] Headless command invokes the same production script/core as GUI mode.
- [x] Output is deterministic.
- [x] Failure/cancellation exit codes are documented.
- [x] CI can run the current source/type/signature milestone end-to-end without
  interactive Ghidra.

## P2.12 Add continuous validation

**Status:** `[x]` — Linux target lanes run for x86-64, AArch64, ARM32, MIPS32
big-endian, and MIPS32 little-endian, plus a Windows-hosted x86-64 ELF export
lane. They build pinned libdwarf, run the real headless exporter for
ET_EXEC/PIE/shared/no-section inputs as applicable, preserve input hashes,
validate with GNU/LLVM/libdwarf tools, and execute GDB/`ptype` natively or
through QEMU. GitHub Actions run 33751896850 passed the complete P2.12
diagnostic/Windows matrix; run 33757707307 added ARM32 and passed all 11 jobs,
including the aggregate `required-validation` gate. Enforcing that gate as a
strict, up-to-date merge requirement on `main` is now enabled through GitHub
branch protection for the public repository.

### Work

CI should include separate jobs for:

- GitHub Actions workflow linting with a pinned, checksum-verified `actionlint`.
- Java/unit tests.
- Native ABI smoke tests.
- Extension build.
- Fixture build/import/export.
- ELF/DWARF validators.
- GDB behavior scripts.
- Determinism/original-hash checks.
- Linux host initially; Windows host once stable.
- An x86-64 end-to-end target lane.
- An AArch64 end-to-end target lane using a dedicated runner or a documented
  cross-compile/emulation environment.
- An ARM32/AArch32 end-to-end target lane using a documented ARMv7
  cross-compile/emulation environment.
- A QEMU-backed MIPS target lane once the MIPS fixture/export path exists.

Every supported target lane must build fixtures, import/analyze/export through
headless Ghidra, run ELF/DWARF validators, and execute applicable scripted GDB
behavior checks. Cross-compilation without exporter and GDB execution is not
an integration pass.

### Completion criteria

- [x] Pull requests cannot merge with failing structural/GDB tests for
  supported paths; strict branch protection requires `required-validation`.
- [x] x86-64 and AArch64 have separate passing hosted end-to-end jobs.
- [x] Both jobs exercise the same production exporter entry point.
- [x] The AArch64 job proves runtime address behavior under a native runner or
  documented emulation setup.
- [x] MIPS32 big/little-endian profiles have hosted QEMU exporter, validator
  and GDB evidence. Release notes retain those narrow profiles and do not
  claim every MIPS ABI or processor variant.
- [x] Test logs expose exact Ghidra/libdwarf/tool versions.
- [x] Native crashes are clearly reported as failures.
- [x] Artifacts/transcripts are retained for failed runs.

**CONFIRMED local reliability follow-up:** hosted GUI/combined run `40055880742`
hit an occupied PID-derived QEMU TCP port in the MIPS32LE shared-object test.
That harness now uses a private UNIX socket with bounded startup/liveness and
cleanup checks. A controlled occupied historical port still permits the full
shared-object GDB oracle to pass; startup failure/timeout cleanup also passes.
Combined run `40068401197` passes the startup/failure controls on x86-64 and
the occupied-port control on MIPS32LE; all five shared-object target oracles
also pass with the private-socket transport.
Other TCP-based QEMU harnesses remain unchanged; this does not claim a general
emulator retry policy or excuse debugger/validator failures.

## P2.13 Produce installable releases

**Status:** `[x]` — deterministic CI artifacts, packaged Linux/Windows natives,
clean-install exports, checksums, operating documentation, third-party
notices, corresponding-source packaging, and hosted verification are
implemented. Fresh run `39892474892` passed all twelve jobs. The verified
native-inclusive bundle and checksum file were published as
[v0.1.0-alpha.1](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.1)
on 2026-10-22 America/Chicago, targeting tested commit `f4a0199`. This closes
alpha release packaging/publication, not the remaining feature-scope items.

**CONFIRMED (2026-10-24):** the corrective
[v0.1.0-alpha.2](https://github.com/zwilcox/GhidraDwarfForge/releases/tag/v0.1.0-alpha.2)
was published at `05:15:20Z` from `2f88c4a`, following all twelve exact-main jobs
in `40064204515` and the final package audit. Draft and published ZIP/checksum
assets were downloaded and verified against the audited bytes, and alpha.1's
tag/assets remain unchanged. This closes the corrective release gate within
the documented target/host profiles; alpha.1 remains affected by its recorded
correctness findings. New semantic features in this branch are not released
by that tag. Exact hashes and audit evidence are in `docs/VALIDATION.md`.

### Work

- [x] Define semantic versioning/release policy.
- [x] Build Ghidra extension ZIPs reproducibly.
- [x] Include native checksums, provenance, third-party notices, and exact
  corresponding source.
- [x] Publish support matrix and known limitations.
- [x] Add installation, run, GDB loading, and troubleshooting instructions.

### Completion criteria

- [x] Release artifact can be installed without compiling libdwarf locally.
- [x] Clean Linux and Windows CI environments export a documented fixture.
- [x] Release documentation identifies supported Ghidra/Java/host/target combinations.
- [x] Checksums and provenance are included in the artifact.
- [x] No generated build directory is required from the source tree.

---

# P3 — Later features after the core is correct

## P3.1 Investigate `.debug_frame`

**Status:** `[x]` — ADR-0002 concludes that the current exporter must rely on
the original ELF's unwind metadata and must not synthesize unsupported CFI.
**Corresponds to:** issue #8.

### Questions

- Does the original target already contain sufficient `.eh_frame`/unwind information?
- Can Ghidra provide reliable CFI data?
- Would synthetic frame information improve variable evaluation or risk corrupt unwinding?

### Completion criteria

- [x] Written decision explains why `.debug_frame` is not required for the
  current ELF milestone.
- [x] No synthetic CFI is emitted without an evidence-backed generation model.
- **NOT APPLICABLE to the accepted design:** if synthetic unwind generation
  is introduced later, it must pass call-stack tests on every claimed architecture.

## P3.2 Improve string/form policy

**Status:** `[x]` — deterministic `DW_FORM_strp`/`.debug_str` output passes the
full hosted target/Windows structural and behavior matrix. Issue #9 was closed
after merge and post-merge validation.
**Corresponds to:** issue #9.

### Work

- Decide when to use inline `DW_FORM_string`, `.debug_str`/`DW_FORM_strp`, and DWARF 5 indexed forms.
- Favor correctness and validator compatibility before size optimization.

### Completion criteria

- [x] Form policy is documented and deterministic.
- [x] `.debug_str` is emitted when selected and all offsets validate.
- [x] Issue #9 was closed only after structural tests passed.

## P3.3 Add richer scopes and declarations

Tracking: [#73](https://github.com/zwilcox/GhidraDwarfForge/issues/73).

**CONFIRMED investigation, not implementation:** isolated x86-64/AArch64
producer/GDB tests show naive linkage-name emission hides the curated name,
and an imported-declaration alias does not fix lookup. Imported labels can
also be ambiguous or analyst-created. Preserve existing display behavior
until an original-ELF binding and consumer policy pass. See
`docs/research/LINKAGE-LOOKUP.md`.

**Status:** `[~]` — namespace-parented globals, typed external-data
declarations, and function-owned static memory labels pass their documented
checks. Hosted run `40063017269` proves the static-scope slice on all five
targets, including ARM32 exec/PIE/rebased-PIE. Its fixture precondition validates
native ARM EHABI instead of requiring a DWARF FDE, with missing/malformed/
unusable coverage controls and unchanged runtime scope/value/return checks.
This supersedes run `40057031192`'s pre-export failure without weakening its
oracle; broader scopes and declarations remain partial.
Artificial auto-parameter emission now has a local x86-64 hidden return-storage
pointer behavior test, including canonical aggregate identity and actual values.
Its PR #48 hosted gate passes; C++ `this` and broader artificial-variable semantics
remain unimplemented. The other scope/declaration work below is
**PLANNED**.

Potential features:

- Lexical blocks.
- Namespaces/classes.
- Thunks/aliases with specification/origin relationships.
- [~] Static locals: explicit Function-owned typed memory labels retain their
  owner, type, and normalized absolute location. Duplicate private names in
  different functions remain distinct from a same-named global. Failed
  decompilation keeps the owner symbol-only, omitting its statics with a
  diagnostic and an accurate exported-static count. Lexical-block
  ownership and inferred/decompiler-only static locals remain unimplemented.
- Artificial variables.
- [~] External declaration-only function DIEs: local model, producer, validator
  and GDB non-interference tests pass. Unknown prototypes stay omitted; GDB
  does not resolve unlocated external prototypes. Hosted validation pending.
- Disambiguation of same-named types from different Ghidra categories: the
  existing-DWARF regression retains both imported and analyst-defined
  `operation` enums, and uses the unique `OP_INVALID` enumerator to query the
  curated type in GDB. Do not discard one based on name alone.

Do not begin until the type/location core is stable.

Completion requires fixtures for scoped functions/classes, shadowed locals,
static locals and distinct same-named types. GDB must preserve analyst-facing
lookup, distinguish the objects, and resolve only defensible addresses/live
ranges. Category paths are not automatically original source namespaces.

**CONFIRMED:** the qualified display-name slice preserves nested plain
function paths and duplicate short names with real GDB address/source/type,
single-breakpoint and owner-static checks on five profiles in PR #26 run
`40071594248`; normal merge `89c07ce` and main push `40073445177` are accepted. C11 namespace-parented function DIEs do not provide the required
qualified lookup in the tested GDB 15.1, so definitions remain CU-owned and use
the recorded qualified display string. External-function declarations, classes,
lexical blocks and qualified namespace-global lookup remain outside this slice.
The naming policy documents exact quoting and conservative collision rejection.

## P3.4 Investigate reconstructed inlining

**Status:** `[x]` — **CONFIRMED**, bounded investigation complete; inline
emission is not implemented.

See `docs/ADR-0003-INLINE-EVIDENCE.md` and the durable transcript under
`docs/research/`. Ghidra 12.0.3's inline flag controls decompilation and can
remove a high-pcode call while the machine call remains. The compiler-DWARF
import path preserves qualifying inline locals in their containing function,
source rows and optional comments; this does not retain the complete instance/
origin/call-site/range model required by the current exporter.

The Linux x86-64 GCC 13.3/GDB 15.1 probe passes compiler DWARF validation,
actual inline-frame/local-value checks, debug/no-debug Ghidra comparisons,
ordinary-call flag toggling and original-hash preservation. Its recorded
importer location limitations are not counted as a clean Forge export.

**PLANNED, conditional:** implement inline DIEs only after ADR 0003's explicit
evidence-provider/model and multiple/nested-instance GDB acceptance conditions
are met. Do not infer compiler inlining from the flag or comments, discard
surviving knowledge, or describe inline export as complete.

## P3.5 Add optional size/performance features

Tracking: [#74](https://github.com/zwilcox/GhidraDwarfForge/issues/74).

**CONFIRMED through PR53's complete hosted gate:** instruction-level stack profiles are created only
when an exported stack location consumes them, then reused within the function.
Five alternating 10,000-function pairs preserve every artifact byte and reduce
median export time from 9.99 to 9.37 seconds on this host; SQLite's 34.76 to
34.10 second difference is small and has overlapping samples. Full corrected
comparison harnesses, validators/GDB, preservation checks and x86-64/AArch64
stack-location exec/PIE/rebase regressions pass. PR53 and its separate main gate also pass; hosted CI is not a new
timing measurement, and no broad speed or memory guarantee is claimed.
See `docs/LAZY-STACK-PROFILES.md` for exact populations, failures and receipts.

**CONFIRMED locally (2026-10-25):** the pinned SQLite workload decompiles 1,539
functions without failures; three exports have median 33.93 seconds, with
identical artifacts and clean strict/LLVM checks. A separate JFR export
identifies stack-depth analysis as a candidate hot path. The retained run
failed only its whole-project backup-file assertion; a precise evidence replay
proves unchanged program data and reports the two rotated backup files. The
revised full harness subsequently passes `run.zf2690wu` with two timed exports
and a separate JFR export of the locally corrected return-recovery candidate. GDB basic behavior passes, but
a DEFAULT return-type discrepancy remains a separate confirmed correctness
gap. See `docs/PERFORMANCE.md` for measured scope and retained failures.

**Status:** `[~]` — synthetic scaling measurements are complete locally, and
the indexed line planner passes component run `40065823442` and combined run
`40068401197`; the first complex-application observation is recorded above.
Broader firmware/host workloads and further profiling remain **PLANNED**. The bounded 10,000-function
comparison improves median whole-process time from 10.86 to 9.18 seconds over
five alternating pairs, with every output pair byte-identical. It does not
establish speed or memory effects for other workloads/hosts.

`src/test/performance/export-benchmark.py` separates one saved-project import
from repeated fresh-JVM exports. The historical 100/1,000/10,000-function cases
pass GNU/LLVM, full DWARF function/address/source checks, runtime GDB, original
hashes and byte-identical reruns; their old exit-zero libdwarf checks were
insufficient and are not clean-validator evidence. The corresponding
export medians were 2.52/3.27/10.62 seconds on the recorded local host; these
small synthetic cases do not predict arbitrary firmware behavior. Commands,
measurement boundaries, evidence and next profiling questions are in
`docs/PERFORMANCE.md`.

After merging strict `99845c7`, focused source/line/range smokes and a fresh
ARM32 exec/PIE/shared export/validator/GDB matrix pass, including byte-identical
exec reruns. The retained paired 10,000-function artifact passes a fresh full
strict/LLVM/GNU/GDB replay, with all 10,002 inherited frame messages precisely
corroborated using the separately bounded validation-only capacity patch.
No timed 10,000-function export was rerun. Component run `40065823442` and
combined run `40068401197` subsequently passed all twelve jobs, including the
Windows host. Representative complex-binary profiling remains **PLANNED**.

**CONFIRMED:** performance PR #24 run `40064815083` failed its validator
capacity gate because the standalone bundle omitted `dwarfdump.conf`. The
follow-up packages the pinned config with an explicit-path launcher and
rejecting relocation/configuration controls. Strict error checks remain intact;
the corrected component and combined hosted runs above pass. This closes the
configuration defect without erasing the failed run or changing measured
planner timings. See `support/validation/README.md`.

Potential features only after correctness:

- `.debug_names` or GDB index generation.
- DWARF section compression.
- String/address indexing.
- Incremental/cached export.
- Parallel decompilation with bounded resource use.
- Large-firmware memory/performance profiling.

### Completion criteria

- [x] The implemented line-table index preserves byte-identical semantic output.
- [x] Local determinism and strict validators pass for the documented index fixtures; the complete combined hosted matrix also passes.
- [x] A paired benchmark demonstrates its measured benefit on the documented workload.

---

# 2. Issue reconciliation checklist

Use the following acceptance gates before updating the original GitHub issues:

## Issue #1 — output directory

- [x] Production export defaults next to `Program.getExecutablePath()`.
- [x] Missing/stale/unwritable paths fail before publication or use an explicit
  headless input/output path; Linux GUI chooser selection/cancellation is
  covered by the automated non-headless test under P2.7.
- [x] Atomic pair behavior is tested on Linux and Windows.
- [x] GUI and headless path behavior is documented.

## Issue #2 — `.dbg` naming

- [x] Production export uses `<executablePath>.dbg`.
- [x] Naming is tested across Linux and Windows paths.
- [x] The named sidecar passes structural validators and GDB behavior tests.

## Issue #3 — `.dbg.c` naming

- [x] Production export uses `<executablePath>.dbg.c`.
- [x] Deterministic source, controlled decompiler failure, cancellation, and
  pair-publication rollback pass integration tests.
- [x] `.debug_line` references the exact final name.

## Issue #4 — `.debug_aranges`

- [x] Issue is historically closed and prototype calls arange generation.
- [x] **HISTORICAL:** the redesigned exporter deliberately omitted the optional
  accelerator and verified CU/subprogram `DW_AT_ranges` instead.
- [x] The separate GDB address-map fix adds exact code-only lookup with a CU
  header offset and independent coverage/formatting regressions. PR #28 exact
  run `40076025207` and main push `40077843290` pass the required matrix;
  detailed five-profile artifact reviews belong to the accepted PR run.
  See `docs/ADDRESS-INDEX.md`.

Do not reopen/close solely from this checklist; use project/user direction.

## Issue #5 — `.debug_info`

- [x] Production CU/subprogram DIEs exist.
- [x] Current supported functions/types/variables/ranges validate across the
  hosted target matrix.
- [x] GDB behavior passes for every claimed target profile.

## Issue #6 — `.debug_abbrev`

- [x] libdwarfp produces abbreviations for the production DIE set.
- [x] Current full DIE-set abbreviations validate across the hosted matrix.
- [x] No stale or invalid form combination is accepted by the validators.

## Issue #7 — `.debug_line`

- [x] Structured source map for contiguous functions.
- [x] Valid DWARF 5 line table for the current supported path.
- [x] GDB `list`/`next` acceptance.

## Issue #8 — `.debug_frame`

- [x] ADR-0002 records the requirement/design investigation.
- [x] Synthetic CFI is deferred unless reliable instruction-range unwind
  evidence and cross-architecture behavior tests become available.

## Issue #9 — `.debug_str`

- [x] String/form policy is documented and deterministic.
- [x] Section/offset validation passes across the hosted matrix.

---

# 3. Required command checklist for each generated fixture

The exact commands may be wrapped by the test harness, but equivalent checks must run.

```bash
sha256sum <binary>

readelf -h <binary>
readelf -S <binary>
readelf -n <binary>

readelf -h <binary>.dbg
readelf -S <binary>.dbg
readelf -n <binary>.dbg
readelf --debug-dump=info <binary>.dbg
readelf --debug-dump=abbrev <binary>.dbg
readelf --debug-dump=aranges <binary>.dbg
readelf --debug-dump=decodedline <binary>.dbg

llvm-dwarfdump --verify <binary>.dbg
dwarfdump <binary>.dbg

sha256sum <binary>
```

Unavailable tools must be reported as unavailable; they must not be marked passed.

GDB script, once P0.8 selects the loading strategy, must assert at least:

```gdb
set pagination off
info functions
break <recovered-function>
list <recovered-function>
ptype <recovered-type>
print <supported-variable>
next
step
quit
```

Add target-specific load/run commands and machine-checkable expectations for addresses, source lines, types, and values.

---

# 4. The next Codex session should start here

**CONFIRMED:** the former eight-step prototype bring-up sequence is complete.
Ghidra 12.0.3, Java 21-compatible bytecode, Gradle 9.3.1, pinned libdwarf 2.3.2,
the audited native bindings, isolated smoke tests, source-built fixtures and
ADR-0001 are established. Do not select new baselines or repeat initial
implementation unless new evidence requires it.

Unless the user changes priorities:

1. Run `git status --short`; read `AGENTS.md`, the current context/status in
   `PROJECT_CONTEXT.md`, and this file's Sections 0.1/1.1. Preserve existing work.
2. Read the current acceptance checkpoints: PRs #25–#41 are merged. Candidate
   content head `b269ec5` passed run `40110565271` and tree-identical main merge
   `2bd6739`. Main-push gates through PR #37 pass; PR #38 main push
   `40113254401` attempt 2 passes after attempt 1's runner loss, with three
   successful earlier jobs explicitly reused.
   Owned writer head `a190026` passed `40116314882`, including exact package,
   all five target artifacts, native Windows 21 and both GUI hosts, and merged
   as `4e050609`. Its separate main push `40118899783` passes all twelve jobs
   and independent GUI/native Windows review. Reported preparation `13e706e5`
   passes exact run `40119714272`, independent package/all-five/both-GUI and
   Windows 22 review, and merged as `25845418`. Its distinct main push
   `40121995458` passes all twelve jobs and independent both-GUI/native Windows
   review. Captured-validation head `f52361a` passes all twelve jobs in
   `40123518106`, all-five-target captures/entry controls, exact package and both
   GUI/native Windows 22 review; normal merge `fdebe181` retains its tree.
   Distinct main push `40126173922` passes all twelve jobs and separate
   both-GUI/native Windows 22 review. PR #42 head `296395e` passes all twelve
   jobs in `40126794530`, exact package/all-five-target/both-GUI/native Windows
   23 review, and merged as `0d2cbc5`; main push `40129499500` also passes all
   twelve jobs and independent host reviews. Preserve
   the first writer run's compiler-oracle TCP collision and the failed
   original PR #32 report-selection attempt and earlier feature histories.
   Require current-base checks under AGENTS.md Section 6.1; do not restart
   completed bring-up or integration.
3. Preserve published alpha.2 at `2f88c4a` and alpha.1 at `f4a0199`. Future
   releases need their own version/notes, exact-commit CI and package/asset
   verification; do not replace or retag either published artifact.
4. Preserve P0.9's documented resource/layout bounds and the resolved strict
   validator gate. Neither direct PN_XNUM execution nor blanket processor/ABI
   coverage follows from the passing import/export tests.
5. Preserve P1.8's bounded acceptance and address remaining P1.7/P3.3 scope
   cases and P1.11a lifetime/storage migration with compiler-oracle/GDB fixtures.
6. Extend explicitly selected target profiles and GUI journeys. Treat optional
   debuglink, inlining research and performance candidates according to their
   recorded scopes; do not invent recovered information to complete them.
   Owned candidate preparation is accepted at PR #39 corrected head `a190026`,
   merged as `4e050609`; detailed report binding/private preparation is accepted
   at PR #40 head `13e706e5`, merged as `25845418`. Captured-validation continuity
   is accepted in PR #41 at `f52361a`, merged as `fdebe181`, as described in
   `docs/VALIDATION-EVIDENCE-HANDOFF.md`. The external-function inventory
   correction is accepted at PR #42; external declaration emission remains
   deferred. Continue the inspection-only host research in
   `docs/research/ATTACHMENT-HOST-OBSERVATIONS.md` before an owned-fixture
   transaction. Preserve the explicit captured-report handoff
   and separate fresh/retained installation scopes. ADR-0005 selects the writer;
   GNU remains a separate test oracle.
   Preserve PR #37's intermediate callback failure evidence and all research/test
   setup failures. Optional attachment remains a separate transaction with receipt,
   validation, host metadata, backup and recovery requirements; these helpers do
   not establish identity or readiness.
7. For each coherent change, run appropriate validators and debugger behavior
   tests, preserve original hashes and deterministic output, and record evidence
   in the handoff documents. Keep the complete supported-profile CI matrix green.

### Incomplete register-body coverage correction (2026-10-25)

**CONFIRMED locally; hosted acceptance pending:** a missing instruction in an
otherwise retained function body bypassed whole-function register safety. In
real AArch64 exec/PIE/rebased-PIE exports, an undecoded syscall made the previous
exporter display a process ID for the actual parameter `-19`. The coverage
guard now retains its name/type without a location, preserves discontiguous
bodies and checks decoded lengths. Five language models pass 421 checks;
nine actual Java 21 packaged suites and eighteen baseline/fixed/control exports
pass their scoped checks. See `docs/REGISTER-BODY-COVERAGE.md` for raw evidence,
validator details and retained model-proxy failure. General lifetime/migration
work remains partial.
