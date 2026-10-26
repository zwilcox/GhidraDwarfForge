# Bounded Linux i386 integer and stack profile

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** The isolated
target table now admits little-endian ELF32 `EM_386` as report target `x86`,
using libdwarf's `x86` producer mode. The initial positive profile is Linux
freestanding integer code: non-PIE, PIE, rebased PIE and an executable with no
section-header table. No libc/startup installation is required by this fixture.

This does not claim shared-library loading, debugger-injected calls, alternate
calling conventions, x87/SSE/vector locations, aggregate returns or broad i386
ABI coverage. The existing five target lanes remain required; the new runtime
profile runs within the Linux x86-64 lane. Windows gains descriptor/storage
checks and an isolated i386 producer test; those do not establish native Windows
execution of a Linux binary or a Windows-hosted i386 GUI journey.

## Target boundary

Only the ELF target-description and register-map tables change in production.
Generic ELF, DWARF, type, source and location code is unchanged. ELF64 and
big-endian combinations are rejected. The initial register map is restricted
to the general-register subset; unmapped floating/vector storage stays unavailable.

| DWARF number | Ghidra register |
| --- | --- |
| 0 | EAX |
| 1 | ECX |
| 2 | EDX |
| 3 | EBX |
| 4 | ESP |
| 5 | EBP |
| 6 | ESI |
| 7 | EDI |
| 8 | EIP |
| 9 | eflags |

The mapping is audited against installed Ghidra 12.0.3
`Processors/x86/data/languages/x86.dwarf`, SHA-256
`598ad09d375b6aa8622bc7b1052ca3a0ad1d0d4f3a533abd266f4bbbd8959727`.
The pinned libdwarf 2.3.2 `dwarf_pro_init.c` explicitly selects `R_386_32` for
its `x86` mode. Its source archive SHA-256 remains
`7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
No JNA declaration or native API call is added. A standalone actual-Java-21
probe exercised sixteen producer lifetimes before the candidate was loaded
inside Ghidra; the public packaged producer smoke subsequently passes the same
sixteen-lifetime/deterministic-buffer check.

The architecture guard now includes i386 identifiers and general registers.
Seven controls include rejected `EM_386` and `ESP` outside the audited files;
the existing missing-source, missing-ripgrep and path-spoof controls remain intact.

## Fixture and acceptance

`i386-profile.c` is source-built with `gcc -m32 -nostdlib`. It exercises signed
32-bit scalar arguments, a 64-bit stack argument/return, and an eight-byte
by-value integer structure. Three distinct positive/negative/wide input sets
make nine calls. Its direct Linux exit syscall supplies a checked process exit
without libc or startup objects. Static PIE has no dynamic relocations; this
is a bounded position-independent fixture, not a dynamic-loader test.

The compiler reference runs first. GDB measures each local address relative to
the actual stack pointer at function entry, supplying independent fixture
bindings without assuming a prologue size. The real input is fully stripped;
curation uses reference ELF addresses and explicit names/types. Ghidra computes
parameter storage from its GCC compiler specification. Saved-program reopening
preserves those choices and repeated exports are byte-identical.

Every instruction in the three fixture functions is checked, including stack
adjustments and return boundaries. The compiler and Forge must read the same
incoming stack bytes; Forge's named parameters must equal the expected values.
The compiler describes its wide argument in a copied slot before that slot is
initialized, so its early oracle uses actual incoming stack bytes. Named compiler
values are required after initialization. Return values are captured before
caller instructions can overwrite EAX/EDX. A separate invocation checks source
`next`/`step`, and both invocations must exit normally.

The separately curated stack local has a positive first-use offset. The
established conservative policy preserves its name/type and reports
`UNKNOWN_LIFETIME` without a location. This profile adds no stack-local lifetime
inference. Actual GDB unavailability and raw DIE absence are both checked.

Independent raw review decodes ELF32 `.debug_loclists`, requires `DW_OP_bregx`
with DWARF register 4, and evaluates each emitted offset using the recorded
runtime ESP. At every instruction it must resolve to the independently measured
incoming slot. The review also compares runtime instruction bytes with original
PT_LOAD bytes, checks complete instruction coverage, type/location ownership,
ELF identity, saved-program preservation, and exact PIE/rebase correspondence.
GNU and LLVM validators pass for reference and sidecar; strict checking reports
zero errors in every case. The sectionless case preserves target bytes and
receives a fresh sidecar section table. No unwind reconstruction is claimed.

## Local evidence and pipeline

Four roles pass eight exports and **1,440 GDB observations**. Twenty packaged
suites and the sixteen-lifetime packaged producer test pass on actual Java 21.
Local headless exports use Java 25; that is separate from the Java 21 evidence.
All five ordinary fixture-reproducibility profiles, workflow lint and the
seven architecture controls pass.

```text
build/i386-review/acceptance.json
SHA-256 70e084c2319b8e392ec1247415f060f4337af2136b89b588d1ffff0eb29b086e
tested JAR fc5a90f5e4ce609e5534acb8493a56cc4f312a44c1dc2d1710cad8d90872a5ab
actual Java 21: build/i386-review/packaged.zchcesx2/result.json
packaged native: build/i386-review/native21.is_rh35d/result.json
accepted inventory: build/i386-review/final-sp-trace-exports.log
```

Accepted cases under `build/test-results/i386-profile/`:

```text
exec.lsfdz41s             sectionless.mzdjutby
pie.xqn3pcg6              pie-rebased.nwlnryp9
```

With a packaged installation and the strict checker configured:

```bash
./gradlew dwarfTargetSmoke variableStorageSmoke
python3 src/test/integration/i386-profile-export.py "$GHIDRA_INSTALL_DIR" --role exec
python3 src/test/integration/i386-profile-export.py "$GHIDRA_INSTALL_DIR" --role sectionless
python3 src/test/integration/i386-profile-export.py "$GHIDRA_INSTALL_DIR" --role pie
python3 src/test/integration/i386-profile-export.py "$GHIDRA_INSTALL_DIR" --role pie-rebased
```

CI requires these four runtime roles in the Linux x86-64 lane, the isolated
packaged producer on Linux/native Windows, and 42 native Windows model tasks.
These added hosted checks are **PRESENT, UNVERIFIED** until the exact-head full
gate and independent artifact review pass. No release publication follows from
this local checkpoint.

## Retained research and failures

The root's `build/x86-32-profile-research/` proves the preceding exporter rejects
machine 3 without final artifacts, while the original compiler/GDB program and
Ghidra import work. Its independent receipt is
`107444353f972078a4696e5276e3403fccfbe3d90c947fb0efddfca98405c4cc`.
It also retains the pinned producer initialization/header snapshots. Its small
three-call fixture is separate from the final nine-call integration fixture.

Early private pilot setup failed because of an incorrect local constructor,
setting stack first-use before attachment, and byte copies that lost execute
permission. The corrected setup uses the actual attached-variable setter and
preserves executable mode. Initial source-navigation probes returned before
`finish`, then observed registers after a caller comparison clobbered them.
Value capture and source navigation now have separate invocations. These failed
logs remain under `build/i386-review/pilot*/`; none is passing feature evidence.

The first dense-instruction probe, `exec.f75ud2tr`, assumed GDB's disassembly end
was exclusive and included the next function's first instruction. Its coverage
assertion correctly rejected that attempt before export. The final probe passes
the last included byte, preserves complete contiguous coverage assertions, and
retains the failed oracle source. Earlier three-point and pre-SP-trace matrices
remain historical; only the frozen final matrix binds the receipt above.

**CONFIRMED locally; hosted acceptance pending:** the bounded [i386 shared-library
follow-up](I386-SHARED-PROFILE.md) adds ordinary/rebased library exports from non-PIE and
PIE drivers, exact typed values and curated/original symbol lookup. It uses the
unchanged production exporter and does not establish broader libc or ABI support.
