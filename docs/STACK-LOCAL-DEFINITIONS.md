# Saved stack-local definitions and reuse

**CONFIRMED locally; hosted acceptance pending:** distinct saved Ghidra locals
can share stack bytes and retain separate first-use offsets. A recorded start
that coincides with one complete decoded stack STORE now establishes a bounded
location after that instruction. Subsequent full loads and copies can preserve
the value in registers or other proven stack slots. This is an analyst binding,
not a recovered original lexical scope.

`StackLocalLifetime` validates the attached USER_DEFINED local, exact storage,
type size, definition instruction, complete straight-line body and competing
saved bindings. `StackValueFlow` provides the shared ordered instruction engine.
Unknown aliases, writes overlapping the local's original slot, frame changes,
and a later overlapping saved owner retire **all** old value carriers. An old
register copy cannot become the new value after assignment or slot reuse.
Full writes at arbitrary later instructions are not inferred redefinitions.
Partial initialization, read-start metadata, ambiguous equal starts, invalid
offsets and unsupported flow retain declarations without invented locations.

A zero-offset stack local with overlapping saved ownership no longer receives a
whole-function location. Ordinary nonoverlapping zero-offset locals and stack
parameters retain their existing behavior. Calls, branch-dependent stack
identity, mixed pieces and inferred lexical lifetimes remain unimplemented by
this proof. Runtime now covers signed four- and eight-byte objects on x86-64
and AArch64. Partial/full writes and known/unknown alias effects also have
separate end-to-end evidence in `STACK-LOCAL-EFFECTS.md`; those runtime results
supersede the earlier pending mutation/alias notes below.

## Evidence and reproduction

The pinned Ghidra 12.0.3 SoftwareModeling source archive is unchanged from
`STACK-FIRST-USE.md`. `FunctionDB.addLocalVariable` and
`VariableUtilities.checkVariableConflict` distinguish saved first-use offsets.
The public attached `LocalVariableDB.setFirstUseOffset` persists them even
though constructors reject nonzero stack starts and decompiler address-tied
mappings discard the PC. No decompiler range is inferred from that encoding.

`StackLocalIdentitySmoke` passes 175 checks on x86-64, AArch64, ARM32 and both
MIPS32 byte orders, including exact and partial overlap, separate symbol IDs,
immutable database reopen and original hashes. `StackLocalLifetimeSmoke`
passes 376 x86-64/AArch64 decoder/extraction checks over 32/64-bit definitions,
reloads, partial/unknown stores, other slots, released frames, wrong starts,
non-curated sources, competing owners and cancellation. Twenty suites pass
against the packaged production JAR on actual Java 21; the test class origins
are recorded in `build/stack-local-review/java21`.

`stack-local-definitions.c` has two separate compiler scopes sharing a stack
slot. It is compiled at 32 and 64 bits with distinct signed values, including
negative and positive values beyond the 32-bit range. Compiler GDB measures the entry-relative coordinate
and proves both values and lexical scope boundaries. Fixture preparation binds
two analyst locals to the immediately preceding initializing stores. Fresh
processes reopen the saved program without analysis or mutation and compare
all symbol IDs, offsets, instruction bytes and raw p-code with preparation.

**HISTORICAL four-byte checkpoint:** six actual Java 21 x86-64/AArch64
exec/PIE/rebased-PIE roles with values 11 and 22 passed twelve candidate exports and
six preceding-package exports. The candidate and previous-package GDB passes
provide 174 instruction observations, including 39 newly available local values;
the previous package omits both nonzero
locals, while the candidate exposes only the exact proven intervals. An
independent raw `.debug_loclists` reader checks each stack/register handoff,
the compiler-measured SP displacement, complete interval coverage and absence
of invented lexical blocks or constants. GDB verifies every available value,
unavailable gap, instruction byte, source lookup, `next`, `step`, and normal
exit. The ordinary zero-offset object remains 37.

GNU, LLVM and the pinned strict checker pass. Retained compiler-frame length
diagnostics are independently corroborated against original ELF frames; they
are not blanket-suppressed. Original inputs, module/harness files and saved
program data remain unchanged, allowing only Ghidra's two documented backup
index rotations. Repeated artifacts are byte-identical. Controlled decompilation failure and
cancellation after 16 MiB preserve the original and prior output pair on
the private JDK 21 installation. Passing saved runs:
`run.4y6PLnHK` (x86-64) and `run.zliH1zxJ` (AArch64), under
`build/test-results/stack-local-definitions`.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC ./gradlew stackLocalIdentitySmoke stackLocalLifetimeSmoke
src/test/integration/stack-local-definitions-export.sh /path/to/private-packaged-ghidra x86_64 aarch64
```

Set `DWARFDUMP` to the pinned standalone validator. Optional
`FORGE_STACK_LOCAL_PREVIOUS_GHIDRA` adds the preceding-package comparison.
`FORGE_STACK_LOCAL_ROLES` selects roles for diagnosis; CI runs all three.
`FORGE_STACK_LOCAL_WIDTHS` selects 32 and/or 64 bits for diagnosis; the default
and both required CI lanes run both widths.
The Linux and native Windows model lists and both required runtime target
lanes include this component. The exact source-commit package passes all manifests, pinned native provenance,
72 embedded production sources and 272 Java 21-compatible classes. Its production
JAR is byte-identical to the runtime and Java 21 suite artifact:
`929929c7d0328ac93340e8d012d00a604acf8b7f424d110319a768d1679789ec`.
Hosted execution/review remains pending. P1.11a and all remaining P3.3 requirements stay open.

## Wide-value runtime checkpoint (2026-10-31)

**CONFIRMED locally; hosted acceptance pending:** all twelve target/width/role
cases pass on actual JDK 21 in `run.TyGDAILE`, with 24 candidate exports and
12 preceding-package exports. Every instruction is checked against unchanged
machine bytes. The 408 candidate/previous instruction observations include
78 newly available values; old locals remain unavailable before definition and
after retirement. Values are -1985229329/305419896 at 32 bits and
-81985529216486895/81985529216486895 at 64 bits, so truncation, wrong signedness
and stale reused bytes cannot pass by coincidental small values. The zero-start
control still produces 37 at both widths.

Independent raw-loclist review, compiler lexical/value checks, GNU/LLVM/pinned
strict validation, deterministic outputs, original/build-ID identity, saved
program and module preservation all pass. PIE/rebased normalized interval
receipts agree for each target and width. Production Java and the packaged JAR
are unchanged from the preceding accepted local checkpoint; its twenty actual
Java 21 model suites remain separate evidence, not freshly rerun tests.
Runtime receipt SHA-256:
`7cddb94033aa3cf82776184462a8c0f85a84f8eaa4b568c9bf48a545bcabc7f9`
in `build/stack-local-review/wide-runtime/runtime-acceptance.json`.

The wider harness is the default in both required runtime lanes. This branch
still awaits integration of PR99's architecture-field rename and the dependency
chain's hosted acceptance. Partial writes/unknown aliases, broader control/calls,
mixed pieces and all remaining P3.3 requirements remain open.

## Retained failures and narrower evidence

The first x86 probe used the older fixture whose first STORE was at function
entry. Inserting its second zero-start local replaced the first identity;
preparation correctly rejected it. The dedicated source adds an entry marker
to exercise separate positive definition starts on both targets. This does
not establish zero-start initialization inference. The first saved-project
script failed compilation because `getLocalVariables()` returns `Variable[]`;
its already-validated local object now receives the explicit cast. The first
fixture-inventory run rejected the unsorted new filename; the inventory order
was fixed without weakening its exact check. Failed logs remain under
`build/stack-local-review` and their result directories.

The first saved-runtime review detected Java 25 in the private headless
launcher, although the packaged standalone suites used Java 21. The installed Java 21 was a JRE; Ghidra requires a JDK and rejected that override.
The official Temurin 21.0.13+9 JDK was downloaded to ignored test storage and
verified against its GitHub release SHA-256
`d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c`.
A subsequent launch exposed Java 25-compiled scripts in the shared OSGi cache.
The private launch configurations now select that JDK and fresh private
settings/cache directories. Configuration replacement uses new inodes to
preserve the shared Ghidra installation. The complete saved-runtime matrix
was rerun after those corrections; earlier attempts are not Java 21 evidence. The earlier
saved six-role runs are superseded by the final runs, which also
validate every previous-package ELF/DWARF artifact independently. Earlier
fresh-import probes and six-role tests remain exploratory evidence;
the saved-program runs above supersede them. Two existing incoming-parameter
stack-transition exec regressions also pass through the shared instruction
engine. Those regressions do not broaden the new stack-local runtime claims.
