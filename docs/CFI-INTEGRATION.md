# Unwind infrastructure integration (#112)

**CONFIRMED locally; hosted acceptance pending.** The integration branch combines
the existing unwind commits with main `8041fdab` using normal merge history.
This is the common validation/integration route for the work reviewed in PRs
167–174 and the subsequent native-export, coexistence and evidence-report commits.
Those earlier branches remain intact. This checkpoint does not close #112.

## Review map

| Area | Implementation and acceptance notes |
| --- | --- |
| Preserve original linked-image unwind data | [Original CFI preservation](ORIGINAL-CFI-PRESERVATION.md), PR167 |
| Encode explicit caller-register rules | [Encoder](CFI-RULE-ENCODER.md), [ABI audit](UNWIND-ABI-AUDIT.md), PR168 |
| Recover instruction/flow/call evidence | [Flow](UNWIND-FLOW.md), [profiles](UNWIND-PROFILES.md), [call proofs](UNWIND-CALLS.md), [projection](UNWIND-FRAME-RECOVERY.md), PR169 |
| Original bytes, frame coverage and loader writes | [Original sources](ORIGINAL-FRAME-SOURCES.md), [precedence](ORIGINAL-UNWIND-PRECEDENCE.md), PR170–171 |
| Memory effects and composition | [Memory](UNWIND-MEMORY-EFFECTS.md), [composition](FRAME-COMPOSITION.md), [writer](QUALIFIED-FRAME-WRITER.md), PR172–174 |
| Program collection and real export | [Collection](UNWIND-PROGRAM-RECOVERY.md), [consistency](EXPORT-CONSISTENCY.md), [native export](NATIVE-FRAME-EXPORT.md) |
| Coexistence and recorded evidence | [Native coexistence](NATIVE-FRAME-COEXISTENCE.md), [runtime coexistence](RUNTIME-FRAME-COEXISTENCE.md), [processor section types](TYPED-UNWIND-SECTIONS.md), [reports](UNWIND-EVIDENCE-REPORT.md) |

The individual documents retain the exact scope and hashes of their historical
checks. They do not substitute for the combined branch's required hosted gate.

## Merge resolution and combined local checks

Main's annotation-aware exporter overloads and the explicit frame-plan exporter
both delegate to one internal implementation. Normal exports retain synthetic
constants and receive no frame plan. The existing test-only frame entry point
uses an empty synthetic-constant set. The implementation preserves the native
producer calls and retains the frame writer's original-metadata checks. Combining
annotations and generated frames in the supported user flow remains part of
normal-entry-point integration; these separate-path tests do not claim that work.

The conflict resolution also retains both fixture inventories and both sets of
historical project notes. Main's annotation/context implementation and the unwind
branch's input/program consistency guard remain present in the standard script.

Fresh tests of the combined package pass:

- Java 21 build; seven component suites covering report consistency, encoding,
  frame projection, original-source inventory, annotation text/composition and
  line tables. The package's 730 classes, 207 production source files and installed
  main script match the tested checkout.
- Installed normal exports of saved analyst programs on x86-64 executable and
  AArch64 PIE: 50 comments and 35 synthetic constants per case, both instruction
  context forms, debugger lookup/source stepping, deterministic repeats, four
  limit failures and eleven genuine cancellation stages per case. Input/project
  preservation passes. The AArch64 system-DSO warning exactly matches its compiler
  reference.
- Eight native recovered-frame cases: six executable/PIE/shared roles across
  x86-64/AArch64, plus two split-prologue shared objects with existing runtime
  frames. These pass 72 exports, 32 failure controls, 32 sidecars and 72 GDB
  sessions, including rebases, original-byte evidence and report comparisons.
- All four intrinsic-context modes, eight deterministic exports, four sidecars
  and four GDB sessions. Ordinary same-spelled calls retain normal behavior.
- All 38 raw strict validator reports remain intact and agree with their
  receipts. Workflow lint, architecture isolation, fixture inventory and the
  x86-64 reproducible fixture build pass.

Two setup corrections are retained: the initial Gradle command used an invalid
line-table task name, and the first AArch64 annotation commands referenced an
absent then an older-schema evidence capture. No production behavior or oracle
was weakened to resolve them. See [the combined receipt](evidence/cfi-integration.json)
for the tested merge, package/source hashes and raw archive.

## Remaining acceptance

The consolidation requires its own current-base protected CI and artifact review.
PR175's final annotation acceptance documentation keeps integration priority.
Older PRs should be reconciled only after their changes are accepted through this
route; passing a subset of the older branches is insufficient.

Full #112 still requires the unchanged compiler-C recovery cases, an explicit
resolution of the global-store/stack-alias policy, complete evidence/provenance and
ADR enablement, and the normal CLI/GUI flow with analyst knowledge preserved.
Current strict memory behavior and ADR-0002's production prohibition remain in
force. No ordinary export selects synthesized frames. The broader goal then
continues with #110 LLDB validation and #109 build-ID installation.

## Standalone large-ELF CI correction

Hosted PR176 run `42217484551`, x86-64 job `127895477474`, stopped at the
large-ELF compile step. The writer's new explicit frame method references types
outside the test's fixed source-file list. The unchanged script reproduces all
four missing-type errors locally. Supplying `src/main/java` as `javac`'s source
path compiles the actual transitive closure; `jdeps` reports only `java.base`.
No extension JAR, Ghidra classes or native libraries are added to its classpath.

The full unchanged test then passes with a 67,108,864-byte maximum heap,
2,147,487,745-byte input and 2,147,491,176-byte sidecar. It checks deterministic
reruns, exact original payload/identity, alias rejection, failed publication,
ELF32 overflow, GNU/LLVM/pinned strict validation and actual GDB source, type,
values, stepping and normal exit. The strict checker retains two independently
corroborated inherited compiler-frame diagnostics; this is not a warning-free
raw libdwarf result. Its complete report and original-frame corroboration are
retained in the [correction receipt](evidence/large-elf-ci-dependencies.json).

An initial local run after compilation reached the alias check but failed because
the external exFAT drive cannot create hard links. No test was weakened: the full
run passed on Linux tmpfs after relocating 30 immutable CI archives with matching
SHA-256 hashes and retaining their old paths as symlinks. Production Java/native
source is unchanged from the combined checkpoint. Hosted acceptance of the new
head remains required.
