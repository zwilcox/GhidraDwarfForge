# GDB loading and explicit debuglink completion

**CONFIRMED scope:** complete issues [#107](https://github.com/zwilcox/GhidraDwarfForge/issues/107)
and [#72](https://github.com/zwilcox/GhidraDwarfForge/issues/72). Neither issue is
complete. This ledger supplements, and does not narrow, their acceptance
criteria or ADR-0004/ADR-0005. Performance issue #74 is outside this goal.

The selected baseline remains Ghidra 12.0.3, Java 21-compatible bytecode,
Gradle 9.3.1 and the existing pinned native producer. No new native producer
declarations are needed for the loader.

## Delivery and evidence ledger

All rows are **PLANNED** until linked evidence proves the complete row.

| ID | Required outcome | Evidence required |
| --- | --- | --- |
| L1 | Optional deterministic companion, explicit CLI/GUI controls and documented loading/override semantics | Packaged exporter and both host GUI/wrapper journeys; disabled-default comparison |
| L2 | Same link-time sidecar at different runtime biases | Actual GDB function breaks, source, globals and available variables at each bias |
| L3 | PIE main/shared, ordinary/rebased, stripped/sectionless | Real exporter fixtures with independent ELF/DWARF validation and GDB |
| L4 | Native launch/attach, remote/QEMU, restart/exec/unload/reload | Runtime transcripts, invalidation/no-duplicate assertions; explicit unsupported-discovery diagnoses and working override |
| L5 | x86-64, AArch64 and validated 32-bit target | Same production path in all three CI lanes; widths/addresses derived from target |
| L6 | Ambiguity, wrong identity, absent mappings, special paths | Negative cases prove no incorrect symbol loading; paths with spaces work |
| L7 | Original/configuration preservation and unchanged default addresses | Hashes, deterministic reruns, publication rollback/cancellation; no .gdbinit edits |
| A1 | Linux/Windows identity and metadata contract | Native host tests for supported preservation and rejected links/streams/locks/security metadata |
| A2 | Explicit disabled-default attachment after validated export | CLI/GUI warning and successful validation binding; fatal/cancel refusal |
| A3 | Receipt-bound files/report/validator evidence/candidate; all-path preflight | Cross-role aliases, symlink traversal, hardlinks, dangling links, log/backup/receipt/stage collisions rejected before writes |
| A4 | Independent exclusive verified backup and atomic replacement | Bytes/metadata/identity observations and no-overwrite/no-copy-fallback tests |
| A5 | Cancellation, failure and durable recovery | Faults around preparation/replace/commit; complete old/new target, recoverable backup, protected concurrent target |
| A6 | Changed-CRC refresh with retained generations | Analyst edit, backup-based re-export, fresh pair basename, receipt chain and rejection of lost/overwritten old pair |
| A7 | Automatic discovery and CRC rejection | Fresh GDB sessions, no-build-ID mismatch, actual runtime checks on host/target matrix |
| C1 | Integration and documentation | Required exact-head CI, artifact review, normal protected merge, TODO/context/help reconciliation |

Attachment must implement the full ADR-0004 transaction: selected explicit
paths, preserved executable image/identity, supported metadata, exclusively
owned staging, independent retained backups, prepared and committed receipts,
flush/durability contract, safe rollback and immutable prior generations.
Existing observations and candidate preparation are prerequisites, not proof
of an attachment transaction. Refresh must preserve the strict Ghidra import
hash contract by exporting against the verified original backup.

## Implementation sequence

1. Implement and test architecture-neutral mapping arithmetic independently.
2. Add runtime identity validation, explicit GDB command, lifecycle handling,
   companion generation and complete artifact-set publication.
3. Exercise the loader with real exports across the full L1–L7 matrix.
4. Finish host transaction primitives and validation/receipt binding, implement
   initial attachment and refresh/recovery, then expose controls.
5. Exercise A1–A7, review every acceptance row and integrate through C1.

Mapping discovery must correlate runtime mapping file offsets with ELF PT_LOAD
virtual addresses. It must not substitute a presumed page size, preferred
image base, first mapping address or runtime .text address for load bias.
Missing or ambiguous evidence must produce a diagnosis; an explicit override
does not waive sidecar/target identity checks. Link-time DWARF stays unchanged.

Primary command/API references: [GDB file commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Files.html),
[process mappings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Information.html),
and [Python lifecycle events](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html).

## Mapping arithmetic checkpoint

**CONFIRMED locally:** `src/main/resources/ghidradwarfforge/gdb/loader.py`
implements bounded mapping parsing and file-offset/PT_LOAD correlation without
assuming a page size, section table or preferred base. It returns all complete
module-instance candidates and refuses ambiguous automatic selection. It does
not yet install a GDB command, verify runtime identity or generate companions.
Thus no L1–L7 row is complete from this checkpoint alone.

Commands run from the `debug-loading` worktree:

```sh
python3 -B -m unittest discover -s src/test/python -p test_gdb_loader.py -v
python3 -B src/test/integration/gdb-loader-mappings.py
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew buildExtension
src/test/integration/architecture-neutrality.sh
git diff --check
```

Ten unit cases pass, including offset padding, split/overlapping mappings,
negative bias, ELF32 overflow, absent/ambiguous/inconsistent evidence and paths
with spaces. The live run in
`build/test-results/gdb-loader-mappings/run.5o_878da/` passes three native
non-PIE launches, three PIE launches with distinct ASLR biases and two shared
library load/unload cycles. Function/global addresses are independently checked
against compiler symbols, and GDB checks source, arguments 19/23, stepping and
global values 7/42. Selected fixture/source/reference hashes remain unchanged.
No attach/remote/cross-target or generated-Forge-companion claim follows.

The three reference images pass GNU readelf inspection without diagnostics,
LLVM verification and the locally installed dwarfdump invocation. These are
complete compiler ELF references loaded as symbols for stripped executables,
not artifacts made by the Forge writer. Earlier `--only-keep-debug` references
retained PT_INTERP headers without interpreter contents: readelf reported
`Unable to find program interpreter name` despite a zero exit code. Those
earlier runs remain under the result directory; the current harness preserves
the complete reference and rejects readelf diagnostics explicitly.

The extension builds. Inspection confirms the packaged loader source matches
the working source and both resource/source archives exclude host Python
bytecode, even after local imports. The new unit and live-reference CI steps
are **PRESENT, UNVERIFIED** on hosted runners. Actual GDB integration, complete
artifact-set publication, all loader acceptance lanes and the full attachment
transaction remain required.

## Generated companion and runtime identity checkpoint

**PRESENT, UNVERIFIED as a product feature:** `GdbCompanion.render` now builds
a deterministic self-contained `<sidecar>.gdb.py` from completed staging bytes
and their selected final paths. It requires copied-prefix and allocated-metadata
agreement with the selected original. The caller still needs three-artifact
publication and CLI/GUI controls; the ordinary exporter does not call it yet.

The generated file embeds the packaged Python runtime and inert base64 JSON.
Sourcing registers `forge-load [ID] [--bias INTEGER] [--module EXACT_RUNTIME_PATH]`
and `forge-unload [ID]`; it does not load symbols. Repeated sourcing reuses the
registry; mixed runtime revisions require a fresh GDB session. `forge-load`
checks all three selected file hashes and relocated immutable executable bytes
before adding symbols. It includes mapped ELF header identity where available,
excluding section-table fields that an eventual attachment changes. These memory
exceptions do not waive the selected original's full file hash.

Current bounded runtime contract: one stopped inferior, Python-enabled GDB with
the inspected lifecycle events and scoped parameter API, exact mapping paths,
at most 1 GiB of streamed immutable identity checks. Writable executable LOADs,
text relocations/changed code and unreadable identity bytes are diagnosed rather
than accepted without evidence. An explicit override permits unavailable mapping
queries, but does not bypass contradictory mappings, target width, file identity
or runtime byte checks. Native launch/restart and shared unload/reload have local
reference evidence; attach, exec, remote override and additional architectures
still require actual tests. Windows-host generation/control acceptance remains
open. These boundaries must be reconciled against the complete issue before
claiming completion.

Local tests now exercise the actual generated script through GDB's `source`
command, twice, from a built extension JAR. The smoke helper puts compiler DWARF
through the production matched sidecar writer, then calls the production
generator. It checks deterministic rendering, cancellation and rejection of an
unmatched compiler ELF. This proves neither Ghidra extraction nor final
artifact-set publication. The runtime tests retain function/global/source/
argument/stepping assertions, plus no duplicate objfiles, exit/unload removal,
wrong bias/module rejection, mismatched target/sidecar/source checks and wrong
runtime-code checks. Rejections leave the objfile list unchanged.

Seventeen Python unit tests pass. The generated-reference run
`build/test-results/gdb-loader-mappings/run.e1y_3jc7/` passes all three roles;
all three produced sidecars pass GNU/LLVM and local dwarfdump inspection. The
workflow now selects the installed extension JAR for this check, after package
installation. Hosted acceptance is **PLANNED**. No L1–L7/A1–A7 row is closed by
this component checkpoint.
