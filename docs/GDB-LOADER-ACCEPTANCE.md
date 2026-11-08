# Optional GDB loader acceptance

**CONFIRMED integrated:** PR157 merged normally on 2026-11-03 as
`c8e3afae3108ffe7d6a4b4d335463040426bc49c`, and issue107 is closed. Final
head `caa4916f22a2f51a86ef2c107ce8c43478308182` passed the complete strict
required-validation gate in [run41602638145](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41602638145).
All final-head package/target/host artifacts were independently reviewed,
including actual default/optional GUI screenshots and fresh validators.
The [final integration receipt](evidence/gdb-loader-41602638145.json) records
archive digests and review indexes. No administrator bypass or branch deletion
was used. This is not release publication or completion of attachment issue #72.

The detailed production acceptance below was established at `5654f53` in
[run41586083925](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/41586083925).
Final `caa4916` changes documentation only; its production JAR, native libraries
and wrappers are byte-identical to that accepted build. The earlier artifact
table is a historical acceptance record; the final receipt identifies the
subsequent complete rerun and protected integration.

The baseline is Ghidra 12.0.3, Java 21 bytecode, Gradle 9.3.1 and libdwarf 2.3.2
at `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`. The exporter, loader runtime,
wrappers and GUI launchers are unchanged by this acceptance documentation.

## Original #107 requirements

| Requirement | Reviewed evidence |
| --- | --- |
| L1: explicit optional generation and documented semantics | [User instructions](GDB-LOADER.md), Bash/PowerShell option-forwarding tests, packaged launchers, Linux and Windows actual Script Manager default/optional selection and cancellation. Disabled mode emits two files; enabled mode emits three. Companions contain the exact packaged runtime and matching target/sidecar/source hashes. |
| L2: correct relocation across runtime biases | Native x86-64 PIE reuses the same artifact across three ASLR launches. Function breakpoints, source, typed arguments and global values are checked. Shared objects use independently observed `link_map` biases; remote executable oracles use `AT_ENTRY` and compiler ELF entry values. |
| L3: PIE/shared, ordinary/rebased and stripped/sectionless | Every target lane executes ordinary exec/PIE/shared, explicitly rebased PIE/shared and sectionless companion tests from real exports. Sidecars receive GNU, LLVM and pinned strict validation. Sectionless fixtures use genuinely recovered symbols; absent curated variables are not fabricated. |
| L4: launch/attach/remote and lifecycle | Native launch/restart and attach/exec, QEMU remote targets, shared unload/reload and repeated loads. Transcripts prove stale objfiles are removed and duplicate loads avoided. Real remote connections with host file access disabled reject automatic discovery and accept a verified explicit bias. |
| L5: x86-64, AArch64 and a validated 32-bit target | The same production path passes x86-64, AArch64, ARM32 hard-float little-endian, MIPS32 big-endian and MIPS32 little-endian. Mapping arithmetic derives target width and PT_LOAD addresses without architecture or page-size constants. |
| L6: ambiguity, mismatch, absent maps and spaces | Real dual-library namespaces require explicit selection; file/code mismatch and wrong bias/module controls reject loading. Paths contain spaces. Compiler-reference controls additionally exercise deterministic packaged generation and rejection; they are distinguished from actual Forge export evidence. |
| L7: originals/configuration/default address semantics | Retained hashes prove original preservation. Native tests retain an unchanged `.gdbinit` sentinel and GDB confirmation setting. Repeated generation is deterministic. Fault/cancellation publisher tests and actual cancellation during production copying preserve the old generation. Default link-time ELF/DWARF semantics remain unchanged. |

The permanent [review receipt](evidence/gdb-loader-41586083925.json) identifies
artifact digests, individual runtime cases, freshly checked sidecars and
package source/manifests. Raw transcripts and artifacts are in the linked
workflow's artifacts; local review scripts/results are retained under
`build/review-41586083925/`. The receipt is an evidence index, not a substitute
for the executable CI tests.

## Artifact review

| Artifact | GitHub artifact ID | Reviewed scope |
| --- | --- | --- |
| Release package | 13208730539 | All manifests, exact source ZIP/Git contents, both wrappers and GUI launchers, runtime source, Java 21 class versions, no bundled private JNA or Python cache |
| x86-64 | 13213208136 | Seven retained actual-export runtime cases, five distinct freshly validated sidecars; Linux default/optional GUI and compiler-reference controls reviewed separately |
| AArch64 | 13213755079 | Nine runtime cases and six distinct freshly validated sidecars |
| ARM32 | 13212099793 | Nine runtime cases and six distinct freshly validated sidecars |
| MIPS32 big-endian | 13211122189 | Nine runtime cases and six distinct freshly validated sidecars |
| MIPS32 little-endian | 13211013190 | Nine runtime cases and six distinct freshly validated sidecars |
| Windows host | 13215280423 | Default/optional GUI selection/cancellation, installed publication/lock checks, headless and packaged exports; four fresh GNU/LLVM/strict sidecar validations |

Artifact archive SHA-256 values match GitHub's published digests. The release
ZIP SHA-256 is `2423124ec55e8ba530658a174070be359a19d21f87006c856ce46b17b6dfab08`.
Its production JAR SHA-256 is
`b89794d5c75a93eba64e182a1ab62725e08e94036a6335f573176af00bdcba9e`.
The Java source archive matches all 108 tracked production source files.

Fresh structural checks include `readelf -h -S` and DWARF info, abbreviation,
range and line inspection, `llvm-dwarfdump --verify`, and the pinned strict
checker through `src/test/integration/check-dwarfdump.py`. MIPS/ARM32 reviewed
sidecars have no strict diagnostics. Existing x86/AArch64 frame diagnostics
are corroborated against unchanged original frame bytes and fresh original
checks; there are no uncorroborated errors. All four reviewed Windows sidecars
have the same three corroborated inherited-frame diagnostics. Windows CI
records standalone `dwarfdump` as unavailable; the downloaded Windows outputs
were subsequently checked with the pinned Linux checker.

AArch64/ARM32 normal QEMU GDB logs contain the same system-supplied DSO string
table warning as their independent compiler-reference oracles. Deliberately
disabling remote file access additionally produces unavailable process-map/
vDSO diagnostics; the loader's refusal and explicit-bias fallback are checked.
These are recorded individual cases, not a blanket warning exemption.

## Boundaries and integration

Windows acceptance proves native Windows generation, GUI interaction,
cancellation, identity and structural behavior. Linux ELF execution in GDB is
performed by the Linux/native/QEMU target lanes, not claimed as a native
Windows runtime test. The loader documents Linux-style mapping discovery,
required GDB Python APIs, explicit-bias fallback, single-inferior operation and
absolute generation-bound paths. These restrictions are explicit diagnostics,
not guessed addresses or broader architecture-support claims.

The original failed run 41569991085 remains failed. Its Windows test used
lexical parent equality and rejected equivalent short/long directory names.
The corrected test requires physical directory identity for all three staged
files, with a Linux symlink-parent regression. The corrected native Windows
smoke and both GUI journeys pass in run 41586083925.

The final documentation head passed the up-to-date `required-validation`
check and merged normally without an administrative bypass. #107 is closed.
#72 remains open independently: companion publication
does not implement executable attachment, metadata preservation, durable
backup receipts or crash recovery.
