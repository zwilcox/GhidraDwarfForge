# Original ELF instruction agreement (#112)

**CONFIRMED locally:** the native unwind call verifier requires every captured
instruction to match the original executable before publishing its proof.
The exporter does not yet enable synthetic CFI; full #112 acceptance remains
in [the synthesis contract](SYNTHETIC-CFI-EVIDENCE.md).

## Mapping and evidence

`ElfCodeBytes` maps normalized instruction virtual addresses through `PT_LOAD`,
using `p_offset + (address - p_vaddr)`. It does not infer file offsets from the
image base or require section headers. A single executable, file-backed load
must contain the entire instruction. Intersecting/overlapping loads, crossings,
zero-fill bytes, width/extent overflow and mismatches are rejected. This is a
conservative proof boundary, not a claim that all rejected layouts are invalid
ELF files. ET_REL requires another address model.

The reader opens one read-only channel and reads only the bounded instruction
bytes (at most 4096), including when file offsets exceed 2 GiB. It records the
original virtual address, file offset, byte count and SHA-256 for each match.
The native verifier retains these records under Ghidra `Address` keys and closes
the channel on success, failure and cancellation. All captured body instructions
must agree, including unreachable instructions; flow verification cannot hide a
patched instruction. The original executable and curated database are unchanged.

Existing source identity checks run around reads. They detect observed file
replacement/size/timestamp changes but are not a transactional file snapshot.
The production export integration must retain input identity through publication
and hold a consistent Ghidra program view. This component does not discharge
that later publication obligation.

## Acceptance and verification

```bash
./gradlew elfCodeBytesSmoke ghidraUnwindCallsSmoke unwindFrameRowsSmoke \
    unwindCallsSmoke unwindFlowSmoke unwindAbiProfileSmoke \
    ghidraUnwindInstructionsSmoke callFrameEncoderSmoke buildExtension
python3 src/test/integration/unwind-frame-recovery.py build/classes/java \
    build/test-results/unwind-frame-recovery --dwarfdump "$DWARFDUMP"
bash src/test/integration/architecture-neutrality.sh
actionlint .github/workflows/ci.yml
```

The ELF component has 140 checks across ELF32/64 and both byte orders, with
sectionless inputs, nonzero file-offset mappings, unordered and overlapping
loads, missing/non-executable/zero-fill mappings, sparse offsets beyond 2 GiB,
source identity changes, closed channels and every observed cancellation poll
plus retry. These layout controls do not establish new architecture support.

The native verifier/planner suite has 26 fixtures and 4148 checks. Deliberately
patched x86-64 and AArch64 save instructions must fail specifically at original
byte agreement, before later return/preservation analysis. The full unaffected
flow/profile/projection/encoder regression suites and extension build pass.

The runtime harness independently checks each recorded file offset/hash using
the fixture's section mapping and requires complete instruction-byte coverage.
Independent rebased JVM recovery must produce identical normalized match records
and frame plans. Four x86-64/AArch64 non-PIE/PIE cases produce eight
plain/compressed artifacts accepted by GNU, LLVM and the pinned strict checker.
Sixteen GDB runs compare reference, absent-CFI and both recovered modes, including
actual DWARF unwinder selection, instruction-boundary traces, register witnesses,
`finish` and normal exit. Original/reference/source hashes and repeated sidecars
remain unchanged. The existing narrowly matched AArch64 QEMU DSO warning remains
identical in all modes; no additional warnings are accepted.

See [the receipt](evidence/unwind-code-agreement.json) for exact source hashes,
commands, logs and artifact archive. CI is wired; hosted acceptance of this
recovery branch is **PRESENT, UNVERIFIED**. The test-only importer and CU do not
replace real exporter acceptance. Global-write alias proof, original unwind
coverage/precedence, production diagnostics/publication and the remaining
compiler/shared/shrink-wrapped/failure cases are still required.
