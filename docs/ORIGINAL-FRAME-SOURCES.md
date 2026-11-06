# Original ELF frame sources (#112)

**CONFIRMED locally:** OriginalFrameSources inventories named and
program-header-derived frame payloads, decodes bounded GNU/gABI zlib storage,
and compares EH search-table locations with their referenced FDEs.
**PLANNED:** runtime relocation qualification, precedence/record reconciliation
and real-exporter integration. Source discovery alone does not authorize
synthesis in apparent gaps or certify the original CFI instructions.

The collector recognizes .debug_frame, .zdebug_frame and .eh_frame. Duplicate
canonical debug encodings or named EH sources are uncertain rather than
silently preferred. A nonempty .eh_frame_hdr without an established frame source
is rejected. PT_GNU_EH_FRAME discovery works with sectionless files and with
named or unnamed section tables. If both sources exist, file offset and virtual
address must agree; the named extent may extend beyond the last table-proven
FDE only with zero termination/padding. Every search-table FDE pointer and initial
location must match the parsed record inventory. The original sectionless
writer API retains its prior behavior; discovery metadata is shared with this
new collector without changing emitted files.

The search-table address requirement has a retained failing-before regression.
The initial source collector accepted a header whose record pointers were valid
but whose advertised function address differed from the referenced FDE.
All four ELF width/byte-order combinations now reject it without returning a
partial inventory. Record preservation and trusted range identification are
different obligations.

Each source records original file offset/address, stored/decoded byte counts,
both SHA-256 digests, whether program headers corroborate it, and its immutable
CIE/FDE inventory. Reads are chunked and use one owned read-only channel after
discovery. Source identity is checked before/after reads and before return.
The existing identity checks detect observed changes, not a transactional
snapshot; final publication still needs its own consistent-input contract.

The aggregate stored and decoded budgets are each 64 MiB. GNU ZLIB headers use
their independent big-endian size field; gABI headers use the original ELF
class/order. Only zlib is currently decoded. Mixed encodings, allocated
compression, wrong header/reserved/alignment fields, excessive declared size,
dictionary dependence, checksum errors, truncated streams, output-size mismatch
and trailing input are rejected. Inflater resources and the source channel are
released on failure/cancellation. Cancellation is checked during reads,
inflation, hashing and record scans. Unknown sources must remain diagnostics
that inhibit synthesis, never empty coverage.

Compression framing follows the [ELF gABI compression contract](https://gabi.xinuos.com/v42/elf/03-sheader.html#compressed-sections)
and is independently checked against GNU objcopy output. The GNU legacy
variant is checked against actual objcopy output and independent Python zlib
decoding. No new native/JNA calls or ABI baseline changes are introduced.

## Validation

~~~bash
./gradlew originalFrameSourcesSmoke originalFrameRangesSmoke \
    sectionlessUnwindSmoke callFrameEncoderSmoke buildExtension
python3 src/test/integration/original-frame-ranges.py build/classes/java \
    build/test-results/original-frame-ranges --dwarfdump "$DWARFDUMP"
bash src/test/integration/architecture-neutrality.sh
actionlint .github/workflows/ci.yml
~~~

The source suite passes 1158 checks across both ELF classes and byte orders,
including plain/empty/gABI/GNU payloads, malformed compression, conflicting
sources, named/header disagreement, unknown/absent distinctions, input changes
during hashing, every observed cancellation poll and retry. The range,
sectionless-preservation and encoder regressions pass 4275/9172/158 checks.
The extension builds, and architecture/workflow checks pass.

The unchanged C compiler fixture yields twelve x86-64/AArch64
exec/PIE/shared reference cases with debug or EH frames. Independent builds
match. Thirty-six source variants cover plain, gABI/GNU compressed, sectionless
and unnamed EH inputs. An independent reader checks source offsets, stored
hashes, decoded bytes/hashes and complete FDE ranges against the plain compiler
reference and GNU/LLVM inventories. Original and source hashes remain unchanged.

All twelve originals and twelve compressed copies pass LLVM and the strict
checker under the existing corroboration policy. The known EH alignment
diagnostics are recorded against independent identical rebuilds; they are not
silently waived. The twelve sectionless/unnamed copies differ only in the
explicitly changed section-header fields; their source inventories match the
unchanged named oracle. These read-only inventory tests do not establish new
GDB behavior, frame synthesis or runtime relocation correctness. See
[the receipt](evidence/original-frame-sources.json).

The pipeline runs these checks in the existing x86-64/AArch64 lanes; hosted
acceptance of this branch remains **PRESENT, UNVERIFIED**. Original metadata
precedence, global-write callee proofs, real publication/diagnostics and the
full synthesis matrix remain in the [full contract](SYNTHETIC-CFI-EVIDENCE.md).
PR166 integration retains priority; #112/#110/#109 remain open.
