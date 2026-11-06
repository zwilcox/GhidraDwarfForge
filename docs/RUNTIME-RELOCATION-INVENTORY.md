# Runtime relocation inventory

**CONFIRMED locally:** `ElfRuntimeRelocations` reads standard gABI runtime
relocation tables from linked ELF inputs. This supplies evidence for #112's
original-frame qualification. It does not apply relocations, certify their
write footprints, or authorize synthetic unwind coverage.

The reader follows `PT_DYNAMIC`, retaining raw tags including repeated
`DT_NEEDED` and processor/OS entries. REL, RELA and PLT records retain their
file positions, target addresses, complete raw `r_info` bits and explicit
signed addends where present. RELR expands address/bitmap records into
pointer-sized target locations without inventing symbol indices or addends.
Table roles and hashes remain available when general and PLT tables overlap
on agreeing record boundaries. Processor-specific `r_info` interpretations
are deliberately outside this generic reader.

Named and sectionless inputs use the same load-backed tables. Allocated
standard relocation sections must agree with a complete dynamic table and
its file mapping, format and entry size. Nonallocated retained link relocation
sections from `--emit-relocs` do not become runtime relocations. Missing,
ambiguous, truncated or conflicting metadata throws; callers must not turn
that failure into an empty inventory.

Reads use one owned channel, bounded chunks and observed input-identity checks.
The limits are 64 MiB of aggregate table reads, 262,144 dynamic entries,
262,144 expanded relocation records and 16,777,216 mapping comparisons.
Address arithmetic respects ELF width and the implementation's nonnegative
signed-long domain. Cancellation releases the channel and returns no inventory.
These checks detect observed changes; they do not create an immutable snapshot.

The format follows the [gABI relocation records and RELR encoding](https://gabi.xinuos.com/elf/06-reloc.html)
and [dynamic-table metadata](https://gabi.xinuos.com/elf/08-dynamic.html).
The inspected primary pages are captured and hashed in the evidence archive.
No native producer calls, register mappings or Ghidra/Java baselines changed.

## Validation

The component suite passes 932 checks across ELF32/ELF64 and both byte orders:
raw high-bit fields, signed addends, repeated unknown/NEEDED tags, consecutive
RELR bitmaps and their highest bits, even unaligned RELR addresses, matching
PLT subsets, allocated/nonallocated distinctions, empty/absent tables,
malformed framing, overflow, ambiguous/BSS mappings, expansion limits,
immutable results, every observed cancellation point, retry and late mutation.

The native fixture yields twelve x86-64/AArch64 executable, PIE and shared
cases with retained link relocations, with and without RELR packing. Independent
compiler rebuilds are byte-identical. Twenty-four named/sectionless variants
match both an independent byte reader and the unchanged named GNU relocation
oracle, including record offsets, raw info, addends, RELR addresses and hashes.
All twelve originals pass LLVM DWARF verification and the pinned strict checker;
existing frame-alignment diagnostics are corroborated against the independent
rebuild's identical frame bytes and complete reports. Originals and sources
remain unchanged. Both target fixture inventories pass reproducibility checks.

Three initial test limitations are retained explicitly:

- LLVM rejects GCC's optimized fortified printf call-site nesting. This relocation
  fixture now uses `-O0`, retaining the actual external call and dynamic tables.
- This host's GNU readelf reports bad symbol indices in the GNU-hash-only
  sectionless copy. The copied bytes differ only in section-table header fields;
  both readers' complete inventories are checked against the unmodified GNU
  oracle. The failed invocation is retained, not counted as validator success.
- GNU AArch64 ld 2.42 warns that RELR packing is ignored. Those cases now require
  LLD 18 explicitly; the PIE test requires at least eighty decoded RELR targets.
  CI installs `lld-18` in the AArch64 lane. The local Ubuntu package was verified
  against its package-index SHA-256 before private extraction.

Commands:

~~~bash
./gradlew elfRuntimeRelocationsSmoke originalFrameSourcesSmoke \
    originalFrameRangesSmoke sectionlessUnwindSmoke buildExtension
python3 src/test/integration/runtime-relocations.py build/classes/java \
    build/test-results/runtime-relocations --dwarfdump "$DWARFDUMP"
bash src/test/integration/fixture-reproducibility.sh x86_64
bash src/test/integration/fixture-reproducibility.sh aarch64
bash src/test/integration/architecture-neutrality.sh
actionlint .github/workflows/ci.yml
~~~

See [the receipt](evidence/runtime-relocations.json). The pipeline runs the
inventory matrix in the existing x86-64/AArch64 lanes; this branch's hosted
execution is **PRESENT, UNVERIFIED**. No exported ELF/DWARF or GDB behavior
changes in this checkpoint, so GDB was not rerun for this read-only component.

## Remaining qualification

**PLANNED:** the selected target policy must account for every relevant raw
processor/OS tag and any non-gABI relocation scheme; an unknown scheme cannot
be silently omitted. REL/RELA write widths, COPY sizes, resolver effects and
relocations touching frame sources or recovered code require a separate proof.
RELR locations alone do not supply that proof for an entire image. Production
identity, original/generated range precedence, frame-record reconciliation,
unchanged global-writing compiler fixtures and the full exporter/GDB failure
matrix remain required by #112. PR166 integration retains priority, followed
by the full #112/#110/#109 goal.
