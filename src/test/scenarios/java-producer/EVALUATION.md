# Java DWARF producer evaluation

## Comparison baselines

| Input | Pinned revision | Role |
| --- | --- | --- |
| Forge | `46df4e94393de15050cc42a4e37fa071d7588cde` | Ghidra 12.2 reference exporter, including upper-half ELF64 support |
| libdwarf | v2.3.2, `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993` | Production producer with the two Forge patches and release build configuration. [Provenance](../../../../native/libdwarf/PROVENANCE.md) |
| gimli | v0.34.0, `86df12a630d43bc97b37eea4d2c7b218fa3ea2e3` | Writer design reference. [Pinned source](https://github.com/gimli-rs/gimli/tree/86df12a630d43bc97b37eea4d2c7b218fa3ea2e3/src/write) |

## Design choices under evaluation

- Reserve a compilation-unit-local identity before defining a DIE. Resolve it to a byte offset when entries have a layout. This lets a member point through a pointer type back to its containing structure. Parent/child links describe a tree even when type references form cycles. [gimli unit writer](https://github.com/gimli-rs/gimli/blob/86df12a630d43bc97b37eea4d2c7b218fa3ea2e3/src/write/unit.rs)
- Intern UTF-8 strings within one export and assign offsets in deterministic insertion order. The offset of a later string depends on preceding encoded byte lengths and their NULs. [gimli string writer](https://github.com/gimli-rs/gimli/blob/86df12a630d43bc97b37eea4d2c7b218fa3ea2e3/src/write/str.rs)
- Model target virtual addresses, CU references, string offsets and section offsets separately. In DWARF 5 with DWARF32 offsets, a target can have eight-byte addresses and four-byte section offsets. Forge already has final linked addresses for its matched sidecar. Symbol-plus-addend relocations would require a distinct capability. [gimli relocation writer](https://github.com/gimli-rs/gimli/blob/86df12a630d43bc97b37eea4d2c7b218fa3ea2e3/src/write/relocate.rs)

## Production comparison path

The native producer returns bytes containing linked address addends. Forge checks the symbolic relocation groups, record bounds, section symbols, address width and expected target addresses. It packages the resolved DWARF bytes. Native units with line, range or location data pass through `Dwarf32InfoRepair`, which narrows section offsets to DWARF32 and adjusts affected CU references. The prototype writes those fields at their final width. Both paths use the same matched ELF writer. [Native exporter](../../../main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java) · [Repair](../../../main/java/ghidradwarfforge/dwarf/Dwarf32InfoRepair.java)

| libdwarfp call group | Production responsibility | Java evaluation |
| --- | --- | --- |
| `dwarf_producer_init`, `dwarf_pro_set_default_string_form`, section callback, `dwarf_producer_finish_a` | Target flags, output sections and symbols, default strp form, handle lifetime | One encoder and per-unit tables per write. The Java fixture receives a nonexistent native-library path. |
| `dwarf_new_die_a`, `dwarf_add_die_to_debug_a` | Allocate and connect DIEs, submit the root | Typed nodes, ordered children, stable identities, abbreviation shapes. The JNA interface also declares `dwarf_die_link_a`; the production exporter uses parent links at creation. |
| `dwarf_add_AT_name_a`, `dwarf_add_AT_comp_dir_a`, `dwarf_add_AT_producer_a` | CU and entity strings in info/str | Export-local UTF-8 interning. |
| `dwarf_add_AT_unsigned_const_a`, `dwarf_add_AT_any_value_{u,s}leb_a`, `dwarf_add_AT_flag_a` | Sizes, bounds, encodings, offsets, constants, flags | Unsigned constants and present flags demonstrated. Signed LEB bytes have boundary tests. Enumerator and signed-constant DIEs remain unsupported. |
| `dwarf_add_AT_reference_c` | Type, declaration, class, import and call relationships | Resolve CU-relative type references after layout. Remaining relationships need their own admissible target kinds. |
| `dwarf_add_AT_dataref_a`, `dwarf_add_AT_targ_address_c` | Line/range/location section offsets, code PCs and entry points | Separate section and address operands. The encoder checks offset bounds and narrows only values that fit. |
| `dwarf_new_expr_a`, `dwarf_add_expr_gen_a`, `dwarf_add_expr_addr_c`, `dwarf_add_AT_location_expr_a`, `dwarf_add_AT_block_a` | Inline stable storage, inheritance, vtable and call-site expressions | The fixture uses the Java location-list encoder. Inline expressions and block attributes remain unsupported. |
| `dwarf_transform_to_disk_form_a`, `dwarf_get_section_bytes_a`, `dwarf_get_relocation_info_count`, `dwarf_get_relocation_info` | Materialize info/abbrev/str, retrieve section buffers and symbolic relocation evidence | Write final section bytes and resolve CU-relative fixups directly. No ET_REL or symbol-plus-addend input contract. |

## Reproduction

Use the pinned Forge release ZIP or a ZIP built from that revision, Ghidra 12.2, JDK 25, Linux x86-64, GCC, GNU binutils, GDB, llvm-dwarfdump, the Forge-built strict dwarfdump, MIPS big-endian GCC/binutils, qemu-mips-static, qemu-system-mips64 and gdb-multiarch. Point `DWARFDUMP` at the validation bundle's launcher. Both commands require a fresh output directory.

```bash
scenario=src/test/scenarios/java-producer
python3 -B "$scenario/compare.py" --ghidra "$GHIDRA_INSTALL_DIR" --extension "$FORGE_ZIP" \
    --output "$RESULTS/comparison"
python3 -B "$scenario/benchmark.py" --ghidra "$GHIDRA_INSTALL_DIR" --extension "$FORGE_ZIP" \
    --input /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 --output "$RESULTS/sqlite"
```

The comparison builds a reference ELF, reads its linker-defined addresses and strips it. Per-case `java/` and `libdwarf/` directories contain the sidecar, source, validator logs and GDB observations. GDB starts in the original ELF directory, loads each sidecar by absolute path and executes the stripped original. The two JSON observations must agree after each has passed the fixture's independent assertions. [Harness](compare.py) · [GDB assertions](observe.py)

## Capability and gap matrix

| Capability | Status and evidence |
| --- | --- |
| DWARF 5 compilation unit, DWARF32 offsets, ELF64 little-endian, ELF32 big-endian, ELF64 upper-half big-endian | **CONFIRMED.** One `DW_TAG_compile_unit` and named `DW_TAG_subprogram`. GDB checks the start, exclusive end, declaration/source lookup, and two line rows. A Malta CPU executes the original upper-half code above `0xffffffff80002000`. [C fixture](fixture.c) · [Malta assembly](upper-half.S) · [Linker map](../../fixtures/mips64-upper-half.ld) |
| CU and function attributes | **CONFIRMED.** `name`, `producer`, `comp_dir` via strp, `language`, `high_pc`, `decl_file` and `decl_line` via udata, `low_pc` via addr, `stmt_list` via sec_offset. The Java fixture sets `external` using flag_present. Source paths are export-specific. |
| Recursive types and DIE references | **CONFIRMED.** Structure, member, pointer, base and variable tags. `type` uses ref4, including a forward reference and reverse edge. GDB checks `next` points to its containing type, `value` starts at the pointer width, integer size is 4 and aggregate size is twice the pointer width. [Fixture model](EvaluationFixture.java) |
| Changing local, two source rows and address index | **CONFIRMED.** The reused Java line, aranges and loclists writers emit the source lookup and two half-open `DW_LLE_start_end` entries with `DW_OP_addr`, terminated by end_of_list. At entry GDB sees `moving` at the first object with value 19. At the transition its address changes to the second object and its value becomes 42. In both states `next->value` is 19. |
| Frame rules | **CONFIRMED** for the x86-64 assembly leaf. Both paths use Forge's frame-aware matched writer, producing a CIE/FDE with the caller's PC at CFA−8. GDB checks the caller PC at both stops against the assembly return label. The production unwind profile rejects generated ordinary MIPS64 frames at this baseline. The Malta run tests code, lines, types and storage. [Leaf](x86-leaf.S) · [Profile](../../../main/java/ghidradwarfforge/targets/UnwindRelocationProfile.java) |
| Encoding and failure isolation | **CONFIRMED.** Exact ULEB/SLEB transitions, multi-byte UTF-8, duplicate strings and offsets, bounds on ELF32 addresses, section offsets and DWARF32 initial lengths. Bad references, tag/child or field mismatches and unsupported sections throw. A/B/A in one JVM produces identical A bytes with isolated strings. Cancellation and failure after staging preserve the original and prior output pair, or leave both output paths absent. [Encoding checks](EncodingChecks.java) · [Lifecycle checks](LifecycleChecks.java) |
| Discontiguous code | **CONFIRMED.** On Malta the function branches across 16 bytes of padding. The CU and function each use `DW_AT_ranges`/`DW_FORM_sec_offset`, referencing separate lists of `DW_RLE_start_end` entries. Readelf compares both lists against linker addresses. GDB checks both ranges at their boundaries and finds no function or source row in the gap. Interior entry PCs, terminal start_length ranges and additional CFI profiles remain **PRESENT, UNVERIFIED** in this evaluation. [Malta fixture](upper-half.S) · [Range writer](../../../main/java/ghidradwarfforge/dwarf/Dwarf5RangeLists.java) |
| Additional types, scopes and declarations | Unsupported by the prototype. Arrays/subranges/count, typedefs, unions, enums/enumerators/const_value, const/volatile/restrict/atomic, references/rvalue references, subroutine types, formal and variadic parameters, bit fields/bit_size/data_bit_offset, namespaces, lexical blocks, globals, imports, specification, inheritance, virtuality and vtable element locations need mappings and independent tests. [Production tag and attribute inventory](../../../main/java/ghidradwarfforge/nativeapi/DwarfConstants.java) |
| Variable/call expressions and calling conventions | Unsupported by the prototype. Production uses exprloc/block, stable `DW_OP_addr`, regx, bregx, piece, bit_piece, deref, call-site/parameter DIEs, entry_value, constu, arithmetic and conditional branches. Prototyped, calling_convention, noreturn, object_pointer, artificial, call/return PC, call origin/value and tail-call claims require ABI and runtime oracles. [Storage expressions](../../../main/java/ghidradwarfforge/dwarf/DwarfLocationExpression.java) · [Call values](../../../main/java/ghidradwarfforge/calls/CallValue.java) |
| Other formats, relocations and hosts | DWARF64 lengths, other DWARF versions, multiple CUs, supplementary references and relocatable object inputs have no prototype interface. Windows, ARM, AArch64, PIE rebasing, firmware and analyst-project extraction are untested for this backend. Existing native validation continues to define production support. |

No gimli source or tests were copied. This evaluation uses Forge code, independently written Java and independently specified fixture values. Track upstream gimli changes to unit layout, fixups and strings by comparing the three pinned writer modules when updating the reference, and translate relevant behavior into a Forge fixture before changing the encoder.

## Local results

The Malta run uses a stripped boot stub to enter the exported function. GDB 15.1 prints a heuristic unwinder warning for that caller. The tests exercise the two exported ranges on Malta and validate caller unwinding on the x86-64 leaf. [Debugger assertions](observe.py)

All six target/model combinations passed on both backends. Within each backend the repeated sidecar and source were byte-identical and the stripped input hash was unchanged. GNU readelf 2.42 decoded the sections, LLVM 18.1.3 reported no verification errors, and GDB 15.1 observed the expected values natively and through QEMU 8.2.2. The strict libdwarf 2.3.2 checker passed through Forge's corroboration harness. On x86-64 it also reported two alignment diagnostics in inherited FDEs, both reproduced against the original ELF. Both MIPS cases had zero reported errors. [Strict checker policy](../../integration/check-dwarfdump.py)

The performance workload was the Ubuntu amd64 `libsqlite3-0` 3.45.1-1ubuntu2.8 shared object, SHA-256 `85265a9d4afca6f4b325ceb078b669c754fb881abed4cafe91ccebe9d625d975`. The benchmark passed identical inventories of 1,403 defined, nonempty dynamic text symbols with distinct addresses to both writers. GNU readelf decoded every emitted name, start and size back to that inventory. The strict checker corroborated all 1,572 inherited FDE alignment diagnostics against SQLite's original bytes. [Benchmark](benchmark.py)

| Backend | Median export | Peak JVM process RSS (two runs) | Matched ELF size |
| --- | ---: | ---: | ---: |
| Java | 3.77 ms | 94,092 / 92,064 KiB | 1,543,112 bytes |
| Packaged libdwarf | 13.31 ms | 150,064 / 150,888 KiB | 1,542,880 bytes |

Intel Core i9-14900KF, x86-64 Linux 7.0.0-38-generic, glibc 2.39, OpenJDK 25.0.5.1, `-Xms128m -Xmx512m`. Two series in reverse backend order, two warmups then five timed exports per JVM. The timer includes target ELF parsing, symbol DIE generation and sidecar writing. Production also runs its model checks and export accounting. RSS includes JVM startup and native allocations. Inventory extraction, Ghidra analysis and decompilation are outside the timer. The archived baseline JAR SHA-256 was `0b098bc8c90afdc9b4105b8ff765660f7369edcc317fedf0bdbe3aee975cfa0d`.

## Decision

**Defer production adoption.** The prototype demonstrates endian-correct DIE layout and live debugger parity for the small tested subset. The symbol-only speedup warrants further experiments. The benchmark does not measure end-to-end Ghidra exports, and the prototype cannot represent most production type, storage and call-site evidence.

Before changing the default, require independent debugger and validator parity for the remaining DIE graph, register and piecewise storage, calls, CFI, relocation models and failure cases across Forge's supported target and host matrix. Measure large typed and optimized Ghidra projects, including peak heap during reference resolution. Writing and maintaining the encoder transfers responsibility for form selection, reference overflow, consumer interoperability and DWARF errata to Forge.

A future cutover must verify the installable extension on clean Linux and Windows hosts without libdwarfp, inventory every consumer-library use, then retire the producer JNA declarations, producer-specific repair, native patches, build and packaging only as their last users disappear. Keep independent libdwarf validation available in CI. Platform-specific filesystem helpers, atomic rename and attachment metadata use separate native paths. [Current packaging](../../../../support/assemble-release.sh) · [Native upgrade #193](https://github.com/zwilcox/GhidraDwarfForge/issues/193) · [Rust alternative #194](https://github.com/zwilcox/GhidraDwarfForge/issues/194)
