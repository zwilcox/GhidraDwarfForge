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

**CONFIRMED.** `MinimalDwarfSidecarExporter` creates native DIEs, attaches attributes, transforms the unit and retrieves both section bytes and symbolic relocations. It applies relocations before replacing or adding Java-written sections. When line, range or location data is present it passes native `.debug_info` and `.debug_abbrev` to `Dwarf32InfoRepair`. The Java prototype must produce valid offset and reference widths before this repair stage. [Native exporter](../../../main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java)

**PLANNED.** Compare each backend independently against expected debugger observations and validators. A byte-identical rerun within a backend checks determinism. Differences in valid abbreviation IDs and string order are allowed between backends. The adoption decision is pending those results and comparative measurements.
