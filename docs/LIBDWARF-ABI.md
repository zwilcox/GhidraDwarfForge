# libdwarf 2.3.2 JNA ABI audit

## Scope and authority

The production binding exposes only the functions used by the exporter and its
isolated smoke test. The authoritative headers are from libdwarf release
`v2.3.2`, source commit
`af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`:

```text
src/lib/libdwarf/libdwarf.h
src/lib/libdwarfp/libdwarfp.h
```

No historical declaration under the repository's top-level `src/` directory
is part of the supported binding.

## Fixed-width and pointer mappings

| C type | Java/JNA mapping |
|---|---|
| `Dwarf_Unsigned`, `Dwarf_Signed`, `Dwarf_Off`, `Dwarf_Addr`, `Dwarf_Tag` | `long` |
| `Dwarf_Half` | `short` |
| `Dwarf_Small` | `byte` |
| `Dwarf_Unsigned *` | `LongByReference` |
| `int *` | `IntByReference` |
| opaque producer handles and `Dwarf_Error` | distinct `PointerType` classes |
| opaque-handle output and other pointer-to-pointer output | `PointerByReference` |
| `char *`/`const char *` input | `String` |
| returned C string | `String` |

`NativeLong` is intentionally absent. It is 32 bits on 64-bit Windows, while
the pinned libdwarf typedefs above are 64-bit on both supported hosts.

`Dwarf_Relocation_Data` is a pointer typedef. Consequently the final producer
argument is a pointer-to-pointer and is mapped as `PointerByReference`. The
pointed-to record is 24 bytes on both supported 64-bit hosts, with its two
64-bit fields at offsets 8 and 16.

## Enabled producer surface

Every declaration below is represented by
`src/main/java/ghidradwarfforge/nativeapi/LibDwarfProducer.java` and checked by
`src/test/native/libdwarf-abi-probe.c` against the pinned header during both
Linux and Windows native builds.

| Header area | Functions |
|---|---|
| Initialization and policy | `dwarf_producer_init`, `dwarf_pro_set_default_string_form` |
| DIE construction | `dwarf_new_die_a`, `dwarf_add_die_to_debug_a`, `dwarf_die_link_a` |
| Attributes | `dwarf_add_AT_name_a`, `dwarf_add_AT_producer_a`, `dwarf_add_AT_unsigned_const_a`, `dwarf_add_AT_reference_c`, `dwarf_add_AT_any_value_sleb_a`, `dwarf_add_AT_any_value_uleb_a`, `dwarf_add_AT_dataref_a`, `dwarf_add_AT_targ_address_c`, `dwarf_add_AT_flag_a`, `dwarf_add_AT_location_expr_a` |
| Expressions | `dwarf_new_expr_a`, `dwarf_add_expr_gen_a`, `dwarf_add_expr_addr_c` |
| Serialization and relocation | `dwarf_transform_to_disk_form_a`, `dwarf_get_section_bytes_a`, `dwarf_get_relocation_info_count`, `dwarf_get_relocation_info` |
| Cleanup | `dwarf_producer_finish_a` |

The consumer binding is limited to `dwarf_package_version`, `dwarf_errno`, and
`dwarf_errmsg_by_number`; the same C probe checks those declarations.

## Callbacks and error ownership

`Dwarf_Callback_Func` returns an ELF section index and writes a distinct
section-symbol index through `Dwarf_Unsigned *`. The Java callback therefore
returns `int` and writes the 64-bit symbol index through `LongByReference`.

`Dwarf_Handler` is `void handler(Dwarf_Error, Dwarf_Ptr)`. The standalone
smoke test registers a strongly referenced callback, deliberately invokes a
producer error without an explicit `Dwarf_Error *`, and verifies that the
callback receives a usable opaque error number and readable message. Normal
exporter calls supply `Dwarf_Error *` explicitly and decode failures before
producer finish. Producer allocations, including errors, are owned by the
producer debug handle and released by `dwarf_producer_finish_a`.

JNA's default C calling convention is used. The supported Windows host is
64-bit MinGW, whose exported functions use the platform x64 C ABI; 32-bit
Windows is not claimed.

## Gates

The native jobs compile the C probe with warnings as errors and run it before
publishing libraries. The isolated Java smoke then exercises values above 32
bits, callback delivery, section creation, string-table relocations, producer
buffers, symbolic relocations, and cleanup in Linux and Windows JVMs. Adding a
new native declaration requires extending both this inventory and the C/Java
smoke coverage.
