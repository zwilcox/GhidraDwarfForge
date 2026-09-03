# DWARF string-form policy

GhidraDwarfForge requests `DW_FORM_strp` from the pinned libdwarf producer
before creating any DIE. This produces a deterministic `.debug_str` table and
allows identical strings to share one entry.

libdwarf 2.3.2 deliberately keeps a string inline as `DW_FORM_string` when its
UTF-8 byte length including the terminating NUL is no larger than the DWARF32
offset field (four bytes). Longer names, the compilation-unit name, and the
producer string use `DW_FORM_strp`. This mixed policy is deterministic and
never makes the output larger merely to force every string through the table.

The exporter requires non-empty `.debug_info`, `.debug_abbrev`, and
`.debug_str` sections. Symbolic relocations from `.debug_info` to `.debug_str`
must reference the section-symbol index assigned by the producer callback.
After relocation resolution, every `DW_FORM_strp` value is a four-byte
DWARF32 offset into `.debug_str`. GNU readelf, LLVM dwarfdump, independent
libdwarf validation, and GDB behavior tests cover the resulting forms through
the normal architecture matrix.

DWARF 5 indexed strings (`DW_FORM_strx*` and `.debug_str_offsets`) are deferred.
They add another table and base attribute without improving correctness for
the current single-unit sidecar. They may be reconsidered only with measured
size or performance evidence.
