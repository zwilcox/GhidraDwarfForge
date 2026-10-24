package ghidradwarfforge.elf;

import java.util.Map;

/** Note-header format exceptions, independent of exporter target support. */
final class ElfNoteFormats {
    private record Abi(int machine, int osAbi) {
    }

    // GNU binutils2.42 readelf is_ia64_vms selects this exact pair. Its
    // include/elf/ia64.h Elf64_External_VMS_Note has three 64-bit header fields;
    // include/elf/common.h defines EM_IA_64=50 and ELFOSABI_OPENVMS=13.
    private static final Map<Abi, String> ALTERNATE_HEADERS = Map.of(
        new Abi(50, 13), "OpenVMS IA-64 note-header format");

    private ElfNoteFormats() {
    }

    static String unsupportedFormat(ElfImage image) {
        return ALTERNATE_HEADERS.get(new Abi(image.machine(),
            Byte.toUnsignedInt(image.headerBytes()[7])));
    }
}
