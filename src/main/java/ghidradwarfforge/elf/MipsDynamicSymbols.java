package ghidradwarfforge.elf;

import java.util.Map;

/** Processor-specific dynamic symbol metadata; never applied to another e_machine. */
final class MipsDynamicSymbols {
    static final long DT_MIPS_SYMTABNO = 0x70000011L;

    private MipsDynamicSymbols() {
    }

    static Long count(ElfImage image, Map<Long, Long> tags) {
        return image.machine() == 8 ? tags.get(DT_MIPS_SYMTABNO) : null;
    }
}
