package ghidradwarfforge;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;

/** The base recorded by the ELF loader, before any subsequent program rebase. */
public final class GhidraImageBase {
    private GhidraImageBase() {
    }

    /**
     * ElfProgramBuilder maps ELF addresses by adding the current program base
     * minus the recorded import base. Ghidra 12.2's DIEContainer reads the same
     * property for compiler DWARF that needs a base fixup. ElfHeader selects
     * the import base from the first 20 program headers.
     */
    public static long originalImageBase(Program program) {
        final Long recorded;
        try {
            recorded = ElfLoader.getElfOriginalImageBase(program);
        }
        catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("Ghidra's ELF original image-base metadata is invalid; " +
                "cannot establish address translation", invalid);
        }
        if (recorded == null) {
            throw new IllegalStateException("Ghidra's ELF original image-base metadata is missing; " +
                "cannot establish address translation");
        }
        return recorded.longValue();
    }
}
