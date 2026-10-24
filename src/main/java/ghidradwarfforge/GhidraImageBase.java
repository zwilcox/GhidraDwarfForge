package ghidradwarfforge;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;

/** The base recorded by the ELF loader, before any subsequent program rebase. */
public final class GhidraImageBase {
    private GhidraImageBase() {
    }

    /**
     * Ghidra 12.0.3 ElfProgramBuilder maps ELF addresses by adding the current
     * program base minus this recorded value. DWARFProgram uses the same
     * property to relocate compiler DWARF. Recomputing the minimum PT_LOAD VA
     * is insufficient: Ghidra's base search examines only its first 20 headers.
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
