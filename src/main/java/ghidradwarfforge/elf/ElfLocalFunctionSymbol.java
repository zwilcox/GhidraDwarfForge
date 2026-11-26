package ghidradwarfforge.elf;

import ghidradwarfforge.UnsignedAddress;

/** A target-planned local function symbol; it does not assert original source linkage. */
public record ElfLocalFunctionSymbol(String name, long value, long size, int sectionIndex) implements ElfLocalSymbol {
    public ElfLocalFunctionSymbol {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 ||
                name.length() > 65536 || !UnsignedAddress.fitsObject(value, size, Long.BYTES) || sectionIndex <= 0) {
            throw new IllegalArgumentException("invalid local ELF function symbol");
        }
    }

    @Override
    public int type() { return 2; }
}
