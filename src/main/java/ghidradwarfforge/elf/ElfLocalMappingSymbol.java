package ghidradwarfforge.elf;

/** A target-validated section mapping boundary, not a function or data object. */
public record ElfLocalMappingSymbol(String name, long value, int sectionIndex) implements ElfLocalSymbol {
    public ElfLocalMappingSymbol {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 ||
                name.length() > 65536 || value < 0 || sectionIndex <= 0) {
            throw new IllegalArgumentException("invalid local ELF mapping symbol");
        }
    }

    @Override
    public long size() { return 0; }

    @Override
    public int type() { return 0; }
}
