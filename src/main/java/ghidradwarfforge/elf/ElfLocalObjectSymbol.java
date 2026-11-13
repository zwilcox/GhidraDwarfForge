package ghidradwarfforge.elf;

/** An explicitly proved ordinary object; neither TLS nor an inferred vtable binding. */
public record ElfLocalObjectSymbol(String name, long value, long size, int sectionIndex) implements ElfLocalSymbol {
    public ElfLocalObjectSymbol {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 || name.length() > 65536 ||
                value < 0 || size <= 0 || sectionIndex <= 0) {
            throw new IllegalArgumentException("invalid local ELF object symbol");
        }
    }

    @Override
    public int type() { return 1; }
}
