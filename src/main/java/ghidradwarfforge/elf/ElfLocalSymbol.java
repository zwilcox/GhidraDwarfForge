package ghidradwarfforge.elf;

/** Explicit local ELF records; target policies own their address semantics. */
public sealed interface ElfLocalSymbol permits ElfLocalFunctionSymbol, ElfLocalMappingSymbol, ElfLocalObjectSymbol {
    String name();
    long value();
    long size();
    int sectionIndex();
    int type();
}
