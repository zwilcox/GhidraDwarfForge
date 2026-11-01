package ghidradwarfforge.elf;

/** Explicit local ELF records; target policies own their address semantics. */
public sealed interface ElfLocalSymbol permits ElfLocalFunctionSymbol, ElfLocalMappingSymbol {
    String name();
    long value();
    long size();
    int sectionIndex();
    int type();
}
