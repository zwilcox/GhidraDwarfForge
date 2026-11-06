package ghidradwarfforge.source;

/** Per-export diagnostic context; off preserves the normal source-only path. */
public enum SourceContextMode {
    OFF(false, false), ASSEMBLY(true, false), PCODE(false, true), BOTH(true, true);

    private final boolean assembly;
    private final boolean pcode;

    SourceContextMode(boolean assembly, boolean pcode) {
        this.assembly = assembly;
        this.pcode = pcode;
    }

    public boolean assembly() { return assembly; }
    public boolean pcode() { return pcode; }

    public static SourceContextMode parse(String value) {
        return switch (value) {
            case "off" -> OFF;
            case "assembly" -> ASSEMBLY;
            case "pcode" -> PCODE;
            case "both" -> BOTH;
            default -> throw new IllegalArgumentException("source-context must be off, assembly, pcode or both");
        };
    }
}
