package ghidradwarfforge;

/** Inverse of the ELF loader's modular target-address translation. Extent sizes are checked separately. */
public final class AddressNormalizer {
    private AddressNormalizer() {
    }

    public static long rebaseDelta(long ghidraImageBase, long elfImageBase) {
        return ghidraImageBase - elfImageBase;
    }

    public static long toGhidraAddress(long elfAddress, long rebaseDelta) {
        return elfAddress + rebaseDelta;
    }

    public static long toElfAddress(long ghidraAddress, long rebaseDelta) {
        return ghidraAddress - rebaseDelta;
    }
}
