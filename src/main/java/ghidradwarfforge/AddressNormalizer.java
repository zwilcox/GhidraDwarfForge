package ghidradwarfforge;

/** Checked conversion between Ghidra database addresses and ELF link-time VAs. */
public final class AddressNormalizer {
    private AddressNormalizer() {
    }

    public static long rebaseDelta(long ghidraImageBase, long elfImageBase) {
        return Math.subtractExact(ghidraImageBase, elfImageBase);
    }

    public static long toElfAddress(long ghidraAddress, long rebaseDelta) {
        return Math.subtractExact(ghidraAddress, rebaseDelta);
    }
}
