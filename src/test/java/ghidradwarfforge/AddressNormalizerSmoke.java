package ghidradwarfforge;

/** Focused regression for rebased-Ghidra to link-time-ELF conversion. */
public final class AddressNormalizerSmoke {
    private AddressNormalizerSmoke() {
    }

    public static void main(String[] args) {
        assertEquals(0x2000000L,
            AddressNormalizer.rebaseDelta(0x2400000L, 0x400000L));
        assertEquals(0x401136L,
            AddressNormalizer.toElfAddress(0x2401136L, 0x2000000L));
        assertEquals(-0x100000L,
            AddressNormalizer.rebaseDelta(0x300000L, 0x400000L));
        assertEquals(0x401136L,
            AddressNormalizer.toElfAddress(0x301136L, -0x100000L));
        assertEquals(Long.MIN_VALUE, AddressNormalizer.rebaseDelta(Long.MAX_VALUE, -1));
        assertEquals(Long.MAX_VALUE, AddressNormalizer.toElfAddress(Long.MIN_VALUE, 1));
        long kernel = 0xffffffff81000000L;
        assertEquals(kernel + 0x123, AddressNormalizer.toElfAddress(0x401123L,
            AddressNormalizer.rebaseDelta(0x401000L, kernel)));
        assertEquals(Long.MIN_VALUE, AddressNormalizer.toGhidraAddress(Long.MAX_VALUE, 1));
        assertEquals(0x401123L, AddressNormalizer.toGhidraAddress(kernel + 0x123,
            AddressNormalizer.rebaseDelta(0x401000L, kernel)));
        System.out.println("address-normalizer-smoke=PASS");
    }

    private static void assertEquals(long expected, long actual) {
        if (expected != actual) {
            throw new AssertionError("expected 0x" + Long.toHexString(expected) +
                " but found 0x" + Long.toHexString(actual));
        }
    }

}
