package ghidradwarfforge;

/** Focused regression for checked rebased-Ghidra to link-time-ELF conversion. */
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
        assertOverflow(() -> AddressNormalizer.rebaseDelta(Long.MAX_VALUE, -1));
        assertOverflow(() -> AddressNormalizer.toElfAddress(Long.MIN_VALUE, 1));
        System.out.println("address-normalizer-smoke=PASS");
    }

    private static void assertEquals(long expected, long actual) {
        if (expected != actual) {
            throw new AssertionError("expected 0x" + Long.toHexString(expected) +
                " but found 0x" + Long.toHexString(actual));
        }
    }

    private static void assertOverflow(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("expected checked address overflow");
        }
        catch (ArithmeticException expected) {
            // Expected.
        }
    }
}
