package ghidradwarfforge;

import java.math.BigInteger;
import java.util.function.LongSupplier;

/** Checks rebasing and unsigned ELF address arithmetic against exact integer results. */
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
        checkUnsignedArithmetic();
        System.out.println("address-normalizer-smoke=PASS");
    }

    private static void checkUnsignedArithmetic() {
        BigInteger addressLimit = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        BigInteger countLimit = BigInteger.valueOf(Long.MAX_VALUE);
        long[] words = {0, 1, 0xffff_ffffL, Long.MAX_VALUE - 1, Long.MAX_VALUE, Long.MIN_VALUE,
            Long.MIN_VALUE + 1, 0xffff_ffff_8100_0000L, -2, -1};
        for (long base : words) {
            BigInteger original = new BigInteger(Long.toUnsignedString(base));
            for (long word : words) {
                BigInteger unsigned = new BigInteger(Long.toUnsignedString(word));
                checkBounded(unsigned.subtract(original), countLimit,
                    () -> UnsignedAddress.distance(base, word));
                checkBounded(original.add(unsigned), addressLimit,
                    () -> UnsignedAddress.addDisplacement(base, word, false));
                checkBounded(original.add(BigInteger.valueOf(word)), addressLimit,
                    () -> UnsignedAddress.addDisplacement(base, word, true));
            }
        }
    }

    private static void checkBounded(BigInteger expected, BigInteger limit, LongSupplier operation) {
        boolean representable = expected.signum() >= 0 && expected.compareTo(limit) <= 0;
        long actual;
        try {
            actual = operation.getAsLong();
        }
        catch (IllegalArgumentException rejected) {
            if (representable) throw new AssertionError("rejected representable result " + expected, rejected);
            return;
        }
        if (!representable) throw new AssertionError("accepted out-of-range result " + expected);
        assertEquals(expected.longValue(), actual);
    }

    private static void assertEquals(long expected, long actual) {
        if (expected != actual) {
            throw new AssertionError("expected 0x" + Long.toHexString(expected) +
                " but found 0x" + Long.toHexString(actual));
        }
    }

}
