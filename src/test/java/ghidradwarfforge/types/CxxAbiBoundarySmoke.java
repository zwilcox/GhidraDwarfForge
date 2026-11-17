package ghidradwarfforge.types;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.targets.CxxAbiProfile;

/** Independent signed-table decoding and subobject containment at ABI boundaries. */
public final class CxxAbiBoundarySmoke {
    private static int checks;
    private static final BigInteger WORD = BigInteger.valueOf(8);

    public static void main(String[] args) {
        checks = 0;
        targets();
        signedDisplacements();
        addressPoints();
        virtualBaseContainment();
        System.out.println("cxx-abi-boundaries=PASS checks=" + checks);
    }

    private static void targets() {
        for (var abi : CxxAbiProfile.values()) {
            for (int machine : new int[] {0, 3, 8, 40, 62, 183}) {
                for (int width : new int[] {-1, 0, 4, 8, 16}) {
                    for (ByteOrder order : Arrays.asList(null, ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        boolean target = (abi == CxxAbiProfile.ITANIUM_X86_64 && machine == 62 ||
                            abi == CxxAbiProfile.ITANIUM_AARCH64 && machine == 183) &&
                            width == 8 && order == ByteOrder.LITTLE_ENDIAN;
                        admission(() -> abi.requireTarget(machine, width, order), target, "ELF target agreement");
                    }
                }
            }
            for (String processor : Arrays.asList(null, "", "x86", "AARCH64", "ARM", "MIPS", "aarch64")) {
                for (int width : new int[] {4, 8, 16}) {
                    for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        boolean target = (abi == CxxAbiProfile.ITANIUM_X86_64 && "x86".equals(processor) ||
                            abi == CxxAbiProfile.ITANIUM_AARCH64 && "AARCH64".equals(processor)) &&
                            width == 8 && order == ByteOrder.LITTLE_ENDIAN;
                        admission(() -> abi.requireProgramTarget(processor, width, order), target,
                            "Ghidra processor agreement");
                    }
                }
            }
        }
    }

    private static void signedDisplacements() {
        long[] displacements = {Long.MIN_VALUE, Long.MIN_VALUE + 1, -0x100000007L,
            Integer.MIN_VALUE, -4096, -24, -1, 0, 1, 24, 4096, Integer.MAX_VALUE,
            0x100000007L, Long.MAX_VALUE - 1, Long.MAX_VALUE};
        for (var abi : List.of(CxxAbiProfile.ITANIUM_X86_64, CxxAbiProfile.ITANIUM_AARCH64)) {
            for (long displacement : displacements) {
                // A one-entry table and a secondary table with preceding vbase words.
                for (int prefixWords : new int[] {0, 1, 3, 7}) {
                    int prefixBytes = prefixWords * 8;
                    byte[] table = new byte[prefixBytes + 32];
                    Arrays.fill(table, (byte) 0xa5);
                    putLittleEndian(table, prefixBytes, BigInteger.valueOf(displacement));
                    putLittleEndian(table, prefixBytes + 8, new BigInteger("fedcba9876543210", 16));
                    putLittleEndian(table, prefixBytes + 16, new BigInteger("123456789abcdef0", 16));
                    byte[] before = table.clone();
                    long actual = abi.offsetToTop(table, prefixBytes + 16);
                    check(actual == displacement, "wrong signed complete-object displacement " + displacement);
                    check(Arrays.equals(table, before), "vtable decoding changed table bytes");
                }
            }
        }
    }

    private static void putLittleEndian(byte[] destination, int offset, BigInteger signed) {
        BigInteger unsigned = signed.mod(BigInteger.ONE.shiftLeft(64));
        BigInteger radix = BigInteger.valueOf(256);
        for (int index = 0; index < 8; index++) {
            BigInteger[] part = unsigned.divideAndRemainder(radix);
            destination[offset + index] = (byte) part[1].intValueExact();
            unsigned = part[0];
        }
    }

    private static void addressPoints() {
        for (var abi : CxxAbiProfile.values()) {
            admission(() -> abi.offsetToTop(null, 16), false, "missing vtable bytes");
            for (int length : new int[] {0, 1, 7, 8, 15, 16, 17, 23, 24, 31, 32, 64}) {
                byte[] table = new byte[length];
                for (int point = -1; point <= length + 8; point++) {
                    int selected = point;
                    // Enumerate complete two-word headers instead of permitting partial entries.
                    boolean header = false;
                    for (int headerStart = 0; headerStart + 16 <= length; headerStart += 8) {
                        header |= selected == headerStart + 16;
                    }
                    admission(() -> abi.offsetToTop(table, selected),
                        abi != CxxAbiProfile.UNSPECIFIED && header, "complete aligned address-point header");
                }
                admission(() -> abi.offsetToTop(table, Integer.MIN_VALUE), false, "negative address point");
                admission(() -> abi.offsetToTop(table, Integer.MAX_VALUE), false, "address point outside table");
            }
        }
    }

    private static void virtualBaseContainment() {
        long[] objects = {Long.MIN_VALUE, -1, 0, 1, 7, 8, 9, 15, 16, 17, 24, 32, Long.MAX_VALUE};
        long[] vptrs = {Long.MIN_VALUE, -8, -1, 0, 1, 7, 8, 9, 16, 24, 32, Long.MAX_VALUE - 7, Long.MAX_VALUE};
        long[] slots = {Long.MIN_VALUE, Long.MIN_VALUE + 1, -0x100000008L, -33, -32, -25, -24, -23, -16, -8, -1, 0, 8, Long.MAX_VALUE};
        for (var abi : CxxAbiProfile.values()) {
            for (long object : objects) {
                for (long pointer : vptrs) {
                    for (long slot : slots) {
                        BigInteger start = BigInteger.valueOf(pointer);
                        BigInteger end = start.add(WORD);
                        BigInteger entry = BigInteger.valueOf(slot).divide(WORD);
                        boolean inside = start.signum() >= 0 && end.compareTo(BigInteger.valueOf(object)) <= 0;
                        boolean aligned = start.mod(WORD).signum() == 0 && BigInteger.valueOf(slot).mod(WORD).signum() == 0;
                        // Offset-to-top and RTTI occupy -2 and -1; vbase entries precede both.
                        boolean vbaseEntry = entry.compareTo(BigInteger.valueOf(-2)) < 0;
                        admission(() -> abi.requireVirtualBase(pointer, slot, object),
                            abi != CxxAbiProfile.UNSPECIFIED && inside && aligned && vbaseEntry,
                            "vptr containment and virtual-base entry " + object + "/" + pointer + "/" + slot);
                    }
                }
            }
        }
    }

    private static void admission(Runnable action, boolean expected, String message) {
        boolean accepted = true;
        try {
            action.run();
        }
        catch (IllegalArgumentException rejected) {
            accepted = false;
        }
        check(accepted == expected, message + ": expected accepted=" + expected);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
