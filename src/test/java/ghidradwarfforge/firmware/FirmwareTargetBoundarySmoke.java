package ghidradwarfforge.firmware;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

/** Valid metadata is distinct from an admitted firmware implementation profile. */
final class FirmwareTargetBoundarySmoke {
    private static int checks;

    static int check() {
        checks = 0;
        var canonical = FirmwareTarget.select("cortex-m3");
        require(canonical.equals(FirmwareTarget.CORTEX_M3), "registry selects exact documented profile");
        for (int field = 0; field < 6; field++) {
            for (String invalid : new String[] {null, "", " \t\n", "bad\0identity"}) {
                String[] text = identity(); text[field] = invalid;
                reject(() -> target(text, 40, 32, 32, ByteOrder.LITTLE_ENDIAN, 0x05000000L), IllegalArgumentException.class);
            }
            String[] changed = identity(); changed[field] += "-different";
            var contradictory = target(changed, 40, 32, 32, ByteOrder.LITTLE_ENDIAN, 0x05000000L);
            reject(contradictory::requireSupported, IllegalArgumentException.class);
            reject(contradictory::metadataSections, IllegalArgumentException.class);
        }
        for (int machine : new int[] {Integer.MIN_VALUE, -1, 0, 65536, Integer.MAX_VALUE}) {
            reject(() -> target(identity(), machine, 32, 32, ByteOrder.LITTLE_ENDIAN, 0), IllegalArgumentException.class);
        }
        for (int width : new int[] {Integer.MIN_VALUE, 0, 16, 31, 33, 63, 65, Integer.MAX_VALUE}) {
            reject(() -> target(identity(), 40, width, 32, ByteOrder.LITTLE_ENDIAN, 0), IllegalArgumentException.class);
            reject(() -> target(identity(), 40, 32, width, ByteOrder.LITTLE_ENDIAN, 0), IllegalArgumentException.class);
        }
        for (long flags : new long[] {Long.MIN_VALUE, -1, 0x1_0000_0000L, Long.MAX_VALUE}) {
            reject(() -> target(identity(), 40, 32, 32, ByteOrder.LITTLE_ENDIAN, flags), IllegalArgumentException.class);
        }
        reject(() -> target(identity(), 40, 32, 32, null, 0), NullPointerException.class);
        reject(() -> FirmwareTarget.select(null), NullPointerException.class);
        for (String profile : List.of("", "CORTEX-M3", "cortex-m3 ", "unknown")) {
            reject(() -> FirmwareTarget.select(profile), IllegalArgumentException.class);
        }
        for (int machine : new int[] {1, 40, 65535}) {
            for (int address : new int[] {32, 64}) {
                for (int pointer : new int[] {32, 64}) {
                    for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        for (long flags : new long[] {0, 0x05000000L, 0xffff_ffffL}) {
                            var descriptor = target(identity(), machine, address, pointer, order, flags);
                            require(descriptor.machine() == machine && descriptor.addressBits() == address &&
                                descriptor.pointerBits() == pointer && descriptor.byteOrder() == order && descriptor.elfFlags() == flags,
                                "metadata fields narrowed or normalized");
                            boolean admitted = machine == 40 && address == 32 && pointer == 32 &&
                                order == ByteOrder.LITTLE_ENDIAN && flags == 0x05000000L;
                            if (admitted) descriptor.requireSupported();
                            else {
                                reject(descriptor::requireSupported, IllegalArgumentException.class);
                                reject(descriptor::metadataSections, IllegalArgumentException.class);
                            }
                        }
                    }
                }
            }
        }
        var first = canonical.metadataSections();
        require(first.size() == 1 && first.getFirst().name().equals(".ARM.attributes") &&
            first.getFirst().type() == 0x70000003L, "profile metadata identity");
        byte[] original = first.getFirst().bytes().clone();
        first.getFirst().bytes()[0] ^= 1;
        require(Arrays.equals(original, canonical.metadataSections().getFirst().bytes()), "caller modified future profile metadata");
        reject(first::clear, UnsupportedOperationException.class);
        require(FirmwareTarget.select("cortex-m3").equals(canonical), "refused descriptors changed registered profile");
        System.out.println("firmware-target-boundaries=PASS checks=" + checks);
        return checks;
    }

    private static String[] identity() {
        return new String[] {"cortex-m3", "ARMv7-M", "AAPCS32-base", "Thumb-only", "ARM:LE:32:Cortex", "default"};
    }
    private static FirmwareTarget target(String[] text, int machine, int address, int pointer, ByteOrder order, long flags) {
        return new FirmwareTarget(text[0], text[1], text[2], machine, address, pointer, order, text[3], text[4], text[5], flags);
    }
    private static void reject(Runnable action, Class<? extends RuntimeException> kind) {
        try { action.run(); }
        catch (RuntimeException expected) {
            require(kind.isInstance(expected), "wrong refusal: " + expected);
            return;
        }
        throw new AssertionError("invalid or unsupported firmware identity accepted");
    }
    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
