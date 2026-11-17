package ghidradwarfforge.unwind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Inherited FDE unions versus a byte-occupancy oracle; no original CFI semantic claim. */
public final class FrameAppendCoverageSmoke {
    private static int checks;

    public static void main(String[] args) {
        for (int width : new int[] {4, 8}) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                exercise(width, order);
            }
        }
        System.out.println("frame-append-coverage=PASS checks=" + checks);
    }

    private static CallFramePlan plan(int width, ByteOrder order, long address, long size) {
        return new CallFramePlan(width, order, 16, Set.of(7, 16),
            Map.of(7, new Undefined(), 16, new Undefined()),
            List.of(frame(address, size)));
    }

    private static Frame frame(long address, long size) {
        return new Frame(address, size, List.of(new Row(address, new Cfa(7, 8),
            Map.of(7, new CfaValue(0), 16, new AtCfaOffset(-8)))));
    }

    private static void exercise(int width, ByteOrder order) {
        // Independent record walking finds serialized FDE address fields. The
        // production OriginalFrameRanges reader does not supply the oracle.
        var initial = new CallFramePlan(width, order, 16, Set.of(7, 16),
            Map.of(7, new Undefined(), 16, new Undefined()),
            List.of(frame(0x1000, 16), frame(0x2000, 16)));
        byte[] seed = DwarfDebugFrame.build(initial, () -> false);
        ByteBuffer data = ByteBuffer.wrap(seed).order(order);
        var addresses = new ArrayList<Integer>();
        for (int offset = 0; offset < seed.length;) {
            int length = data.getInt(offset);
            require(length >= 4 && offset + 4 + length <= seed.length, "invalid seed record extent");
            if (data.getInt(offset + 4) != -1) addresses.add(offset + 8);
            offset += length + 4;
        }
        require(addresses.size() == 2, "seed must contain two FDEs");
        if (width == 8) {
            byte[] crossing = seed.clone();
            ByteBuffer fields = ByteBuffer.wrap(crossing).order(order);
            fields.putLong(addresses.get(0), Long.MAX_VALUE - 1);
            fields.putLong(addresses.get(0) + width, 3);
            try {
                DwarfDebugFrame.append(crossing, plan(width, order, 0x3000, 1), () -> false);
                throw new AssertionError("unsupported inherited signed-domain crossing accepted");
            }
            catch (IllegalArgumentException refused) {
                require(refused.getMessage().contains("FDE extent overflows"), "wrong unsupported-domain refusal");
            }
        }
        long base = width == 4 ? 0x1000 : Long.MAX_VALUE - 32;
        for (int a : new int[] {0, 2, 4}) {
            for (int aSize : new int[] {0, 1, 3, 6}) {
                for (int b : new int[] {0, 2, 4}) {
                    for (int bSize : new int[] {0, 1, 3, 6}) {
                        byte[] original = seed.clone();
                        ByteBuffer fields = ByteBuffer.wrap(original).order(order);
                        put(fields, addresses.get(0), width, base + a);
                        put(fields, addresses.get(0) + width, width, aSize);
                        put(fields, addresses.get(1), width, base + b);
                        put(fields, addresses.get(1) + width, width, bSize);
                        byte[] preserved = original.clone();
                        boolean[] occupied = new boolean[16];
                        for (int index = a; index < a + aSize; index++) occupied[index] = true;
                        for (int index = b; index < b + bSize; index++) occupied[index] = true;
                        for (int start = -1; start <= 11; start++) {
                            for (int size = 1; size <= 3; size++) {
                                boolean overlap = false;
                                for (int index = start; index < start + size; index++) {
                                    if (index >= 0 && occupied[index]) overlap = true;
                                }
                                var addition = plan(width, order, base + start, size);
                                try {
                                    byte[] result = DwarfDebugFrame.append(original, addition, () -> false);
                                    require(!overlap, "generated FDE overlaps an inherited occupied byte");
                                    require(result.length > original.length &&
                                        Arrays.equals(original, Arrays.copyOf(result, original.length)),
                                        "append changed inherited frame bytes");
                                }
                                catch (IllegalArgumentException refused) {
                                    require(overlap && refused.getMessage().contains("overlaps original coverage"),
                                        "disjoint generated FDE refused: " + refused.getMessage());
                                }
                                require(Arrays.equals(preserved, original), "append or refusal modified input array");
                            }
                        }
                    }
                }
            }
        }
    }

    private static void put(ByteBuffer fields, int offset, int width, long value) {
        if (width == 4) fields.putInt(offset, (int) value);
        else fields.putLong(offset, value);
    }

    private static void require(boolean condition, String reason) {
        checks++;
        if (!condition) throw new AssertionError(reason);
    }
}
