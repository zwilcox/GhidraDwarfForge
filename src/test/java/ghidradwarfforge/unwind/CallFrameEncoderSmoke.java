package ghidradwarfforge.unwind;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Invalid/incomplete-plan and cancellation controls; external consumers check the format. */
public final class CallFrameEncoderSmoke {
    private static int checks;

    private static Row row(long address, long offset) {
        return new Row(address, new Cfa(7, offset), Map.of(7, new CfaValue(0),
            12, new SameValue(), 16, new AtCfaOffset(-8)));
    }

    private static CallFramePlan plan(int width, ByteOrder order, List<Frame> frames) {
        return new CallFramePlan(width, order, 16, Set.of(7, 12, 16), frames);
    }

    private static void rejected(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid call-frame plan accepted");
        }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("call-frame encoder control failed");
        checks++;
    }

    public static void main(String[] args) {
        var first = new Frame(0x1000, 0x40, List.of(row(0x1000, 8), row(0x1010, 24), row(0x1030, 8)));
        var second = new Frame(0x2000, 0x10, List.of(row(0x2000, 8)));
        for (int width : List.of(4, 8)) {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var value = plan(width, order, List.of(first, second));
                int[] polls = { 0 };
                byte[] encoded = DwarfDebugFrame.build(value, () -> { polls[0]++; return false; });
                require(encoded.length != 0 && encoded.length % width == 0);
                require(Arrays.equals(encoded, DwarfDebugFrame.build(plan(width, order,
                    List.of(second, first)), () -> false)));
                for (int limit = 1; limit <= polls[0]; limit++) {
                    final int selected = limit;
                    int[] count = { 0 };
                    try {
                        DwarfDebugFrame.build(value, () -> ++count[0] == selected);
                        throw new AssertionError("frame encoding ignored cancellation " + selected);
                    }
                    catch (CancellationException expected) { checks++; }
                }
                require(Arrays.equals(encoded, DwarfDebugFrame.build(value, () -> false)));
                require(DwarfDebugFrame.build(plan(width, order, List.of()), () -> false).length == 0);
                rejected(() -> DwarfDebugFrame.build(plan(width, order, List.of(first, first)), () -> false));
            }
        }
        rejected(() -> new Frame(0x1000, 0, List.of(row(0x1000, 8))));
        rejected(() -> new Frame(-16L, 32, List.of(row(-16L, 8))));
        rejected(() -> new Frame(0x1000, 16, List.of(row(0x1001, 8))));
        rejected(() -> new Frame(0x1000, 16, List.of(row(0x1000, 8), row(0x1010, 8))));
        rejected(() -> new Frame(0x1000, 16, List.of(row(0x1000, 8), row(0x1008, 8), row(0x1004, 8))));
        rejected(() -> new Cfa(-1, 0));
        rejected(() -> new InRegister(4096));
        rejected(() -> plan(2, ByteOrder.LITTLE_ENDIAN, List.of(first)));
        rejected(() -> DwarfDebugFrame.build(plan(4, ByteOrder.LITTLE_ENDIAN,
            List.of(new Frame(0xffff_fff0L, 32, List.of(row(0xffff_fff0L, 8))))), () -> false));
        // Endpoints fit ELF32, but its address-sized FDE length cannot encode 2^32.
        for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            rejected(() -> DwarfDebugFrame.build(plan(4, order,
                List.of(new Frame(0, 0x1_0000_0000L, List.of(row(0, 8))))), () -> false));
            require(DwarfDebugFrame.build(plan(4, order,
                List.of(new Frame(0, 0xffff_ffffL, List.of(row(0, 8))))), () -> false).length > 0);
        }
        rejected(() -> DwarfDebugFrame.build(plan(8, ByteOrder.LITTLE_ENDIAN,
            List.of(new Frame(0x1000, 16, List.of(new Row(0x1000, new Cfa(7, 8),
                Map.of(16, new AtCfaOffset(-8))))))), () -> false));
        rejected(() -> DwarfDebugFrame.build(plan(8, ByteOrder.LITTLE_ENDIAN,
            List.of(new Frame(0x1000, 16, List.of(new Row(0x1000, new Cfa(6, 8),
                row(0x1000, 8).rules()))))), () -> false));
        rejected(() -> DwarfDebugFrame.build(plan(8, ByteOrder.LITTLE_ENDIAN,
            List.of(new Frame(0x1000, 16, List.of(new Row(0x1000, new Cfa(7, 8),
                Map.of(7, new CfaValue(0), 12, new InRegister(5), 16, new AtCfaOffset(-8))))))), () -> false));
        var mutable = new HashMap<Integer, Rule>(row(0x1000, 8).rules());
        var immutable = new Row(0x1000, new Cfa(7, 8), mutable);
        mutable.clear();
        require(immutable.rules().size() == 3);
        var frames = new ArrayList<>(List.of(first));
        var immutablePlan = plan(8, ByteOrder.LITTLE_ENDIAN, frames);
        frames.clear();
        require(immutablePlan.frames().size() == 1);
        var highest = new Frame(-1L, 1, List.of(row(-1L, Long.MIN_VALUE)));
        require(DwarfDebugFrame.build(plan(8, ByteOrder.BIG_ENDIAN, List.of(highest)), () -> false).length > 0);
        System.out.println("call-frame-encoder-smoke=PASS checks=" + checks);
    }
}
