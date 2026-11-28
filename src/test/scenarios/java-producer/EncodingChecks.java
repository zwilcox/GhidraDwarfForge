package evaluation;

import java.nio.ByteOrder;
import java.util.HexFormat;
import java.util.function.Consumer;

final class EncodingChecks {
    private static void bytes(int addressBytes, ByteOrder order, String hex, Consumer<DwarfOutput> write) {
        DwarfOutput out = new DwarfOutput(addressBytes, order);
        write.accept(out);
        String actual = HexFormat.of().formatHex(out.toByteArray());
        if (!actual.equals(hex)) {
            throw new AssertionError("expected " + hex + ", got " + actual);
        }
    }

    private static void reject(Runnable bad) {
        try {
            bad.run();
        }
        catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("invalid input accepted");
    }

    public static void main(String[] args) {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        ByteOrder be = ByteOrder.BIG_ENDIAN;
        bytes(8, le, "00000081ffffffff04030201", out -> {
            out.address(0xffffffff81000000L);
            out.offset(0x01020304);
        });
        bytes(4, be, "fedcba98ffffffef", out -> {
            out.address(0xfedcba98L);
            out.unitLength(0xffffffefL);
        });
        bytes(8, be, "007f8001ff7f808001ffffffffffffffffff01", out -> {
            for (long value : new long[]{0, 127, 128, 16383, 16384, -1L}) {
                out.uleb(value);
            }
        });
        bytes(4, le, "bf7f407f003fc000ff00", out -> {
            for (long value : new long[]{-65, -64, -1, 0, 63, 64, 127}) {
                out.sleb(value);
            }
        });
        bytes(8, be, "8080808080808080807fffffffffffffffffff00", out -> {
            out.sleb(Long.MIN_VALUE);
            out.sleb(Long.MAX_VALUE);
        });
        bytes(4, be, "c3a9f09f9880", out -> out.writeBytes(DwarfOutput.stringBytes("é😀")));
        DwarfOutput out = new DwarfOutput(4, le);
        reject(() -> out.offset(-1));
        reject(() -> out.offset(0x100000000L));
        reject(() -> out.address(0x100000000L));
        reject(() -> out.unitLength(0xfffffff0L));
        reject(() -> DwarfOutput.stringBytes("a\0b"));
        reject(() -> DwarfOutput.stringBytes(String.valueOf(Character.MIN_HIGH_SURROGATE)));
        System.out.println("DWARF primitive byte and rejection checks passed");
    }
}
