package evaluation;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.Consumer;
import evaluation.JavaUnitWriter.Die;
import evaluation.JavaUnitWriter.Field;
import evaluation.JavaUnitWriter.Id;
import evaluation.JavaUnitWriter.Tag;

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

    private static void unitChecks(ByteOrder order) {
        var name = new Id("unit");
        var symbol = new Id("function");
        var function = new Die(symbol, Tag.FUNCTION, Map.of(Field.NAME, "é😀"), List.of());
        var unit = new Die(name, Tag.UNIT, Map.of(Field.NAME, "é😀", Field.PRODUCER, "Z"), List.of(function));
        var result = JavaUnitWriter.write(unit, 8, order, Map.of(), () -> false);
        var info = ByteBuffer.wrap(result.get(".debug_info")).order(order);
        // DWARF32 header ends at 12, each abbreviation code below occupies one byte.
        if (info.getInt(13) != 0 || info.getInt(17) != 7 || info.getInt(22) != 0 ||
                !Arrays.equals(result.get(".debug_str"), HexFormat.of().parseHex("c3a9f09f9880005a00"))) {
            throw new AssertionError("duplicate or multi-byte string offset");
        }
        Consumer<Die> write = die -> JavaUnitWriter.write(die, 4, order, Map.of(), () -> false);
        reject(() -> write.accept(new Die(name, Tag.UNIT, Map.of(), List.of(function, function))));
        for (Id target : List.of(new Id("missing"), name)) {
            var pointer = new Die(new Id("p"), Tag.POINTER, Map.of(Field.TYPE, target), List.of());
            reject(() -> write.accept(new Die(name, Tag.UNIT, Map.of(), List.of(pointer))));
        }
        reject(() -> write.accept(new Die(name, Tag.UNIT, Map.of(Field.NAME, 5L), List.of())));
        reject(() -> write.accept(new Die(name, Tag.UNIT, Map.of(Field.STMT_LIST, 1L), List.of())));
        reject(() -> new Die(name, Tag.UNIT, Map.of(Field.LOW_PC, 0L), List.of()));
        reject(() -> new Die(symbol, Tag.BASE, Map.of(Field.LOCATION, 0), List.of()));
        reject(() -> new Die(symbol, Tag.BASE, Map.of(), List.of(function)));
        reject(() -> JavaUnitWriter.write(unit, 4, order, Map.of(".debug_macro", new byte[1]), () -> false));
        try {
            int[] calls = {0};
            JavaUnitWriter.write(unit, 8, order, Map.of(), () -> ++calls[0] == 2);
            throw new AssertionError("ignored cancellation during DIE emission");
        }
        catch (CancellationException expected) {
            // The cancellation supplier fires at the first child.
        }
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
        bytes(4, le, "ffbf7f8040ff3f80c000", out -> {
            for (long value : new long[]{-8193, -8192, 8191, 8192}) out.sleb(value);
        });
        bytes(4, be, "c3a9f09f9880", out -> out.writeBytes(DwarfOutput.stringBytes("é😀")));
        DwarfOutput out = new DwarfOutput(4, le);
        reject(() -> out.offset(-1));
        reject(() -> out.offset(0x100000000L));
        reject(() -> out.address(0x100000000L));
        reject(() -> out.unitLength(0xfffffff0L));
        reject(() -> DwarfOutput.stringBytes("a\0b"));
        reject(() -> DwarfOutput.stringBytes(String.valueOf(Character.MIN_HIGH_SURROGATE)));
        unitChecks(le);
        unitChecks(be);
        System.out.println("DWARF primitive byte and rejection checks passed");
    }
}
