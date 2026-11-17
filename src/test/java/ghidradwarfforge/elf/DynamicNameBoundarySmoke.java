package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Bounded long/overlapping dynamic names in actual ELF32/64 containers of both byte orders. */
final class DynamicNameBoundarySmoke {
    private static int checks;
    private static final int LIMIT = 65536;

    static void check(Path root, boolean wide, ByteOrder order) throws Exception {
        checks = 0;
        Path file = root.resolve("dynamic-name-boundaries");
        try {
            byte[] exact = overlapping(wide, order, LIMIT, 1);
            var result = read(file, exact);
            require(result.names().length == LIMIT + 2 && result.records().length == (wide ? 48 : 32),
                "exact individual limit preserved");
            reject(file, overlapping(wide, order, LIMIT + 1, 1), "dynamic name exceeds limit");
            // Every distinct symbol starts one byte later in the same physical
            // string. Their decoded byte count is an arithmetic series, not
            // the small string table's physical size.
            long accepted = 256L * LIMIT - 256L * 255 / 2;
            long rejected = accepted + LIMIT - 256;
            require(accepted <= 16L * 1024 * 1024 && rejected > 16L * 1024 * 1024,
                "aggregate boundary premise");
            var aggregate = read(file, overlapping(wide, order, LIMIT, 256));
            require(aggregate.existingNames().size() == 257 && aggregate.names().length == LIMIT + 2,
                "distinct suffix identities retained without expanding input table");
            reject(file, overlapping(wide, order, LIMIT, 257), "dynamic names exceed aggregate limit");
            for (boolean hidden : new boolean[] {false, true}) {
                String suffix = hidden ? "@V1" : "@@V2";
                int count = LIMIT - suffix.length();
                byte[] input = qualified(wide, order, count, hidden);
                var mirror = read(file, input);
                int symbol = hidden ? 2 : 3;
                int name = ByteBuffer.wrap(mirror.records()).order(order).getInt(symbol * (wide ? 24 : 16));
                byte[] expected = ("a".repeat(count) + suffix).getBytes(StandardCharsets.US_ASCII);
                require(Arrays.equals(expected, Arrays.copyOfRange(mirror.names(), name, name + LIMIT)) &&
                    mirror.names()[name + LIMIT] == 0, "qualified name exact boundary and separator");
                reject(file, qualified(wide, order, count + 1, hidden), "qualified dynamic name exceeds limit");
            }
            Files.write(file, exact);
            var image = ElfImage.read(file);
            var polls = new AtomicInteger();
            DynamicSymbolMirror.read(image, () -> { polls.incrementAndGet(); return false; });
            require(polls.get() >= LIMIT / 1024, "long-name scan must poll cancellation within its byte loop");
            for (int stop : new int[] {1, polls.get() / 2, polls.get() - 1}) {
                var calls = new AtomicInteger();
                try {
                    DynamicSymbolMirror.read(image, () -> calls.incrementAndGet() == stop);
                    throw new AssertionError("long-name inventory ignored cancellation");
                }
                catch (CancellationException expected) {
                    require(calls.get() == stop, "cancel promptly at observed scan poll");
                }
                require(Arrays.equals(exact, Files.readAllBytes(file)), "cancelled inventory changed original");
            }
            require(Arrays.equals(read(file, exact).records(), result.records()), "retry after cancellation differs");
        }
        finally { Files.deleteIfExists(file); }
        System.out.println("dynamic-name-boundaries=PASS wide=" + wide + " order=" + order + " checks=" + checks);
    }

    private static byte[] overlapping(boolean wide, ByteOrder order, int length, int symbols) {
        int width = wide ? 24 : 16;
        byte[] input = Arrays.copyOf(DynamicSymbolMirrorSmoke.fixture(wide, order, false, false), 0x12000 + (symbols + 1) * width);
        Arrays.fill(input, 0x801, 0x801 + length, (byte) 'a');
        LocalSymbolMergeSmoke.field(input, 2, "offset", 0x800);
        LocalSymbolMergeSmoke.field(input, 2, "size", length + 2);
        LocalSymbolMergeSmoke.field(input, 3, "offset", 0x12000);
        LocalSymbolMergeSmoke.field(input, 3, "size", (symbols + 1L) * width);
        LocalSymbolMergeSmoke.field(input, 3, "info", 1);
        var rows = ByteBuffer.wrap(input).order(order);
        for (int index = 1; index <= symbols; index++) {
            int offset = 0x12000 + index * width;
            rows.putInt(offset, index);
            rows.put(offset + (wide ? 4 : 12), (byte) 0x12);
            rows.putShort(offset + (wide ? 6 : 14), (short) 1);
            if (wide) rows.putLong(offset + 8, 0x1040).putLong(offset + 16, 16);
            else rows.putInt(offset + 4, 0x1040).putInt(offset + 8, 16);
        }
        return input;
    }

    private static byte[] qualified(boolean wide, ByteOrder order, int length, boolean hidden) {
        byte[] base = DynamicSymbolMirrorSmoke.fixture(wide, order, true, false);
        var data = ByteBuffer.wrap(base).order(order);
        int field = 0x400 + 2 * (wide ? 64 : 40) + (wide ? 32 : 20);
        int oldLength = wide ? Math.toIntExact(data.getLong(field)) : data.getInt(field);
        byte[] input = Arrays.copyOf(base, 0x800 + oldLength + length + 1);
        System.arraycopy(base, 0x180, input, 0x800, oldLength);
        Arrays.fill(input, 0x800 + oldLength, input.length - 1, (byte) 'a');
        LocalSymbolMergeSmoke.field(input, 2, "offset", 0x800);
        LocalSymbolMergeSmoke.field(input, 2, "size", oldLength + length + 1);
        ByteBuffer.wrap(input).order(order).putInt(0x200 + (hidden ? 2 : 3) * (wide ? 24 : 16), oldLength);
        return input;
    }

    private static DynamicSymbolMirror.Snapshot read(Path file, byte[] input) throws Exception {
        Files.write(file, input);
        var result = DynamicSymbolMirror.read(ElfImage.read(file), () -> false);
        require(Arrays.equals(input, Files.readAllBytes(file)), "inventory changed original");
        return result;
    }

    private static void reject(Path file, byte[] input, String message) throws Exception {
        Files.write(file, input);
        try {
            DynamicSymbolMirror.read(ElfImage.read(file), () -> false);
            throw new AssertionError("unsafe dynamic name inventory accepted: " + message);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(message), "wrong boundary rejection: " + expected);
        }
        require(Arrays.equals(input, Files.readAllBytes(file)), "rejected inventory changed original");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
