package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

public final class ElfRuntimeRelocationsSmoke {
    private static int checks;
    private static void require(boolean value, String reason) { if (!value) throw new AssertionError(reason); checks++; }
    private interface Checked { void run() throws Exception; }
    private static void reject(Checked action, String reason) throws Exception {
        try { action.run(); throw new AssertionError("accepted " + reason); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void word(ByteBuffer out, int position, boolean wide, long value) {
        if (wide) out.putLong(position, value); else out.putInt(position, (int) value);
    }
    private static void segment(ByteBuffer out, boolean wide, int index, int type,
            long offset, long address, long fileSize, long memorySize) {
        int at = (wide ? 64 : 52) + index * (wide ? 56 : 32);
        out.putInt(at, type);
        if (wide) out.putInt(at + 4, 6).putLong(at + 8, offset).putLong(at + 16, address)
            .putLong(at + 24, address).putLong(at + 32, fileSize).putLong(at + 40, memorySize).putLong(at + 48, 1);
        else out.putInt(at + 4, (int) offset).putInt(at + 8, (int) address).putInt(at + 12, (int) address)
            .putInt(at + 16, (int) fileSize).putInt(at + 20, (int) memorySize).putInt(at + 24, 6).putInt(at + 28, 1);
    }
    private static void section(ByteBuffer out, boolean wide, int index, int type, long address,
            long offset, long size, int entrySize, long flags) {
        int at = 0x800 + index * (wide ? 64 : 40);
        out.putInt(at + 4, type);
        if (wide) out.putLong(at + 8, flags).putLong(at + 16, address).putLong(at + 24, offset)
            .putLong(at + 32, size).putLong(at + 48, 1).putLong(at + 56, entrySize);
        else out.putInt(at + 8, (int) flags).putInt(at + 12, (int) address).putInt(at + 16, (int) offset)
            .putInt(at + 20, (int) size).putInt(at + 32, 1).putInt(at + 36, entrySize);
    }
    private static byte[] fixture(boolean wide, ByteOrder order, boolean sections) {
        int width = wide ? 8 : 4;
        var out = ByteBuffer.allocate(0x1000).order(order);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0});
        out.putShort(16, (short) 3).putShort(18, (short) (wide ? 62 : 8)).putInt(20, 1);
        if (wide) out.putLong(32, 64).putLong(40, sections ? 0x800 : 0).putShort(52, (short) 64)
            .putShort(54, (short) 56).putShort(56, (short) 2).putShort(58, (short) 64).putShort(60, (short) (sections ? 6 : 0));
        else out.putInt(28, 52).putInt(32, sections ? 0x800 : 0).putShort(40, (short) 52)
            .putShort(42, (short) 32).putShort(44, (short) 2).putShort(46, (short) 40).putShort(48, (short) (sections ? 6 : 0));
        long[][] tags = {{17, 0x1400}, {18, width * 2}, {19, width * 2},
            {7, 0x1440}, {8, width * 3}, {9, width * 3},
            {36, 0x1480}, {35, width * 4}, {37, width},
            {23, 0x14c0}, {2, width * 3}, {20, 7}, {1, 1}, {1, 2},
            {0x70000001L, 0xfedcba9876543210L}, {0, 0}};
        for (int i = 0; i < tags.length; i++) {
            word(out, 0x200 + i * width * 2, wide, tags[i][0]);
            word(out, 0x200 + i * width * 2 + width, wide, tags[i][1]);
        }
        segment(out, wide, 0, 1, 0, 0x1000, 0x1000, 0x1000);
        segment(out, wide, 1, 2, 0x200, 0x1200, tags.length * width * 2, tags.length * width * 2);
        word(out, 0x400, wide, 0x1700); word(out, 0x400 + width, wide, wide ? 0xfedcba9876543210L : 0xfedcba98L);
        word(out, 0x440, wide, 0x1710); word(out, 0x440 + width, wide, 0x1234); word(out, 0x440 + width * 2, wide, -17);
        word(out, 0x480, wide, 0x1702); // Even, deliberately not naturally aligned: valid RELR encoding.
        word(out, 0x480 + width, wide, 0xb); // first and third units
        word(out, 0x480 + width * 2, wide, 3); // next bitmap, first unit
        word(out, 0x480 + width * 3, wide, 0x1a00);
        word(out, 0x4c0, wide, 0x1720); word(out, 0x4c0 + width, wide, 0x56); word(out, 0x4c0 + width * 2, wide, 42);
        if (sections) {
            section(out, wide, 1, 6, 0x1200, 0x200, tags.length * width * 2, width * 2, 3);
            section(out, wide, 2, 9, 0x1400, 0x400, width * 2, width * 2, 2);
            section(out, wide, 3, 4, 0x1440, 0x440, width * 3, width * 3, 2);
            section(out, wide, 4, 19, 0x1480, 0x480, width * 4, width, 2);
            section(out, wide, 5, 4, 0x14c0, 0x4c0, width * 3, width * 3, 2);
        }
        return out.array();
    }
    private static ElfRuntimeRelocations.Inventory inspect(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes); return ElfRuntimeRelocations.inspect(ElfImage.read(path), () -> false);
    }
    private static void variants(Path path, boolean wide, ByteOrder order) throws Exception {
        int width = wide ? 8 : 4;
        var reference = inspect(path, fixture(wide, order, false));
        require(reference.equals(inspect(path, fixture(wide, order, true))), "sectionless relocation inventory differs");
        require(reference.tags().size() == 15 && reference.tags().stream().filter(t -> t.tag() == 1).count() == 2,
            "raw duplicate NEEDED or processor tags lost");
        require(reference.tables().size() == 4 && reference.tables().getFirst().format() == ElfRuntimeRelocations.Format.RELR,
            "RELR must precede ordinary tables");
        var relr = reference.tables().getFirst().relocations();
        require(relr.stream().map(ElfRuntimeRelocations.Relocation::address).toList().equals(List.of(
            0x1702L, 0x1702L + width, 0x1702L + width * 3, 0x1702L + width * width * 8, 0x1a00L)),
            "RELR bitmap expansion mismatch");
        require(relr.stream().allMatch(r -> r.info() == null && r.addend() == null), "fabricated RELR fields");
        require(reference.tables().get(1).relocations().getFirst().info() ==
            (wide ? 0xfedcba9876543210L : 0xfedcba98L), "raw info lost bit pattern");
        require(reference.tables().get(2).relocations().getFirst().addend() == -17, "signed explicit addend lost");
        try { reference.tags().clear(); throw new AssertionError("mutable tags"); } catch (UnsupportedOperationException expected) { checks++; }
        try { reference.tables().getFirst().relocations().clear(); throw new AssertionError("mutable rows"); } catch (UnsupportedOperationException expected) { checks++; }
        byte[] good = fixture(wide, order, true);
        for (String fault : List.of("missing-size", "bad-entry", "bad-plt", "duplicate", "unterminated", "bitmap-first",
                "unmapped", "partial-map", "bss", "overlap", "dynamic-map", "section-map", "section-entry", "orphan-section",
                "wrong-kind", "conflicting-tables", "relr-overflow", "dynamic-memory", "duplicate-dynamic",
                "no-dynamic", "misframed", "compressed", "oversized", "incomplete-plt")) {
            byte[] bytes = good.clone(); var out = ByteBuffer.wrap(bytes).order(order);
            switch (fault) {
                case "missing-size" -> word(out, 0x200 + width * 2, wide, 0x60000001);
                case "bad-entry" -> word(out, 0x200 + width * 5, wide, 1);
                case "bad-plt" -> word(out, 0x200 + width * 23, wide, 36);
                case "duplicate" -> word(out, 0x200 + width * 28, wide, 17);
                case "unterminated" -> word(out, 0x200 + width * 30, wide, 1);
                case "bitmap-first" -> word(out, 0x480, wide, 3);
                case "unmapped" -> word(out, 0x200 + width, wide, 0x5000);
                case "partial-map" -> word(out, 0x200 + width, wide, 0x1fff);
                case "bss" -> segment(out, wide, 0, 1, 0, 0x1000, 0x400, 0x1000);
                case "overlap" -> {
                    out.putShort(wide ? 56 : 44, (short) 3);
                    segment(out, wide, 2, 1, 0, 0x1000, 0x1000, 0x1000);
                }
                case "dynamic-map" -> segment(out, wide, 1, 2, 0x210, 0x1200, width * 32, width * 32);
                case "section-map" -> section(out, wide, 2, 9, 0x1400, 0x401, width * 2, width * 2, 2);
                case "section-entry" -> section(out, wide, 2, 9, 0x1400, 0x400, width * 2, 1, 2);
                case "orphan-section" -> section(out, wide, 2, 9, 0x1600, 0x600, width * 2, width * 2, 2);
                case "wrong-kind" -> out.putShort(16, (short) 1);
                case "conflicting-tables" -> word(out, 0x200 + width * 19, wide, 0x1400);
                case "relr-overflow" -> word(out, 0x480, wide, wide ? Long.MAX_VALUE - 1 : 0xffff_fffeL);
                case "dynamic-memory" -> segment(out, wide, 1, 2, 0x200, 0x1200, width * 32, width);
                case "duplicate-dynamic" -> {
                    out.putShort(wide ? 56 : 44, (short) 3);
                    segment(out, wide, 2, 2, 0x200, 0x1200, width * 32, width * 32);
                }
                case "no-dynamic" -> out.putInt((wide ? 64 : 52) + (wide ? 56 : 32), 0);
                case "misframed" -> word(out, 0x200 + width * 3, wide, width * 2 + 1);
                case "compressed" -> section(out, wide, 2, 9, 0x1400, 0x400, width * 2, width * 2, 0x802);
                case "oversized" -> word(out, 0x200 + width * 3, wide, 64L * 1024 * 1024);
                case "incomplete-plt" -> word(out, 0x200 + width * 22, wide, 0x60000001);
                default -> throw new AssertionError(fault);
            }
            reject(() -> inspect(path, bytes), fault);
        }
        // Nonallocated --emit-relocs sections are not runtime relocation tables.
        var retained = ByteBuffer.wrap(good.clone()).order(order);
        section(retained, wide, 2, 9, 0x1600, 0x600, width * 2, width * 2, 0);
        require(inspect(path, retained.array()).equals(reference), "retained link relocations changed dynamic inventory");
        for (boolean dynamic : List.of(false, true)) {
            var empty = ByteBuffer.wrap(fixture(wide, order, false)).order(order);
            if (dynamic) word(empty, 0x200, wide, 0);
            else empty.putInt((wide ? 64 : 52) + (wide ? 56 : 32), 0);
            var none = inspect(path, empty.array());
            require(none.tables().isEmpty() && none.tags().isEmpty(), "absent table inventory is not empty");
        }
        var highBit = ByteBuffer.wrap(fixture(wide, order, false)).order(order);
        word(highBit, 0x480 + width, wide, wide ? Long.MIN_VALUE | 1 : 0x8000_0001L);
        var highRows = inspect(path, highBit.array()).tables().getFirst().relocations();
        require(highRows.get(1).address() == 0x1702L + (width * 8 - 1) * width, "highest RELR bitmap bit lost");
        // A general/PLT overlap with matching record framing is valid evidence,
        // and roles remain distinguishable instead of silently deduplicated.
        var overlap = ByteBuffer.wrap(fixture(wide, order, false)).order(order);
        word(overlap, 0x200 + width * 19, wide, 0x1440);
        var overlapping = inspect(path, overlap.array());
        require(overlapping.tables().get(2).relocations().equals(overlapping.tables().get(3).relocations()),
            "aligned same-format PLT subset rejected or changed");
        byte[] expanded = Arrays.copyOf(fixture(wide, order, false), 0x20000);
        var expansion = ByteBuffer.wrap(expanded).order(order);
        int bitmapCount = 262144 / (width * 8 - 1) + 1;
        segment(expansion, wide, 0, 1, 0, 0x1000, expanded.length, expanded.length);
        word(expansion, 0x200 + width * 15, wide, (long) (bitmapCount + 1) * width);
        word(expansion, 0x480, wide, 0x1000);
        for (int index = 1; index <= bitmapCount; index++) word(expansion, 0x480 + index * width, wide, -1);
        reject(() -> inspect(path, expanded), "bounded RELR expansion");
        inspect(path, retained.array());
        var image = ElfImage.read(path); int[] polls = {0};
        var before = Files.readAllBytes(path);
        ElfRuntimeRelocations.inspect(image, () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int chosen = stop; int[] seen = {0};
            try { ElfRuntimeRelocations.inspect(image, () -> ++seen[0] == chosen); throw new AssertionError("missed cancellation"); }
            catch (CancellationException expected) { checks++; }
        }
        require(reference.equals(ElfRuntimeRelocations.inspect(image, () -> false)), "cancellation poisoned retry");
        require(Arrays.equals(before, Files.readAllBytes(path)), "inventory modified original");
        int[] mutationPolls = {0};
        long timestamp = Files.getLastModifiedTime(path).toMillis();
        try {
            ElfRuntimeRelocations.inspect(image, () -> {
                if (++mutationPolls[0] == polls[0] - 3) {
                    try { Files.setLastModifiedTime(path, FileTime.fromMillis(timestamp + 10000)); }
                    catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
                }
                return false;
            });
            throw new AssertionError("accepted late observed source mutation");
        }
        catch (java.io.IOException expected) { checks++; }
        Files.setLastModifiedTime(path, FileTime.fromMillis(Files.getLastModifiedTime(path).toMillis() + 10000));
        try { ElfRuntimeRelocations.inspect(image, () -> false); throw new AssertionError("accepted changed source"); }
        catch (java.io.IOException expected) { checks++; }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            var value = ElfRuntimeRelocations.inspect(ElfImage.read(Path.of(args[0])), () -> false);
            for (var table : value.tables()) {
                System.out.println("TABLE " + table.role() + " " + table.format() + " " + table.address() + " " +
                    table.offset() + " " + table.size() + " " + table.entrySize() + " " + table.sha256());
                for (var row : table.relocations()) System.out.println("ROW " + row.recordOffset() + " " + row.address() + " " +
                    (row.info() == null ? "none" : Long.toUnsignedString(row.info())) + " " + row.addend());
            }
            return;
        }
        var path = Files.createTempFile("runtime-relocations-", ".elf");
        try {
            for (boolean wide : List.of(false, true)) for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                variants(path, wide, order);
            }
        }
        finally { Files.deleteIfExists(path); }
        System.out.println("runtime-relocations-smoke=PASS checks=" + checks);
    }
}
