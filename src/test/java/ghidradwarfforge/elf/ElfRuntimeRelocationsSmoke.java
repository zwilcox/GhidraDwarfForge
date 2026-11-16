package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
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
        Files.write(path, bytes);
        try { return ElfRuntimeRelocations.inspect(ElfImage.read(path), () -> false); }
        finally { require(Arrays.equals(bytes, Files.readAllBytes(path)), "relocation inspection changed its input"); }
    }

    private static byte[] metadata(boolean wide, ByteOrder order, long[]... tags) {
        byte[] bytes = fixture(wide, order, false);
        Arrays.fill(bytes, 0x200, 0x400, (byte) 0);
        var out = ByteBuffer.wrap(bytes).order(order);
        int width = wide ? 8 : 4;
        for (int index = 0; index < tags.length; index++) {
            word(out, 0x200 + index * width * 2, wide, tags[index][0]);
            word(out, 0x200 + index * width * 2 + width, wide, tags[index][1]);
        }
        long size = (tags.length + 1L) * width * 2; // Includes the terminating DT_NULL.
        segment(out, wide, 1, 2, 0x200, 0x1200, size, size);
        return bytes;
    }

    private static ElfRuntimeRelocations.Inventory accepted(Path path, byte[] bytes) throws Exception {
        try { return inspect(path, bytes); }
        catch (IllegalArgumentException failure) {
            throw new AssertionError("valid relocation metadata was rejected", failure);
        }
    }

    private static void metadataMatrix(Path path, boolean wide, ByteOrder order) throws Exception {
        int width = wide ? 8 : 4;
        // gABI dynamic-section dependencies and table shapes:
        // https://gabi.xinuos.com/elf.pdf (4.3 draft, 2025-09-04, section 8.3)
        // Each general table needs pointer, byte size and entry size together.
        // An entry-size descriptor alone does not invent a general table.
        long[][] layouts = {{17, 18, 19, 0x1400, 2}, {7, 8, 9, 0x1440, 3}, {36, 35, 37, 0x1480, 1}};
        var formats = List.of(ElfRuntimeRelocations.Format.REL, ElfRuntimeRelocations.Format.RELA,
            ElfRuntimeRelocations.Format.RELR);
        var roles = List.of("DT_REL", "DT_RELA", "DT_RELR");
        for (int layout = 0; layout < layouts.length; layout++) {
            long[] row = layouts[layout];
            int entrySize = (int) row[4] * width;
            for (int mask = 0; mask < 8; mask++) {
                var tags = new ArrayList<long[]>();
                if ((mask & 1) != 0) tags.add(new long[] {row[0], row[3]});
                if ((mask & 2) != 0) tags.add(new long[] {row[1], entrySize});
                if ((mask & 4) != 0) tags.add(new long[] {row[2], entrySize});
                byte[] bytes = metadata(wide, order, tags.toArray(long[][]::new));
                if (mask != 0 && mask != 4 && mask != 7) {
                    reject(() -> inspect(path, bytes), roles.get(layout) + " incomplete tag mask " + mask);
                    continue;
                }
                var inventory = accepted(path, bytes);
                require(inventory.tags().equals(tags.stream().map(tag ->
                    new ElfRuntimeRelocations.Tag(tag[0], tag[1])).toList()), "raw metadata tags changed");
                require(inventory.tables().size() == (mask == 7 ? 1 : 0), "descriptor invented or hid a table");
                if (mask == 7) {
                    var table = inventory.tables().getFirst();
                    require(table.role().equals(roles.get(layout)) && table.format() == formats.get(layout) &&
                        table.address() == row[3] && table.offset() == row[3] - 0x1000 &&
                        table.size() == entrySize && table.entrySize() == entrySize, "general table identity changed");
                    long address = layout == 0 ? 0x1700 : layout == 1 ? 0x1710 : 0x1702;
                    Long info = layout == 0 ? Long.valueOf(wide ? 0xfedcba9876543210L : 0xfedcba98L) :
                        layout == 1 ? Long.valueOf(0x1234) : null;
                    Long addend = layout == 1 ? Long.valueOf(-17) : null;
                    require(table.relocations().equals(List.of(new ElfRuntimeRelocations.Relocation(
                        row[3] - 0x1000, address, info, addend))), "decoded general relocation changed");
                }
            }
            for (long bad : new long[] {0, entrySize - 1, entrySize + 1}) {
                byte[] bytes = metadata(wide, order, new long[] {row[2], bad});
                reject(() -> inspect(path, bytes), "wrong standalone " + roles.get(layout) + " width");
            }
        }
        // PLT-only REL and RELA tables, with and without the standalone width.
        for (boolean explicitAddend : List.of(false, true)) {
            int entrySize = width * (explicitAddend ? 3 : 2);
            int type = explicitAddend ? 7 : 17;
            long pointer = explicitAddend ? 0x1440 : 0x1400;
            for (int mask = 0; mask < 8; mask++) {
                var tags = new ArrayList<long[]>();
                if ((mask & 1) != 0) tags.add(new long[] {23, pointer});
                if ((mask & 2) != 0) tags.add(new long[] {2, entrySize});
                if ((mask & 4) != 0) tags.add(new long[] {20, type});
                byte[] bytes = metadata(wide, order, tags.toArray(long[][]::new));
                if (mask != 0 && mask != 7) {
                    reject(() -> inspect(path, bytes), "incomplete PLT tag mask " + mask);
                    continue;
                }
                var inventory = accepted(path, bytes);
                if (mask == 0) {
                    require(inventory.tables().isEmpty(), "absent PLT acquired relocations");
                    continue;
                }
                require(inventory.tables().size() == 1, "PLT-only fixture acquired a general table");
                var table = inventory.tables().getFirst();
                require(table.role().equals("DT_JMPREL") && table.format() ==
                    (explicitAddend ? ElfRuntimeRelocations.Format.RELA : ElfRuntimeRelocations.Format.REL) &&
                    table.address() == pointer && table.offset() == pointer - 0x1000 &&
                    table.size() == entrySize && table.entrySize() == entrySize, "PLT format or extent changed");
                require(table.relocations().equals(List.of(new ElfRuntimeRelocations.Relocation(
                    pointer - 0x1000, explicitAddend ? 0x1710 : 0x1700,
                    explicitAddend ? 0x1234L : wide ? 0xfedcba9876543210L : 0xfedcba98L,
                    explicitAddend ? Long.valueOf(-17) : null))), "PLT relocation changed");
                tags.add(new long[] {explicitAddend ? 9 : 19, entrySize});
                require(accepted(path, metadata(wide, order, tags.toArray(long[][]::new))).tables().equals(inventory.tables()),
                    "standalone width changed PLT-only relocation inventory");
            }
        }
        for (long address : new long[] {0, 0x9000}) {
            var empty = accepted(path, metadata(wide, order,
                new long[] {17, address}, new long[] {18, 0}, new long[] {19, width * 2},
                new long[] {7, address}, new long[] {8, 0}, new long[] {9, width * 3},
                new long[] {36, address}, new long[] {35, 0}, new long[] {37, width},
                new long[] {23, address}, new long[] {2, 0}, new long[] {20, 7}));
            require(empty.tables().stream().map(ElfRuntimeRelocations.Table::role).toList()
                .equals(List.of("DT_RELR", "DT_REL", "DT_RELA", "DT_JMPREL")), "empty table roles were discarded");
            require(empty.tables().stream().allMatch(table -> table.address() == address && table.offset() == 0 &&
                table.size() == 0 && table.relocations().isEmpty() &&
                table.sha256().equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
                "empty table accessed unmapped bytes or invented a relocation");
        }
        var mixed = accepted(path, metadata(wide, order,
            new long[] {36, 0x1480}, new long[] {35, width}, new long[] {37, width},
            new long[] {17, 0x9000}, new long[] {18, 0}, new long[] {19, width * 2},
            new long[] {7, 0x1440}, new long[] {8, width * 3}, new long[] {9, width * 3},
            new long[] {23, 0x9000}, new long[] {2, 0}, new long[] {20, 7}));
        require(mixed.tables().stream().map(table -> table.relocations().size()).toList().equals(List.of(1, 0, 1, 0)),
            "empty roles conflicted with or erased nonempty tables");
        for (boolean generalFirst : List.of(false, true)) {
            long general = 0x1440 + (generalFirst ? 0 : width);
            long plt = 0x1440 + (generalFirst ? width : 0);
            byte[] bytes = metadata(wide, order,
                new long[] {7, general}, new long[] {8, width * 6}, new long[] {9, width * 3},
                new long[] {23, plt}, new long[] {2, width * 6}, new long[] {20, 7});
            reject(() -> inspect(path, bytes), "overlapping roles with misaligned record boundaries");
        }
        if (wide) {
            for (long[] row : layouts) {
                // Isolate the direct entry: a later RELR bitmap would reject
                // the negative running address independently and mask this guard.
                byte[] bytes = metadata(true, order, new long[] {row[0], row[3]},
                    new long[] {row[1], row[4] * 8}, new long[] {row[2], row[4] * 8});
                ByteBuffer.wrap(bytes).order(order).putLong((int) row[3] - 0x1000, Long.MIN_VALUE);
                reject(() -> inspect(path, bytes), "relocation target outside supported signed address domain");
            }
        }
        else {
            byte[] bytes = metadata(false, order, new long[] {36, 0x1480}, new long[] {35, 8}, new long[] {37, 4});
            ByteBuffer.wrap(bytes).order(order).putInt(0x480, 0xffff_fffc).putInt(0x484, 3);
            reject(() -> inspect(path, bytes), "RELR bitmap target beyond ELF32");
        }
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
                metadataMatrix(path, wide, order);
            }
        }
        finally { Files.deleteIfExists(path); }
        System.out.println("runtime-relocations-smoke=PASS checks=" + checks);
    }
}
