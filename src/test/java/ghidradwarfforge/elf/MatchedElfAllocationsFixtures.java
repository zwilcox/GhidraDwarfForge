package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Independent byte-level mutations of the existing source-built ELF corpus. */
final class MatchedElfAllocationsFixtures {
    record Pair(Path original, Path candidate, boolean wide, ByteOrder order) {
    }

    private MatchedElfAllocationsFixtures() {
    }

    static Pair create(Path directory, boolean wide, ByteOrder order,
            MatchedElfPrefixFixtures.Shape shape) throws IOException {
        var pair = MatchedElfPrefixFixtures.create(directory, wide, order, shape);
        return new Pair(pair.original(), pair.candidate(), wide, order);
    }

    static Pair sparse(Path directory) throws IOException {
        var pair = MatchedElfPrefixFixtures.sparse(directory, (1L << 31) + 65537);
        return new Pair(pair.original(), pair.candidate(), pair.wide(), pair.order());
    }

    static void rewrite(Pair pair) throws IOException {
        new MatchedElfSidecarWriter().write(pair.original(), pair.candidate(),
            Map.of(".debug_info", new byte[] {1, 2, 3}, ".debug_line", new byte[] {4, 5}));
    }

    static Path copy(Path source, String label) throws IOException {
        Path result = source.resolveSibling(label);
        return Files.copy(source, result);
    }

    static void field(Path file, int index, String field, long value) throws IOException {
        ElfImage image = ElfImage.read(file);
        boolean wide = image.is64Bit();
        ByteBuffer header = ByteBuffer.wrap(image.headerBytes()).order(image.byteOrder());
        long table = wide ? header.getLong(40) : Integer.toUnsignedLong(header.getInt(32));
        int size = Short.toUnsignedInt(header.getShort(wide ? 58 : 46));
        int offset = switch (field) {
            case "name" -> 0;
            case "type" -> 4;
            case "flags" -> 8;
            case "address" -> wide ? 16 : 12;
            case "offset" -> wide ? 24 : 16;
            case "size" -> wide ? 32 : 20;
            case "link" -> wide ? 40 : 24;
            case "info" -> wide ? 44 : 28;
            case "alignment" -> wide ? 48 : 32;
            case "entrySize" -> wide ? 56 : 36;
            default -> throw new AssertionError(field);
        };
        boolean field64 = wide && !field.equals("name") && !field.equals("type") &&
            !field.equals("link") && !field.equals("info");
        put(file, table + (long) index * size + offset, field64 ? 8 : 4, value, image.byteOrder());
    }

    static void program(Path file, int index, String field, long value) throws IOException {
        ElfImage image = ElfImage.read(file);
        boolean wide = image.is64Bit();
        ByteBuffer h = ByteBuffer.wrap(image.headerBytes()).order(image.byteOrder());
        long table = wide ? h.getLong(32) : Integer.toUnsignedLong(h.getInt(28));
        int size = Short.toUnsignedInt(h.getShort(wide ? 54 : 42));
        int offset = switch (field) {
            case "type" -> 0;
            case "flags" -> wide ? 4 : 24;
            case "offset" -> wide ? 8 : 4;
            case "address" -> wide ? 16 : 8;
            case "fileSize" -> wide ? 32 : 16;
            case "memorySize" -> wide ? 40 : 20;
            case "alignment" -> wide ? 48 : 28;
            default -> throw new AssertionError(field);
        };
        put(file, table + (long) index * size + offset,
            wide && !field.equals("type") && !field.equals("flags") ? 8 : 4, value, image.byteOrder());
    }

    static void put(Path file, long offset, int size, long value, ByteOrder order) throws IOException {
        ByteBuffer bytes = ByteBuffer.allocate(size).order(order);
        switch (size) {
            case 1 -> bytes.put((byte) value);
            case 2 -> bytes.putShort((short) value);
            case 4 -> bytes.putInt((int) value);
            case 8 -> bytes.putLong(value);
            default -> throw new AssertionError(size);
        }
        write(file, offset, bytes.array());
    }

    static void write(Path file, long offset, byte[] bytes) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.position(offset);
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                if (channel.write(buffer) <= 0) {
                    throw new IOException("fixture write made no progress");
                }
            }
        }
    }

    static void name(Path file, int index, byte[] value) throws IOException {
        ElfImage image = ElfImage.read(file);
        var table = image.sections().get(image.sectionNameIndex());
        write(file, table.offset + image.sections().get(index).nameOffset, value);
    }

    static void appendName(Path file, int index, String value) throws IOException {
        ElfImage image = ElfImage.read(file);
        var table = image.sections().get(image.sectionNameIndex());
        byte[] bytes = (value + "\0").getBytes(StandardCharsets.UTF_8);
        write(file, table.offset + table.size, bytes);
        field(file, image.sectionNameIndex(), "size", table.size + bytes.length);
        field(file, index, "name", table.size);
    }

    static void thirdNote(Pair pair, long address) throws IOException {
        byte[] data = Files.readAllBytes(pair.original());
        ByteBuffer h = ByteBuffer.wrap(data).order(pair.order());
        int base = pair.wide() ? (int) h.getLong(32) : h.getInt(28);
        int size = pair.wide() ? 56 : 32;
        System.arraycopy(data, base + size, data, base + 2 * size, size);
        h.putShort(pair.wide() ? 56 : 44, (short) 3);
        if (pair.wide()) {
            h.putLong(base + 2 * size + 16, address);
        }
        else {
            h.putInt(base + 2 * size + 8, (int) address);
        }
        Files.write(pair.original(), data);
    }

    static Pair manyNotes(Path directory) throws IOException {
        Pair pair = create(directory, false, ByteOrder.LITTLE_ENDIAN, MatchedElfPrefixFixtures.Shape.EXTENDED_PROGRAMS);
        byte[] bytes = Files.readAllBytes(pair.original());
        // Existing fixture: 65535 NULL headers, LOAD, NOTE; plus one typed note.
        // 65534 converted NULLs + original NOTE + SHT_NOTE = exactly 65536 views.
        int table = ByteBuffer.wrap(bytes).order(pair.order()).getInt(28);
        int last = table + 65536 * 32;
        for (int index = 0; index < 65534; index++) {
            System.arraycopy(bytes, last, bytes, table + index * 32, 32);
        }
        Files.write(pair.original(), bytes);
        rewrite(pair);
        return pair;
    }

    static Pair longRawNames(Path directory, boolean aggregate) throws IOException {
        Pair pair = create(directory, false, ByteOrder.LITTLE_ENDIAN, MatchedElfPrefixFixtures.Shape.NAMED);
        byte[] old = Files.readAllBytes(pair.original());
        ByteBuffer oldHeader = ByteBuffer.wrap(old).order(pair.order());
        int oldTable = oldHeader.getInt(32);
        int rows = aggregate ? 512 : 4;
        int nameSize = aggregate ? 65538 : 65539;
        int names = old.length + 16;
        int table = (names + nameSize + 7) & ~7;
        byte[] bytes = java.util.Arrays.copyOf(old, table + rows * 40);
        for (int offset = 1; offset < nameSize - 1; offset += 2) {
            bytes[names + offset] = 'x';
        }
        ByteBuffer b = ByteBuffer.wrap(bytes).order(pair.order());
        b.putInt(32, table).putShort(48, (short) rows);
        for (int index = 0; index < rows; index++) {
            System.arraycopy(old, oldTable + Math.min(index, 3) * 40, bytes, table + index * 40, 40);
            if (index >= 4) {
                System.arraycopy(old, oldTable + 40, bytes, table + index * 40, 40);
            }
            b.putInt(table + index * 40, index == 0 ? 0 : index * 2 - 1);
        }
        b.putInt(table + 3 * 40 + 16, names).putInt(table + 3 * 40 + 20, nameSize);
        Files.write(pair.original(), bytes);
        rewrite(pair);
        return pair;
    }
}
