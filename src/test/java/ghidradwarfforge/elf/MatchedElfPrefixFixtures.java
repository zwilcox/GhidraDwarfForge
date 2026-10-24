package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/** Source-built ELF containers, independent of prefix-comparison implementation. */
final class MatchedElfPrefixFixtures {
    enum Shape { NAMED, NAMELESS, SECTIONLESS, EXTENDED_SECTIONS, EXTENDED_PROGRAMS, LARGE_HEADER }

    record Pair(Path original, Path candidate, boolean wide, ByteOrder order) {
    }

    private MatchedElfPrefixFixtures() {
    }

    static Pair create(Path directory, boolean wide, ByteOrder order, Shape shape) throws IOException {
        Files.createDirectories(directory);
        int headerSize = wide ? 64 : 52;
        int phSize = wide ? 56 : 32;
        int shSize = wide ? 64 : 40;
        int phCount = shape == Shape.EXTENDED_PROGRAMS ? 65537 : 2;
        int shCount = shape == Shape.EXTENDED_SECTIONS ? 0xff02 : 4;
        int nameIndex = shCount - 1;
        int phOffset = shape == Shape.EXTENDED_PROGRAMS ? 0x800 : 0x80;
        int shOffset = Math.max(0x300, phOffset + phSize * phCount + 16);
        shOffset = (shOffset + 7) & ~7;
        int fileSize = shOffset + shSize * shCount + 65;
        ByteBuffer b = ByteBuffer.allocate(fileSize).order(order);
        b.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0x7f, (byte) 0x83,
            1, 2, 3, 4, 5, 6, 7 });
        b.putShort(16, (short) 3);
        b.putShort(18, (short) 0xffee); // No processor whitelist belongs in this comparison.
        b.putInt(20, 1);
        if (wide) {
            b.putLong(24, 0xffff_ffff_ffff_fff0L);
            b.putLong(32, phOffset);
            b.putLong(40, shape == Shape.SECTIONLESS ? 0 : shOffset);
            b.putInt(48, 0x8000_0001);
        }
        else {
            b.putInt(24, 0xffff_fff0);
            b.putInt(28, phOffset);
            b.putInt(32, shape == Shape.SECTIONLESS ? 0 : shOffset);
            b.putInt(36, 0x8000_0001);
        }
        b.putShort(wide ? 52 : 40, (short) (headerSize + (shape == Shape.LARGE_HEADER ? 16 : 0)));
        b.putShort(wide ? 54 : 42, (short) phSize);
        b.putShort(wide ? 56 : 44, (short) Math.min(phCount, 0xffff));
        b.putShort(wide ? 58 : 46, (short) (shape == Shape.SECTIONLESS ? 0 : shSize));
        b.putShort(wide ? 60 : 48, (short) (shape == Shape.SECTIONLESS || shCount >= 0xff00 ? 0 : shCount));
        b.putShort(wide ? 62 : 50, (short) (shape == Shape.SECTIONLESS || shape == Shape.NAMELESS ? 0
            : nameIndex >= 0xff00 ? 0xffff : nameIndex));
        if (shape == Shape.LARGE_HEADER) {
            for (int index = headerSize; index < headerSize + 16; index++) {
                b.put(index, (byte) (index * 11));
            }
        }
        program(b, phOffset + phSize * (phCount - 2), wide, 1, 5, 0, 0x400000, fileSize, fileSize + 16, 0x1000);
        program(b, phOffset + phSize * (phCount - 1), wide, 4, 4, 0x200, 0x400200, 36, 36, 4);
        b.putInt(0x200, 4).putInt(0x204, 20).putInt(0x208, 3);
        b.position(0x20c);
        b.put(new byte[] { 'G', 'N', 'U', 0 });
        for (int index = 0; index < 20; index++) {
            b.put((byte) (index + 1));
        }
        for (int index = 0; index < 32; index++) {
            b.put(0x240 + index, (byte) (index * 13 + 7));
        }
        byte[] names = "\0.text\0.note.gnu.build-id\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);
        b.position(0x280);
        b.put(names);
        section(b, shOffset, wide, 0, 0, 0, 0, 0, shCount >= 0xff00 ? shCount : 0,
            nameIndex >= 0xff00 ? nameIndex : 0, phCount >= 0xffff ? phCount : 0, 0, 0);
        section(b, shOffset + shSize, wide, 1, 1, 6, 0x400240, 0x240, 32, 0, 0, 16, 0);
        section(b, shOffset + 2 * shSize, wide, 7, 7, 2, 0x400200, 0x200, 36, 0, 0, 4, 0);
        section(b, shOffset + nameIndex * shSize, wide, 26, 3, 0, 0, 0x280, names.length, 0, 0, 1, 0);
        for (int offset = shOffset + shSize * shCount; offset < fileSize; offset++) {
            b.put(offset, (byte) (offset * 17 + 3));
        }
        Path original = directory.resolve("original.elf");
        Path candidate = directory.resolve("candidate.dbg");
        Files.write(original, b.array());
        Map<String, byte[]> debug = new LinkedHashMap<>();
        debug.put(".debug_info", new byte[] { 1, 2, 3, 4 });
        debug.put(".debug_line", new byte[] { 5, 6, 7, 8 });
        new MatchedElfSidecarWriter().write(original, candidate, debug);
        return new Pair(original, candidate, wide, order);
    }

    static Pair sparse(Path directory, long originalSize) throws IOException {
        Pair small = create(directory.resolve("small"), true, ByteOrder.LITTLE_ENDIAN, Shape.NAMED);
        byte[] before = Files.readAllBytes(small.original());
        byte[] after = Files.readAllBytes(small.candidate());
        ByteBuffer b = ByteBuffer.wrap(after).order(small.order());
        long delta = originalSize - before.length;
        int oldTable = Math.toIntExact(b.getLong(40));
        int count = Short.toUnsignedInt(b.getShort(60));
        int entrySize = Short.toUnsignedInt(b.getShort(58));
        b.putLong(40, oldTable + delta);
        for (int index = 1; index < count; index++) {
            int location = oldTable + entrySize * index + 24;
            long offset = b.getLong(location);
            if (offset >= before.length) {
                b.putLong(location, offset + delta);
            }
        }
        Path original = directory.resolve("sparse-original.elf");
        Path candidate = directory.resolve("sparse-candidate.dbg");
        try (FileChannel output = FileChannel.open(original, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            write(output, ByteBuffer.wrap(before));
            output.position(originalSize - 1);
            write(output, ByteBuffer.wrap(new byte[] { 77 }));
        }
        try (FileChannel output = FileChannel.open(candidate, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            write(output, ByteBuffer.wrap(after, 0, before.length));
            output.position(originalSize - 1);
            write(output, ByteBuffer.wrap(new byte[] { 77 }));
            output.position(originalSize);
            write(output, ByteBuffer.wrap(after, before.length, after.length - before.length));
        }
        return new Pair(original, candidate, true, small.order());
    }

    static Path changed(Pair pair, String name, long offset, byte value) throws IOException {
        Path copy = pair.candidate().resolveSibling(name);
        Files.copy(pair.candidate(), copy);
        try (FileChannel output = FileChannel.open(copy, StandardOpenOption.WRITE)) {
            output.position(offset);
            write(output, ByteBuffer.wrap(new byte[] { value }));
        }
        return copy;
    }

    private static void write(FileChannel channel, ByteBuffer bytes) throws IOException {
        while (bytes.hasRemaining()) {
            if (channel.write(bytes) <= 0) {
                throw new IOException("fixture output stopped making progress");
            }
        }
    }

    private static void program(ByteBuffer b, int offset, boolean wide, int type, int flags,
            long fileOffset, long address, long fileSize, long memorySize, long alignment) {
        b.putInt(offset, type);
        if (wide) {
            b.putInt(offset + 4, flags).putLong(offset + 8, fileOffset).putLong(offset + 16, address)
                .putLong(offset + 24, address).putLong(offset + 32, fileSize)
                .putLong(offset + 40, memorySize).putLong(offset + 48, alignment);
        }
        else {
            b.putInt(offset + 4, (int) fileOffset).putInt(offset + 8, (int) address)
                .putInt(offset + 12, (int) address).putInt(offset + 16, (int) fileSize)
                .putInt(offset + 20, (int) memorySize).putInt(offset + 24, flags)
                .putInt(offset + 28, (int) alignment);
        }
    }

    private static void section(ByteBuffer b, int offset, boolean wide, int name, int type,
            long flags, long address, long fileOffset, long size, int link, int info, long alignment, long entrySize) {
        b.putInt(offset, name).putInt(offset + 4, type);
        if (wide) {
            b.putLong(offset + 8, flags).putLong(offset + 16, address).putLong(offset + 24, fileOffset)
                .putLong(offset + 32, size).putInt(offset + 40, link).putInt(offset + 44, info)
                .putLong(offset + 48, alignment).putLong(offset + 56, entrySize);
        }
        else {
            b.putInt(offset + 8, (int) flags).putInt(offset + 12, (int) address).putInt(offset + 16, (int) fileOffset)
                .putInt(offset + 20, (int) size).putInt(offset + 24, link).putInt(offset + 28, info)
                .putInt(offset + 32, (int) alignment).putInt(offset + 36, (int) entrySize);
        }
    }
}
