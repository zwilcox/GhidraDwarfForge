package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Independent raw fixtures, not executable or DWARF validity claims. */
final class OwnedDebuglinkCandidateFixtures {
    static final int TABLE = 0x900;
    static final int NAMES = 0x700;
    static final byte[] NAME_BYTES = new byte[] {
        0, '.', 't', 'e', 'x', 't', 0, '.', 'b', 's', 's', 0,
        '.', 'r', 'e', 'l', '.', 'd', 'y', 'n', 0,
        '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0,
        '.', 'd', 'y', 'n', 's', 'y', 'm', 0, (byte) 0xff, 'x', 0 };

    record Input(Path original, Path sidecar, Path parent, boolean wide, ByteOrder order) {
        int entrySize() { return wide ? 64 : 40; }
    }

    static Input create(Path directory, boolean wide, ByteOrder order) throws IOException {
        Files.createDirectories(directory);
        Path parent = Files.createDirectory(directory.resolve("workspace"));
        byte[] data = new byte[TABLE + 8 * (wide ? 64 : 40) + 19];
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0});
        b.putShort(16, (short) 2).putShort(18, (short) 0x7777).putInt(20, 1);
        word(b, 24, 0x400200, wide);
        word(b, wide ? 32 : 28, 0x100, wide);
        word(b, wide ? 40 : 32, TABLE, wide);
        b.putInt(wide ? 48 : 36, 0xfedcba98);
        b.putShort(wide ? 52 : 40, (short) 0x80);
        b.putShort(wide ? 54 : 42, (short) ((wide ? 56 : 32) + 8));
        b.putShort(wide ? 56 : 44, (short) 2);
        b.putShort(wide ? 58 : 46, (short) (wide ? 64 : 40));
        b.putShort(wide ? 60 : 48, (short) 8);
        b.putShort(wide ? 62 : 50, (short) 4);
        for (int i = wide ? 64 : 52; i < 0x80; i++) { data[i] = (byte) (i * 7); }
        program(b, 0x100, wide, 1, 0x200, 0x600);
        word(b, 0x100 + (wide ? 24 : 12), 0x12345678, wide); // p_paddr
        int phWidth = (wide ? 56 : 32) + 8;
        // Unknown extension and completely inactive row bytes are preserved.
        Arrays.fill(data, 0x100 + phWidth - 8, 0x100 + phWidth, (byte) 0x93);
        Arrays.fill(data, 0x100 + phWidth + 4, 0x100 + 2 * phWidth, (byte) 0xa5);
        for (int i = 0x200; i < 0x700; i++) { data[i] = (byte) (i * 13); }
        System.arraycopy(NAME_BYTES, 0, data, NAMES, NAME_BYTES.length);
        int e = wide ? 64 : 40;
        section(b, TABLE + e, wide, 1, 1, 6, 0x400200, 0x200, 0x80, 0, 0, 16, 0);
        section(b, TABLE + 2 * e, wide, 7, 8, 3, 0x500000, 0xfffffff0L, 0x3000, 0, 0, 8, 0);
        section(b, TABLE + 3 * e, wide, 12, 9, 2, 0x400300, 0x300, 0x20, 5, 1, 4, 8);
        section(b, TABLE + 4 * e, wide, 21, 3, 0, 0, NAMES, NAME_BYTES.length, 0, 0, 1, 0);
        section(b, TABLE + 5 * e, wide, 31, 11, 0, 0, 0x400, 0x30, 4, 2, 4, wide ? 24 : 16);
        section(b, TABLE + 6 * e, wide, 39, 1, 0, 0, 0x500, 1, 5, 3, 1, 0);
        section(b, TABLE + 7 * e, wide, 40, 1, 0, 0, 0x501, 1, 6, 7, 1, 0); // suffix name
        Arrays.fill(data, TABLE + 8 * e, data.length, (byte) 0xd9);
        Path original = directory.resolve("original.elf");
        Path sidecar = directory.resolve("selected.bytes");
        Files.write(original, data);
        Files.write(sidecar, "not an ELF sidecar; byte association only\n".getBytes(StandardCharsets.US_ASCII));
        return new Input(original, sidecar, parent, wide, order);
    }

    static void extendSections(Input input, int count) throws IOException {
        byte[] old = Files.readAllBytes(input.original());
        int e = input.entrySize();
        byte[] data = Arrays.copyOf(old, TABLE + count * e);
        Arrays.fill(data, TABLE + 8 * e, data.length, (byte) 0);
        ByteBuffer b = ByteBuffer.wrap(data).order(input.order());
        b.putShort(input.wide() ? 60 : 48, (short) (count >= 0xff00 ? 0 : count));
        word(b, TABLE + (input.wide() ? 32 : 20), count >= 0xff00 ? count : 0, input.wide());
        Files.write(input.original(), data);
    }

    static void extendedPrograms(Input input) throws IOException {
        byte[] old = Files.readAllBytes(input.original());
        int width = (input.wide() ? 56 : 32) + 8;
        int offset = 0x1000;
        byte[] data = Arrays.copyOf(old, offset + 65535 * width);
        System.arraycopy(old, 0x100, data, offset, 2 * width);
        ByteBuffer b = ByteBuffer.wrap(data).order(input.order());
        word(b, input.wide() ? 32 : 28, offset, input.wide());
        b.putShort(input.wide() ? 56 : 44, (short) 0xffff);
        b.putInt(TABLE + (input.wide() ? 44 : 28), 65535);
        Files.write(input.original(), data);
    }

    static void program(ByteBuffer b, int at, boolean wide, int type, long offset, long size) {
        b.putInt(at, type);
        b.putInt(at + (wide ? 4 : 24), 5);
        word(b, at + (wide ? 8 : 4), offset, wide);
        word(b, at + (wide ? 16 : 8), 0x400000 + offset, wide);
        word(b, at + (wide ? 32 : 16), size, wide);
        word(b, at + (wide ? 40 : 20), size, wide);
        word(b, at + (wide ? 48 : 28), 1, wide);
    }

    static void section(ByteBuffer b, int at, boolean wide, long name, long type,
            long flags, long address, long offset, long size, int link, int info, long align, long entry) {
        b.putInt(at, (int) name).putInt(at + 4, (int) type);
        word(b, at + 8, flags, wide);
        word(b, at + (wide ? 16 : 12), address, wide);
        word(b, at + (wide ? 24 : 16), offset, wide);
        word(b, at + (wide ? 32 : 20), size, wide);
        b.putInt(at + (wide ? 40 : 24), link).putInt(at + (wide ? 44 : 28), info);
        word(b, at + (wide ? 48 : 32), align, wide);
        word(b, at + (wide ? 56 : 36), entry, wide);
    }

    static void field(Input input, int section, int wideOffset, int narrowOffset, long value, boolean word) throws IOException {
        boolean large = input.wide() && word;
        ByteBuffer b = ByteBuffer.allocate(large ? 8 : 4).order(input.order());
        word(b, 0, value, large);
        write(input.original(), TABLE + (long) section * input.entrySize() + (input.wide() ? wideOffset : narrowOffset), b.array());
    }

    static void word(ByteBuffer b, int at, long value, boolean wide) {
        if (wide) { b.putLong(at, value); } else { b.putInt(at, (int) value); }
    }

    static void write(Path path, long offset, byte[] bytes) throws IOException {
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.WRITE)) {
            ByteBuffer b = ByteBuffer.wrap(bytes);
            while (b.hasRemaining()) { file.write(b, offset + b.position()); }
        }
    }
}
