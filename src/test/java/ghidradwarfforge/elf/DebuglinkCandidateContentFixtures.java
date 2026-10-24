package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.zip.CRC32;

/** Independent byte-encoded ELF fixtures; these are not runtime-validity claims. */
final class DebuglinkCandidateContentFixtures {
    static final int TEXT = 1;
    static final int BSS = 2;
    static final int RELOC = 3;
    static final int NAMES = 4;
    static final int LINK = 5;
    static final int ORIGINAL_TABLE = 0x2000;
    static final int CANDIDATE_TABLE = 0x2400;
    static final int NAME_BYTES = 0x1800;
    static final int LINK_BYTES = 0x3000;
    static final byte[] NAMES_BYTES = new byte[] {
        0, '.', 't', 'e', 'x', 't', 0, '.', 'b', 's', 's', 0,
        '.', 'r', 'e', 'l', 'a', '.', 'd', 'y', 'n', 0,
        '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0,
        '.', 'g', 'n', 'u', '_', 'd', 'e', 'b', 'u', 'g', 'l', 'i', 'n', 'k', 0,
        '.', 'o', 't', 'h', 'e', 'r', 0 };

    record Pair(Path original, Path candidate, Path sidecar, boolean wide, ByteOrder order,
            byte[] basename) {
        int size() { return wide ? 64 : 40; }
        long header(boolean candidate, int index) {
            return (candidate ? CANDIDATE_TABLE : ORIGINAL_TABLE) + (long) index * size();
        }
    }

    private DebuglinkCandidateContentFixtures() {
    }

    static Pair create(Path directory, boolean wide, ByteOrder order, byte[] basename) throws Exception {
        Files.createDirectories(directory);
        Path sidecar = directory.resolve("selected-sidecar.bytes");
        // Deliberately not ELF: CRC agreement cannot establish sidecar validity.
        Files.write(sidecar, new byte[] {1, 2, 3, 4, (byte) 255, 17});
        byte[] data = new byte[ORIGINAL_TABLE + 5 * (wide ? 64 : 40)];
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0});
        b.putShort(16, (short) 2);
        b.putShort(18, (short) 0x7777);
        b.putInt(20, 1);
        word(b, 24, 0x401000, wide);
        word(b, wide ? 32 : 28, 0x100, wide);
        word(b, wide ? 40 : 32, ORIGINAL_TABLE, wide);
        b.putShort(wide ? 52 : 40, (short) (wide ? 64 : 52));
        b.putShort(wide ? 54 : 42, (short) (wide ? 56 : 32));
        b.putShort(wide ? 56 : 44, (short) 2);
        b.putShort(wide ? 58 : 46, (short) (wide ? 64 : 40));
        b.putShort(wide ? 60 : 48, (short) 5);
        b.putShort(wide ? 62 : 50, (short) NAMES);
        program(b, 0x100, wide, 1, 0x1000, 0x100);
        program(b, 0x100 + (wide ? 56 : 32), wide, 0x700000aa, 0x1100, 0x100);
        for (int index = 0x1000; index < 0x1200; index++) {
            data[index] = (byte) (index * 13 + 7);
        }
        System.arraycopy(NAMES_BYTES, 0, data, NAME_BYTES, NAMES_BYTES.length);
        int entry = wide ? 64 : 40;
        section(b, ORIGINAL_TABLE + TEXT * entry, wide, 1, 1, 6, 0x401000, 0x1000, 0x180, 16);
        section(b, ORIGINAL_TABLE + BSS * entry, wide, 7, 8, 3, 0x500000, 0xffffff00L, 0x1000, 8);
        section(b, ORIGINAL_TABLE + RELOC * entry, wide, 12, 4, 2, 0x401180, 0x1180, 0x40, 8);
        section(b, ORIGINAL_TABLE + NAMES * entry, wide, 22, 3, 0, 0, NAME_BYTES, NAMES_BYTES.length, 1);
        Path original = directory.resolve("original.elf");
        Path candidate = directory.resolve("candidate.elf");
        Files.write(original, data);
        byte[] payload = payload(basename, Files.readAllBytes(sidecar), order);
        byte[] next = Arrays.copyOf(data, Math.max(CANDIDATE_TABLE + 6 * entry, LINK_BYTES + payload.length));
        System.arraycopy(data, ORIGINAL_TABLE, next, CANDIDATE_TABLE, 5 * entry);
        b = ByteBuffer.wrap(next).order(order);
        word(b, wide ? 40 : 32, CANDIDATE_TABLE, wide);
        b.putShort(wide ? 60 : 48, (short) 6);
        section(b, CANDIDATE_TABLE + LINK * entry, wide, 32, 1, 0, 0, LINK_BYTES, payload.length, 4);
        System.arraycopy(payload, 0, next, LINK_BYTES, payload.length);
        Files.write(candidate, next);
        return new Pair(original, candidate, sidecar, wide, order, basename.clone());
    }

    static byte[] payload(byte[] basename, byte[] content, ByteOrder order) {
        CRC32 crc = new CRC32();
        crc.update(content);
        int at = (basename.length + 4) & ~3;
        byte[] result = Arrays.copyOf(basename, at + 4);
        ByteBuffer.wrap(result).order(order).putInt(at, (int) crc.getValue());
        return result;
    }

    static void section(ByteBuffer data, int at, boolean wide, long name, long type,
            long flags, long address, long offset, long size, long alignment) {
        data.putInt(at, (int) name);
        data.putInt(at + 4, (int) type);
        word(data, at + 8, flags, wide);
        word(data, at + (wide ? 16 : 12), address, wide);
        word(data, at + (wide ? 24 : 16), offset, wide);
        word(data, at + (wide ? 32 : 20), size, wide);
        word(data, at + (wide ? 48 : 32), alignment, wide);
    }

    private static void program(ByteBuffer b, int at, boolean wide, int type, long offset, long size) {
        b.putInt(at, type);
        b.putInt(at + (wide ? 4 : 24), 5);
        word(b, at + (wide ? 8 : 4), offset, wide);
        word(b, at + (wide ? 16 : 8), 0x400000 + offset, wide);
        word(b, at + (wide ? 32 : 16), size, wide);
        word(b, at + (wide ? 40 : 20), size, wide);
        word(b, at + (wide ? 48 : 28), 1, wide);
    }

    static void word(ByteBuffer b, int at, long value, boolean wide) {
        if (wide) { b.putLong(at, value); }
        else { b.putInt(at, (int) value); }
    }

    static void field(Pair pair, boolean candidate, int index, String field, long value) throws IOException {
        String[] names = {"name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entrySize"};
        int[] wide = {0, 4, 8, 16, 24, 32, 40, 44, 48, 56};
        int[] narrow = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36};
        int at = Arrays.asList(names).indexOf(field);
        if (at < 0) { throw new IllegalArgumentException(field); }
        boolean large = pair.wide() && at != 0 && at != 1 && at != 6 && at != 7;
        ByteBuffer data = ByteBuffer.allocate(large ? 8 : 4).order(pair.order());
        word(data, 0, value, large);
        write(candidate ? pair.candidate() : pair.original(),
            pair.header(candidate, index) + (pair.wide() ? wide[at] : narrow[at]), data.array());
    }

    static void write(Path path, long offset, byte[] bytes) throws IOException {
        try (FileChannel output = FileChannel.open(path, StandardOpenOption.WRITE)) {
            ByteBuffer data = ByteBuffer.wrap(bytes);
            while (data.hasRemaining()) { output.write(data, offset + data.position()); }
        }
    }
}
