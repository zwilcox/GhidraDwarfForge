package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/** Independent synthetic ELF metadata; no production serialization is reused. */
final class ElfBuildIdFixtures {
    record View(long offset, long size, long alignment, long type, long flags) {
        static View section(long offset, long size, long alignment) {
            return new View(offset, size, alignment, 7, 0);
        }

        static View segment(long offset, long size, long alignment) {
            return new View(offset, size, alignment, 4, 0);
        }
    }

    record Fixture(Path path, boolean elf64, ByteOrder order, long dataOffset,
            long sectionOffset, long programOffset, int sectionCount, int programCount) {
        void patch(long offset, int width, long value) throws IOException {
            ByteBuffer data = ByteBuffer.allocate(width).order(order);
            put(data, 0, width, value);
            try (FileChannel output = FileChannel.open(path, StandardOpenOption.WRITE)) {
                write(output, offset, data.array());
            }
        }

        long section(int index) {
            return sectionOffset + (long) index * (elf64 ? 64 : 40);
        }

        long segment(int index) {
            return programOffset + (long) index * (elf64 ? 56 : 32);
        }
    }

    private ElfBuildIdFixtures() {
    }

    static byte[] note(ByteOrder order, int alignment, byte[] owner, long type, byte[] descriptor) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.writeBytes(ByteBuffer.allocate(12).order(order).putInt(owner.length)
            .putInt(descriptor.length).putInt((int) type).array());
        result.writeBytes(owner);
        while (result.size() % alignment != 0) {
            result.write(0xa5); // Padding is deliberately nonzero.
        }
        result.writeBytes(descriptor);
        while (result.size() % alignment != 0) {
            result.write(0x5a);
        }
        return result.toByteArray();
    }

    static byte[] join(byte[]... arrays) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (byte[] array : arrays) {
            result.writeBytes(array);
        }
        return result.toByteArray();
    }

    static Fixture create(Path path, boolean elf64, ByteOrder order, byte[] payload,
            List<View> sections, List<View> segments, boolean names, boolean extendedSections,
            boolean extendedPrograms, long minimumDataOffset) throws IOException {
        int eh = elf64 ? 64 : 52;
        int ph = elf64 ? 56 : 32;
        int sh = elf64 ? 64 : 40;
        int pc = extendedPrograms ? 0xffff : segments.size();
        boolean table = !sections.isEmpty() || extendedSections || extendedPrograms;
        int sc = extendedSections ? 0xff01 : table ? 1 + sections.size() + (names ? 1 : 0) : 0;
        long po = pc == 0 ? 0 : eh;
        long so = sc == 0 ? 0 : align(eh + (long) pc * ph, 8);
        long strings = sc == 0 ? eh + (long) pc * ph : so + (long) sc * sh;
        byte[] nameBytes = new byte[] { 0, '.', 'o', 't', 'h', 'e', 'r', 0,
            '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0 };
        long dataOffset = Math.max(minimumDataOffset, align(strings + nameBytes.length, 4096));
        ByteBuffer header = ByteBuffer.allocate(eh).order(order);
        header.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0 });
        header.putShort(16, (short) 2);
        header.putShort(18, (short) (elf64 ? 62 : 3));
        header.putInt(20, 1);
        put(header, elf64 ? 32 : 28, elf64 ? 8 : 4, po);
        put(header, elf64 ? 40 : 32, elf64 ? 8 : 4, so);
        header.putShort(elf64 ? 52 : 40, (short) eh);
        header.putShort(elf64 ? 54 : 42, (short) ph);
        header.putShort(elf64 ? 56 : 44, (short) pc);
        header.putShort(elf64 ? 58 : 46, (short) sh);
        header.putShort(elf64 ? 60 : 48, (short) (extendedSections ? 0 : sc));
        int nameIndex = names && sc != 0 ? sc - 1 : 0;
        header.putShort(elf64 ? 62 : 50, (short) (nameIndex >= 0xff00 ? 0xffff : nameIndex));
        // This helper owns its temporary fixture path. CREATE_NEW is needed for
        // the Windows provider to honor SPARSE on the >2 GiB metadata controls.
        Files.deleteIfExists(path);
        try (FileChannel output = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.SPARSE, StandardOpenOption.WRITE)) {
            write(output, 0, header.array());
            if (sc > 0) {
                ByteBuffer tableBytes = ByteBuffer.allocate(sc * sh).order(order);
                if (extendedSections) {
                    put(tableBytes, elf64 ? 32 : 20, elf64 ? 8 : 4, sc);
                }
                if (nameIndex >= 0xff00) {
                    tableBytes.putInt(elf64 ? 40 : 24, nameIndex);
                }
                if (extendedPrograms) {
                    tableBytes.putInt(elf64 ? 44 : 28, pc);
                }
                for (int index = 0; index < sections.size(); index++) {
                    View view = sections.get(index);
                    int start = (index + 1) * sh;
                    tableBytes.putInt(start, names ? 1 : 0);
                    tableBytes.putInt(start + 4, (int) view.type);
                    put(tableBytes, start + 8, elf64 ? 8 : 4, view.flags);
                    put(tableBytes, start + (elf64 ? 24 : 16), elf64 ? 8 : 4, dataOffset + view.offset);
                    put(tableBytes, start + (elf64 ? 32 : 20), elf64 ? 8 : 4, view.size);
                    put(tableBytes, start + (elf64 ? 48 : 32), elf64 ? 8 : 4, view.alignment);
                }
                if (nameIndex != 0) {
                    int start = nameIndex * sh;
                    tableBytes.putInt(start, 8);
                    tableBytes.putInt(start + 4, 3);
                    put(tableBytes, start + (elf64 ? 24 : 16), elf64 ? 8 : 4, strings);
                    put(tableBytes, start + (elf64 ? 32 : 20), elf64 ? 8 : 4, nameBytes.length);
                    write(output, strings, nameBytes);
                }
                write(output, so, tableBytes.array());
            }
            if (pc > 0) {
                ByteBuffer tableBytes = ByteBuffer.allocate(pc * ph).order(order);
                for (int index = 0; index < segments.size(); index++) {
                    View view = segments.get(index);
                    int start = (pc - segments.size() + index) * ph;
                    tableBytes.putInt(start, (int) view.type);
                    put(tableBytes, start + (elf64 ? 8 : 4), elf64 ? 8 : 4, dataOffset + view.offset);
                    put(tableBytes, start + (elf64 ? 32 : 16), elf64 ? 8 : 4, view.size);
                    put(tableBytes, start + (elf64 ? 40 : 20), elf64 ? 8 : 4, view.size);
                    put(tableBytes, start + (elf64 ? 48 : 28), elf64 ? 8 : 4, view.alignment);
                }
                write(output, po, tableBytes.array());
            }
            if (payload.length == 0) {
                write(output, dataOffset - 1, new byte[1]);
            }
            else {
                write(output, dataOffset, payload);
            }
        }
        return new Fixture(path, elf64, order, dataOffset, so, po, sc, pc);
    }

    private static long align(long value, long alignment) {
        return (value + alignment - 1) / alignment * alignment;
    }

    private static void put(ByteBuffer target, int offset, int size, long value) {
        if (size == 8) {
            target.putLong(offset, value);
        }
        else if (size == 4) {
            target.putInt(offset, (int) value);
        }
        else if (size == 2) {
            target.putShort(offset, (short) value);
        }
        else {
            target.put(offset, (byte) value);
        }
    }

    private static void write(FileChannel output, long offset, byte[] bytes) throws IOException {
        ByteBuffer data = ByteBuffer.wrap(bytes);
        while (data.hasRemaining()) {
            if (output.write(data, offset + data.position()) <= 0) {
                throw new IOException("fixture write stopped making progress");
            }
        }
    }
}
