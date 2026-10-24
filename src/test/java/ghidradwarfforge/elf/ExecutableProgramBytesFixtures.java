package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Independent small/sparse ELF metadata fixtures, not executable runtime claims. */
final class ExecutableProgramBytesFixtures {
    enum Shape { NORMAL, NO_PROGRAMS, INACTIVE, MEMORY_ONLY, NOTE_ONLY, EXTENDED_PROGRAMS, EXTENDED_SECTIONS }

    record Pair(Path original, Path candidate, boolean wide, ByteOrder order, int headerSize,
            int programOffset, int entrySize, int programCount, int firstProgram,
            int originalSections, int candidateSections) {
        int program(int index) {
            return programOffset + (firstProgram + index) * entrySize;
        }

        int sectionSize() {
            return wide ? 64 : 40;
        }

        int sectionInfo() {
            return wide ? 44 : 28;
        }
    }

    private ExecutableProgramBytesFixtures() {
    }

    static Pair create(Path directory, boolean wide, ByteOrder order, Shape shape) throws Exception {
        Files.createDirectories(directory);
        int standardHeader = wide ? 64 : 52;
        int headerSize = standardHeader + 16;
        int entrySize = (wide ? 56 : 32) + 8;
        int prefix = shape == Shape.EXTENDED_PROGRAMS ? 0xffff : 0;
        int programCount = shape == Shape.NO_PROGRAMS ? 0 : prefix + 4;
        int programOffset = programCount == 0 ? 0 : prefix == 0 ? 0x100 : 0x4000;
        int sectionSize = wide ? 64 : 40;
        int oldCount = shape == Shape.EXTENDED_SECTIONS ? 0xff01 : 4;
        int oldNamesIndex = oldCount - 1;
        int originalSections = Math.max(0x2000, programOffset + programCount * entrySize + 0x100);
        int candidateSections = originalSections + oldCount * sectionSize + 0x200;
        byte[] original = new byte[originalSections + oldCount * sectionSize];
        ByteBuffer data = ByteBuffer.wrap(original).order(order);
        data.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0 });
        data.putShort(16, (short) 2);
        data.putShort(18, (short) 0x7777); // Generic observer must not need an ISA mapping.
        data.putInt(20, 1);
        putWord(data, 24, wide ? Long.MIN_VALUE + 0x1234 : 0x8000_1234L, wide);
        putWord(data, wide ? 32 : 28, programOffset, wide);
        putWord(data, wide ? 40 : 32, originalSections, wide);
        data.putInt(wide ? 48 : 36, 0x8765_4321);
        data.putShort(wide ? 52 : 40, (short) headerSize);
        data.putShort(wide ? 54 : 42, (short) entrySize);
        data.putShort(wide ? 56 : 44, (short) (prefix == 0 ? programCount : 0xffff));
        data.putShort(wide ? 58 : 46, (short) sectionSize);
        countAndNames(data, wide, originalSections, oldCount, oldNamesIndex);
        for (int index = standardHeader; index < headerSize; index++) {
            original[index] = (byte) (index * 11);
        }
        for (int index = 0x800; index < 0x820; index++) {
            original[index] = (byte) (index * 7);
        }
        for (int index = 0x1000; index < 0x1120; index++) {
            original[index] = (byte) (index * 3 + 1);
        }
        if (programCount > 0) {
            int first = programOffset + prefix * entrySize;
            program(data, first, wide, shape == Shape.INACTIVE ? 0 :
                shape == Shape.NOTE_ONLY ? 4 : 1, 5, 0x1000, 0x401000,
                shape == Shape.MEMORY_ONLY ? 0 : 0x100, 0x180);
            program(data, first + entrySize, wide, shape == Shape.INACTIVE ? 0 : 4,
                4, 0x800, 0x400800, 0x20, 0x20);
            program(data, first + 2 * entrySize, wide, shape == Shape.INACTIVE ? 0 : 0x700000aa,
                4, 0x1080, 0x401080, 0xa0, 0xa0);
            // Inactive bytes and extension bytes must still be compared verbatim.
            program(data, first + 3 * entrySize, wide, 0, 0x55, 0xfffffff0L,
                0xffffffffL, 0xffffffffL, 0xffffffffL);
            for (int row = 0; row < 4; row++) {
                Arrays.fill(original, first + row * entrySize + (wide ? 56 : 32),
                    first + (row + 1) * entrySize, (byte) (0x41 + row));
            }
        }
        if (prefix != 0) {
            data.putInt(originalSections + (wide ? 44 : 28), programCount);
        }
        byte[] names = "\0.text\0.gnu_debuglink\0.shstrtab\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(names, 0, original, 0x1900, names.length);
        byte[] link = "owned.dbg\0\0\0\u0012\u0034\u0056\u0078"
            .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        System.arraycopy(link, 0, original, 0x1800, link.length);
        section(data, originalSections + sectionSize, wide, 1, 1, 6, 0x401000, 0x1000, 0x100, 16);
        section(data, originalSections + 2 * sectionSize, wide, 7, 1, 0, 0, 0x1800, link.length, 4);
        section(data, originalSections + oldNamesIndex * sectionSize, wide, 22, 3, 0, 0, 0x1900, names.length, 1);
        byte[] candidate = Arrays.copyOf(original, candidateSections + (oldCount + 1) * sectionSize);
        System.arraycopy(original, originalSections, candidate, candidateSections, oldCount * sectionSize);
        ByteBuffer next = ByteBuffer.wrap(candidate).order(order);
        putWord(next, wide ? 40 : 32, candidateSections, wide);
        countAndNames(next, wide, candidateSections, oldCount + 1, oldCount);
        // Rebuild the name table at a different unused offset and index.
        System.arraycopy(names, 0, candidate, 0x1a00, names.length);
        section(next, candidateSections + oldCount * sectionSize, wide, 22, 3, 0, 0, 0x1a00, names.length, 1);
        if (prefix != 0) {
            next.putInt(candidateSections + (wide ? 44 : 28), programCount);
        }
        Path before = directory.resolve("original.elf");
        Path after = directory.resolve("candidate.elf");
        Files.write(before, original);
        Files.write(after, candidate);
        return new Pair(before, after, wide, order, headerSize, programOffset, entrySize,
            programCount, prefix, originalSections, candidateSections);
    }

    private static void countAndNames(ByteBuffer data, boolean wide, int table, int count, int names) {
        data.putShort(wide ? 60 : 48, (short) (count >= 0xff00 ? 0 : count));
        data.putShort(wide ? 62 : 50, (short) (names >= 0xff00 ? 0xffff : names));
        putWord(data, table + (wide ? 32 : 20), count >= 0xff00 ? count : 0, wide);
        data.putInt(table + (wide ? 40 : 24), names >= 0xff00 ? names : 0);
    }

    static void program(ByteBuffer data, int at, boolean wide, int type, int flags,
            long offset, long address, long fileSize, long memorySize) {
        data.putInt(at, type);
        data.putInt(at + (wide ? 4 : 24), flags);
        putWord(data, at + (wide ? 8 : 4), offset, wide);
        putWord(data, at + (wide ? 16 : 8), address, wide);
        putWord(data, at + (wide ? 24 : 12), 0x12345678L, wide);
        putWord(data, at + (wide ? 32 : 16), fileSize, wide);
        putWord(data, at + (wide ? 40 : 20), memorySize, wide);
        putWord(data, at + (wide ? 48 : 28), 4, wide);
    }

    private static void section(ByteBuffer data, int at, boolean wide, int name, int type,
            long flags, long address, long offset, long size, long alignment) {
        data.putInt(at, name);
        data.putInt(at + 4, type);
        putWord(data, at + 8, flags, wide);
        putWord(data, at + (wide ? 16 : 12), address, wide);
        putWord(data, at + (wide ? 24 : 16), offset, wide);
        putWord(data, at + (wide ? 32 : 20), size, wide);
        putWord(data, at + (wide ? 48 : 32), alignment, wide);
    }

    static void putWord(ByteBuffer data, int offset, long value, boolean wide) {
        if (wide) {
            data.putLong(offset, value);
        }
        else {
            data.putInt(offset, (int) value);
        }
    }
}
