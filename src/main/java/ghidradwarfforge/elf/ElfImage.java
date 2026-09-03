package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Strict ELF32/ELF64 metadata reader used by the matched-copy sidecar writer. */
public final class ElfImage {
    static final int SHT_NOBITS = 8;
    private static final long PT_LOAD = 1;
    private static final int SHN_XINDEX = 0xffff;

    private final byte[] bytes;
    private final ByteBuffer buffer;
    private final boolean elf64;
    private final List<Section> sections;
    private final List<Segment> segments;
    private final int sectionNameIndex;

    private ElfImage(byte[] bytes) {
        this.bytes = bytes;
        if (bytes.length < 16 || bytes[0] != 0x7f || bytes[1] != 'E' ||
                bytes[2] != 'L' || bytes[3] != 'F') {
            throw new IllegalArgumentException("not an ELF file");
        }
        int elfClass = Byte.toUnsignedInt(bytes[4]);
        if (elfClass != 1 && elfClass != 2) {
            throw new IllegalArgumentException("unsupported ELF class " + elfClass);
        }
        elf64 = elfClass == 2;
        int dataEncoding = Byte.toUnsignedInt(bytes[5]);
        if (dataEncoding != 1 && dataEncoding != 2) {
            throw new IllegalArgumentException("unsupported ELF byte order " + dataEncoding);
        }
        buffer = ByteBuffer.wrap(bytes).order(
            dataEncoding == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        int headerSize = elf64 ? 64 : 52;
        if (bytes.length < headerSize) {
            throw new IllegalArgumentException("truncated ELF header");
        }
        segments = Collections.unmodifiableList(readSegments());

        long sectionOffset = elf64 ? unsignedLong(40) : unsignedInt(32);
        int entrySize = unsignedShort(elf64 ? 58 : 46);
        int encodedCount = unsignedShort(elf64 ? 60 : 48);
        int encodedNameIndex = unsignedShort(elf64 ? 62 : 50);
        if (sectionOffset == 0 && encodedCount == 0) {
            sections = List.of();
            sectionNameIndex = 0;
            return;
        }
        int requiredEntrySize = elf64 ? 64 : 40;
        if (sectionOffset == 0 || entrySize < requiredEntrySize) {
            throw new IllegalArgumentException("invalid ELF section table metadata");
        }

        Section sectionZero = readSection(sectionOffset, entrySize, 0);
        long countLong = encodedCount == 0 ? sectionZero.size : encodedCount;
        if (countLong <= 0 || countLong > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("unsupported ELF section count " + countLong);
        }
        int count = Math.toIntExact(countLong);
        long tableEnd = checkedAdd(sectionOffset, checkedMultiply(entrySize, count));
        requireRange(sectionOffset, tableEnd - sectionOffset, "section table");

        List<Section> parsed = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            parsed.add(readSection(sectionOffset, entrySize, index));
        }
        long nameIndexLong = encodedNameIndex == SHN_XINDEX ? sectionZero.link : encodedNameIndex;
        if (nameIndexLong < 0 || nameIndexLong >= count) {
            throw new IllegalArgumentException("invalid section-name table index " + nameIndexLong);
        }
        sectionNameIndex = Math.toIntExact(nameIndexLong);
        Section nameTable = parsed.get(sectionNameIndex);
        requireRange(nameTable.offset, nameTable.size, "section-name table");
        for (Section section : parsed) {
            section.name = readString(nameTable, section.nameOffset);
        }
        sections = Collections.unmodifiableList(parsed);
    }

    public static ElfImage read(Path path) throws IOException {
        return new ElfImage(Files.readAllBytes(path));
    }

    public boolean is64Bit() {
        return elf64;
    }

    public ByteOrder byteOrder() {
        return buffer.order();
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public List<Section> sections() {
        return sections;
    }

    public int sectionNameIndex() {
        return sectionNameIndex;
    }

    public List<Segment> segments() {
        return segments;
    }

    public byte[] sectionData(Section section) {
        if (section.type == SHT_NOBITS) {
            return new byte[0];
        }
        requireRange(section.offset, section.size, "section " + section.name);
        byte[] result = new byte[Math.toIntExact(section.size)];
        System.arraycopy(bytes, Math.toIntExact(section.offset), result, 0, result.length);
        return result;
    }

    public int machine() {
        return unsignedShort(18);
    }

    public int type() {
        return unsignedShort(16);
    }

    public long flags() {
        return unsignedInt(elf64 ? 48 : 36);
    }

    /** Link-time base used to translate a rebased Ghidra address back to ELF VA. */
    public long preferredImageBase() {
        long result = Long.MAX_VALUE;
        for (Segment segment : segments) {
            if (segment.type != PT_LOAD) {
                continue;
            }
            if (segment.virtualAddress < segment.offset) {
                throw new IllegalArgumentException(
                    "PT_LOAD virtual address is below its file offset");
            }
            result = Math.min(result, segment.virtualAddress - segment.offset);
        }
        if (result == Long.MAX_VALUE) {
            throw new IllegalArgumentException("ELF has no PT_LOAD image base");
        }
        return result;
    }

    private Section readSection(long tableOffset, int entrySize, int index) {
        long start = checkedAdd(tableOffset, checkedMultiply(entrySize, index));
        requireRange(start, entrySize, "section header " + index);
        int offset = Math.toIntExact(start);
        Section section = new Section();
        section.originalIndex = index;
        section.nameOffset = unsignedInt(offset);
        section.type = unsignedInt(offset + 4);
        if (elf64) {
            section.flags = unsignedLong(offset + 8);
            section.address = unsignedLong(offset + 16);
            section.offset = unsignedLong(offset + 24);
            section.size = unsignedLong(offset + 32);
            section.link = unsignedInt(offset + 40);
            section.info = unsignedInt(offset + 44);
            section.alignment = unsignedLong(offset + 48);
            section.entrySize = unsignedLong(offset + 56);
        }
        else {
            section.flags = unsignedInt(offset + 8);
            section.address = unsignedInt(offset + 12);
            section.offset = unsignedInt(offset + 16);
            section.size = unsignedInt(offset + 20);
            section.link = unsignedInt(offset + 24);
            section.info = unsignedInt(offset + 28);
            section.alignment = unsignedInt(offset + 32);
            section.entrySize = unsignedInt(offset + 36);
        }
        return section;
    }

    private List<Segment> readSegments() {
        long tableOffset = elf64 ? unsignedLong(32) : unsignedInt(28);
        int entrySize = unsignedShort(elf64 ? 54 : 42);
        int count = unsignedShort(elf64 ? 56 : 44);
        if (count == 0) {
            return List.of();
        }
        int requiredEntrySize = elf64 ? 56 : 32;
        if (tableOffset == 0 || entrySize < requiredEntrySize) {
            throw new IllegalArgumentException("invalid ELF program table metadata");
        }
        requireRange(tableOffset, checkedMultiply(entrySize, count), "program table");
        List<Segment> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            int offset = Math.toIntExact(checkedAdd(tableOffset,
                checkedMultiply(entrySize, index)));
            Segment segment = new Segment();
            segment.type = unsignedInt(offset);
            if (elf64) {
                segment.flags = unsignedInt(offset + 4);
                segment.offset = unsignedLong(offset + 8);
                segment.virtualAddress = unsignedLong(offset + 16);
                segment.fileSize = unsignedLong(offset + 32);
                segment.memorySize = unsignedLong(offset + 40);
                segment.alignment = unsignedLong(offset + 48);
            }
            else {
                segment.offset = unsignedInt(offset + 4);
                segment.virtualAddress = unsignedInt(offset + 8);
                segment.fileSize = unsignedInt(offset + 16);
                segment.memorySize = unsignedInt(offset + 20);
                segment.flags = unsignedInt(offset + 24);
                segment.alignment = unsignedInt(offset + 28);
            }
            if (segment.fileSize > 0) {
                requireRange(segment.offset, segment.fileSize, "program segment " + index);
            }
            result.add(segment);
        }
        return result;
    }

    private String readString(Section stringTable, long relativeOffset) {
        if (relativeOffset < 0 || relativeOffset >= stringTable.size) {
            throw new IllegalArgumentException("invalid section-name offset " + relativeOffset);
        }
        int start = Math.toIntExact(checkedAdd(stringTable.offset, relativeOffset));
        int limit = Math.toIntExact(checkedAdd(stringTable.offset, stringTable.size));
        int end = start;
        while (end < limit && bytes[end] != 0) {
            end++;
        }
        if (end == limit) {
            throw new IllegalArgumentException("unterminated section name");
        }
        return new String(bytes, start, end - start, java.nio.charset.StandardCharsets.UTF_8);
    }

    private int unsignedShort(int offset) {
        return Short.toUnsignedInt(buffer.getShort(offset));
    }

    private long unsignedInt(int offset) {
        return Integer.toUnsignedLong(buffer.getInt(offset));
    }

    private long unsignedLong(int offset) {
        long value = buffer.getLong(offset);
        if (value < 0) {
            throw new IllegalArgumentException("ELF value exceeds signed 64-bit range");
        }
        return value;
    }

    private void requireRange(long offset, long size, String description) {
        if (offset < 0 || size < 0 || offset > bytes.length || size > bytes.length - offset) {
            throw new IllegalArgumentException("invalid " + description + " range");
        }
    }

    private static long checkedAdd(long left, long right) {
        return Math.addExact(left, right);
    }

    private static long checkedMultiply(long left, long right) {
        return Math.multiplyExact(left, right);
    }

    public static final class Section {
        int originalIndex;
        long nameOffset;
        String name = "";
        long type;
        long flags;
        long address;
        long offset;
        long size;
        long link;
        long info;
        long alignment;
        long entrySize;

        Section copy() {
            Section copy = new Section();
            copy.originalIndex = originalIndex;
            copy.nameOffset = nameOffset;
            copy.name = name;
            copy.type = type;
            copy.flags = flags;
            copy.address = address;
            copy.offset = offset;
            copy.size = size;
            copy.link = link;
            copy.info = info;
            copy.alignment = alignment;
            copy.entrySize = entrySize;
            return copy;
        }

        public String name() {
            return name;
        }

        public long size() {
            return size;
        }
    }

    public static final class Segment {
        long type;
        long flags;
        long offset;
        long virtualAddress;
        long fileSize;
        long memorySize;
        long alignment;
    }

}
