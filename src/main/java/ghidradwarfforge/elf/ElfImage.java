package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Bounded, file-backed ELF32/ELF64 metadata for the matched sidecar writer.
 * No source channel remains open after an operation. File sizes/offsets use signed
 * 64-bit values; the original image is never buffered in its entirety.
 * Safety limits are 262144 entries per header table, 64 MiB per table or
 * convenience byte-array read, 16 MiB for the section-name table and aggregate
 * decoded names, and 65536 bytes per individual name (excluding its NUL).
 * These are explicit resource limits, not additional ELF format constraints.
 */
public final class ElfImage {
    private static final int SHT_NULL = 0;
    private static final int SHT_STRTAB = 3;
    static final int SHT_NOBITS = 8;
    private static final long PT_LOAD = 1;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int SHN_XINDEX = 0xffff;
    private static final int PN_XNUM = 0xffff;
    static final int MAX_HEADER_COUNT = 262144;
    static final int MAX_TABLE_BYTES = 64 * 1024 * 1024;
    static final int MAX_NAME_TABLE_BYTES = 16 * 1024 * 1024;
    static final int MAX_NAME_BYTES = 65536;

    private final Path source;
    private final BasicFileAttributes identity;
    private final long fileSize;
    private final byte[] header;
    private final ByteBuffer buffer;
    private final boolean elf64;
    private final List<Section> sections;
    private final List<Segment> segments;
    private final int sectionNameIndex;

    private ElfImage(Path path) throws IOException {
        // Resolve actual filesystem traversal before removing any dot segments:
        // symlink/../input may name a different file from lexical normalization.
        source = path.toRealPath();
        identity = Files.readAttributes(source, BasicFileAttributes.class);
        if (!identity.isRegularFile()) {
            throw new IllegalArgumentException("ELF input is not a regular file: " + source);
        }
        fileSize = identity.size();
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ)) {
            byte[] ident = readRange(input, 0, 16, 16, "ELF identification");
            if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
                throw new IllegalArgumentException("not an ELF file");
            }
            int elfClass = Byte.toUnsignedInt(ident[4]);
            if (elfClass != 1 && elfClass != 2) {
                throw new IllegalArgumentException("unsupported ELF class " + elfClass);
            }
            elf64 = elfClass == 2;
            int encoding = Byte.toUnsignedInt(ident[5]);
            if (encoding != 1 && encoding != 2) {
                throw new IllegalArgumentException("unsupported ELF byte order " + encoding);
            }
            int headerSize = elf64 ? 64 : 52;
            header = readRange(input, 0, headerSize, headerSize, "ELF header");
            buffer = ByteBuffer.wrap(header).order(
                encoding == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
            if (ident[6] != 1 || unsignedInt(buffer, 20) != 1) {
                throw new IllegalArgumentException("unsupported ELF version");
            }
            int encodedHeaderSize = unsignedShort(elf64 ? 52 : 40);
            if (encodedHeaderSize < headerSize) {
                throw new IllegalArgumentException("invalid ELF header size " + encodedHeaderSize);
            }
            requireRange(0, encodedHeaderSize, "ELF header");

            long sectionOffset = elf64 ? unsignedLong(buffer, 40) : unsignedInt(buffer, 32);
            int entrySize = unsignedShort(elf64 ? 58 : 46);
            int encodedCount = unsignedShort(elf64 ? 60 : 48);
            int encodedNameIndex = unsignedShort(elf64 ? 62 : 50);
            Section sectionZero = null;
            if (sectionOffset == 0) {
                if (encodedCount != 0 || encodedNameIndex != 0) {
                    throw new IllegalArgumentException("missing ELF section table with nonzero count/name index");
                }
                sections = List.of();
                sectionNameIndex = 0;
            }
            else {
                int requiredEntrySize = elf64 ? 64 : 40;
                if (sectionOffset < encodedHeaderSize || entrySize < requiredEntrySize ||
                        encodedCount >= SHN_LORESERVE) {
                    throw new IllegalArgumentException("invalid ELF section table metadata");
                }
                ByteBuffer first = wrap(readRange(input, sectionOffset, entrySize,
                    MAX_TABLE_BYTES, "section header zero"));
                sectionZero = readSection(first, 0, 0);
                if (sectionZero.type != SHT_NULL || sectionZero.nameOffset != 0) {
                    throw new IllegalArgumentException("section zero must have SHT_NULL type and name offset zero");
                }
                long countLong = encodedCount == 0 ? sectionZero.size : encodedCount;
                if (encodedCount == 0 && countLong < SHN_LORESERVE) {
                    throw new IllegalArgumentException("invalid extended ELF section count " + countLong);
                }
                int count = headerCount(countLong, "section");
                ByteBuffer table = wrap(readRange(input, sectionOffset,
                    (long) entrySize * count, MAX_TABLE_BYTES, "section table"));
                List<Section> parsed = new ArrayList<>(count);
                for (int index = 0; index < count; index++) {
                    Section section = readSection(table, index * entrySize, index);
                    if (section.type != SHT_NULL && section.type != SHT_NOBITS) {
                        requireRange(section.offset, section.size, "section " + index);
                    }
                    parsed.add(section);
                }
                long nameIndex = encodedNameIndex == SHN_XINDEX
                        ? sectionZero.link : encodedNameIndex;
                if ((encodedNameIndex == SHN_XINDEX && nameIndex < SHN_LORESERVE) ||
                        (encodedNameIndex != SHN_XINDEX && encodedNameIndex >= SHN_LORESERVE) ||
                        nameIndex >= count) {
                    throw new IllegalArgumentException("invalid section-name table index " + nameIndex);
                }
                sectionNameIndex = (int) nameIndex;
                // SHN_UNDEF means there are no names, not that section zero is
                // a string table. Preserve unknown names as empty strings.
                if (sectionNameIndex != 0) {
                    readNames(input, parsed, parsed.get(sectionNameIndex));
                }
                sections = List.copyOf(parsed);
            }
            segments = List.copyOf(readSegments(input, sectionZero, encodedHeaderSize));
            requireUnchanged(input);
        }
    }

    public static ElfImage read(Path path) throws IOException {
        return new ElfImage(path);
    }

    public boolean is64Bit() {
        return elf64;
    }

    public ByteOrder byteOrder() {
        return buffer.order();
    }

    public byte[] headerBytes() {
        return header.clone();
    }

    public long fileSize() {
        return fileSize;
    }

    /** Bounded convenience API; use copyTo for original images larger than 64 MiB. */
    public byte[] bytes() throws IOException {
        return readSourceRange(0, fileSize, "whole ELF byte-array read");
    }

    /** Copies the original to the destination's current position, leaving it open. */
    public void copyTo(FileChannel destination) throws IOException {
        copyTo(destination, () -> false);
    }

    /** Checks cancellation between bounded copy operations; never closes the destination. */
    public void copyTo(FileChannel destination, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCopyCancelled(cancelled);
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ)) {
            requireUnchanged(input);
            long position = 0;
            ByteBuffer fallback = null;
            while (position < fileSize) {
                checkCopyCancelled(cancelled);
                long copied = input.transferTo(position,
                    Math.min(16L * 1024 * 1024, fileSize - position), destination);
                if (copied == 0) {
                    if (fallback == null) {
                        fallback = ByteBuffer.allocate(1024 * 1024);
                    }
                    fallback.clear();
                    fallback.limit((int) Math.min(fallback.capacity(), fileSize - position));
                    int count = input.read(fallback, position);
                    if (count <= 0) {
                        throw new IOException("ELF input ended or stopped making progress during copy");
                    }
                    fallback.flip();
                    while (fallback.hasRemaining()) {
                        checkCopyCancelled(cancelled);
                        if (destination.write(fallback) <= 0) {
                            throw new IOException("ELF destination stopped making progress during copy");
                        }
                    }
                    copied = count;
                }
                position += copied;
            }
            checkCopyCancelled(cancelled);
            requireUnchanged(input);
        }
    }

    private static void checkCopyCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("ELF copy cancelled");
        }
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

    public byte[] sectionData(Section section) throws IOException {
        if (section.type == SHT_NULL || section.type == SHT_NOBITS) {
            return new byte[0];
        }
        return readSourceRange(section.offset, section.size, "section " + section.name);
    }

    public int machine() {
        return unsignedShort(18);
    }

    public int type() {
        return unsignedShort(16);
    }

    public long flags() {
        return unsignedInt(buffer, elf64 ? 48 : 36);
    }

    /**
     * Minimum link-time PT_LOAD virtual address. This need not equal Ghidra's
     * recorded import base, which is authoritative for database rebasing.
     */
    public long preferredImageBase() {
        long result = Long.MAX_VALUE;
        boolean foundLoad = false;
        for (Segment segment : segments) {
            if (segment.type != PT_LOAD) {
                continue;
            }
            foundLoad = true;
            result = Math.min(result, segment.virtualAddress);
        }
        if (!foundLoad) {
            throw new IllegalArgumentException("ELF has no PT_LOAD image base");
        }
        return result;
    }

    private Section readSection(ByteBuffer table, int offset, int index) {
        Section section = new Section();
        section.originalIndex = index;
        section.nameOffset = unsignedInt(table, offset);
        section.type = unsignedInt(table, offset + 4);
        if (elf64) {
            section.flags = unsignedLong(table, offset + 8);
            section.address = unsignedLong(table, offset + 16);
            section.offset = unsignedLong(table, offset + 24);
            section.size = unsignedLong(table, offset + 32);
            section.link = unsignedInt(table, offset + 40);
            section.info = unsignedInt(table, offset + 44);
            section.alignment = unsignedLong(table, offset + 48);
            section.entrySize = unsignedLong(table, offset + 56);
        }
        else {
            section.flags = unsignedInt(table, offset + 8);
            section.address = unsignedInt(table, offset + 12);
            section.offset = unsignedInt(table, offset + 16);
            section.size = unsignedInt(table, offset + 20);
            section.link = unsignedInt(table, offset + 24);
            section.info = unsignedInt(table, offset + 28);
            section.alignment = unsignedInt(table, offset + 32);
            section.entrySize = unsignedInt(table, offset + 36);
        }
        return section;
    }

    private List<Segment> readSegments(FileChannel input, Section sectionZero, int headerSize)
            throws IOException {
        long tableOffset = elf64 ? unsignedLong(buffer, 32) : unsignedInt(buffer, 28);
        int entrySize = unsignedShort(elf64 ? 54 : 42);
        int encodedCount = unsignedShort(elf64 ? 56 : 44);
        if (encodedCount == 0) {
            if (tableOffset != 0) {
                throw new IllegalArgumentException("ELF program table offset has zero header count");
            }
            return List.of();
        }
        long countLong = encodedCount;
        if (encodedCount == PN_XNUM) {
            if (sectionZero == null || sectionZero.info < PN_XNUM) {
                throw new IllegalArgumentException("invalid PN_XNUM program count in section zero");
            }
            countLong = sectionZero.info;
        }
        int count = headerCount(countLong, "program");
        int requiredEntrySize = elf64 ? 56 : 32;
        if (tableOffset < headerSize || entrySize < requiredEntrySize) {
            throw new IllegalArgumentException("invalid ELF program table metadata");
        }
        ByteBuffer table = wrap(readRange(input, tableOffset, (long) entrySize * count,
            MAX_TABLE_BYTES, "program table"));
        List<Segment> result = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            int offset = index * entrySize;
            Segment segment = new Segment();
            segment.type = unsignedInt(table, offset);
            if (segment.type == 0) {
                result.add(segment);
                continue;
            }
            if (elf64) {
                segment.flags = unsignedInt(table, offset + 4);
                segment.offset = unsignedLong(table, offset + 8);
                segment.virtualAddress = unsignedLong(table, offset + 16);
                segment.fileSize = unsignedLong(table, offset + 32);
                segment.memorySize = unsignedLong(table, offset + 40);
                segment.alignment = unsignedLong(table, offset + 48);
            }
            else {
                segment.offset = unsignedInt(table, offset + 4);
                segment.virtualAddress = unsignedInt(table, offset + 8);
                segment.fileSize = unsignedInt(table, offset + 16);
                segment.memorySize = unsignedInt(table, offset + 20);
                segment.flags = unsignedInt(table, offset + 24);
                segment.alignment = unsignedInt(table, offset + 28);
            }
            if (segment.fileSize > 0) {
                requireRange(segment.offset, segment.fileSize, "program segment " + index);
            }
            if (segment.type == PT_LOAD && segment.fileSize > segment.memorySize) {
                throw new IllegalArgumentException("PT_LOAD file size exceeds memory size at " + index);
            }
            result.add(segment);
        }
        return result;
    }

    private void readNames(FileChannel input, List<Section> parsed, Section nameTable)
            throws IOException {
        if (nameTable.type != SHT_STRTAB) {
            throw new IllegalArgumentException("section-name table is not SHT_STRTAB");
        }
        byte[] names = readRange(input, nameTable.offset, nameTable.size,
            MAX_NAME_TABLE_BYTES, "section-name table");
        if (names.length == 0 || names[0] != 0 || names[names.length - 1] != 0) {
            throw new IllegalArgumentException("section-name table must begin and end with NUL");
        }
        Map<Long, String> decoded = new HashMap<>();
        int decodedBytes = 0;
        for (Section section : parsed) {
            if (section.nameOffset >= names.length) {
                throw new IllegalArgumentException("invalid section-name offset " + section.nameOffset);
            }
            String name = decoded.get(section.nameOffset);
            if (name == null) {
                int start = (int) section.nameOffset;
                int end = start;
                while (end < names.length && names[end] != 0) {
                    if (end - start == MAX_NAME_BYTES) {
                        throw new IllegalArgumentException("section name exceeds safety limit " + MAX_NAME_BYTES);
                    }
                    end++;
                }
                decodedBytes += end - start;
                if (decodedBytes > MAX_NAME_TABLE_BYTES) {
                    throw new IllegalArgumentException("decoded section names exceed safety limit " + MAX_NAME_TABLE_BYTES);
                }
                name = new String(names, start, end - start, StandardCharsets.UTF_8);
                decoded.put(section.nameOffset, name);
            }
            section.name = name;
        }
    }

    // Package readers share the same bounded reads and source-change checks;
    // each call owns and closes its channel. This is not a snapshot guarantee.
    byte[] readSourceRange(long offset, long size, String description) throws IOException {
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ)) {
            requireUnchanged(input);
            byte[] data = readRange(input, offset, size, MAX_TABLE_BYTES, description);
            requireUnchanged(input);
            return data;
        }
    }

    private byte[] readRange(FileChannel input, long offset, long size, int limit,
            String description) throws IOException {
        requireRange(offset, size, description);
        if (size > limit) {
            throw new IllegalArgumentException(description + " exceeds safety limit " + limit + " bytes");
        }
        ByteBuffer data = ByteBuffer.allocate((int) size);
        while (data.hasRemaining()) {
            if (input.read(data, offset + data.position()) <= 0) {
                throw new IOException("truncated " + description + " while reading ELF input");
            }
        }
        return data.array();
    }

    private void requireUnchanged(FileChannel input) throws IOException {
        BasicFileAttributes current = Files.readAttributes(source, BasicFileAttributes.class);
        if (!current.isRegularFile() || input.size() != fileSize || current.size() != fileSize ||
                !current.lastModifiedTime().equals(identity.lastModifiedTime()) ||
                !Objects.equals(current.fileKey(), identity.fileKey())) {
            throw new IOException("ELF input changed after metadata was read: " + source);
        }
    }

    private static int headerCount(long count, String kind) {
        if (count <= 0 || count > MAX_HEADER_COUNT) {
            throw new IllegalArgumentException("ELF " + kind + " header count " + count +
                " is outside safety limit 1.." + MAX_HEADER_COUNT);
        }
        return (int) count;
    }

    private ByteBuffer wrap(byte[] data) {
        return ByteBuffer.wrap(data).order(byteOrder());
    }

    private int unsignedShort(int offset) {
        return Short.toUnsignedInt(buffer.getShort(offset));
    }

    private static long unsignedInt(ByteBuffer data, int offset) {
        return Integer.toUnsignedLong(data.getInt(offset));
    }

    private static long unsignedLong(ByteBuffer data, int offset) {
        long value = data.getLong(offset);
        if (value < 0) {
            throw new IllegalArgumentException("ELF value exceeds signed 64-bit range");
        }
        return value;
    }

    private void requireRange(long offset, long size, String description) {
        if (offset < 0 || size < 0 || offset > fileSize || size > fileSize - offset) {
            throw new IllegalArgumentException("invalid " + description + " range");
        }
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
