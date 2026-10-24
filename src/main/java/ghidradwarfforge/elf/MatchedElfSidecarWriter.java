package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ElfImage.Section;
import ghidradwarfforge.elf.ElfImage.Segment;

/**
 * Creates a matched, non-loadable sidecar while leaving the original ELF unchanged.
 * Target identity and note data are retained, but the sidecar has no program
 * headers; GDB obtains runtime mappings from the original executable.
 */
public final class MatchedElfSidecarWriter {
    private static final long SHT_NULL = 0;
    private static final long SHT_PROGBITS = 1;
    private static final long SHT_STRTAB = 3;
    private static final long SHT_RELA = 4;
    private static final long SHT_NOTE = 7;
    private static final long SHT_NOBITS = 8;
    private static final long SHT_REL = 9;
    private static final long SHF_ALLOC = 0x2;
    private static final long PT_NOTE = 4;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int SHN_XINDEX = 0xffff;

    private record Layout(List<Section> sections, byte[] names, byte[] header,
            long sectionTableOffset, long fileSize) {
    }

    public void write(Path input, Path output, Map<String, byte[]> debugSections)
            throws IOException {
        write(input, output, debugSections, () -> false);
    }

    public void write(Path input, Path output, Map<String, byte[]> debugSections,
            BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        Path original = input.toRealPath();
        Path absoluteOutput = output.toAbsolutePath();
        Path parent = absoluteOutput.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("sidecar output directory does not exist: " + parent);
        }
        parent = parent.toRealPath();
        Path destinationPath = parent.resolve(absoluteOutput.getFileName());
        if (original.equals(destinationPath) ||
                (Files.exists(destinationPath) && Files.isSameFile(original, destinationPath))) {
            throw new IllegalArgumentException("sidecar output must differ from input");
        }
        if (debugSections.isEmpty()) {
            throw new IllegalArgumentException("at least one debug section is required");
        }
        for (Map.Entry<String, byte[]> entry : debugSections.entrySet()) {
            if (entry.getKey() == null || !entry.getKey().startsWith(".debug_") ||
                    entry.getKey().indexOf('\0') >= 0 || entry.getValue() == null) {
                throw new IllegalArgumentException("invalid debug section " + entry.getKey());
            }
        }

        ElfImage image = ElfImage.read(original);
        Layout layout = prepare(image, debugSections);
        Path temporary = Files.createTempFile(parent, ".ghidra-dwarf-forge-", ".tmp");
        boolean moved = false;
        try {
            try (FileChannel destination = FileChannel.open(temporary,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                image.copyTo(destination, cancelled);
                if (destination.position() != image.fileSize()) {
                    throw new IOException("original ELF copy has an unexpected size");
                }
                for (byte[] bytes : debugSections.values()) {
                    writeBytes(destination, bytes, cancelled);
                }
                writeBytes(destination, layout.names(), cancelled);
                int padding = Math.toIntExact(layout.sectionTableOffset() -
                    destination.position());
                writeBytes(destination, new byte[padding], cancelled);
                for (Section section : layout.sections()) {
                    writeBytes(destination,
                        serializeSection(section, image.is64Bit(), image.byteOrder()), cancelled);
                }
                if (destination.position() != layout.fileSize()) {
                    throw new IOException("sidecar has an unexpected size");
                }
                destination.position(0);
                writeBytes(destination, layout.header(), cancelled);
            }
            checkCancelled(cancelled);
            try {
                Files.move(temporary, destinationPath, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException unsupported) {
                throw new IOException("output filesystem does not support atomic replacement",
                    unsupported);
            }
            moved = true;
        }
        finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    /** Plan and validate the append-only layout before copying any input bytes. */
    private Layout prepare(ElfImage image, Map<String, byte[]> debugSections) {
        long offset = image.fileSize();
        List<Section> sections = new ArrayList<>();
        if (image.sections().isEmpty()) {
            Section nullSection = new Section();
            nullSection.type = SHT_NULL;
            sections.add(nullSection);
        }
        else {
            Set<String> replacementNames = new HashSet<>();
            for (Section section : image.sections()) {
                Section copy = section.copy();
                if (section.originalIndex == 0) {
                    // Section zero belongs to the output header's numbering
                    // scheme, not the input's section/program-header counts.
                    copy = new Section();
                    copy.type = SHT_NULL;
                }
                else if (copy.type == SHT_REL || copy.type == SHT_RELA) {
                    omitRelocationSection(copy);
                }
                else if (section.originalIndex == image.sectionNameIndex()) {
                    copy.name = ".shstrtab.old";
                }
                else if (isInheritedDebugMetadata(copy.name) &&
                        (!debugSections.containsKey(copy.name) ||
                            !replacementNames.add(copy.name))) {
                    copy.name = ".forge.stale" + copy.name;
                }
                sections.add(copy);
            }
        }
        addIdentityNoteSections(image, sections);

        for (Map.Entry<String, byte[]> entry : debugSections.entrySet()) {
            long dataOffset = offset;
            offset = addOffset(offset, entry.getValue().length);
            Section target = findSection(sections, entry.getKey());
            if (target == null) {
                target = new Section();
                target.name = entry.getKey();
                sections.add(target);
            }
            target.type = SHT_PROGBITS;
            target.flags = 0;
            target.address = 0;
            target.offset = dataOffset;
            target.size = entry.getValue().length;
            target.link = 0;
            target.info = 0;
            target.alignment = 1;
            target.entrySize = 0;
        }

        Section newNameTable = new Section();
        newNameTable.name = ".shstrtab";
        newNameTable.type = SHT_STRTAB;
        newNameTable.alignment = 1;
        sections.add(newNameTable);
        int sectionCount = sections.size();
        if (sectionCount > ElfImage.MAX_HEADER_COUNT) {
            throw new IllegalArgumentException("sidecar section count exceeds supported limit " +
                ElfImage.MAX_HEADER_COUNT);
        }
        int nameTableIndex = sectionCount - 1;
        int encodedSectionCount = sectionCount >= SHN_LORESERVE ? 0 : sectionCount;
        int encodedNameTableIndex = nameTableIndex >= SHN_LORESERVE
                ? SHN_XINDEX : nameTableIndex;
        Section sectionZero = sections.get(0);
        sectionZero.size = encodedSectionCount == 0 ? sectionCount : 0;
        sectionZero.link = encodedNameTableIndex == SHN_XINDEX ? nameTableIndex : 0;

        ByteArrayOutputStream names = new ByteArrayOutputStream();
        names.write(0);
        Map<String, Integer> nameOffsets = new LinkedHashMap<>();
        nameOffsets.put("", 0);
        for (Section section : sections) {
            section.nameOffset = nameOffsets.computeIfAbsent(section.name, name -> {
                byte[] encoded = name.getBytes(StandardCharsets.UTF_8);
                if (encoded.length > ElfImage.MAX_NAME_BYTES ||
                        (long) names.size() + encoded.length + 1 > ElfImage.MAX_NAME_TABLE_BYTES) {
                    throw new IllegalArgumentException("sidecar section names exceed supported limit");
                }
                int nameOffset = names.size();
                names.writeBytes(encoded);
                names.write(0);
                return nameOffset;
            });
        }
        newNameTable.offset = offset;
        newNameTable.size = names.size();
        offset = addOffset(offset, names.size());

        int sectionAlignment = image.is64Bit() ? 8 : 4;
        long sectionTableOffset = addOffset(offset, sectionAlignment - 1) & -sectionAlignment;
        int entrySize = image.is64Bit() ? 64 : 40;
        long fileSize = addOffset(sectionTableOffset, (long) sections.size() * entrySize);
        if (!image.is64Bit() && fileSize > 0x1_0000_0000L) {
            throw new IllegalArgumentException("ELF32 output exceeds 32-bit file-offset range");
        }
        for (Section section : sections) {
            // Reject unrepresentable fields before spending time copying a large file.
            serializeSection(section, image.is64Bit(), image.byteOrder());
        }

        byte[] headerBytes = image.headerBytes();
        ByteBuffer header = ByteBuffer.wrap(headerBytes).order(image.byteOrder());
        if (image.is64Bit()) {
            header.putLong(32, 0);
            header.putLong(40, sectionTableOffset);
            header.putShort(54, (short) 0);
            header.putShort(56, (short) 0);
            header.putShort(58, (short) entrySize);
            header.putShort(60, (short) encodedSectionCount);
            header.putShort(62, (short) encodedNameTableIndex);
        }
        else {
            if (sectionTableOffset > 0xffff_ffffL) {
                throw new IllegalArgumentException("ELF32 section table offset exceeds 32 bits");
            }
            header.putInt(28, 0);
            header.putInt(32, (int) sectionTableOffset);
            header.putShort(42, (short) 0);
            header.putShort(44, (short) 0);
            header.putShort(46, (short) entrySize);
            header.putShort(48, (short) encodedSectionCount);
            header.putShort(50, (short) encodedNameTableIndex);
        }
        return new Layout(sections, names.toByteArray(), headerBytes, sectionTableOffset,
            fileSize);
    }

    private static boolean isInheritedDebugMetadata(String name) {
        // The current export replaces the original debug view. Old indexes,
        // compressed DWARF, and separate-debug references must not remain active
        // alongside the newly generated sections. Their bytes are still retained.
        return name.startsWith(".debug_") || name.startsWith(".zdebug_") ||
            name.startsWith(".rel.debug_") || name.startsWith(".rela.debug_") ||
            name.equals(".gdb_index") || name.equals(".gnu_debuglink") ||
            name.equals(".gnu_debugaltlink") || name.equals(".gnu_debugdata");
    }

    private static void omitRelocationSection(Section section) {
        if (!section.name.isEmpty()) {
            section.name = ".forge.omitted" + section.name;
        }
        section.type = SHT_NOBITS;
        section.flags = 0;
        section.address = 0;
        section.offset = 0;
        section.size = 0;
        section.link = 0;
        section.info = 0;
        section.alignment = 1;
        section.entrySize = 0;
    }

    private static void addIdentityNoteSections(ElfImage image, List<Section> sections) {
        TreeMap<Long, Long> covered = new TreeMap<>();
        for (Section section : sections) {
            if (section.type == SHT_NOTE && section.size != 0) {
                coverNoteRange(covered, section.offset, addOffset(section.offset, section.size));
            }
        }
        int noteIndex = 0;
        for (Segment segment : image.segments()) {
            if (segment.type != PT_NOTE || segment.fileSize == 0) {
                continue;
            }
            long end = addOffset(segment.offset, segment.fileSize);
            long offset = segment.offset;
            while (offset < end) {
                Map.Entry<Long, Long> existing = covered.floorEntry(offset);
                if (existing != null && existing.getValue() > offset) {
                    offset = Math.min(end, existing.getValue());
                    continue;
                }
                Map.Entry<Long, Long> next = covered.ceilingEntry(offset);
                long uncoveredEnd = next == null ? end : Math.min(end, next.getKey());
                long alignment = Math.max(1, segment.alignment);
                // Existing typed sections establish complete-note boundaries.
                // Do not reinterpret a short gap or a boundary that conflicts
                // with the segment's note alignment as a new note payload.
                if (uncoveredEnd - offset < 12 || (offset - segment.offset) % alignment != 0) {
                    throw new IllegalArgumentException(
                        "unsupported partial PT_NOTE coverage: no aligned complete-note range");
                }
                Section section = new Section();
                section.name = ".note.forge." + noteIndex++;
                section.type = SHT_NOTE;
                section.flags = SHF_ALLOC;
                section.address = addOffset(segment.virtualAddress, offset - segment.offset);
                section.offset = offset;
                section.size = uncoveredEnd - offset;
                section.alignment = alignment;
                sections.add(section);
                coverNoteRange(covered, offset, uncoveredEnd);
                offset = uncoveredEnd;
            }
        }
    }

    private static void coverNoteRange(TreeMap<Long, Long> covered, long start, long end) {
        Map.Entry<Long, Long> previous = covered.floorEntry(start);
        if (previous != null && previous.getValue() >= start) {
            start = previous.getKey();
            end = Math.max(end, previous.getValue());
            covered.remove(previous.getKey());
        }
        Map.Entry<Long, Long> next = covered.ceilingEntry(start);
        while (next != null && next.getKey() <= end) {
            end = Math.max(end, next.getValue());
            covered.remove(next.getKey());
            next = covered.ceilingEntry(start);
        }
        covered.put(start, end);
    }

    private static Section findSection(List<Section> sections, String name) {
        for (Section section : sections) {
            if (name.equals(section.name)) {
                return section;
            }
        }
        return null;
    }

    private static byte[] serializeSection(Section section, boolean elf64,
            ByteOrder byteOrder) {
        ByteBuffer result = ByteBuffer.allocate(elf64 ? 64 : 40).order(byteOrder);
        putUnsignedInt(result, section.nameOffset);
        putUnsignedInt(result, section.type);
        if (elf64) {
            result.putLong(section.flags);
            result.putLong(section.address);
            result.putLong(section.offset);
            result.putLong(section.size);
            putUnsignedInt(result, section.link);
            putUnsignedInt(result, section.info);
            result.putLong(section.alignment);
            result.putLong(section.entrySize);
        }
        else {
            putUnsignedInt(result, section.flags);
            putUnsignedInt(result, section.address);
            putUnsignedInt(result, section.offset);
            putUnsignedInt(result, section.size);
            putUnsignedInt(result, section.link);
            putUnsignedInt(result, section.info);
            putUnsignedInt(result, section.alignment);
            putUnsignedInt(result, section.entrySize);
        }
        return result.array();
    }

    private static void putUnsignedInt(ByteBuffer buffer, long value) {
        if (value < 0 || value > 0xffff_ffffL) {
            throw new IllegalArgumentException("ELF32 field out of range: " + value);
        }
        buffer.putInt((int) value);
    }

    private static long addOffset(long offset, long size) {
        try {
            return Math.addExact(offset, size);
        }
        catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("sidecar exceeds supported signed 64-bit size", overflow);
        }
    }

    private static void writeBytes(FileChannel destination, byte[] bytes,
            BooleanSupplier cancelled) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            checkCancelled(cancelled);
            int limit = buffer.limit();
            buffer.limit(buffer.position() + Math.min(buffer.remaining(), 1024 * 1024));
            if (destination.write(buffer) <= 0) {
                throw new IOException("sidecar write made no progress");
            }
            buffer.limit(limit);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("ELF sidecar publication cancelled");
        }
    }
}
