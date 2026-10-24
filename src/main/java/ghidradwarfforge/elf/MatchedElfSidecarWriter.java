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
    private static final long SHT_SYMTAB = 2;
    private static final long SHT_STRTAB = 3;
    private static final long SHT_RELA = 4;
    private static final long SHT_NOTE = 7;
    private static final long SHT_NOBITS = 8;
    private static final long SHT_REL = 9;
    private static final long SHT_SYMTAB_SHNDX = 18;
    private static final long SHF_WRITE = 0x1;
    private static final long SHF_ALLOC = 0x2;
    private static final long SHF_EXECINSTR = 0x4;
    private static final long PT_LOAD = 1;
    private static final long PT_NOTE = 4;
    private static final long PF_X = 0x1;
    private static final long PF_W = 0x2;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int SHN_XINDEX = 0xffff;

    private record Layout(List<Section> sections, List<byte[]> symbolPayloads,
            byte[] names, byte[] header,
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
        write(ElfImage.read(input), output, debugSections, List.of(), cancelled);
    }

    /** Serialize target-planned local symbols against the same image used for planning. */
    public void write(ElfImage image, Path output, Map<String, byte[]> debugSections,
            List<ElfLocalFunctionSymbol> symbols, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(cancelled, "cancelled");
        symbols = List.copyOf(symbols);
        checkCancelled(cancelled);
        Path original = image.sourcePath();
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

        Layout layout = prepare(image, debugSections, symbols, cancelled);
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
                for (byte[] bytes : layout.symbolPayloads()) {
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
    private Layout prepare(ElfImage image, Map<String, byte[]> debugSections,
            List<ElfLocalFunctionSymbol> symbols, BooleanSupplier cancelled) {
        long offset = image.fileSize();
        List<Section> sections = new ArrayList<>();
        if (image.sections().isEmpty()) {
            Section nullSection = new Section();
            nullSection.type = SHT_NULL;
            sections.add(nullSection);
            addLoadRangeSections(image, sections);
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

        List<byte[]> symbolPayloads = new ArrayList<>();
        offset = addFunctionSymbols(image, sections, symbols, symbolPayloads, offset, cancelled);

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
        return new Layout(sections, List.copyOf(symbolPayloads), names.toByteArray(),
            headerBytes, sectionTableOffset,
            fileSize);
    }

    private static long addFunctionSymbols(ElfImage image, List<Section> sections,
            List<ElfLocalFunctionSymbol> symbols, List<byte[]> payloads, long offset,
            BooleanSupplier cancelled) {
        if (symbols.isEmpty()) {
            return offset;
        }
        if (symbols.size() > 65536) {
            throw new IllegalArgumentException("local function symbol count exceeds safety limit");
        }
        for (Section section : sections) {
            checkCancelled(cancelled);
            if (section.type == SHT_SYMTAB || section.name.equals(".symtab") ||
                    section.name.equals(".strtab") || section.name.equals(".symtab_shndx")) {
                throw new IllegalArgumentException("local function symbols conflict with existing sections");
            }
        }
        int count = symbols.size() + 1;
        int width = image.is64Bit() ? 24 : 16;
        ByteBuffer table = ByteBuffer.allocate(Math.multiplyExact(count, width)).order(image.byteOrder());
        ByteBuffer indices = ByteBuffer.allocate(Math.multiplyExact(count, 4)).order(image.byteOrder());
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        strings.write(0);
        Set<String> names = new HashSet<>();
        boolean extended = false;
        for (int index = 0; index < symbols.size(); index++) {
            checkCancelled(cancelled);
            ElfLocalFunctionSymbol symbol = symbols.get(index);
            if (symbol.sectionIndex() >= sections.size() ||
                    (sections.get(symbol.sectionIndex()).flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
                        (SHF_ALLOC | SHF_EXECINSTR) || !names.add(symbol.name())) {
                throw new IllegalArgumentException("invalid or duplicate planned local function symbol");
            }
            byte[] name = symbol.name().getBytes(StandardCharsets.UTF_8);
            if (name.length > ElfImage.MAX_NAME_BYTES ||
                    (long) strings.size() + name.length + 1 > ElfImage.MAX_NAME_TABLE_BYTES) {
                throw new IllegalArgumentException("local symbol names exceed safety limit");
            }
            int nameOffset = strings.size();
            strings.writeBytes(name);
            strings.write(0);
            boolean escaped = symbol.sectionIndex() >= SHN_LORESERVE;
            int encoded = escaped ? SHN_XINDEX : symbol.sectionIndex();
            extended |= escaped;
            indices.putInt((index + 1) * 4, escaped ? symbol.sectionIndex() : 0);
            table.position((index + 1) * width);
            putUnsignedInt(table, nameOffset);
            if (image.is64Bit()) {
                table.put((byte) 2); // STB_LOCAL | STT_FUNC; no original linkage assertion.
                table.put((byte) 0);
                table.putShort((short) encoded);
                table.putLong(symbol.value());
                table.putLong(symbol.size());
            }
            else {
                putUnsignedInt(table, symbol.value());
                putUnsignedInt(table, symbol.size());
                table.put((byte) 2);
                table.put((byte) 0);
                table.putShort((short) encoded);
            }
        }
        Section namesSection = new Section();
        namesSection.name = ".strtab";
        namesSection.type = SHT_STRTAB;
        namesSection.alignment = 1;
        namesSection.offset = offset;
        namesSection.size = strings.size();
        int namesIndex = sections.size();
        sections.add(namesSection);
        payloads.add(strings.toByteArray());
        offset = addOffset(offset, namesSection.size);

        int alignment = image.is64Bit() ? 8 : 4;
        int padding = (int) ((alignment - offset % alignment) % alignment);
        payloads.add(new byte[padding]);
        offset = addOffset(offset, padding);
        Section tableSection = new Section();
        tableSection.name = ".symtab";
        tableSection.type = SHT_SYMTAB;
        tableSection.offset = offset;
        tableSection.size = table.capacity();
        tableSection.link = namesIndex;
        tableSection.info = count;
        tableSection.alignment = alignment;
        tableSection.entrySize = width;
        int tableIndex = sections.size();
        sections.add(tableSection);
        payloads.add(table.array());
        offset = addOffset(offset, table.capacity());
        if (extended) {
            Section extendedSection = new Section();
            extendedSection.name = ".symtab_shndx";
            extendedSection.type = SHT_SYMTAB_SHNDX;
            extendedSection.offset = offset;
            extendedSection.size = indices.capacity();
            extendedSection.link = tableIndex;
            extendedSection.alignment = 4;
            extendedSection.entrySize = 4;
            sections.add(extendedSection);
            payloads.add(indices.array());
            offset = addOffset(offset, indices.capacity());
        }
        return offset;
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

    /** Preserve known allocation extents when no original section table exists. */
    private static void addLoadRangeSections(ElfImage image, List<Section> sections) {
        for (int index = 0; index < image.segments().size(); index++) {
            Segment segment = image.segments().get(index);
            if (segment.type != PT_LOAD || segment.memorySize == 0) {
                continue;
            }
            long end;
            try {
                end = Math.addExact(segment.virtualAddress, segment.memorySize);
            }
            catch (ArithmeticException overflow) {
                throw new IllegalArgumentException(
                    "PT_LOAD virtual range exceeds supported signed 64-bit addresses at " + index,
                    overflow);
            }
            if (!image.is64Bit() && end > 0x1_0000_0000L) {
                throw new IllegalArgumentException(
                    "PT_LOAD virtual range exceeds ELF32 address space at " + index);
            }
            Section section = new Section();
            // These are segment-derived allocation records, not recovered
            // original section names or contents. NOBITS keeps them inert.
            section.name = ".forge.load." + index;
            section.type = SHT_NOBITS;
            section.flags = SHF_ALLOC;
            if ((segment.flags & PF_W) != 0) {
                section.flags |= SHF_WRITE;
            }
            if ((segment.flags & PF_X) != 0) {
                section.flags |= SHF_EXECINSTR;
            }
            section.address = segment.virtualAddress;
            section.offset = segment.offset;
            section.size = segment.memorySize;
            // p_align constrains VA/file-offset congruence, not VA alignment.
            // For example, VA 0x403df8 may legitimately have p_align 0x1000.
            section.alignment = 1;
            sections.add(section);
        }
    }

    private static void omitRelocationSection(Section section) {
        if ((section.flags & SHF_ALLOC) != 0) {
            // GDB matches allocated sections by name/address when attaching a
            // separate debug file. Retire the relocation semantics, but keep
            // the original allocation extent as an inert NOBITS placeholder.
            section.flags = SHF_ALLOC;
        }
        else {
            if (!section.name.isEmpty()) {
                section.name = ".forge.omitted" + section.name;
            }
            section.flags = 0;
            section.address = 0;
            section.offset = 0;
            section.size = 0;
            section.alignment = 1;
        }
        section.type = SHT_NOBITS;
        section.link = 0;
        section.info = 0;
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
