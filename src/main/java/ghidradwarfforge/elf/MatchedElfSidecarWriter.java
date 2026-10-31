package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.CharBuffer;
import java.util.HashMap;
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
    private static final long SHF_ALLOC = 0x2;
    private static final long SHF_EXECINSTR = 0x4;
    private static final long PT_NOTE = 4;
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
            List<ElfLocalFunctionSymbol> symbols, BooleanSupplier cancelled) throws IOException {
        long offset = image.fileSize();
        List<Section> sections = new ArrayList<>();
        if (image.sections().isEmpty()) {
            Section nullSection = new Section();
            nullSection.type = SHT_NULL;
            sections.add(nullSection);
            for (var allocation : ElfLoadAllocations.read(image, cancelled)) {
                sections.add(allocation.section());
            }
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

    private static final int MAX_SYMBOLS = 262144;

    private record SymbolTableInput(Section table, Section strings, Section indices,
            int count, int locals, byte[] records, byte[] names, byte[] extended,
            Set<ByteBuffer> existingNames, boolean synthesized) {
    }

    private static long addFunctionSymbols(ElfImage image, List<Section> sections,
            List<ElfLocalFunctionSymbol> symbols, List<byte[]> payloads, long offset,
            BooleanSupplier cancelled) throws IOException {
        if (symbols.isEmpty()) {
            return offset;
        }
        if (symbols.size() > 65536) {
            throw new IllegalArgumentException("local function symbol count exceeds safety limit");
        }
        int width = image.is64Bit() ? 24 : 16;
        SymbolTableInput old = readSymbolTable(image, sections, width, cancelled);
        int oldCount = old == null ? 1 : old.count();
        int oldLocals = old == null ? 1 : old.locals();
        int count = Math.addExact(oldCount, symbols.size());
        if (count > MAX_SYMBOLS) {
            throw new IllegalArgumentException("merged symbol count exceeds safety limit");
        }
        ByteBuffer table = ByteBuffer.allocate(Math.multiplyExact(count, width)).order(image.byteOrder());
        ByteBuffer indices = ByteBuffer.allocate(Math.multiplyExact(count, 4)).order(image.byteOrder());
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        if (old == null) {
            strings.write(0);
        }
        else {
            strings.writeBytes(old.names());
            // Insert new locals before the first original nonlocal. Every original
            // record and its string offset stays byte-for-byte intact. Dependent
            // symbol-index sections must be retired or explicitly handled below.
            int split = oldLocals * width;
            table.put(0, old.records(), 0, split);
            table.put((oldLocals + symbols.size()) * width, old.records(), split,
                old.records().length - split);
            if (old.extended() != null) {
                int indexSplit = oldLocals * 4;
                indices.put(0, old.extended(), 0, indexSplit);
                indices.put((oldLocals + symbols.size()) * 4, old.extended(), indexSplit,
                    old.extended().length - indexSplit);
            }
        }
        Set<String> names = new HashSet<>();
        boolean extended = old != null && old.extended() != null;
        for (int index = 0; index < symbols.size(); index++) {
            checkCancelled(cancelled);
            ElfLocalFunctionSymbol symbol = symbols.get(index);
            if (symbol.sectionIndex() >= sections.size() ||
                    (sections.get(symbol.sectionIndex()).flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
                        (SHF_ALLOC | SHF_EXECINSTR) || !names.add(symbol.name())) {
                throw new IllegalArgumentException("invalid or duplicate planned local function symbol");
            }
            byte[] name;
            try {
                ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(symbol.name()));
                name = new byte[encoded.remaining()];
                encoded.get(name);
            }
            catch (CharacterCodingException invalid) {
                throw new IllegalArgumentException("local symbol name is not valid Unicode", invalid);
            }
            if (name.length > ElfImage.MAX_NAME_BYTES ||
                    (long) strings.size() + name.length + 1 > ElfImage.MAX_NAME_TABLE_BYTES) {
                throw new IllegalArgumentException("local symbol names exceed safety limit");
            }
            if (old != null && old.existingNames().contains(ByteBuffer.wrap(name))) {
                throw new IllegalArgumentException("local symbol name conflicts with existing symbol: " + symbol.name());
            }
            int nameOffset = strings.size();
            strings.writeBytes(name);
            strings.write(0);
            boolean escaped = symbol.sectionIndex() >= SHN_LORESERVE;
            int encoded = escaped ? SHN_XINDEX : symbol.sectionIndex();
            extended |= escaped;
            indices.putInt((oldLocals + index) * 4, escaped ? symbol.sectionIndex() : 0);
            table.position((oldLocals + index) * width);
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
        Section namesSection = old == null || old.synthesized() ? new Section() : old.strings();
        if (old == null || old.synthesized()) {
            namesSection.name = ".strtab";
            namesSection.type = SHT_STRTAB;
            namesSection.alignment = 1;
            sections.add(namesSection);
        }
        // Nonallocated string data needs only byte alignment in the new layout.
        namesSection.alignment = 1;
        namesSection.offset = offset;
        namesSection.size = strings.size();
        int namesIndex = sections.indexOf(namesSection);
        payloads.add(strings.toByteArray());
        offset = addOffset(offset, namesSection.size);

        int alignment = image.is64Bit() ? 8 : 4;
        int padding = (int) ((alignment - offset % alignment) % alignment);
        payloads.add(new byte[padding]);
        offset = addOffset(offset, padding);
        Section tableSection = old == null || old.synthesized() ? new Section() : old.table();
        if (old == null || old.synthesized()) {
            tableSection.name = ".symtab";
            tableSection.type = SHT_SYMTAB;
            sections.add(tableSection);
        }
        tableSection.offset = offset;
        tableSection.size = table.capacity();
        tableSection.link = namesIndex;
        tableSection.info = oldLocals + symbols.size();
        tableSection.alignment = alignment;
        tableSection.entrySize = width;
        int tableIndex = sections.indexOf(tableSection);
        payloads.add(table.array());
        offset = addOffset(offset, table.capacity());
        if (extended) {
            Section extendedSection = old == null || old.synthesized() ? null : old.indices();
            if (extendedSection == null) {
                if (sections.stream().anyMatch(section -> section.name.equals(".symtab_shndx"))) {
                    throw new IllegalArgumentException("extended symbol-index section name conflict");
                }
                extendedSection = new Section();
                extendedSection.name = ".symtab_shndx";
                extendedSection.type = SHT_SYMTAB_SHNDX;
                sections.add(extendedSection);
            }
            extendedSection.offset = offset;
            extendedSection.size = indices.capacity();
            extendedSection.link = tableIndex;
            extendedSection.alignment = 4;
            extendedSection.entrySize = 4;
            payloads.add(indices.array());
            offset = addOffset(offset, indices.capacity());
        }
        return offset;
    }

    /** Read only the symbol metadata needed for a lossless local insertion. */
    private static SymbolTableInput readSymbolTable(ElfImage image, List<Section> sections,
            int width, BooleanSupplier cancelled) throws IOException {
        Section table = null;
        for (Section section : sections) {
            checkCancelled(cancelled);
            if (section.type == SHT_SYMTAB) {
                if (table != null) {
                    throw new IllegalArgumentException("multiple static symbol tables cannot be merged");
                }
                table = section;
            }
        }
        if (table == null) {
            for (Section section : sections) {
                if (section.name.equals(".symtab") || section.name.equals(".strtab") ||
                        section.name.equals(".symtab_shndx")) {
                    throw new IllegalArgumentException("local function symbols conflict with existing sections");
                }
            }
            DynamicSymbolMirror.Snapshot mirror = DynamicSymbolMirror.read(image, cancelled);
            if (mirror == null) {
                return null;
            }
            return new SymbolTableInput(null, null, null, mirror.records().length / width,
                mirror.locals(), mirror.records(), mirror.names(), mirror.indices(),
                mirror.existingNames(), true);
        }
        int tableIndex = sections.indexOf(table);
        if (table.entrySize != width || table.size < width || table.size % width != 0 ||
                table.size / width > MAX_SYMBOLS || table.info < 1 || table.info > table.size / width ||
                table.flags != 0 || table.address != 0 || table.link <= 0 || table.link >= image.sections().size()) {
            throw new IllegalArgumentException("unsupported static symbol table metadata");
        }
        Section strings = sections.get((int) table.link);
        if (strings.type != SHT_STRTAB || strings.flags != 0 || strings.address != 0 ||
                strings.size < 1 || strings.size > ElfImage.MAX_NAME_TABLE_BYTES ||
                strings.offset != image.sections().get((int) table.link).offset) {
            throw new IllegalArgumentException("unsupported static symbol string table");
        }
        int count = (int) (table.size / width);
        Section indices = null;
        for (Section section : sections) {
            checkCancelled(cancelled);
            if (section.link != tableIndex) {
                continue;
            }
            if (section.type != SHT_SYMTAB_SHNDX || indices != null || section.flags != 0 ||
                    section.address != 0 || section.entrySize != 4 || section.info != 0 || section.size != count * 4L) {
                throw new IllegalArgumentException("unsupported dependent symbol-index section: " + section.name);
            }
            indices = section;
        }
        byte[] records = image.sectionData(table);
        byte[] names = image.sectionData(strings);
        byte[] extended = indices == null ? null : image.sectionData(indices);
        ByteBuffer values = ByteBuffer.wrap(records).order(image.byteOrder());
        ByteBuffer extra = extended == null ? null : ByteBuffer.wrap(extended).order(image.byteOrder());
        if (names[0] != 0 || names[names.length - 1] != 0) {
            throw new IllegalArgumentException("static symbol strings lack boundary terminators");
        }
        for (int i = 0; i < width; i++) {
            if (records[i] != 0) {
                throw new IllegalArgumentException("static null symbol is not zero");
            }
        }
        Map<Integer, ByteBuffer> decoded = new HashMap<>();
        Set<ByteBuffer> existingNames = new HashSet<>();
        long nameBytes = 0;
        for (int index = 0; index < count; index++) {
            checkCancelled(cancelled);
            int record = index * width;
            long name = Integer.toUnsignedLong(values.getInt(record));
            int info = Byte.toUnsignedInt(records[record + (image.is64Bit() ? 4 : 12)]);
            int section = Short.toUnsignedInt(values.getShort(record + (image.is64Bit() ? 6 : 14)));
            if (((info >>> 4) == 0) != (index < table.info) || name >= names.length ||
                    (section < SHN_LORESERVE && section >= image.sections().size())) {
                throw new IllegalArgumentException("invalid static symbol name, binding order or section");
            }
            long extendedIndex = extra == null ? 0 : Integer.toUnsignedLong(extra.getInt(index * 4));
            if (section == SHN_XINDEX ? extra == null || extendedIndex == 0 || extendedIndex >= image.sections().size()
                    : extendedIndex != 0) {
                throw new IllegalArgumentException("invalid extended static symbol index");
            }
            int nameIndex = (int) name;
            ByteBuffer key = decoded.get(nameIndex);
            if (key == null) {
                int end = nameIndex;
                while (end < names.length && names[end] != 0 && end - nameIndex <= ElfImage.MAX_NAME_BYTES) {
                    if ((end & 1023) == 0) {
                        checkCancelled(cancelled);
                    }
                    end++;
                }
                if (end == names.length || end - nameIndex > ElfImage.MAX_NAME_BYTES ||
                        (nameBytes += end - nameIndex) > ElfImage.MAX_NAME_TABLE_BYTES) {
                    throw new IllegalArgumentException("static symbol names exceed supported bounds");
                }
                // ELF names are bytes, not necessarily UTF-8. Compare exact bytes
                // without replacing malformed sequences or claiming a source encoding.
                key = ByteBuffer.wrap(names, nameIndex, end - nameIndex).asReadOnlyBuffer();
                decoded.put(nameIndex, key);
                existingNames.add(key);
            }
        }
        return new SymbolTableInput(table, strings, indices, count, (int) table.info,
            records, names, extended, existingNames, false);
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
