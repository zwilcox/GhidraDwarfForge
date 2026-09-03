package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
    private static final long SHT_NOTE = 7;
    private static final long SHF_ALLOC = 0x2;
    private static final long PT_NOTE = 4;
    private static final int SHN_LORESERVE = 0xff00;

    public void write(Path input, Path output, Map<String, byte[]> debugSections)
            throws IOException {
        if (input.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException("sidecar output must differ from input");
        }
        if (debugSections.isEmpty()) {
            throw new IllegalArgumentException("at least one debug section is required");
        }
        for (Map.Entry<String, byte[]> entry : debugSections.entrySet()) {
            if (!entry.getKey().startsWith(".debug_") || entry.getValue() == null) {
                throw new IllegalArgumentException("invalid debug section " + entry.getKey());
            }
        }

        ElfImage image = ElfImage.read(input);
        byte[] result = build(image, debugSections);
        Path parent = output.toAbsolutePath().normalize().getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("sidecar output directory does not exist: " + parent);
        }
        Path temporary = Files.createTempFile(parent, ".ghidra-dwarf-forge-", ".tmp");
        boolean moved = false;
        try {
            Files.write(temporary, result);
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE,
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

    private byte[] build(ElfImage image, Map<String, byte[]> debugSections) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(image.bytes());
        List<Section> sections = new ArrayList<>();
        if (image.sections().isEmpty()) {
            Section nullSection = new Section();
            nullSection.type = SHT_NULL;
            sections.add(nullSection);
            addIdentityNoteSections(image, sections);
        }
        else {
            for (Section section : image.sections()) {
                Section copy = section.copy();
                if (section.originalIndex == image.sectionNameIndex()) {
                    copy.name = ".shstrtab.old";
                }
                else if ((copy.name.startsWith(".debug_") ||
                        copy.name.startsWith(".rel.debug_") ||
                        copy.name.startsWith(".rela.debug_")) &&
                        !debugSections.containsKey(copy.name)) {
                    copy.name = ".forge.stale" + copy.name;
                }
                sections.add(copy);
            }
        }

        for (Map.Entry<String, byte[]> entry : debugSections.entrySet()) {
            align(output, 1);
            long dataOffset = output.size();
            output.writeBytes(entry.getValue());
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
        if (sections.size() >= SHN_LORESERVE) {
            throw new IllegalArgumentException("extended ELF section numbering not supported yet");
        }

        ByteArrayOutputStream names = new ByteArrayOutputStream();
        names.write(0);
        Map<String, Integer> nameOffsets = new LinkedHashMap<>();
        nameOffsets.put("", 0);
        for (Section section : sections) {
            section.nameOffset = nameOffsets.computeIfAbsent(section.name, name -> {
                int offset = names.size();
                names.writeBytes(name.getBytes(StandardCharsets.UTF_8));
                names.write(0);
                return offset;
            });
        }
        newNameTable.offset = output.size();
        newNameTable.size = names.size();
        output.writeBytes(names.toByteArray());

        int sectionAlignment = image.is64Bit() ? 8 : 4;
        align(output, sectionAlignment);
        long sectionTableOffset = output.size();
        for (Section section : sections) {
            output.writeBytes(serializeSection(section, image.is64Bit(), image.byteOrder()));
        }

        byte[] result = output.toByteArray();
        ByteBuffer header = ByteBuffer.wrap(result).order(image.byteOrder());
        int entrySize = image.is64Bit() ? 64 : 40;
        if (image.is64Bit()) {
            header.putLong(32, 0);
            header.putLong(40, sectionTableOffset);
            header.putShort(54, (short) 0);
            header.putShort(56, (short) 0);
            header.putShort(58, (short) entrySize);
            header.putShort(60, (short) sections.size());
            header.putShort(62, (short) (sections.size() - 1));
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
            header.putShort(48, (short) sections.size());
            header.putShort(50, (short) (sections.size() - 1));
        }
        return result;
    }

    private static void addIdentityNoteSections(ElfImage image, List<Section> sections) {
        int noteIndex = 0;
        for (Segment segment : image.segments()) {
            if (segment.type != PT_NOTE) {
                continue;
            }
            Section section = new Section();
            section.name = ".note.forge." + noteIndex++;
            section.type = SHT_NOTE;
            section.flags = SHF_ALLOC;
            section.address = segment.virtualAddress;
            section.offset = segment.offset;
            section.size = segment.fileSize;
            section.alignment = Math.max(1, segment.alignment);
            sections.add(section);
        }
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

    private static void align(ByteArrayOutputStream output, int alignment) {
        while ((output.size() % alignment) != 0) {
            output.write(0);
        }
    }
}
