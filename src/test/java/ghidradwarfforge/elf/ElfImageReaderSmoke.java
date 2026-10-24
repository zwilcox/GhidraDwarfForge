package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Independent ELF fixtures for file-backed metadata, overflow counts and limits. */
public final class ElfImageReaderSmoke {
    private static final byte[] NAMES = { 0, '.', 'p', 'a', 'y', 'l', 'o', 'a', 'd', 0,
        '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0 };
    private static final byte[] PAYLOAD = { 7, 6, 5, 4 };

    private ElfImageReaderSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path directory = Files.createTempDirectory("forge-elf-reader-");
        try {
            for (boolean elf64 : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Path input = directory.resolve((elf64 ? "elf64-" : "elf32-") + order);
                    checkBasic(input, elf64, order);
                    checkMalformed(input, elf64, order);
                    checkProgramCounts(input, elf64, order);
                    checkHighOffsets(input, elf64, order);
                    checkPartialNotes(input, elf64, order);
                }
            }
            checkLimits(directory.resolve("limits.elf"));
            checkChangedSource(directory.resolve("changed.elf"));
            checkSymlinkTraversal(directory.resolve("paths"));
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        System.out.println("elf-image-reader-smoke=PASS");
    }

    private static void checkBasic(Path input, boolean elf64, ByteOrder order) throws Exception {
        Fixture fixture = create(input, elf64, order, 2, 3, true, 0, 0, 0, NAMES.length);
        ElfImage image = ElfImage.read(input);
        require(image.is64Bit() == elf64 && image.byteOrder() == order, "wrong identity");
        require(image.fileSize() == Files.size(input), "wrong file size");
        require(image.preferredImageBase() == 0x401000, "wrong load base");
        require(image.sections().get(1).name().equals(".payload"), "wrong section name");
        require(Arrays.equals(image.sectionData(image.sections().get(1)), PAYLOAD), "wrong data");
        require(image.sectionData(image.sections().get(0)).length == 0, "NULL section has data");
        byte[] header = image.headerBytes();
        header[0] = 0;
        require(image.headerBytes()[0] == 0x7f, "header is mutable through accessor");
        byte[] original = Files.readAllBytes(input);
        require(Arrays.equals(original, image.bytes()), "bounded convenience bytes differ");
        Path copy = input.resolveSibling(input.getFileName() + ".copy");
        try (FileChannel output = FileChannel.open(copy, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            output.write(ByteBuffer.wrap(new byte[] { 42 }));
            image.copyTo(output);
            require(output.position() == original.length + 1L, "copy position differs");
            output.write(ByteBuffer.wrap(new byte[] { 43 }));
        }
        byte[] copied = Files.readAllBytes(copy);
        require(copied[0] == 42 && copied[copied.length - 1] == 43 &&
            Arrays.equals(original, Arrays.copyOfRange(copied, 1, copied.length - 1)),
            "copy did not preserve bytes or caller channel");
        Files.delete(copy);

        fixture.half(elf64 ? 62 : 50, 0);
        image = ElfImage.read(input);
        require(image.sectionNameIndex() == 0 && image.sections().size() == 3,
            "nameless table was treated as absent");
        require(image.sections().stream().allMatch(section -> section.name().isEmpty()),
            "missing names were invented");
        require(Arrays.equals(PAYLOAD, image.sectionData(image.sections().get(1))),
            "nameless payload lost");

        // NOBITS offsets/sizes do not describe a payload in the file.
        fixture.word(fixture.sectionOffset(1) + 4, 8);
        fixture.address(fixture.sectionOffset(1) + (elf64 ? 24 : 16), 0xfffffff0L);
        fixture.address(fixture.sectionOffset(1) + (elf64 ? 32 : 20), 0xfffffff0L);
        image = ElfImage.read(input);
        require(image.sectionData(image.sections().get(1)).length == 0, "NOBITS read data");

        fixture.address(elf64 ? 40 : 32, 0);
        fixture.half(elf64 ? 60 : 48, 0);
        require(ElfImage.read(input).sections().isEmpty(), "sectionless input rejected");
    }

    private static void checkMalformed(Path input, boolean elf64, ByteOrder order)
            throws Exception {
        Fixture fixture = create(input, elf64, order, 2, 3, true, 0, 0, 0, NAMES.length);
        byte[] valid = Files.readAllBytes(input);
        expectBadHeader(input, fixture, valid, 6, 1, 0, "version");
        expectBadHeader(input, fixture, valid, 20, 4, 0, "version");
        expectBadHeader(input, fixture, valid, elf64 ? 52 : 40, 2, 1, "header size");
        expectBadHeader(input, fixture, valid, elf64 ? 58 : 46, 2, 1, "section table");
        expectBadHeader(input, fixture, valid, elf64 ? 54 : 42, 2, 1, "program table");
        expectBadHeader(input, fixture, valid, elf64 ? 62 : 50, 2, 3, "name table index");
        expectBadHeader(input, fixture, valid, elf64 ? 62 : 50, 2, 0xff00, "name table index");
        expectBadHeader(input, fixture, valid, elf64 ? 60 : 48, 2, 0xff00, "section table");
        expectBadHeader(input, fixture, valid, fixture.sectionOffset(0), 4, 1, "section zero");
        expectBadHeader(input, fixture, valid, fixture.sectionOffset(0) + 4, 4, 1, "section zero");
        expectBadHeader(input, fixture, valid, fixture.sectionOffset(2) + 4, 4, 1, "SHT_STRTAB");
        expectBadHeader(input, fixture, valid, fixture.sectionOffset(1), 4, NAMES.length,
            "section-name offset");
        expectBadHeader(input, fixture, valid, fixture.names, 1, 'x', "begin and end");
        expectBadHeader(input, fixture, valid, fixture.names + NAMES.length - 1, 1, 'x',
            "begin and end");
        expectBadHeader(input, fixture, valid, fixture.sectionOffset(1) + (elf64 ? 24 : 16),
            elf64 ? 8 : 4, valid.length + 1L, "section 1 range");
        expectBadHeader(input, fixture, valid, fixture.programs + (elf64 ? 8 : 4),
            elf64 ? 8 : 4, valid.length + 1L, "program segment 0 range");
        expectBadHeader(input, fixture, valid, fixture.programs + (elf64 ? 40 : 20),
            elf64 ? 8 : 4, 0, "file size exceeds memory size");
        expectBadHeader(input, fixture, valid, elf64 ? 32 : 28, elf64 ? 8 : 4,
            valid.length - 1L, "program table range");
        expectBadHeader(input, fixture, valid, elf64 ? 40 : 32, elf64 ? 8 : 4,
            valid.length - 1L, "section header zero range");
        expectBadHeader(input, fixture, valid, elf64 ? 40 : 32, elf64 ? 8 : 4,
            0, "missing ELF section table");
        expectBadHeader(input, fixture, valid, elf64 ? 56 : 44, 2, 0,
            "program table offset has zero");
        if (elf64) {
            expectBadHeader(input, fixture, valid, 40, 8, -1, "signed 64-bit range");
            expectBadHeader(input, fixture, valid, 40, 8, Long.MAX_VALUE - 8,
                "section header zero range");
        }
        Files.write(input, Arrays.copyOf(valid, 15));
        expectFailure(() -> ElfImage.read(input), "ELF identification range");
        Files.write(input, Arrays.copyOf(valid, elf64 ? 63 : 51));
        expectFailure(() -> ElfImage.read(input), "ELF header range");
    }

    private static void checkProgramCounts(Path input, boolean elf64, ByteOrder order)
            throws Exception {
        for (int count : new int[] { 65534, 65535, 65537 }) {
            Fixture fixture = create(input, elf64, order, count, 1, false, 0, 0, 0, 0);
            ElfImage image = ElfImage.read(input);
            require(image.segments().size() == count, "extended program count truncated");
            require(image.preferredImageBase() == 0x401000, "late PT_LOAD was lost");
            ElfImage.Segment note = image.segments().get(count - 1);
            require(note.type == 4 && note.fileSize == 20 && note.offset == fixture.payload + 4,
                "late PT_NOTE metadata was lost");
            require(image.sectionData(image.sections().get(0)).length == 0,
                "section-zero metadata exposed as payload");
            if (count == 65537) {
                byte[] original = Files.readAllBytes(input);
                Path output = input.resolveSibling(input.getFileName() + ".dbg");
                new MatchedElfSidecarWriter().write(input, output,
                    Map.of(".debug_info", PAYLOAD));
                ElfImage sidecar = ElfImage.read(output);
                ElfImage.Section retainedNote = sidecar.sections().stream()
                    .filter(section -> section.name().startsWith(".note.forge."))
                    .findFirst().orElseThrow(() -> new AssertionError("late PT_NOTE was not retained"));
                require(Arrays.equals(Arrays.copyOfRange(original, (int) note.offset,
                    (int) (note.offset + note.fileSize)), sidecar.sectionData(retainedNote)),
                    "late identity note bytes changed");
                require(sidecar.segments().isEmpty() && sidecar.sections().get(0).info == 0,
                    "sidecar retained program-header metadata");
                require(Arrays.equals(original, Files.readAllBytes(input)),
                    "extended-program input changed");
                Files.delete(output);
                fixture.word(fixture.sections + (elf64 ? 44 : 28), 2);
                expectFailure(() -> ElfImage.read(input), "PN_XNUM");
            }
        }
        Fixture fixture = create(input, elf64, order, 2, 1, false, 0, 0, 0, 0);
        fixture.half(elf64 ? 56 : 44, 0xffff);
        fixture.address(elf64 ? 40 : 32, 0);
        fixture.half(elf64 ? 60 : 48, 0);
        expectFailure(() -> ElfImage.read(input), "PN_XNUM");
    }

    private static void checkHighOffsets(Path input, boolean elf64, ByteOrder order)
            throws Exception {
        Fixture fixture = create(input, elf64, order, 2, 3, true,
            0x80002000L, 0, 0, NAMES.length);
        ElfImage image = ElfImage.read(input);
        require(image.fileSize() > Integer.MAX_VALUE, "fixture is not larger than 2 GiB");
        require(image.sections().get(1).offset == fixture.payload &&
            image.segments().get(0).offset == fixture.payload, "high file offset truncated");
        require(Arrays.equals(PAYLOAD, image.sectionData(image.sections().get(1))),
            "high payload differs");
        expectFailure(image::bytes, "whole ELF byte-array read exceeds safety limit");
    }

    private static void checkPartialNotes(Path input, boolean elf64, ByteOrder order)
            throws Exception {
        Fixture fixture = create(input, elf64, order, 2, 3, true, 0, 0, 0, NAMES.length);
        long firstNote = fixture.payload + 4;
        long secondNote = firstNote + 20;
        ByteBuffer extra = ByteBuffer.allocate(20).order(order);
        extra.putInt(4).putInt(4).putInt(7).put(new byte[] { 'F', 'O', 'O', 0, 5, 6, 7, 8 });
        fixture.write(secondNote, extra.array());
        fixture.write(fixture.sectionOffset(1),
            section(elf64, order, 1, 7, firstNote, 20, 0, 0));
        fixture.write(fixture.programs + (elf64 ? 56 : 32),
            segment(elf64, order, 4, firstNote, 0x500000, 40));
        byte[] original = Files.readAllBytes(input);
        Path output = input.resolveSibling(input.getFileName() + ".notes.dbg");
        new MatchedElfSidecarWriter().write(input, output, Map.of(".debug_info", PAYLOAD));
        ElfImage result = ElfImage.read(output);
        List<ElfImage.Section> notes = result.sections().stream()
            .filter(section -> section.type == 7).toList();
        require(notes.size() == 2, "partial note coverage produced extra or missing sections");
        require(notes.get(0).originalIndex == 1 && notes.get(0).offset == firstNote &&
            notes.get(0).size == 20, "existing note identity/index changed");
        require(notes.get(1).offset == secondNote && notes.get(1).size == 20 &&
            notes.get(1).address == 0x500014,
            "reconstructed note overlaps the original or has the wrong address");
        require(Arrays.equals(Arrays.copyOfRange(original, (int) firstNote,
            (int) firstNote + 20), result.sectionData(notes.get(0))),
            "original build-ID note bytes changed");
        require(Arrays.equals(extra.array(), result.sectionData(notes.get(1))),
            "uncovered note bytes changed");
        require(Arrays.equals(original, Files.readAllBytes(input)), "partial-note input changed");
        Files.delete(output);
    }

    private static void checkLimits(Path input) throws Exception {
        Fixture fixture = create(input, true, ByteOrder.LITTLE_ENDIAN,
            ElfImage.MAX_HEADER_COUNT, 1, false, 0, 0, 0, 0);
        require(ElfImage.read(input).segments().size() == ElfImage.MAX_HEADER_COUNT,
            "maximum program count rejected");
        fixture.word(fixture.sections + 44, ElfImage.MAX_HEADER_COUNT + 1L);
        expectFailure(() -> ElfImage.read(input), "program header count");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2,
            ElfImage.MAX_HEADER_COUNT, false, 0, 0, 0, 0);
        require(ElfImage.read(input).sections().size() == ElfImage.MAX_HEADER_COUNT,
            "maximum section count rejected");
        expectWriterFailure(input, "sidecar section count exceeds supported limit");
        fixture.address(fixture.sections + 32, ElfImage.MAX_HEADER_COUNT + 1L);
        expectFailure(() -> ElfImage.read(input), "section header count");

        // One recovered note, one debug section and the new string table add
        // three entries. The exact output limit must remain readable.
        create(input, true, ByteOrder.LITTLE_ENDIAN, 2,
            ElfImage.MAX_HEADER_COUNT - 3, false, 0, 0, 0, 0);
        Path maximumOutput = input.resolveSibling("maximum-sections.dbg");
        new MatchedElfSidecarWriter().write(input, maximumOutput,
            Map.of(".debug_info", PAYLOAD));
        require(ElfImage.read(maximumOutput).sections().size() == ElfImage.MAX_HEADER_COUNT,
            "maximum output section count could not be reread");
        Files.delete(maximumOutput);

        // Sparse tables exercise the exact byte cap without a fixture-sized
        // Java allocation. Undefined fields of PT_NULL entries stay zero.
        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN,
            ElfImage.MAX_HEADER_COUNT, 1, false, 0, 256, 0, 0);
        require(ElfImage.read(input).segments().size() == ElfImage.MAX_HEADER_COUNT,
            "maximum table byte size rejected");
        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN,
            ElfImage.MAX_HEADER_COUNT, 1, false, 0, 257, 0, 0);
        expectFailure(() -> ElfImage.read(input), "program table exceeds safety limit");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2,
            ElfImage.MAX_HEADER_COUNT, false, 0, 0, 256, 0);
        require(ElfImage.read(input).sections().size() == ElfImage.MAX_HEADER_COUNT,
            "maximum section-table byte size rejected");
        create(input, true, ByteOrder.LITTLE_ENDIAN, 2,
            ElfImage.MAX_HEADER_COUNT, false, 0, 0, 257, 0);
        expectFailure(() -> ElfImage.read(input), "section table exceeds safety limit");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true,
            0, 0, 0, ElfImage.MAX_NAME_TABLE_BYTES);
        require(ElfImage.read(input).sections().size() == 3, "maximum name table rejected");
        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true,
            0, 0, 0, ElfImage.MAX_NAME_TABLE_BYTES + 1);
        expectFailure(() -> ElfImage.read(input), "section-name table exceeds safety limit");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 260, true,
            0, 0, 0, ElfImage.MAX_NAME_BYTES + 2);
        byte[] longName = new byte[ElfImage.MAX_NAME_BYTES];
        Arrays.fill(longName, (byte) 'a');
        fixture.write(fixture.names + 1, longName);
        fixture.word(fixture.sectionOffset(259), 0);
        // Different offsets into one long string stress the aggregate budget;
        // caching repeated offsets prevents needless duplicate allocations.
        for (int index = 1; index <= 256; index++) {
            fixture.word(fixture.sectionOffset(index), index);
        }
        fixture.word(fixture.sectionOffset(257), 32897);
        ElfImage image = ElfImage.read(input);
        require(image.sections().get(1).name().length() == ElfImage.MAX_NAME_BYTES,
            "maximum individual or aggregate name size rejected");
        // Input suffix sharing fits exactly in the decoded-name budget. The
        // output stores each unique name plus its NUL, so it must fail before
        // publication instead of creating an unreadable name table.
        expectWriterFailure(input, "sidecar section names exceed supported limit");
        fixture.word(fixture.sectionOffset(258), ElfImage.MAX_NAME_BYTES);
        expectFailure(() -> ElfImage.read(input), "decoded section names exceed safety limit");
        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true,
            0, 0, 0, ElfImage.MAX_NAME_BYTES + 3);
        fixture.write(fixture.names + 1, longName);
        fixture.write(fixture.names + 1 + longName.length, new byte[] { 'a' });
        expectFailure(() -> ElfImage.read(input), "section name exceeds safety limit");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true, 0, 0, 0, NAMES.length);
        fixture.address(fixture.sectionOffset(1) + 32, ElfImage.MAX_TABLE_BYTES + 1L);
        fixture.write(fixture.payload + ElfImage.MAX_TABLE_BYTES, new byte[] { 0 });
        image = ElfImage.read(input);
        ElfImage bounded = image;
        expectFailure(() -> bounded.sectionData(bounded.sections().get(1)),
            "section .payload exceeds safety limit");

        fixture = create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true,
            0, 0, 0, NAMES.length);
        fixture.write(ElfImage.MAX_TABLE_BYTES - 1L, new byte[] { 0 });
        require(ElfImage.read(input).bytes().length == ElfImage.MAX_TABLE_BYTES,
            "maximum convenience byte-array read rejected");
        fixture.write(ElfImage.MAX_TABLE_BYTES, new byte[] { 0 });
        expectFailure(() -> ElfImage.read(input).bytes(),
            "whole ELF byte-array read exceeds safety limit");
    }

    private static void checkChangedSource(Path input) throws Exception {
        create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true, 0, 0, 0, NAMES.length);
        ElfImage image = ElfImage.read(input);
        Files.setLastModifiedTime(input, FileTime.fromMillis(
            Files.getLastModifiedTime(input).toMillis() + 10000));
        expectFailure(image::bytes, "input changed");
        image = ElfImage.read(input);
        Files.write(input, new byte[] { 1 }, StandardOpenOption.APPEND);
        ElfImage changed = image;
        Path output = input.resolveSibling("changed-copy");
        try (FileChannel channel = FileChannel.open(output, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            expectFailure(() -> changed.copyTo(channel), "input changed");
            require(channel.size() == 0, "changed input was copied");
        }
        create(input, true, ByteOrder.LITTLE_ENDIAN, 2, 3, true, 0, 0, 0, NAMES.length);
        ElfImage replaced = ElfImage.read(input);
        Path replacement = input.resolveSibling("replacement.elf");
        Files.copy(input, replacement);
        Files.setLastModifiedTime(replacement, Files.getLastModifiedTime(input));
        Object oldKey = Files.readAttributes(input,
            java.nio.file.attribute.BasicFileAttributes.class).fileKey();
        Object newKey = Files.readAttributes(replacement,
            java.nio.file.attribute.BasicFileAttributes.class).fileKey();
        Files.move(replacement, input, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        if (oldKey != null && newKey != null && !oldKey.equals(newKey)) {
            expectFailure(replaced::bytes, "input changed");
        }
    }

    private static void expectWriterFailure(Path input, String message) throws Exception {
        Path output = input.resolveSibling("prior-artifact.dbg");
        Files.write(output, PAYLOAD);
        byte[] before = hash(input);
        expectFailure(() -> new MatchedElfSidecarWriter().write(input, output,
            Map.of(".debug_info", PAYLOAD)), message);
        require(Arrays.equals(PAYLOAD, Files.readAllBytes(output)),
            "writer limit failure replaced the existing destination");
        require(Arrays.equals(before, hash(input)), "writer limit failure changed the input");
        try (var children = Files.list(input.getParent())) {
            require(children.noneMatch(path -> path.getFileName().toString()
                .startsWith(".ghidra-dwarf-forge-")), "writer limit failure leaked a temporary file");
        }
        Files.delete(output);
    }

    private static byte[] hash(Path path) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = input.read(buffer)) != -1) {
                hash.update(buffer, 0, count);
            }
        }
        return hash.digest();
    }

    private static void checkSymlinkTraversal(Path directory) throws Exception {
        Path nested = directory.resolve("nested");
        Path deep = nested.resolve("deep");
        Files.createDirectories(deep);
        create(directory.resolve("input"), true, ByteOrder.LITTLE_ENDIAN,
            2, 3, true, 0, 0, 0, NAMES.length);
        create(nested.resolve("input"), false, ByteOrder.BIG_ENDIAN,
            2, 3, true, 0, 0, 0, NAMES.length);
        Path link = directory.resolve("link");
        try {
            Files.createSymbolicLink(link, deep);
        }
        catch (UnsupportedOperationException | IOException unavailable) {
            System.out.println("elf-reader-symlink-traversal=SKIPPED: " + unavailable);
            return;
        }
        Path requested = link.resolve("..").resolve("input");
        ElfImage actual = ElfImage.read(requested);
        require(!actual.is64Bit() && actual.byteOrder() == ByteOrder.BIG_ENDIAN,
            "lexical normalization changed the requested input file");
        require(Arrays.equals(actual.bytes(), Files.readAllBytes(nested.resolve("input"))),
            "source reopening changed symlink traversal");
        System.out.println("elf-reader-symlink-traversal=PASS");
    }

    private static Fixture create(Path path, boolean elf64, ByteOrder order,
            int programCount, int sectionCount, boolean names, long highOffset,
            int programEntrySize, int sectionEntrySize, int nameTableBytes) throws Exception {
        Files.deleteIfExists(path);
        int headerSize = elf64 ? 64 : 52;
        int programSize = programEntrySize == 0 ? (elf64 ? 56 : 32) : programEntrySize;
        int sectionSize = sectionEntrySize == 0 ? (elf64 ? 64 : 40) : sectionEntrySize;
        long programs = highOffset == 0 ? headerSize : highOffset;
        long sections = programs + (long) programCount * programSize;
        long strings = sections + (long) sectionCount * sectionSize;
        long payload = strings + nameTableBytes;
        Fixture fixture = new Fixture(path, elf64, order, programs, sections, strings,
            payload, sectionSize);
        ByteBuffer header = ByteBuffer.allocate(headerSize).order(order);
        header.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        header.position(16);
        header.putShort((short) 2).putShort((short) (elf64 ? 62 : 8)).putInt(1);
        if (elf64) {
            header.putLong(0x401000).putLong(programs).putLong(sections);
        }
        else {
            header.putInt(0x401000).putInt((int) programs).putInt((int) sections);
        }
        header.putInt(0).putShort((short) headerSize).putShort((short) programSize);
        header.putShort((short) Math.min(programCount, 0xffff)).putShort((short) sectionSize);
        header.putShort((short) (sectionCount >= 0xff00 ? 0 : sectionCount));
        int nameIndex = names ? sectionCount - 1 : 0;
        header.putShort((short) (nameIndex >= 0xff00 ? 0xffff : nameIndex));
        fixture.write(0, header.array());
        fixture.write(payload, PAYLOAD);
        ByteBuffer note = ByteBuffer.allocate(20).order(order);
        note.putInt(4).putInt(4).putInt(3).put(new byte[] { 'G', 'N', 'U', 0, 1, 2, 3, 4 });
        fixture.write(payload + 4, note.array());
        int loadIndex = Math.max(0, programCount - 2);
        fixture.write(programs + (long) loadIndex * programSize,
            segment(elf64, order, 1, payload, 0x401000, PAYLOAD.length));
        if (programCount > 1) {
            fixture.write(programs + (long) (programCount - 1) * programSize,
                segment(elf64, order, 4, payload + 4, 0, note.capacity()));
        }
        fixture.write(sections, section(elf64, order, 0, 0, 0,
            sectionCount >= 0xff00 ? sectionCount : 0,
            nameIndex >= 0xff00 ? nameIndex : 0, programCount >= 0xffff ? programCount : 0));
        if (sectionCount > 1) {
            fixture.write(fixture.sectionOffset(1), section(elf64, order, 1, 1,
                payload, PAYLOAD.length, 0, 0));
        }
        if (names) {
            fixture.write(fixture.sectionOffset(nameIndex), section(elf64, order, 10, 3,
                strings, nameTableBytes, 0, 0));
            fixture.write(strings, NAMES);
        }
        return fixture;
    }

    private static byte[] section(boolean elf64, ByteOrder order, int name, int type,
            long offset, long size, int link, int info) {
        ByteBuffer result = ByteBuffer.allocate(elf64 ? 64 : 40).order(order);
        result.putInt(name).putInt(type);
        if (elf64) {
            result.putLong(0).putLong(0).putLong(offset).putLong(size);
        }
        else {
            result.putInt(0).putInt(0).putInt((int) offset).putInt((int) size);
        }
        result.putInt(link).putInt(info);
        return result.array();
    }

    private static byte[] segment(boolean elf64, ByteOrder order, int type,
            long offset, long address, int size) {
        ByteBuffer result = ByteBuffer.allocate(elf64 ? 56 : 32).order(order);
        result.putInt(type);
        if (elf64) {
            result.putInt(5).putLong(offset).putLong(address).putLong(address);
            result.putLong(size).putLong(size).putLong(1);
        }
        else {
            result.putInt((int) offset).putInt((int) address).putInt((int) address);
            result.putInt(size).putInt(size).putInt(5).putInt(1);
        }
        return result.array();
    }

    private record Fixture(Path path, boolean elf64, ByteOrder order, long programs,
            long sections, long names, long payload, int sectionSize) {
        long sectionOffset(int index) {
            return sections + (long) index * sectionSize;
        }

        void write(long offset, byte[] bytes) throws IOException {
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE)) {
                ByteBuffer data = ByteBuffer.wrap(bytes);
                while (data.hasRemaining()) {
                    channel.write(data, offset + data.position());
                }
            }
        }

        void half(long offset, int value) throws IOException {
            write(offset, ByteBuffer.allocate(2).order(order).putShort((short) value).array());
        }

        void word(long offset, long value) throws IOException {
            write(offset, ByteBuffer.allocate(4).order(order).putInt((int) value).array());
        }

        void address(long offset, long value) throws IOException {
            if (elf64) {
                write(offset, ByteBuffer.allocate(8).order(order).putLong(value).array());
            }
            else {
                word(offset, value);
            }
        }
    }

    private static void expectBadHeader(Path input, Fixture fixture, byte[] valid,
            long offset, int width, long value, String message) throws Exception {
        Files.write(input, valid);
        if (width == 1) {
            fixture.write(offset, new byte[] { (byte) value });
        }
        else if (width == 2) {
            fixture.half(offset, (int) value);
        }
        else if (width == 4) {
            fixture.word(offset, value);
        }
        else {
            fixture.address(offset, value);
        }
        expectFailure(() -> ElfImage.read(input), message);
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }

    private static void expectFailure(CheckedAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected failure containing " + message);
        }
        catch (IllegalArgumentException | IOException expected) {
            require(expected.getMessage().contains(message), "unexpected failure: " + expected);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
