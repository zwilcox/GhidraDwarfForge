package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Exercises real section-number escape thresholds without native dependencies.
 * Optional arguments build executable extended-numbering integration fixtures.
 */
public final class ExtendedSectionNumberingSmoke {
    private static final int SHN_LORESERVE = 0xff00;
    private static final int SHN_XINDEX = 0xffff;
    private static final int EXTENDED_FIXTURE_COUNT = SHN_LORESERVE + 1;
    private static final byte[] DEBUG_PAYLOAD = { 7, 6, 5, 4 };
    private static final String[] TARGETS = {
        "x86_64", "aarch64", "arm32", "mips32be", "mips32le"
    };

    private ExtendedSectionNumberingSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-extended-sections-");
        try {
            for (boolean elf64 : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    String profile = (elf64 ? "elf64-" : "elf32-") +
                        (order == ByteOrder.LITTLE_ENDIAN ? "le" : "be");
                    byte[] template = template(elf64, order);
                    // One replacement section and one new name table add one
                    // output header. Cover each side of both escape thresholds.
                    for (int count : new int[] { SHN_LORESERVE - 2, SHN_LORESERVE - 1,
                            SHN_LORESERVE, SHN_LORESERVE + 1 }) {
                        checkCase(directory, profile + "-" + count,
                            extendSections(template, count), count + 1);
                    }
                    checkStaleZero(directory, profile, template);
                }
            }
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        System.out.println("extended-section-numbering-smoke=PASS");
        if (args.length > 0) {
            Path fixtureRoot = Path.of(args[0]).toAbsolutePath().normalize();
            String[] targets = args.length == 1 ? TARGETS :
                Arrays.copyOfRange(args, 1, args.length);
            createIntegrationFixtures(fixtureRoot, targets);
        }
    }

    private static void checkCase(Path directory, String profile, byte[] inputBytes,
            int expectedCount) throws Exception {
        Path input = directory.resolve(profile + ".elf");
        Path output = directory.resolve(profile + ".dbg");
        Files.write(input, inputBytes);
        byte[] inputHash = sha256(inputBytes);
        ElfImage original = ElfImage.read(input);
        MatchedElfSidecarWriter writer = new MatchedElfSidecarWriter();
        writer.write(input, output, Map.of(".debug_info", DEBUG_PAYLOAD));
        require(Arrays.equals(inputHash, sha256(Files.readAllBytes(input))),
            "writer modified original input");
        ElfImage result = ElfImage.read(output);
        byte[] resultBytes = result.bytes();
        require(original.sectionData(original.sections().get(0)).length == 0 &&
            result.sectionData(result.sections().get(0)).length == 0,
            "section zero's extended count was exposed as section data");
        require(result.sections().size() == expectedCount, "incorrect section count");
        require(result.sectionNameIndex() == expectedCount - 1,
            "incorrect section-name index");
        require(original.type() == result.type() && original.machine() == result.machine() &&
            original.is64Bit() == result.is64Bit() &&
            original.byteOrder() == result.byteOrder() && original.flags() == result.flags(),
            "target identity changed");
        require(Arrays.equals(Arrays.copyOf(inputBytes, 16),
            Arrays.copyOf(resultBytes, 16)), "ELF identification changed");
        require(result.segments().isEmpty(), "sidecar retained a program table");
        checkEncodedHeader(resultBytes, expectedCount);

        for (int index = 1; index < original.sections().size(); index++) {
            ElfImage.Section before = original.sections().get(index);
            ElfImage.Section after = result.sections().get(index);
            if (before.name().equals(".debug_info")) {
                require(Arrays.equals(DEBUG_PAYLOAD, result.sectionData(after)),
                    "replacement debug bytes differ");
                continue;
            }
            require(before.type == after.type && before.flags == after.flags &&
                before.address == after.address && before.offset == after.offset &&
                before.size == after.size && before.link == after.link &&
                before.info == after.info && before.entrySize == after.entrySize &&
                before.alignment == after.alignment,
                "section metadata/index changed at " + index);
            String expectedName = index == original.sectionNameIndex()
                    ? ".shstrtab.old" : before.name();
            require(expectedName.equals(after.name()), "section name changed at " + index);
            if (before.type != 0) {
                require(Arrays.equals(original.sectionData(before), result.sectionData(after)),
                    "section payload changed at " + index);
            }
        }
        require(result.sections().get(5).link == 4,
            "symbol table lost its original string-table index");
        ByteBuffer symbols = ByteBuffer.wrap(result.sectionData(result.sections().get(5)))
            .order(result.byteOrder());
        int symbolSectionOffset = result.is64Bit() ? 24 + 6 : 16 + 14;
        require(Short.toUnsignedInt(symbols.getShort(symbolSectionOffset)) == 1,
            "symbol lost its original text-section index");

        Path repeat = directory.resolve(profile + ".repeat.dbg");
        writer.write(input, repeat, Map.of(".debug_info", DEBUG_PAYLOAD));
        require(Arrays.equals(resultBytes, Files.readAllBytes(repeat)),
            "sidecar is not deterministic");
        checkFailedPublication(directory, profile, writer, input, output, resultBytes);
        System.out.println("extended-section-case=" + profile + " output=" + expectedCount +
            " PASS");
    }

    private static void checkEncodedHeader(byte[] bytes, int count) {
        boolean elf64 = bytes[4] == 2;
        ByteBuffer header = ByteBuffer.wrap(bytes).order(byteOrder(bytes));
        int encodedCount = Short.toUnsignedInt(header.getShort(elf64 ? 60 : 48));
        int encodedName = Short.toUnsignedInt(header.getShort(elf64 ? 62 : 50));
        int zeroOffset = Math.toIntExact(elf64 ? header.getLong(40) :
            Integer.toUnsignedLong(header.getInt(32)));
        int expectedName = count - 1;
        require(encodedCount == (count >= SHN_LORESERVE ? 0 : count),
            "wrong e_shnum encoding");
        require(encodedName == (expectedName >= SHN_LORESERVE ? SHN_XINDEX : expectedName),
            "wrong e_shstrndx encoding");
        long extendedCount = elf64 ? header.getLong(zeroOffset + 32) :
            Integer.toUnsignedLong(header.getInt(zeroOffset + 20));
        long extendedName = Integer.toUnsignedLong(header.getInt(zeroOffset +
            (elf64 ? 40 : 24)));
        require(extendedCount == (count >= SHN_LORESERVE ? count : 0),
            "wrong section-zero size");
        require(extendedName == (expectedName >= SHN_LORESERVE ? expectedName : 0),
            "wrong section-zero link");
        byte[] canonicalZero = new byte[elf64 ? 64 : 40];
        ByteBuffer zero = ByteBuffer.wrap(canonicalZero).order(header.order());
        if (elf64) {
            zero.putLong(32, extendedCount);
        }
        else {
            zero.putInt(20, (int) extendedCount);
        }
        zero.putInt(elf64 ? 40 : 24, (int) extendedName);
        require(Arrays.equals(canonicalZero, Arrays.copyOfRange(bytes, zeroOffset,
            zeroOffset + canonicalZero.length)),
            "section zero has a name, stale program count, or other invalid metadata");
    }

    private static void checkStaleZero(Path directory, String profile, byte[] template)
            throws Exception {
        byte[] stale = template.clone();
        ByteBuffer header = ByteBuffer.wrap(stale).order(byteOrder(stale));
        boolean elf64 = stale[4] == 2;
        int offset = Math.toIntExact(elf64 ? header.getLong(40) :
            Integer.toUnsignedLong(header.getInt(32)));
        // Normal header fields are authoritative for this deliberately stale
        // input. No old extension fields may leak into the canonical output.
        if (elf64) {
            header.putLong(offset + 32, 100);
        }
        else {
            header.putInt(offset + 20, 100);
        }
        header.putInt(offset + (elf64 ? 40 : 24), 101);
        header.putInt(offset + (elf64 ? 44 : 28), 102);
        checkCase(directory, profile + "-stale-zero", stale, 8);
    }

    private static void checkFailedPublication(Path directory, String profile,
            MatchedElfSidecarWriter writer, Path input, Path output, byte[] previous)
            throws Exception {
        try {
            writer.write(input, output, Map.of(".not_debug", DEBUG_PAYLOAD));
            throw new AssertionError("invalid debug section was accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("invalid debug section"),
                "unexpected publication failure");
        }
        require(Arrays.equals(previous, Files.readAllBytes(output)),
            "failed export replaced the prior artifact");
        Path invalidInput = directory.resolve(profile + ".truncated");
        Path absentOutput = directory.resolve(profile + ".failure.dbg");
        Files.write(invalidInput, new byte[] { 0x7f, 'E', 'L', 'F' });
        try {
            writer.write(invalidInput, absentOutput, Map.of(".debug_info", DEBUG_PAYLOAD));
            throw new AssertionError("truncated input was accepted");
        }
        catch (IllegalArgumentException expected) {
            require(!Files.exists(absentOutput), "failure published a partial artifact");
        }
        try (var files = Files.list(directory)) {
            require(files.noneMatch(path -> path.getFileName().toString()
                .startsWith(".ghidra-dwarf-forge-")), "failed export left a temporary file");
        }
    }

    private static void createIntegrationFixtures(Path root, String[] targets) throws Exception {
        for (String target : targets) {
            if (!Arrays.asList(TARGETS).contains(target)) {
                throw new IllegalArgumentException("unknown fixture target " + target);
            }
            for (String role : List.of("exec", "pie")) {
                Path input = root.resolve(target).resolve("semantic." + role + ".stripped");
                Path output = root.resolve(target)
                    .resolve("semantic." + role + ".extended-sections");
                byte[] original = Files.readAllBytes(input);
                byte[] originalHash = sha256(original);
                byte[] extended = extendSections(original, EXTENDED_FIXTURE_COUNT);
                Files.write(output, extended);
                if (!output.toFile().setExecutable(true, false) && !Files.isExecutable(output)) {
                    throw new IOException("cannot make generated fixture executable: " + output);
                }
                require(Arrays.equals(originalHash, sha256(Files.readAllBytes(input))),
                    "fixture generation modified the original");
                ElfImage image = ElfImage.read(output);
                require(image.sections().size() == EXTENDED_FIXTURE_COUNT &&
                    image.sectionNameIndex() == SHN_LORESERVE,
                    "generated fixture does not use both extended encodings");
                System.out.printf("extended-section-fixture=%s sections=%d name-index=%d%n",
                    output, image.sections().size(), image.sectionNameIndex());
            }
        }
    }

    /** Independent fixture encoder: original section indexes and bytes are retained. */
    private static byte[] extendSections(byte[] original, int count) {
        ByteBuffer input = ByteBuffer.wrap(original).order(byteOrder(original));
        boolean elf64 = original[4] == 2;
        int oldCount = Short.toUnsignedInt(input.getShort(elf64 ? 60 : 48));
        int oldNames = Short.toUnsignedInt(input.getShort(elf64 ? 62 : 50));
        int entrySize = Short.toUnsignedInt(input.getShort(elf64 ? 58 : 46));
        int oldTable = Math.toIntExact(elf64 ? input.getLong(40) :
            Integer.toUnsignedLong(input.getInt(32)));
        if (oldCount == 0 || oldNames == 0 || oldNames >= oldCount || count <= oldCount ||
                entrySize != (elf64 ? 64 : 40)) {
            throw new IllegalArgumentException("fixture requires an ordinary named section table");
        }
        int oldNameHeader = oldTable + oldNames * entrySize;
        int namesOffset = Math.toIntExact(elf64 ? input.getLong(oldNameHeader + 24) :
            Integer.toUnsignedLong(input.getInt(oldNameHeader + 16)));
        int namesLength = Math.toIntExact(elf64 ? input.getLong(oldNameHeader + 32) :
            Integer.toUnsignedLong(input.getInt(oldNameHeader + 20)));
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        strings.writeBytes(Arrays.copyOfRange(original, namesOffset, namesOffset + namesLength));
        int paddingName = addString(strings, ".forge.padding");
        int retainedName = addString(strings, ".fixture.original.shstrtab");
        int newName = addString(strings, ".shstrtab");
        byte[] names = strings.toByteArray();
        int newTable = align(Math.addExact(original.length, names.length), elf64 ? 8 : 4);
        byte[] result = Arrays.copyOf(original,
            Math.addExact(newTable, Math.multiplyExact(count, entrySize)));
        System.arraycopy(names, 0, result, original.length, names.length);
        System.arraycopy(original, oldTable, result, newTable, oldCount * entrySize);
        ByteBuffer output = ByteBuffer.wrap(result).order(input.order());
        output.putInt(newTable + oldNames * entrySize, retainedName);
        for (int index = oldCount; index < count - 1; index++) {
            // Ghidra's fallback name lookup scans all headers for every unnamed
            // section; one explicit name avoids quadratic fixture import time.
            output.putInt(newTable + index * entrySize, paddingName);
        }
        writeSection(output, newTable + (count - 1) * entrySize, elf64, newName,
            3, 0, 0, original.length, names.length, 0, 0, 1, 0);
        Arrays.fill(result, newTable, newTable + entrySize, (byte) 0);
        if (elf64) {
            output.putLong(40, newTable);
            output.putLong(newTable + 32, count >= SHN_LORESERVE ? count : 0);
        }
        else {
            output.putInt(32, newTable);
            output.putInt(newTable + 20, count >= SHN_LORESERVE ? count : 0);
        }
        output.putInt(newTable + (elf64 ? 40 : 24),
            count - 1 >= SHN_LORESERVE ? count - 1 : 0);
        output.putShort(elf64 ? 60 : 48, (short) (count >= SHN_LORESERVE ? 0 : count));
        output.putShort(elf64 ? 62 : 50,
            (short) (count - 1 >= SHN_LORESERVE ? SHN_XINDEX : count - 1));
        return result;
    }

    private static byte[] template(boolean elf64, ByteOrder order) {
        int headerSize = elf64 ? 64 : 52;
        int programSize = elf64 ? 56 : 32;
        int sectionSize = elf64 ? 64 : 40;
        int symbolSize = elf64 ? 24 : 16;
        int textOffset = headerSize + programSize;
        int noteOffset = textOffset + 4;
        int debugOffset = noteOffset + 20;
        int stringOffset = debugOffset + 4;
        byte[] symbolStrings = "\0sample\0".getBytes(StandardCharsets.UTF_8);
        int symbolOffset = align(stringOffset + symbolStrings.length, elf64 ? 8 : 4);
        int nameOffset = symbolOffset + 2 * symbolSize;
        ByteArrayOutputStream names = new ByteArrayOutputStream();
        names.write(0);
        int[] nameIndexes = new int[7];
        String[] sectionNames = { "", ".text", ".note.gnu.build-id", ".debug_info",
            ".strtab", ".symtab", ".shstrtab" };
        for (int index = 1; index < sectionNames.length; index++) {
            nameIndexes[index] = addString(names, sectionNames[index]);
        }
        int tableOffset = align(nameOffset + names.size(), elf64 ? 8 : 4);
        byte[] result = new byte[tableOffset + sectionNames.length * sectionSize];
        ByteBuffer output = ByteBuffer.wrap(result).order(order);
        output.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 3 });
        output.position(16);
        output.putShort((short) 2).putShort((short) (elf64 ? 21 : 8)).putInt(1);
        if (elf64) {
            output.putLong(0x400000 + textOffset).putLong(headerSize).putLong(tableOffset);
        }
        else {
            output.putInt(0x400000 + textOffset).putInt(headerSize).putInt(tableOffset);
        }
        output.putInt(0x12345678).putShort((short) headerSize).putShort((short) programSize);
        output.putShort((short) 1).putShort((short) sectionSize);
        output.putShort((short) sectionNames.length).putShort((short) 6);
        output.position(headerSize);
        if (elf64) {
            output.putInt(1).putInt(5).putLong(0).putLong(0x400000).putLong(0x400000);
            output.putLong(result.length).putLong(result.length).putLong(0x1000);
        }
        else {
            output.putInt(1).putInt(0).putInt(0x400000).putInt(0x400000);
            output.putInt(result.length).putInt(result.length).putInt(5).putInt(0x1000);
        }
        output.position(textOffset);
        output.put(new byte[] { 1, 2, 3, 4 });
        output.position(noteOffset);
        output.putInt(4).putInt(4).putInt(3).put(new byte[] { 'G', 'N', 'U', 0 });
        output.put(new byte[] { 10, 20, 30, 40 });
        output.position(debugOffset);
        output.put(new byte[] { 0, 1, 2, 3 });
        output.position(stringOffset);
        output.put(symbolStrings);
        output.position(symbolOffset + symbolSize);
        output.putInt(1);
        if (elf64) {
            output.put((byte) 0x12).put((byte) 0).putShort((short) 1);
            output.putLong(0x400000 + textOffset).putLong(4);
        }
        else {
            output.putInt(0x400000 + textOffset).putInt(4);
            output.put((byte) 0x12).put((byte) 0).putShort((short) 1);
        }
        output.position(nameOffset);
        output.put(names.toByteArray());
        writeSection(output, tableOffset + sectionSize, elf64, nameIndexes[1],
            1, 6, 0x400000 + textOffset, textOffset, 4, 0, 0, 1, 0);
        writeSection(output, tableOffset + 2 * sectionSize, elf64, nameIndexes[2],
            7, 2, 0x400000 + noteOffset, noteOffset, 20, 0, 0, 4, 0);
        writeSection(output, tableOffset + 3 * sectionSize, elf64, nameIndexes[3],
            1, 0, 0, debugOffset, 4, 0, 0, 1, 0);
        writeSection(output, tableOffset + 4 * sectionSize, elf64, nameIndexes[4],
            3, 0, 0, stringOffset, symbolStrings.length, 0, 0, 1, 0);
        writeSection(output, tableOffset + 5 * sectionSize, elf64, nameIndexes[5],
            2, 0, 0, symbolOffset, 2 * symbolSize, 4, 1, elf64 ? 8 : 4, symbolSize);
        writeSection(output, tableOffset + 6 * sectionSize, elf64, nameIndexes[6],
            3, 0, 0, nameOffset, names.size(), 0, 0, 1, 0);
        return result;
    }

    private static void writeSection(ByteBuffer output, int position, boolean elf64,
            int name, int type, long flags, long address, long offset, long size,
            int link, int info, long alignment, long entrySize) {
        output.position(position);
        output.putInt(name).putInt(type);
        if (elf64) {
            output.putLong(flags).putLong(address).putLong(offset).putLong(size);
            output.putInt(link).putInt(info).putLong(alignment).putLong(entrySize);
        }
        else {
            output.putInt(Math.toIntExact(flags)).putInt(Math.toIntExact(address));
            output.putInt(Math.toIntExact(offset)).putInt(Math.toIntExact(size));
            output.putInt(link).putInt(info);
            output.putInt(Math.toIntExact(alignment)).putInt(Math.toIntExact(entrySize));
        }
    }

    private static int addString(ByteArrayOutputStream output, String value) {
        int offset = output.size();
        output.writeBytes(value.getBytes(StandardCharsets.UTF_8));
        output.write(0);
        return offset;
    }

    private static int align(int value, int alignment) {
        return Math.addExact(value, alignment - 1) & -alignment;
    }

    private static ByteOrder byteOrder(byte[] bytes) {
        return bytes[5] == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
    }

    private static byte[] sha256(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
