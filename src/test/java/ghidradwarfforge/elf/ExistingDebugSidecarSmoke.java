package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Native-independent retirement of inherited debug metadata in ELF32/ELF64.
 * Debug payloads are opaque sentinels; integration tests validate real DWARF.
 */
public final class ExistingDebugSidecarSmoke {
    private static final long SHF_COMPRESSED = 0x800;
    private static final List<String> RETIRED_NAMES = List.of(
        ".debug_aranges", ".debug_names", ".zdebug_info", ".zdebug_abbrev",
        ".gdb_index", ".gnu_debuglink", ".gnu_debugaltlink", ".gnu_debugdata");

    private record FixtureSection(String name, int type, long flags, long address,
            byte[] bytes) {
        private FixtureSection(String name) {
            this(name, 1, 0, 0, ("original:" + name).getBytes(StandardCharsets.UTF_8));
        }
    }

    private ExistingDebugSidecarSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-existing-debug-");
        try {
            for (boolean elf64 : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    checkCase(directory, elf64, order);
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
        System.out.println("existing-debug-sidecar-smoke=PASS");
    }

    private static void checkCase(Path directory, boolean elf64, ByteOrder order)
            throws Exception {
        String caseName = (elf64 ? "elf64-" : "elf32-") +
            (order == ByteOrder.LITTLE_ENDIAN ? "le" : "be");
        Path input = directory.resolve(caseName);
        Path output = directory.resolve(caseName + ".dbg");
        Files.write(input, fixture(elf64, order));
        byte[] originalBytes = Files.readAllBytes(input);
        byte[] originalHash = sha256(originalBytes);
        ElfImage original = ElfImage.read(input);
        Map<String, byte[]> replacement = new LinkedHashMap<>();
        replacement.put(".debug_info", new byte[] { 1, 2, 3, 4 });
        replacement.put(".debug_abbrev", new byte[] { 5, 6, 7 });
        replacement.put(".debug_str", "Forge-only strings\0".getBytes(StandardCharsets.UTF_8));

        new MatchedElfSidecarWriter().write(input, output, replacement);
        require(Arrays.equals(originalHash, sha256(Files.readAllBytes(input))),
            "original input changed");
        ElfImage result = ElfImage.read(output);
        require(result.is64Bit() == original.is64Bit() &&
            result.byteOrder() == original.byteOrder() &&
            result.machine() == original.machine() &&
            result.type() == original.type() && result.flags() == original.flags(),
            "target identity changed");
        byte[] resultBytes = result.bytes();
        require(Arrays.equals(Arrays.copyOf(originalBytes, 16),
            Arrays.copyOf(resultBytes, 16)), "ELF identity bytes changed");
        require(result.segments().isEmpty(), "sidecar unexpectedly has load segments");

        for (Map.Entry<String, byte[]> entry : replacement.entrySet()) {
            ElfImage.Section section = exactlyOne(result, entry.getKey());
            require(Arrays.equals(entry.getValue(), result.sectionData(section)),
                "replacement payload differs: " + entry.getKey());
            require(section.type == 1 && section.flags == 0 && section.address == 0 &&
                section.link == 0 && section.info == 0 && section.entrySize == 0 &&
                section.alignment == 1, "replacement retained stale metadata");
        }
        require(result.sections().stream().filter(section ->
            section.name().startsWith(".debug_")).count() == replacement.size(),
            "unexpected active DWARF sections");
        for (String name : RETIRED_NAMES) {
            require(result.sections().stream().noneMatch(section -> section.name().equals(name)),
                "old debug metadata is still active: " + name);
            require(result.sections().stream().anyMatch(section ->
                section.name().equals(".forge.stale" + name)),
                "retired section is missing: " + name);
        }
        require(result.sections().stream().filter(section ->
            section.name().equals(".forge.stale.debug_info")).count() == 1,
            "duplicate original debug_info was not retired");
        require(result.sections().stream().filter(section ->
            section.name().equals(".forge.stale.zdebug_info")).count() == 2,
            "existing stale-name collision lost a section");

        // Every original section payload remains at its original file offset,
        // even when its new section header points to replacement debug data.
        for (ElfImage.Section section : original.sections()) {
            if (section.size() != 0) {
                require(Arrays.equals(original.sectionData(section),
                    Arrays.copyOfRange(resultBytes, Math.toIntExact(section.offset),
                        Math.toIntExact(section.offset + section.size()))),
                    "original payload was changed: " + section.name());
            }
        }
        for (String name : Set.of(".text", ".eh_frame", ".note.gnu.build-id")) {
            ElfImage.Section before = exactlyOne(original, name);
            ElfImage.Section after = exactlyOne(result, name);
            require(before.type == after.type && before.flags == after.flags &&
                before.address == after.address && before.offset == after.offset &&
                before.size == after.size, "non-debug metadata changed: " + name);
            require(Arrays.equals(original.sectionData(before), result.sectionData(after)),
                "non-debug section bytes changed: " + name);
        }

        Path repeat = directory.resolve(caseName + ".repeat.dbg");
        new MatchedElfSidecarWriter().write(input, repeat, replacement);
        require(Arrays.equals(resultBytes, Files.readAllBytes(repeat)),
            "sidecar generation is not deterministic");
        System.out.println("existing-debug-sidecar-case=" + caseName + " PASS");
    }

    private static byte[] fixture(boolean elf64, ByteOrder order) {
        List<FixtureSection> sections = new ArrayList<>();
        sections.add(new FixtureSection("", 0, 0, 0, new byte[0]));
        sections.add(new FixtureSection(".text", 1, 6, 0x1000, new byte[] { 1, 2, 3, 4 }));
        sections.add(new FixtureSection(".eh_frame", 1, 2, 0x2000, new byte[] { 0, 0, 0, 0 }));
        ByteBuffer note = ByteBuffer.allocate(20).order(order);
        note.putInt(4).putInt(4).putInt(3).put(new byte[] { 'G', 'N', 'U', 0 });
        note.put(new byte[] { 10, 20, 30, 40 });
        sections.add(new FixtureSection(".note.gnu.build-id", 7, 2, 0x3000, note.array()));
        sections.add(new FixtureSection(".debug_info", 1, SHF_COMPRESSED, 0,
            "compressed original info".getBytes(StandardCharsets.UTF_8)));
        sections.add(new FixtureSection(".debug_info"));
        sections.add(new FixtureSection(".debug_abbrev"));
        for (String name : RETIRED_NAMES) {
            sections.add(new FixtureSection(name));
        }
        sections.add(new FixtureSection(".forge.stale.zdebug_info"));

        ByteArrayOutputStream names = new ByteArrayOutputStream();
        List<Integer> nameOffsets = new ArrayList<>();
        for (FixtureSection section : sections) {
            nameOffsets.add(names.size());
            names.writeBytes(section.name().getBytes(StandardCharsets.UTF_8));
            names.write(0);
        }
        nameOffsets.add(names.size());
        names.writeBytes(".shstrtab\0".getBytes(StandardCharsets.UTF_8));
        sections.add(new FixtureSection(".shstrtab", 3, 0, 0, names.toByteArray()));

        int headerSize = elf64 ? 64 : 52;
        int entrySize = elf64 ? 64 : 40;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.writeBytes(new byte[headerSize]);
        List<Integer> offsets = new ArrayList<>();
        for (FixtureSection section : sections) {
            offsets.add(section.type() == 0 ? 0 : result.size());
            result.writeBytes(section.bytes());
        }
        while (result.size() % (elf64 ? 8 : 4) != 0) {
            result.write(0);
        }
        int tableOffset = result.size();
        for (int index = 0; index < sections.size(); index++) {
            FixtureSection section = sections.get(index);
            ByteBuffer row = ByteBuffer.allocate(entrySize).order(order);
            row.putInt(nameOffsets.get(index)).putInt(section.type());
            if (elf64) {
                row.putLong(section.flags()).putLong(section.address());
                row.putLong(offsets.get(index)).putLong(section.bytes().length);
                row.putInt(0).putInt(0).putLong(section.type() == 0 ? 0 : 1).putLong(0);
            }
            else {
                row.putInt((int) section.flags()).putInt((int) section.address());
                row.putInt(offsets.get(index)).putInt(section.bytes().length);
                row.putInt(0).putInt(0).putInt(section.type() == 0 ? 0 : 1).putInt(0);
            }
            result.writeBytes(row.array());
        }
        byte[] bytes = result.toByteArray();
        ByteBuffer header = ByteBuffer.wrap(bytes).order(order);
        header.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 3 });
        header.position(16);
        header.putShort((short) 3).putShort((short) (elf64 ? 21 : 8)).putInt(1);
        if (elf64) {
            header.putLong(0x1000).putLong(0).putLong(tableOffset);
        }
        else {
            header.putInt(0x1000).putInt(0).putInt(tableOffset);
        }
        header.putInt(0x12345678).putShort((short) headerSize);
        header.putShort((short) 0).putShort((short) 0).putShort((short) entrySize);
        header.putShort((short) sections.size()).putShort((short) (sections.size() - 1));
        return bytes;
    }

    private static ElfImage.Section exactlyOne(ElfImage image, String name) {
        List<ElfImage.Section> sections = image.sections().stream()
            .filter(section -> section.name().equals(name)).toList();
        require(sections.size() == 1, "expected exactly one section named " + name);
        return sections.get(0);
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
