package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds matched debug sidecars from program-header-only ELF fixtures. */
public final class SectionlessSidecarSmoke {
    private static final long SHT_RELA = 4;
    private static final long SHT_REL = 9;
    private static final String[] TARGETS = {
        "x86_64", "aarch64", "arm32", "mips32be", "mips32le"
    };
    private record Variant(String referenceName, String inputName, String outputName,
        boolean expectNoInputSections) {
    }
    private static final Variant[] VARIANTS = {
        new Variant("semantic.exec.reference", "semantic.exec.stripped",
            "semantic.exec.forge-container.dbg", false),
        new Variant("semantic.exec.reference", "semantic.exec.no-sections.stripped",
            "semantic.exec.no-sections.forge-container.dbg", true),
        new Variant("semantic.pie.reference", "semantic.pie.stripped",
            "semantic.pie.forge-container.dbg", false)
    };

    private SectionlessSidecarSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "usage: SectionlessSidecarSmoke <fixture-root> [target ...]");
        }
        Path fixtureRoot = Path.of(args[0]).toAbsolutePath().normalize();
        MatchedElfSidecarWriter writer = new MatchedElfSidecarWriter();
        checkSyntheticLoads(writer, fixtureRoot);
        String[] selectedTargets = args.length == 1 ? TARGETS :
            Arrays.copyOfRange(args, 1, args.length);
        for (String target : selectedTargets) {
            Path directory = fixtureRoot.resolve(target);
            for (Variant variant : VARIANTS) {
                Path reference = directory.resolve(variant.referenceName());
                Path input = directory.resolve(variant.inputName());
                Path output = directory.resolve(variant.outputName());
                byte[] originalHash = sha256(input);

                ElfImage referenceImage = ElfImage.read(reference);
                Map<String, byte[]> debugSections = new LinkedHashMap<>();
                for (ElfImage.Section section : referenceImage.sections()) {
                    if (section.name().startsWith(".debug_")) {
                        debugSections.put(section.name(), referenceImage.sectionData(section));
                    }
                }
                if (!debugSections.containsKey(".debug_info") ||
                    !debugSections.containsKey(".debug_abbrev")) {
                    throw new IllegalStateException("reference lacks required DWARF sections");
                }

                ElfImage inputImage = ElfImage.read(input);
                if (variant.expectNoInputSections() != inputImage.sections().isEmpty()) {
                    throw new IllegalStateException("unexpected input section-table state");
                }
                writer.write(input, output, debugSections);
                if (!Arrays.equals(originalHash, sha256(input))) {
                    throw new IllegalStateException("writer modified original input");
                }

                ElfImage result = ElfImage.read(output);
                if (result.sections().isEmpty() || result.machine() != inputImage.machine() ||
                    result.type() != inputImage.type() || result.flags() != inputImage.flags() ||
                    result.is64Bit() != inputImage.is64Bit() ||
                    result.byteOrder() != inputImage.byteOrder()) {
                    throw new IllegalStateException("sidecar target identity mismatch for " + target);
                }
                if (result.sections().stream().anyMatch(section ->
                        section.type == SHT_REL || section.type == SHT_RELA)) {
                    throw new IllegalStateException(
                        "matched sidecar retained an unresolved relocation section");
                }
                checkLoadMetadata(inputImage, result);
                for (Map.Entry<String, byte[]> expected : debugSections.entrySet()) {
                    ElfImage.Section actual = result.sections().stream()
                    .filter(section -> expected.getKey().equals(section.name()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                        "missing output section " + expected.getKey()));
                    if (!Arrays.equals(expected.getValue(), result.sectionData(actual))) {
                        throw new IllegalStateException("section data mismatch " + expected.getKey());
                    }
                }
                System.out.printf(
                    "target=%s input=%s class=%s endian=%s machine=%d sections=%d%n",
                    target, variant.inputName(), result.is64Bit() ? "ELF64" : "ELF32",
                    result.byteOrder(), result.machine(), result.sections().size());
            }
        }
        System.out.println("sectionless-sidecar-smoke=PASS");
    }

    private static void checkLoadMetadata(ElfImage input, ElfImage output) {
        require(output.segments().isEmpty(), "sidecar retained program headers");
        var generated = output.sections().stream()
            .filter(section -> section.name().startsWith(".forge.load.")).toList();
        if (!input.sections().isEmpty()) {
            require(generated.isEmpty(), "existing-section fixture acquired generated load sections");
            return;
        }
        int count = 0;
        for (int index = 0; index < input.segments().size(); index++) {
            var segment = input.segments().get(index);
            if (segment.type != 1 || segment.memorySize == 0) {
                continue;
            }
            String name = ".forge.load." + index;
            var matches = generated.stream().filter(section -> section.name().equals(name)).toList();
            require(matches.size() == 1, "missing or duplicate segment extent " + name);
            var section = matches.get(0);
            long flags = 2 | ((segment.flags & 2) != 0 ? 1 : 0) |
                ((segment.flags & 1) != 0 ? 4 : 0);
            require(section.type == 8 && section.flags == flags &&
                section.address == segment.virtualAddress && section.offset == segment.offset &&
                section.size == segment.memorySize && section.alignment == 1 &&
                section.link == 0 && section.info == 0 && section.entrySize == 0,
                "segment extent differs from original program header " + index);
            count++;
        }
        require(generated.size() == count, "unexpected generated load extent");
    }

    private static void checkSyntheticLoads(MatchedElfSidecarWriter writer, Path root)
            throws Exception {
        Files.createDirectories(root);
        Path directory = Files.createTempDirectory(root, "sectionless-load-metadata-");
        Map<String, byte[]> debug = Map.of(".debug_info", new byte[] { 1, 2, 3, 4 });
        for (boolean wide : new boolean[] { false, true }) {
            for (ByteOrder order : new ByteOrder[] { ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN }) {
                String name = (wide ? "64-" : "32-") + order;
                byte[] bytes = sectionlessFixture(wide, order);
                Path input = directory.resolve(name + ".elf");
                Path output = directory.resolve(name + ".dbg");
                Files.write(input, bytes);
                byte[] originalHash = sha256(input);
                writer.write(input, output, debug);
                ElfImage original = ElfImage.read(input);
                ElfImage result = ElfImage.read(output);
                checkLoadMetadata(original, result);
                require(result.is64Bit() == wide && result.byteOrder() == order,
                    "synthetic load identity changed");
                for (var section : result.sections()) {
                    if (section.name().startsWith(".forge.load.")) {
                        require(result.sectionData(section).length == 0,
                            "NOBITS load extent gained a payload");
                    }
                }
                require(result.sections().stream().filter(section -> section.type == 7).count() == 1,
                    "load extents changed note reconstruction");
                byte[] after = Files.readAllBytes(output);
                int headerSize = wide ? 64 : 52;
                require(Arrays.equals(Arrays.copyOfRange(bytes, headerSize, bytes.length),
                    Arrays.copyOfRange(after, headerSize, bytes.length)),
                    "copied source payload or program table changed");
                Path repeated = directory.resolve(name + ".repeat.dbg");
                writer.write(input, repeated, debug);
                require(Arrays.equals(sha256(output), sha256(repeated)), "load extents are not deterministic");
                require(Arrays.equals(originalHash, sha256(input)), "synthetic original changed");

                // The final memory-only segment may end exactly at the supported
                // address boundary; wrapping past it must fail before publication.
                byte[] boundary = bytes.clone();
                ByteBuffer fields = ByteBuffer.wrap(boundary).order(order);
                long address = wide ? Long.MAX_VALUE - 0x10 : 0xfffffff0L;
                putProgramHeader(fields, wide, 6, 1, 4, 0x400, address, 0, 0x10, 1);
                Path boundaryInput = directory.resolve(name + ".boundary.elf");
                Path boundaryOutput = directory.resolve(name + ".boundary.dbg");
                Files.write(boundaryInput, boundary);
                writer.write(boundaryInput, boundaryOutput, debug);
                checkLoadMetadata(ElfImage.read(boundaryInput), ElfImage.read(boundaryOutput));
                putProgramHeader(fields, wide, 6, 1, 4, 0x400, address, 0, 0x11, 1);
                Path invalid = directory.resolve(name + ".overflow.elf");
                Files.write(invalid, boundary);
                byte[] invalidHash = sha256(invalid);
                byte[] previous = sha256(output);
                try {
                    writer.write(invalid, output, debug);
                    throw new IllegalStateException("overflowing load extent accepted");
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains("PT_LOAD virtual range"),
                        "overflow failed for an unrelated reason");
                }
                require(Arrays.equals(previous, sha256(output)) &&
                    Arrays.equals(invalidHash, sha256(invalid)), "overflow replaced an input or prior output");
                try (var files = Files.list(directory)) {
                    require(files.noneMatch(path -> path.getFileName().toString()
                        .startsWith(".ghidra-dwarf-forge-")), "overflow left a temporary artifact");
                }
                System.out.println("sectionless-load-metadata=" + name + " PASS");
            }
        }
    }

    private static byte[] sectionlessFixture(boolean wide, ByteOrder order) {
        ByteBuffer bytes = ByteBuffer.allocate(0x500).order(order);
        bytes.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        bytes.putShort(16, (short) 2);
        bytes.putShort(18, (short) (wide ? 21 : 8));
        bytes.putInt(20, 1);
        if (wide) {
            bytes.putLong(24, 0x500320);
            bytes.putLong(32, 64);
            bytes.putShort(52, (short) 64);
            bytes.putShort(54, (short) 56);
            bytes.putShort(56, (short) 7);
        }
        else {
            bytes.putInt(24, 0x500320);
            bytes.putInt(28, 52);
            bytes.putShort(40, (short) 52);
            bytes.putShort(42, (short) 32);
            bytes.putShort(44, (short) 7);
        }
        // PT_NULL and the empty PT_LOAD still consume their physical indexes.
        putProgramHeader(bytes, wide, 0, 0, 0, 0, 0, 0, 0, 0);
        putProgramHeader(bytes, wide, 1, 1, 4, 0x200, 0x400200, 0x30, 0x70, 0x1000);
        putProgramHeader(bytes, wide, 2, 1, 7, 0, 0, 0, 0, 0x1000);
        putProgramHeader(bytes, wide, 3, 4, 4, 0x200, 0x400200, 20, 20, 4);
        putProgramHeader(bytes, wide, 4, 1, 5, 0x320, 0x500320, 0x20, 0x20, 0x1000);
        putProgramHeader(bytes, wide, 5, 1, 6, 0x380, 0x600380, 0x10, 0x80, 0x1000);
        putProgramHeader(bytes, wide, 6, 1, 4, 0x400, 0x700400, 0, 0x30, 0x1000);
        bytes.position(0x200);
        bytes.putInt(4).putInt(4).putInt(3).put(new byte[] { 'G', 'N', 'U', 0 }).putInt(0x12345678);
        return bytes.array();
    }

    private static void putProgramHeader(ByteBuffer bytes, boolean wide, int index,
            long type, long flags, long offset, long address, long fileSize,
            long memorySize, long alignment) {
        int start = (wide ? 64 : 52) + index * (wide ? 56 : 32);
        bytes.putInt(start, (int) type);
        if (wide) {
            bytes.putInt(start + 4, (int) flags);
            bytes.putLong(start + 8, offset);
            bytes.putLong(start + 16, address);
            bytes.putLong(start + 24, address);
            bytes.putLong(start + 32, fileSize);
            bytes.putLong(start + 40, memorySize);
            bytes.putLong(start + 48, alignment);
        }
        else {
            bytes.putInt(start + 4, (int) offset);
            bytes.putInt(start + 8, (int) address);
            bytes.putInt(start + 12, (int) address);
            bytes.putInt(start + 16, (int) fileSize);
            bytes.putInt(start + 20, (int) memorySize);
            bytes.putInt(start + 24, (int) flags);
            bytes.putInt(start + 28, (int) alignment);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static byte[] sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) != -1;) {
                digest.update(buffer, 0, count);
            }
        }
        return digest.digest();
    }
}
