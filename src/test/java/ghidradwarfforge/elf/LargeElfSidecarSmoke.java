package ghidradwarfforge.elf;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Linux integration oracle: a source-built ELF grows beyond Java array offsets. */
public final class LargeElfSidecarSmoke {
    private static final long LARGE_SIZE = (1L << 31) + 4097;

    private LargeElfSidecarSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: <source-built ELF64> <result directory>");
        }
        require(Runtime.getRuntime().maxMemory() <= 96L * 1024 * 1024,
            "run with -Xmx64m to prove bounded source-file memory");
        Path fixture = Path.of(args[0]).toAbsolutePath().normalize();
        Path directory = Path.of(args[1]).toAbsolutePath().normalize();
        Files.createDirectories(directory);
        ElfImage small = ElfImage.read(fixture);
        require(small.is64Bit(), "large runtime fixture must be ELF64");
        Map<String, byte[]> debug = new LinkedHashMap<>();
        for (ElfImage.Section section : small.sections()) {
            if (section.name().startsWith(".debug_")) {
                debug.put(section.name(), small.sectionData(section));
            }
        }
        require(debug.containsKey(".debug_info") && debug.containsKey(".debug_line"),
            "fixture must contain compiler DWARF");
        Path input = directory.resolve("large.elf");
        Path output = directory.resolve("large.dbg");
        Files.copy(fixture, input);
        try (FileChannel file = FileChannel.open(input, StandardOpenOption.WRITE)) {
            file.position(LARGE_SIZE - 1);
            file.write(ByteBuffer.wrap(new byte[] { 0x5a }));
        }
        require(Files.size(input) == LARGE_SIZE, "large fixture was not created");
        byte[] inputHash = digest(input, 0, Files.size(input));
        ElfImage original = ElfImage.read(input);
        require(original.fileSize() > Integer.MAX_VALUE, "input did not cross 2 GiB");

        MatchedElfSidecarWriter writer = new MatchedElfSidecarWriter();
        writer.write(input, output, debug);
        ElfImage result = ElfImage.read(output);
        require(result.fileSize() > LARGE_SIZE && result.segments().isEmpty(),
            "sidecar size or program-header policy changed");
        require(result.machine() == original.machine() && result.flags() == original.flags() &&
            result.type() == original.type() && result.byteOrder() == original.byteOrder(),
            "sidecar target identity changed");
        require(Arrays.equals(Arrays.copyOf(result.headerBytes(), 16),
            Arrays.copyOf(original.headerBytes(), 16)), "ELF identification changed");
        long headerSize = original.headerBytes().length;
        require(Arrays.equals(digest(input, headerSize, LARGE_SIZE - headerSize),
            digest(output, headerSize, LARGE_SIZE - headerSize)),
            "source payload outside the ELF header changed");
        for (Map.Entry<String, byte[]> entry : debug.entrySet()) {
            ElfImage.Section section = result.sections().stream()
                .filter(candidate -> candidate.name().equals(entry.getKey()))
                .findFirst().orElseThrow();
            require(section.offset > Integer.MAX_VALUE &&
                Arrays.equals(entry.getValue(), result.sectionData(section)),
                "large-offset debug payload is incorrect: " + entry.getKey());
        }
        for (String name : new String[] { ".text", ".symtab", ".strtab" }) {
            ElfImage.Section before = original.sections().stream()
                .filter(section -> section.name().equals(name)).findFirst().orElseThrow();
            ElfImage.Section after = result.sections().get(before.originalIndex);
            require(before.type == after.type && before.offset == after.offset &&
                before.address == after.address && before.size == after.size &&
                before.link == after.link && before.info == after.info,
                "original section identity/index changed: " + name);
        }
        byte[] outputHash = digest(output, 0, result.fileSize());
        Path repeated = directory.resolve("large.repeat.dbg");
        writer.write(input, repeated, debug);
        require(Files.size(repeated) == result.fileSize() &&
            Arrays.equals(outputHash, digest(repeated, 0, Files.size(repeated))),
            "large sidecar rerun was not byte-identical");
        Files.delete(repeated);
        require(Arrays.equals(inputHash, digest(input, 0, Files.size(input))),
            "writer modified the source ELF");

        checkAliases(writer, fixture, directory, debug);
        checkFailureCleanup(writer, fixture, directory, debug);
        checkElf32Overflow(writer, directory);
        requireNoTemporaryFiles(directory);
        System.out.println("max_heap_bytes=" + Runtime.getRuntime().maxMemory());
        System.out.println("input_bytes=" + original.fileSize());
        System.out.println("sidecar_bytes=" + result.fileSize());
        System.out.println("input_sha256=" + HexFormat.of().formatHex(inputHash));
        System.out.println("sidecar_sha256=" + HexFormat.of().formatHex(outputHash));
        System.out.println("large-elf-sidecar-smoke=PASS");
    }

    private static void checkAliases(MatchedElfSidecarWriter writer, Path fixture,
            Path directory, Map<String, byte[]> debug) throws Exception {
        byte[] before = Files.readAllBytes(fixture);
        Path hardlink = directory.resolve("input-hardlink");
        Files.createLink(hardlink, fixture);
        Path parentAlias = directory.resolve("input-parent-alias");
        Files.createSymbolicLink(parentAlias, fixture.getParent());
        for (Path alias : new Path[] { hardlink, parentAlias.resolve(fixture.getFileName()) }) {
            requireAliasRejected(writer, fixture, alias, debug);
        }
        require(Arrays.equals(before, Files.readAllBytes(fixture)),
            "alias rejection modified the original");
        Files.delete(hardlink);
        Files.delete(parentAlias);

        Path lexical = Files.createDirectory(directory.resolve("lexical"));
        Path physical = Files.createDirectory(directory.resolve("physical"));
        Path child = Files.createDirectory(physical.resolve("child"));
        Path lexicalInput = Files.copy(fixture, lexical.resolve("original.elf"));
        Path physicalInput = Files.copy(fixture, physical.resolve("original.elf"));
        byte[] physicalBytes = Arrays.copyOf(before, before.length + 1);
        physicalBytes[before.length] = 0x47;
        Files.write(physicalInput, physicalBytes);
        Files.createSymbolicLink(lexical.resolve("link"), child);
        Path physicalAlias = directory.resolve("physical-hardlink");
        Files.createLink(physicalAlias, physicalInput);
        Path ambiguousInput = lexical.resolve("link/../original.elf");
        requireAliasRejected(writer, ambiguousInput, physicalAlias, debug);
        // A symlink followed by '..' must retain filesystem traversal semantics.
        // The lexical sibling is a distinct file, not the source being copied.
        Path actualSourceOutput = directory.resolve("physical-source.dbg");
        writer.write(ambiguousInput, actualSourceOutput, debug);
        int headerSize = ElfImage.read(physicalInput).headerBytes().length;
        require(Arrays.equals(Arrays.copyOfRange(physicalBytes, headerSize, physicalBytes.length),
            Arrays.copyOfRange(Files.readAllBytes(actualSourceOutput), headerSize,
                physicalBytes.length)), "writer copied the lexical rather than physical input");
        Path lexicalOutput = lexical.resolve("result.dbg");
        byte[] sentinel = new byte[] { 9, 8, 7 };
        Files.write(lexicalOutput, sentinel);
        writer.write(fixture, lexical.resolve("link/../result.dbg"), debug);
        require(Files.isRegularFile(physical.resolve("result.dbg")) &&
            Arrays.equals(sentinel, Files.readAllBytes(lexicalOutput)),
            "writer redirected output to the lexical rather than physical parent");
        require(Arrays.equals(before, Files.readAllBytes(lexicalInput)) &&
            Arrays.equals(physicalBytes, Files.readAllBytes(physicalInput)),
            "ambiguous input alias damaged a source file");
    }

    private static void requireAliasRejected(MatchedElfSidecarWriter writer, Path input,
            Path alias, Map<String, byte[]> debug) throws IOException {
        try {
            writer.write(input, alias, debug);
            throw new AssertionError("writer accepted an input alias: " + alias);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("differ from input"),
                "unexpected alias rejection: " + expected.getMessage());
        }
    }

    private static void checkFailureCleanup(MatchedElfSidecarWriter writer, Path fixture,
            Path directory, Map<String, byte[]> debug) throws Exception {
        Path destination = directory.resolve("existing-directory");
        Files.createDirectory(destination);
        Path previous = destination.resolve("preserve");
        byte[] sentinel = new byte[] { 7, 8, 9 };
        Files.write(previous, sentinel);
        try {
            writer.write(fixture, destination, debug);
            throw new AssertionError("writer replaced a nonempty directory");
        }
        catch (IOException expected) {
            require(Arrays.equals(sentinel, Files.readAllBytes(previous)),
                "failed atomic publication damaged an existing destination");
            requireNoTemporaryFiles(directory);
        }
    }

    private static void checkElf32Overflow(MatchedElfSidecarWriter writer, Path directory)
            throws Exception {
        Path input = directory.resolve("overflow32.elf");
        byte[] bytes = new byte[52];
        ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        header.put(new byte[] { 0x7f, 'E', 'L', 'F', 1, 2, 1, 0 });
        header.putShort(16, (short) 2).putShort(18, (short) 8).putInt(20, 1);
        header.putShort(40, (short) 52).putShort(46, (short) 40);
        try (FileChannel file = FileChannel.open(input, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            file.write(ByteBuffer.wrap(bytes));
            file.position(0x1_0000_0000L);
            file.write(ByteBuffer.wrap(new byte[] { 0x34 }));
        }
        Path existing = directory.resolve("overflow32.dbg");
        byte[] previous = new byte[] { 2, 4, 6 };
        Files.write(existing, previous);
        Path absent = directory.resolve("overflow32.absent.dbg");
        for (Path output : new Path[] { existing, absent }) {
            try {
                writer.write(input, output, Map.of(".debug_info", new byte[] { 1 }));
                throw new AssertionError("ELF32 accepted an unrepresentable output offset");
            }
            catch (IllegalArgumentException expected) {
                require(expected.getMessage().contains("ELF32 output exceeds"),
                    "unexpected overflow rejection: " + expected.getMessage());
            }
        }
        require(Arrays.equals(previous, Files.readAllBytes(existing)) && !Files.exists(absent),
            "ELF32 overflow changed the final output");
        require(Files.size(input) == 0x1_0000_0001L &&
            Arrays.equals(bytes, ElfImage.read(input).headerBytes()),
            "ELF32 overflow changed its input");
        requireNoTemporaryFiles(directory);
        Files.delete(input);
    }

    private static byte[] digest(Path path, long offset, long size) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            input.skipNBytes(offset);
            byte[] block = new byte[1024 * 1024];
            long remaining = size;
            while (remaining != 0) {
                int count = input.read(block, 0, (int) Math.min(block.length, remaining));
                if (count < 0) {
                    throw new IOException("unexpected EOF while hashing " + path);
                }
                hash.update(block, 0, count);
                remaining -= count;
            }
        }
        return hash.digest();
    }

    private static void requireNoTemporaryFiles(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            require(files.noneMatch(path -> path.getFileName().toString()
                .startsWith(".ghidra-dwarf-forge-")), "failed write left a temporary sidecar");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
