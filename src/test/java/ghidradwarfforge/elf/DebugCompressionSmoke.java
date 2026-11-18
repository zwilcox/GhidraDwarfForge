package ghidradwarfforge.elf;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.InflaterInputStream;

/** Container/cancellation controls; arbitrary payload bytes are not valid DWARF. */
public final class DebugCompressionSmoke {
    private DebugCompressionSmoke() { }

    public static void main(String[] args) throws Exception {
        alignmentContracts();
        require(DebugSectionCompression.parse("none") == DebugSectionCompression.NONE, "none parsing");
        require(DebugSectionCompression.parse("zlib") == DebugSectionCompression.ZLIB, "zlib parsing");
        try {
            DebugSectionCompression.parse("zstd");
            throw new AssertionError("unsupported compression accepted");
        }
        catch (IllegalArgumentException expected) { }
        Path root = Files.createTempDirectory("forge-compression-");
        try {
            byte[] repeated = new byte[2 * 1024 * 1024];
            for (int index = 0; index < repeated.length; index++) {
                repeated[index] = (byte) (index % 71);
            }
            byte[] random = new byte[200_003];
            new Random(914).nextBytes(random);
            var debug = new LinkedHashMap<String, byte[]>();
            debug.put(".debug_info", repeated);
            debug.put(".debug_line", random);
            debug.put(".debug_str", new byte[] { 'a', 0 });
            debug.put(".debug_abbrev", new byte[0]);
            for (boolean wide : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    for (var shape : List.of(MatchedElfPrefixFixtures.Shape.NAMED,
                            MatchedElfPrefixFixtures.Shape.SECTIONLESS)) {
                        var pair = MatchedElfPrefixFixtures.create(root.resolve(wide + "-" + order + "-" + shape),
                            wide, order, shape);
                        byte[] original = Files.readAllBytes(pair.original());
                        Path plain = pair.original().resolveSibling("plain.dbg");
                        Path explicitPlain = pair.original().resolveSibling("explicit-plain.dbg");
                        new MatchedElfSidecarWriter().write(pair.original(), plain, debug);
                        new MatchedElfSidecarWriter(DebugSectionCompression.NONE).write(pair.original(), explicitPlain, debug);
                        require(Arrays.equals(Files.readAllBytes(plain), Files.readAllBytes(explicitPlain)), "default changed");
                        var writer = new MatchedElfSidecarWriter(DebugSectionCompression.ZLIB);
                        writer.write(pair.original(), pair.candidate(), debug);
                        byte[] first = Files.readAllBytes(pair.candidate());
                        writer.write(pair.original(), pair.candidate(), debug);
                        require(Arrays.equals(first, Files.readAllBytes(pair.candidate())), "nondeterministic compression");
                        require(Arrays.equals(original, Files.readAllBytes(pair.original())), "original changed");
                        require(MatchedElfPrefix.compare(pair.original(), pair.candidate()).status() ==
                            MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX, "target identity/prefix changed");
                        ElfImage image = ElfImage.read(pair.candidate());
                        for (var section : image.sections()) {
                            if (!debug.containsKey(section.name)) {
                                continue;
                            }
                            byte[] bytes = image.sectionData(section);
                            boolean compressed = section.name.equals(".debug_info");
                            require(section.flags == (compressed ? 0x800 : 0), "wrong section flags");
                            require(section.address == 0 && section.offset % section.alignment == 0, "address/alignment");
                            if (compressed) {
                                ByteBuffer header = ByteBuffer.wrap(bytes).order(order);
                                require(header.getInt() == 1, "not zlib");
                                if (wide) {
                                    require(header.getInt() == 0, "nonzero reserved header");
                                    require(header.getLong() == repeated.length && header.getLong() == 1, "wide header");
                                }
                                else {
                                    require(header.getInt() == repeated.length && header.getInt() == 1, "narrow header");
                                }
                                require(section.alignment == (wide ? 8 : 4), "compressed header alignment");
                                try (var inflated = new InflaterInputStream(new ByteArrayInputStream(bytes,
                                        header.position(), bytes.length - header.position()))) {
                                    require(Arrays.equals(repeated, inflated.readAllBytes()), "inflated payload differs");
                                }
                            }
                            else {
                                require(Arrays.equals(bytes, debug.get(section.name)), "plain fallback differs");
                            }
                        }
                        AtomicInteger polls = new AtomicInteger();
                        try {
                            writer.write(pair.original(), pair.candidate(), debug, () -> {
                                boolean compressing = StackWalker.getInstance().walk(frames -> frames.anyMatch(
                                    frame -> frame.getClassName().equals(DebugSectionCompression.class.getName())));
                                return compressing && polls.incrementAndGet() == 4;
                            });
                            throw new AssertionError("compression cancellation ignored");
                        }
                        catch (CancellationException expected) { }
                        require(polls.get() == 4, "cancellation did not reach the compressor");
                        require(Arrays.equals(first, Files.readAllBytes(pair.candidate())), "cancel replaced prior artifact");
                        require(Arrays.equals(original, Files.readAllBytes(pair.original())), "cancel changed original");
                        try (var paths = Files.list(pair.original().getParent())) {
                            require(paths.noneMatch(path -> path.getFileName().toString().endsWith(".tmp")), "partial artifact remains");
                        }
                    }
                }
            }
            // A completed retry after cancellation also exercises native deflater cleanup.
            require(DebugSectionCompression.ZLIB.encode(repeated, true, ByteOrder.BIG_ENDIAN,
                () -> false).compressed(), "retry failed");
            System.out.println("debug-compression-smoke=PASS layouts=8 cancellation=8");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void alignmentContracts() throws Exception {
        byte[] compressible = new byte[4096];
        Arrays.fill(compressible, (byte) 37);
        for (var encoding : DebugSectionCompression.values()) {
            for (boolean wide : List.of(false, true)) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    for (int alignment : new int[] {-1, 0, 3, 7, 16, Integer.MAX_VALUE}) {
                        try {
                            encoding.encode(compressible, wide, order, alignment, () -> false);
                            throw new AssertionError("unsupported plain alignment accepted: " + alignment);
                        }
                        catch (IllegalArgumentException expected) { }
                    }
                    for (int alignment : new int[] {1, 2, 4, 8}) {
                        var stored = encoding.encode(compressible, wide, order, alignment, () -> false);
                        if (encoding == DebugSectionCompression.NONE) {
                            require(stored.alignment() == alignment && !stored.compressed() &&
                                Arrays.equals(stored.bytes(), compressible), "plain alignment or payload changed");
                        }
                        else {
                            require(stored.compressed() && stored.alignment() == (wide ? 8 : 4), "compressed section alignment changed");
                            var header = ByteBuffer.wrap(stored.bytes()).order(order);
                            require((wide ? header.getLong(16) : Integer.toUnsignedLong(header.getInt(8))) == alignment,
                                "compressed header lost decoded alignment");
                            try (var decoded = new InflaterInputStream(new ByteArrayInputStream(stored.bytes(),
                                    wide ? 24 : 12, stored.bytes().length - (wide ? 24 : 12)))) {
                                require(Arrays.equals(decoded.readAllBytes(), compressible), "alignment changed compressed payload");
                            }
                        }
                        byte[] tiny = new byte[wide ? 24 : 12];
                        var fallback = encoding.encode(tiny, wide, order, alignment, () -> false);
                        require(!fallback.compressed() && fallback.alignment() == alignment && Arrays.equals(fallback.bytes(), tiny),
                            "header-sized fallback lost decoded alignment");
                    }
                }
            }
        }
        require(compressible[0] == 37 && compressible[4095] == 37, "alignment checks changed input");
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
