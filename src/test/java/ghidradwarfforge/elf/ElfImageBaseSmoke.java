package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import ghidradwarfforge.AddressNormalizer;

/** Verifies the ELF base used by pinned Ghidra's PT_LOAD address convention. */
public final class ElfImageBaseSmoke {
    private record Segment(int type, long offset, long address) {
    }

    private ElfImageBaseSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-elf-image-base-");
        try {
            for (boolean elf64 : new boolean[] { false, true }) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    Path input = directory.resolve((elf64 ? "elf64-" : "elf32-") + order);
                    assertBase(input, elf64, order, 0x401000,
                        new Segment(1, 0x1000, 0x401000),
                        new Segment(1, 0x2000, 0x402000));
                    assertBase(input, elf64, order, 0x400000,
                        new Segment(1, 0, 0x400000),
                        new Segment(1, 0x2000, 0x402000));
                    assertBase(input, elf64, order, 0,
                        new Segment(1, 0, 0), new Segment(1, 0x2000, 0x2000));
                    // A valid PIE load can start at VA zero while its file
                    // payload begins on a later aligned page.
                    assertBase(input, elf64, order, 0,
                        new Segment(1, 0x1000, 0), new Segment(1, 0x3000, 0x2000));
                    // Segment offsets and non-load program headers cannot
                    // override the minimum load VA used by Ghidra.
                    assertBase(input, elf64, order, 0x401000,
                        new Segment(4, 0, 0),
                        new Segment(1, 0x1000, 0x401000),
                        new Segment(1, 0x3000, 0x402000));
                    Files.write(input, image(elf64, order, new Segment(4, 0, 0)));
                    try {
                        ElfImage.read(input).preferredImageBase();
                        throw new AssertionError("ELF without a PT_LOAD was accepted");
                    }
                    catch (IllegalArgumentException expected) {
                        if (!expected.getMessage().contains("no PT_LOAD")) {
                            throw expected;
                        }
                    }
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
        System.out.println("elf-image-base-smoke=PASS");
    }

    private static void assertBase(Path input, boolean elf64, ByteOrder order, long expected,
            Segment... segments) throws Exception {
        Files.write(input, image(elf64, order, segments));
        long actual = ElfImage.read(input).preferredImageBase();
        assertEquals(expected, actual);
        long linkAddress = expected + 0x20;
        for (long rebase : new long[] { 0, 0x2000000, -0x100000 }) {
            long delta = AddressNormalizer.rebaseDelta(expected + rebase, actual);
            assertEquals(rebase, delta);
            assertEquals(linkAddress, AddressNormalizer.toElfAddress(linkAddress + rebase, delta));
        }
    }

    private static byte[] image(boolean elf64, ByteOrder order, Segment... segments) {
        int headerSize = elf64 ? 64 : 52;
        int entrySize = elf64 ? 56 : 32;
        ByteBuffer result = ByteBuffer.allocate(0x4000).order(order);
        result.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (elf64 ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        result.position(16);
        result.putShort((short) 2).putShort((short) (elf64 ? 62 : 8)).putInt(1);
        if (elf64) {
            result.putLong(0).putLong(headerSize).putLong(0);
        }
        else {
            result.putInt(0).putInt(headerSize).putInt(0);
        }
        result.putInt(0).putShort((short) headerSize).putShort((short) entrySize);
        result.putShort((short) segments.length);
        result.position(headerSize);
        for (Segment segment : segments) {
            if (elf64) {
                result.putInt(segment.type()).putInt(5).putLong(segment.offset());
                result.putLong(segment.address()).putLong(segment.address());
                result.putLong(16).putLong(16).putLong(0x1000);
            }
            else {
                result.putInt(segment.type()).putInt((int) segment.offset());
                result.putInt((int) segment.address()).putInt((int) segment.address());
                result.putInt(16).putInt(16).putInt(5).putInt(0x1000);
            }
        }
        return result.array();
    }

    private static void assertEquals(long expected, long actual) {
        if (expected != actual) {
            throw new AssertionError("expected 0x" + Long.toHexString(expected) +
                " but found 0x" + Long.toHexString(actual));
        }
    }
}
