package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;

/** Real ELF class/order/load layouts, including sectionless and sparse inputs. */
public final class ElfCodeBytesSmoke {
    private record Segment(long address, long offset, long fileSize, long memorySize, int flags) { }
    private static final byte[] CODE = {1, 2, 3, 4};
    private static int checks;
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); checks++; }
    private static void reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid code agreement accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void changed(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("changed/closed original read accepted"); }
        catch (IOException expected) { checks++; }
    }
    private static ElfImage fixture(Path path, boolean wide, ByteOrder order, List<Segment> segments) throws Exception {
        int header = wide ? 64 : 52, entry = wide ? 56 : 32;
        var data = ByteBuffer.allocate(0x240).order(order);
        data.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0, 0});
        data.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 8)).putInt(20, 1);
        if (wide) data.putLong(32, segments.isEmpty() ? 0 : header).putShort(52, (short) header)
            .putShort(54, (short) entry).putShort(56, (short) segments.size());
        else data.putInt(28, segments.isEmpty() ? 0 : header).putShort(40, (short) header)
            .putShort(42, (short) entry).putShort(44, (short) segments.size());
        for (int index = 0; index < segments.size(); index++) {
            Segment segment = segments.get(index); int at = header + index * entry;
            data.putInt(at, 1);
            if (wide) data.putInt(at + 4, segment.flags()).putLong(at + 8, segment.offset())
                .putLong(at + 16, segment.address()).putLong(at + 32, segment.fileSize())
                .putLong(at + 40, segment.memorySize()).putLong(at + 48, 1);
            else data.putInt(at + 4, (int) segment.offset()).putInt(at + 8, (int) segment.address())
                .putInt(at + 16, (int) segment.fileSize()).putInt(at + 20, (int) segment.memorySize())
                .putInt(at + 24, segment.flags()).putInt(at + 28, 1);
        }
        Files.write(path, data.array());
        try (var channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            for (Segment segment : segments) if (segment.fileSize() > 0) {
                if (segment.fileSize() != CODE.length) throw new AssertionError("fixture payload size");
                channel.write(ByteBuffer.wrap(CODE), segment.offset());
            }
        }
        return ElfImage.read(path);
    }
    private static void check(Path path, boolean wide, ByteOrder order) throws Exception {
        Segment ordinary = new Segment(0x401000, 0x200, 4, 8, 5);
        var image = fixture(path, wide, order, List.of(ordinary));
        byte[] before = Files.readAllBytes(path);
        require(image.sections().isEmpty(), "sectionless fixture has sections");
        try (var bytes = ElfCodeBytes.open(image, () -> false)) {
            var first = bytes.requireMatches(0x401000, CODE, () -> false);
            require(first.fileOffset() == 0x200 && first.bytes() == 4 && first.sha256().length() == 64, "wrong first mapping");
            require(bytes.requireMatches(0x401003, new byte[] {4}, () -> false).fileOffset() == 0x203, "file end byte mapping");
            reject(() -> bytes.requireMatches(0x401003, new byte[] {4, 0}, () -> false));
            reject(() -> bytes.requireMatches(0x401004, new byte[] {0}, () -> false));
            reject(() -> bytes.requireMatches(0x400fff, CODE, () -> false));
            reject(() -> bytes.requireMatches(0x200, CODE, () -> false));
            reject(() -> bytes.requireMatches(0x401000, new byte[] {9, 2, 3, 4}, () -> false));
            reject(() -> bytes.requireMatches(0x401000, new byte[0], () -> false));
            reject(() -> bytes.requireMatches(0x401000, new byte[4097], () -> false));
            reject(() -> bytes.requireMatches(-1, CODE, () -> false));
            reject(() -> bytes.requireMatches(Long.MAX_VALUE, CODE, () -> false));
        }
        require(Arrays.equals(before, Files.readAllBytes(path)), "code comparison changed original");
        var closed = ElfCodeBytes.open(image, () -> false); closed.close();
        changed(() -> closed.requireMatches(0x401000, CODE, () -> false));
        int[] polls = {0};
        try (var bytes = ElfCodeBytes.open(image, () -> { polls[0]++; return false; })) {
            bytes.requireMatches(0x401000, CODE, () -> { polls[0]++; return false; });
        }
        for (int limit = 1; limit <= polls[0]; limit++) {
            int stop = limit; int[] seen = {0};
            try (var bytes = ElfCodeBytes.open(image, () -> ++seen[0] == stop)) {
                bytes.requireMatches(0x401000, CODE, () -> ++seen[0] == stop);
                throw new AssertionError("code agreement ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        try (var bytes = ElfCodeBytes.open(image, () -> false)) {
            require(bytes.requireMatches(0x401000, CODE, () -> false).fileOffset() == 0x200, "cancelled read poisoned retry");
        }
        for (List<Segment> invalid : List.of(
                List.<Segment>of(),
                List.of(new Segment(0x401000, 0x200, 4, 4, 4)),
                List.of(new Segment(0x401000, 0x200, 0, 4, 5)),
                List.of(ordinary, new Segment(0x401002, 0x210, 4, 4, 5)),
                List.of(ordinary, new Segment(0x400000, 0x210, 0, 0x2000, 4)),
                List.of(new Segment(0x401000, 0x200, 4, 4, 5), new Segment(0x401004, 0x210, 4, 4, 5)))) {
            var other = fixture(path, wide, order, invalid);
            try (var bytes = ElfCodeBytes.open(other, () -> false)) {
                reject(() -> bytes.requireMatches(0x401000, invalid.size() == 2 && invalid.get(1).address() == 0x401004 ?
                    new byte[] {1, 2, 3, 4, 1} : CODE, () -> false));
            }
        }
        var disjoint = fixture(path, wide, order, List.of(new Segment(0x401010, 0x210, 4, 4, 5), ordinary));
        try (var bytes = ElfCodeBytes.open(disjoint, () -> false)) {
            require(bytes.requireMatches(0x401011, new byte[] {2, 3}, () -> false).fileOffset() == 0x211,
                "unordered program headers mapped to wrong file bytes");
        }
        var stale = fixture(path, wide, order, List.of(ordinary));
        try (var bytes = ElfCodeBytes.open(stale, () -> false)) {
            FileTime old = Files.getLastModifiedTime(path);
            Files.setLastModifiedTime(path, FileTime.fromMillis(old.toMillis() + 10_000));
            changed(() -> bytes.requireMatches(0x401000, CODE, () -> false));
        }
        var overflowing = fixture(path, wide, order,
            List.of(new Segment(wide ? Long.MAX_VALUE - 1 : 0xffff_fffeL, 0x200, 4, 4, 5)));
        reject(() -> { try (var unused = ElfCodeBytes.open(overflowing, () -> false)) { } });
        if (wide) {
            var sparse = fixture(path, true, order, List.of(new Segment(0x401000, 0x8000_0200L, 4, 4, 5)));
            require(sparse.fileSize() > Integer.MAX_VALUE, "sparse fixture is too small");
            try (var bytes = ElfCodeBytes.open(sparse, () -> false)) {
                require(bytes.requireMatches(0x401000, CODE, () -> false).fileOffset() == 0x8000_0200L,
                    "large file offset was truncated or entire file buffered");
            }
        }
    }
    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-code-bytes-");
        try {
            for (boolean wide : List.of(false, true)) for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                check(directory.resolve(wide + "-" + order + ".elf"), wide, order);
            }
        }
        finally {
            try (var files = Files.walk(directory)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("elf-code-bytes-smoke=PASS checks=" + checks);
    }
}
