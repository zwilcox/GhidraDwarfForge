package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Independent CIE/FDE framing and search-table fixtures, not a runtime unwinding claim. */
public final class SectionlessUnwindBoundarySmoke {
    private static int checks;
    private static final long BASE = 0x4000;
    private static final int TABLE = 0x200;

    private SectionlessUnwindBoundarySmoke() { }

    public static void main(String[] args) throws Exception { run(); }

    static void run() throws Exception {
        checks = 0;
        Path input = Files.createTempFile("forge-unwind-boundary-", ".elf");
        try {
            for (boolean wide : List.of(false, true)) {
                for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    for (int version : new int[] {1, 3, 4}) {
                        var fixture = fixture(wide, order, version, version == 4 ? 11 : 9, 3);
                        accepted(input, fixture);
                    }
                    var valid = fixture(wide, order, 4, 11, 3);
                    for (String fault : List.of("same-pc", "descending-pc", "same-fde", "before-frame",
                            "outside-frame-budget", "cie-underflow", "unindexed-fde")) {
                        byte[] bytes = valid.bytes().clone();
                        var b = ByteBuffer.wrap(bytes).order(order);
                        String diagnostic;
                        switch (fault) {
                            case "same-pc" -> {
                                b.putInt(TABLE + 20, b.getInt(TABLE + 12));
                                diagnostic = "unordered or duplicate unwind search-table entry";
                            }
                            case "descending-pc" -> {
                                b.putInt(TABLE + 20, b.getInt(TABLE + 12) - 1);
                                diagnostic = "unordered or duplicate unwind search-table entry";
                            }
                            case "same-fde" -> {
                                b.putInt(TABLE + 24, b.getInt(TABLE + 16));
                                diagnostic = "unordered or duplicate unwind search-table entry";
                            }
                            case "before-frame" -> {
                                b.putInt(TABLE + 16, (int) (BASE + valid.frame() - 1));
                                diagnostic = "unwind FDE outside bounded frame extent";
                            }
                            case "outside-frame-budget" -> {
                                b.putInt(TABLE + 16, (int) (BASE + valid.frame() + ElfImage.MAX_TABLE_BYTES));
                                diagnostic = "unwind FDE outside bounded frame extent";
                            }
                            case "cie-underflow" -> {
                                b.putInt(valid.frame() + valid.cieSize() + 4, -1);
                                diagnostic = "does not reference an earlier complete CIE";
                            }
                            case "unindexed-fde" -> {
                                b.putInt(TABLE + 8, 1);
                                b.putInt(TABLE + 12, b.getInt(TABLE + 28));
                                b.putInt(TABLE + 16, b.getInt(TABLE + 32));
                                diagnostic = "unwind records disagree with search-table boundaries";
                            }
                            default -> throw new AssertionError(fault);
                        }
                        refused(input, bytes, diagnostic);
                    }
                    refused(input, fixture(wide, order, 4, 10, 3).bytes(), "truncated version-4 unwind CIE");
                }
            }
            // The budget includes the CIE, not just the indexed FDEs. The larger
            // case remains within the search-table limit but exceeds the record cap.
            accepted(input, fixture(true, ByteOrder.LITTLE_ENDIAN, 4, 11, 262143));
            refused(input, fixture(true, ByteOrder.LITTLE_ENDIAN, 4, 11, 262144).bytes(),
                "unwind record count exceeds budget");
        }
        finally { Files.deleteIfExists(input); }
        System.out.println("sectionless-unwind-boundaries=PASS checks=" + checks);
    }

    private static void accepted(Path input, Fixture fixture) throws Exception {
        var messages = new ArrayList<String>();
        var result = inspect(input, fixture.bytes(), messages);
        require(result != null && messages.isEmpty(), "valid unwind framing rejected: " + messages);
        var section = result.section();
        require(section.name.equals(".eh_frame") && section.type == 1 && section.flags == 2 &&
            section.address == BASE + fixture.frame() && section.offset == fixture.frame() &&
            section.size == fixture.cieSize() + (long) fixture.count() * fixture.fdeSize(),
            "discovered extent must describe exactly the independent CIE/FDE records");
        require(result.initialLocations().size() == fixture.count(), "discovery lost indexed records");
        for (int index = 0; index < fixture.count(); index++) {
            long fde = BASE + fixture.frame() + fixture.cieSize() + (long) index * fixture.fdeSize();
            require(Objects.equals(result.initialLocations().get(fde), BASE + 0x100 + index * 16L),
                "search-table coordinate or initial location changed");
        }
        try { result.initialLocations().clear(); throw new AssertionError("mutable frame inventory"); }
        catch (UnsupportedOperationException expected) { checks++; }
    }

    private static void refused(Path input, byte[] bytes, String message) throws Exception {
        var diagnostics = new ArrayList<String>();
        require(inspect(input, bytes, diagnostics) == null, "malformed unwind framing accepted: " + message);
        require(diagnostics.size() == 1 && diagnostics.getFirst().contains(message),
            "wrong or missing bounded refusal: " + diagnostics);
    }

    private static SectionlessUnwind.Discovery inspect(Path input, byte[] bytes, List<String> diagnostics)
            throws Exception {
        Files.write(input, bytes);
        var before = Files.readAttributes(input, BasicFileAttributes.class);
        try {
            return SectionlessUnwind.inventoryFromProgramHeaders(ElfImage.read(input), () -> false, diagnostics::add);
        }
        finally {
            var after = Files.readAttributes(input, BasicFileAttributes.class);
            require(Arrays.equals(bytes, Files.readAllBytes(input)) && Objects.equals(before.fileKey(), after.fileKey()) &&
                before.lastModifiedTime().equals(after.lastModifiedTime()), "unwind discovery modified original input");
        }
    }

    private record Fixture(byte[] bytes, int frame, int cieSize, int fdeSize, int count) { }

    private static Fixture fixture(boolean wide, ByteOrder order, int version, int cieLength, int count) {
        int tableSize = 12 + count * 8;
        int frame = (TABLE + tableSize + 15) & ~15;
        int cieSize = 4 + cieLength;
        int pointer = wide ? 8 : 4;
        int fdeSize = 8 + pointer * 2;
        var b = ByteBuffer.allocate(frame + cieSize + count * fdeSize).order(order);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
        b.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 3)).putInt(20, 1);
        if (wide) {
            b.putLong(32, 64).putShort(52, (short) 64).putShort(54, (short) 56).putShort(56, (short) 2);
        }
        else {
            b.putInt(28, 52).putShort(40, (short) 52).putShort(42, (short) 32).putShort(44, (short) 2);
        }
        segment(b, wide, 0, 1, 0, b.capacity());
        segment(b, wide, 1, 0x6474e550, TABLE, tableSize);
        b.position(TABLE);
        b.put((byte) 1).put((byte) 3).put((byte) 3).put((byte) 3);
        b.putInt((int) (BASE + frame)).putInt(count);
        b.position(frame);
        b.putInt(cieLength).putInt(0).put((byte) version).put((byte) 0);
        if (version == 4) b.put((byte) pointer).put((byte) 0);
        b.put((byte) 1).put((byte) 0x78);
        if (b.position() < frame + cieSize) b.put((byte) (wide ? 16 : 8));
        for (int index = 0; index < count; index++) {
            int at = frame + cieSize + index * fdeSize;
            long pc = BASE + 0x100 + index * 16L;
            b.putInt(TABLE + 12 + index * 8, (int) pc).putInt(TABLE + 16 + index * 8, (int) (BASE + at));
            b.position(at);
            b.putInt(fdeSize - 4).putInt(at + 4 - frame);
            if (wide) b.putLong(pc).putLong(16);
            else b.putInt((int) pc).putInt(16);
        }
        return new Fixture(b.array(), frame, cieSize, fdeSize, count);
    }

    private static void segment(ByteBuffer b, boolean wide, int index, int type, int offset, int size) {
        int at = (wide ? 64 : 52) + index * (wide ? 56 : 32);
        b.putInt(at, type);
        if (wide) {
            b.putInt(at + 4, 5).putLong(at + 8, offset).putLong(at + 16, BASE + offset)
                .putLong(at + 32, size).putLong(at + 40, size).putLong(at + 48, 1);
        }
        else {
            b.putInt(at + 4, offset).putInt(at + 8, (int) BASE + offset).putInt(at + 16, size)
                .putInt(at + 20, size).putInt(at + 24, 5).putInt(at + 28, 1);
        }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
