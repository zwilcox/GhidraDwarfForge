package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent frame carriers exercise framing, address encodings and transactional publication. */
public final class SectionlessUnwindSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-sectionless-unwind-");
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (int form : List.of(0, 2, 3, 4, 10, 11, 12)) {
                    for (int application : List.of(0, 0x10, 0x30)) {
                        // Negative PC-relative values need signed encodings.
                        if (application != 0 && form < 10) continue;
                        positive(root, fixture(wide, order, application | form));
                    }
                }
                byte[] valid = fixture(wide, order, 0x3b);
                for (String mutation : List.of("version", "pointer-form", "table-form", "count-relative",
                        "count-zero", "count-large", "header-short", "header-mapping", "frame-outside",
                        "frame-bss", "length-zero", "length-extended", "length-excessive", "cie-pointer",
                        "cie-short", "cie-version", "fde-short", "fde-in-middle", "unindexed-fde", "truncated-record", "duplicate-header",
                        "overlapping-load", "overflow-load", "table-truncated")) {
                    byte[] bad = valid.clone();
                    mutate(bad, mutation, wide, order);
                    Path path = root.resolve("bad");
                    Files.write(path, bad);
                    var messages = new ArrayList<String>();
                    require(SectionlessUnwind.find(ElfImage.read(path), () -> false, messages::add) == null,
                        "accepted " + mutation);
                    require(messages.size() == 1 && messages.getFirst().startsWith("Omitted original .eh_frame:"),
                        "missing diagnostic " + mutation);
                    Path output = root.resolve("omitted.dbg");
                    if (mutation.equals("overflow-load")) {
                        Files.writeString(output, "previous");
                        try {
                            new MatchedElfSidecarWriter().write(ElfImage.read(path), output,
                                Map.of(".debug_info", new byte[] {1}), List.of(), () -> false);
                            throw new AssertionError("invalid load allocation accepted");
                        }
                        catch (IllegalArgumentException expected) {
                            require(Files.readString(output).equals("previous"), "invalid load replaced prior output");
                        }
                        continue;
                    }
                    new MatchedElfSidecarWriter().write(ElfImage.read(path), output,
                        Map.of(".debug_info", new byte[] {1}), List.of(), () -> false, ignored -> { });
                    require(ElfImage.read(output).sections().stream().noneMatch(s -> s.name.equals(".eh_frame")),
                        "published unsupported metadata " + mutation);
                    require(Arrays.equals(Files.readAllBytes(path), bad), "malformed input changed");
                }
                cancellation(root, valid);
                byte[] absent = valid.clone();
                ByteBuffer.wrap(absent).order(order).putInt(wide ? 120 : 84, 0);
                Path path = root.resolve("absent");Files.write(path, absent);
                require(SectionlessUnwind.find(ElfImage.read(path), () -> false,
                    ignored -> { throw new AssertionError("absent header diagnosed as malformed"); }) == null,
                    "invented absent unwind header");
                Path changed = root.resolve("changed");Files.write(changed, valid);
                var image = ElfImage.read(changed);
                Files.setLastModifiedTime(changed, FileTime.fromMillis(Files.getLastModifiedTime(changed).toMillis() + 10000));
                try {
                    SectionlessUnwind.find(image, () -> false, ignored -> { });
                    throw new AssertionError("changed source accepted");
                }
                catch (IOException expected) { checks++; }
            }
        }
        System.out.println("sectionless-unwind-smoke=PASS checks=" + checks);
    }

    private static void positive(Path root, byte[] bytes) throws Exception {
        Path input = root.resolve("positive");Files.write(input, bytes);
        var image = ElfImage.read(input);
        var section = SectionlessUnwind.find(image, () -> false,
            message -> { throw new AssertionError(message); });
        require(section != null && section.address == 0x4300 && section.offset == 0x300 && section.size == 40,
            "incorrect original frame extent");
        require(section.type == 1 && section.flags == 2 && section.alignment == 1, "incorrect frame semantics");
        Path output = root.resolve("positive.dbg");
        for (int repeat = 0; repeat < 2; repeat++) {
            new MatchedElfSidecarWriter().write(image, output, Map.of(".debug_info", new byte[] {1}),
                List.of(new ElfLocalFunctionSymbol("alias", 0x4100, 16, 1)), () -> false);
            var result = ElfImage.read(output);
            var recovered = result.sections().stream().filter(s -> s.name.equals(".eh_frame")).findFirst().orElseThrow();
            require(Arrays.equals(result.sectionData(recovered), Arrays.copyOfRange(bytes, 0x300, 0x328)),
                "frame payload changed");
            require(result.sections().get(1).name.equals(".forge.load.0"), "load symbol index changed");
            require(Arrays.equals(Files.readAllBytes(input), bytes), "original changed");
            if (repeat == 0) Files.copy(output, root.resolve("first.dbg"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            else require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(root.resolve("first.dbg"))),
                "nondeterministic metadata");
        }
    }

    private static void cancellation(Path root, byte[] bytes) throws Exception {
        Path input = root.resolve("cancel");Files.write(input, bytes);
        for (int threshold : List.of(1, 6, 12, 20, 30)) {
            var count = new AtomicInteger();
            Path output = root.resolve("cancel.dbg");Files.writeString(output, "previous");
            try {
                new MatchedElfSidecarWriter().write(ElfImage.read(input), output,
                    Map.of(".debug_info", new byte[] {1}), List.of(), () -> count.incrementAndGet() >= threshold);
                throw new AssertionError("cancellation ignored at " + threshold);
            }
            catch (CancellationException expected) {
                require(Files.readString(output).equals("previous"), "cancellation replaced prior output");
                require(Arrays.equals(Files.readAllBytes(input), bytes), "cancel changed input");
            }
        }
    }

    private static byte[] fixture(boolean wide, ByteOrder order, int encoding) {
        ByteBuffer b = ByteBuffer.allocate(0x800).order(order);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1), (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
        b.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 3)).putInt(20, 1);
        if (wide) {
            b.putLong(32, 64).putShort(52, (short) 64).putShort(54, (short) 56).putShort(56, (short) 3);
        }
        else {
            b.putInt(28, 52).putShort(40, (short) 52).putShort(42, (short) 32).putShort(44, (short) 3);
        }
        segment(b, wide, 0, 1, 0, 0x4000, 0x800, 0x900);
        b.position(0x200);b.put((byte) 1).put((byte) encoding).put((byte) 3).put((byte) encoding);
        encoded(b, wide, encoding, 0x4300);b.putInt(1);
        encoded(b, wide, encoding, 0x4100);encoded(b, wide, encoding, 0x4314);
        segment(b, wide, 1, 0x6474e550, 0x200, 0x4200, b.position() - 0x200, b.position() - 0x200);
        b.position(0x300);b.putInt(16).putInt(0).put((byte) 1).put((byte) 'z').put((byte) 'R').put((byte) 0);
        b.put((byte) 1).put((byte) 0x78).put((byte) 8).put((byte) 1).put((byte) 0x1b);
        b.position(0x314);b.putInt(16).putInt(24).putInt(0x4100 - 0x431c).putInt(16).putInt(0);
        return b.array();
    }

    private static void encoded(ByteBuffer b, boolean wide, int encoding, long address) {
        long value = address - ((encoding & 0xf0) == 0x10 ? 0x4000 + b.position() :
            (encoding & 0xf0) == 0x30 ? 0x4200 : 0);
        int form = encoding & 15;
        int width = form == 0 ? wide ? 8 : 4 : form == 2 || form == 10 ? 2 : form == 3 || form == 11 ? 4 : 8;
        if (width == 2) b.putShort((short) value);
        else if (width == 4) b.putInt((int) value);
        else b.putLong(value);
    }

    private static void segment(ByteBuffer b, boolean wide, int index, int type, long offset,
            long address, long fileSize, long memorySize) {
        int at = (wide ? 64 : 52) + index * (wide ? 56 : 32);
        b.putInt(at, type);
        if (wide) {
            b.putInt(at + 4, 5).putLong(at + 8, offset).putLong(at + 16, address)
                .putLong(at + 32, fileSize).putLong(at + 40, memorySize).putLong(at + 48, 1);
        }
        else {
            b.putInt(at + 4, (int) offset).putInt(at + 8, (int) address).putInt(at + 16, (int) fileSize)
                .putInt(at + 20, (int) memorySize).putInt(at + 24, 5).putInt(at + 28, 1);
        }
    }

    private static void mutate(byte[] bytes, String mutation, boolean wide, ByteOrder order) {
        ByteBuffer b = ByteBuffer.wrap(bytes).order(order);
        switch (mutation) {
            case "version" -> b.put(0x200, (byte) 2);
            case "pointer-form" -> b.put(0x201, (byte) 0x9b);
            case "table-form" -> b.put(0x203, (byte) 1);
            case "count-relative" -> b.put(0x202, (byte) 0x13);
            case "count-zero" -> b.putInt(0x208, 0);
            case "count-large" -> b.putInt(0x208, 262145);
            case "header-short" -> segment(b, wide, 1, 0x6474e550, 0x200, 0x4200, 3, 3);
            case "header-mapping" -> segment(b, wide, 1, 0x6474e550, 0x201, 0x4200, 20, 20);
            case "frame-outside" -> b.putInt(0x204, 0x1000);
            case "frame-bss" -> b.putInt(0x210, 0x680);
            case "length-zero" -> b.putInt(0x314, 0);
            case "length-extended" -> b.putInt(0x314, -1);
            case "length-excessive" -> b.putInt(0x314, 0x4000001);
            case "cie-pointer" -> b.putInt(0x318, 23);
            case "cie-short" -> b.putInt(0x300, 4);
            case "cie-version" -> b.put(0x308, (byte) 0);
            case "fde-short" -> b.putInt(0x314, 4);
            case "fde-in-middle" -> b.putInt(0x210, 0x118);
            case "unindexed-fde" -> { b.putInt(0x300, 16);b.putInt(0x304, 4); }
            case "truncated-record" -> b.putInt(0x300, 24);
            case "duplicate-header" -> segment(b, wide, 2, 0x6474e550, 0x200, 0x4200, 20, 20);
            case "overlapping-load" -> segment(b, wide, 2, 1, 0x200, 0x4200, 32, 32);
            case "overflow-load" -> segment(b, wide, 0, 1, 0, wide ? Long.MAX_VALUE - 1 : 0xfffffff0L, 0x800, 0x900);
            case "table-truncated" -> segment(b, wide, 1, 0x6474e550, 0x200, 0x4200, 16, 16);
            default -> throw new AssertionError(mutation);
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
