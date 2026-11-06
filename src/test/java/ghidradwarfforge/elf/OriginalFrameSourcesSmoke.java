package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.zip.Deflater;

import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.unwind.CallFramePlan;
import ghidradwarfforge.unwind.CallFramePlan.*;

public final class OriginalFrameSourcesSmoke {
    private record Section(String name, int type, long flags, byte[] data) { }
    private static int checks;
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void require(boolean ok, String message) { if (!ok) throw new AssertionError(message); checks++; }
    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("unknown frame source accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void cancelEvery(ElfImage image) throws Exception {
        int[] polls = {0};
        var expected = OriginalFrameSources.inspect(image, () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop; int[] count = {0};
            try {
                OriginalFrameSources.inspect(image, () -> ++count[0] == selected);
                throw new AssertionError("program-header inventory ignored cancellation");
            }
            catch (CancellationException cancelled) { checks++; }
        }
        require(OriginalFrameSources.inspect(image, () -> false).equals(expected),
            "cancelled program-header inventory poisoned retry");
    }
    private static byte[] plain(int width, ByteOrder order) {
        Map<Integer, Rule> rules = Map.of(0, new CfaValue(0), 1, new AtCfaOffset(-width));
        var row = new Row(0x1000, new Cfa(0, width), rules);
        return DwarfDebugFrame.build(new CallFramePlan(width, order, 1, Set.of(0, 1),
            Map.of(0, new Undefined(), 1, new Undefined()), List.of(new Frame(0x1000, 32, List.of(row)))), () -> false);
    }
    private static byte[] compressed(byte[] plain, boolean wide, ByteOrder order, boolean gnu, boolean dictionary) {
        var deflater = new Deflater();
        byte[] zip;
        try {
            if (dictionary) deflater.setDictionary(new byte[] {1, 2, 3, 4});
            deflater.setInput(plain); deflater.finish();
            var out = new ByteArrayOutputStream(); byte[] buffer = new byte[128];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer); if (count == 0) throw new AssertionError("fixture deflate stalled");
                out.write(buffer, 0, count);
            }
            zip = out.toByteArray();
        }
        finally { deflater.end(); }
        int header = gnu || !wide ? 12 : 24;
        var out = ByteBuffer.allocate(header + zip.length).order(gnu ? ByteOrder.BIG_ENDIAN : order);
        if (gnu) out.put(new byte[] {'Z', 'L', 'I', 'B'}).putLong(plain.length);
        else {
            out.putInt(1);
            if (wide) out.putInt(0).putLong(plain.length).putLong(8);
            else out.putInt(plain.length).putInt(4);
        }
        out.put(zip); return out.array();
    }
    private static void section(ByteBuffer out, int at, boolean wide, int name, int type, long flags,
            long address, long offset, long size) {
        out.putInt(at, name).putInt(at + 4, type);
        if (wide) out.putLong(at + 8, flags).putLong(at + 16, address).putLong(at + 24, offset)
            .putLong(at + 32, size).putLong(at + 48, 1);
        else out.putInt(at + 8, (int) flags).putInt(at + 12, (int) address).putInt(at + 16, (int) offset)
            .putInt(at + 20, (int) size).putInt(at + 32, 1);
    }
    private static ElfImage fixture(Path path, boolean wide, ByteOrder order, List<Section> sections) throws Exception {
        int count = sections.size() + 2, shSize = wide ? 64 : 40;
        byte[] names = ("\0.shstrtab\0" + String.join("\0", sections.stream().map(Section::name).toList()) + "\0")
            .getBytes(StandardCharsets.US_ASCII);
        var out = ByteBuffer.allocate(0x1000 + sections.stream().mapToInt(s -> s.data().length).sum()).order(order);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0});
        out.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 8)).putInt(20, 1);
        if (wide) out.putLong(40, 0x200).putShort(52, (short) 64).putShort(58, (short) shSize)
            .putShort(60, (short) count).putShort(62, (short) 1);
        else out.putInt(32, 0x200).putShort(40, (short) 52).putShort(46, (short) shSize)
            .putShort(48, (short) count).putShort(50, (short) 1);
        out.position(0x100); out.put(names);
        section(out, 0x200 + shSize, wide, 1, 3, 0, 0, 0x100, names.length);
        int offset = 0x1000, name = 11, index = 2;
        for (var value : sections) {
            section(out, 0x200 + shSize * index++, wide, name, value.type(), value.flags(), 0, offset, value.data().length);
            out.position(offset); out.put(value.data()); offset += value.data().length; name += value.name().length() + 1;
        }
        Files.write(path, out.array()); return ElfImage.read(path);
    }
    private static void check(Path path, boolean wide, ByteOrder order) throws Exception {
        byte[] plain = plain(wide ? 8 : 4, order);
        for (String mode : List.of("plain", "gabi", "gnu")) {
            boolean gnu = mode.equals("gnu"), packed = !mode.equals("plain");
            String name = gnu ? ".zdebug_frame" : ".debug_frame";
            long flags = mode.equals("gabi") ? 0x800 : 0;
            byte[] stored = packed ? compressed(plain, wide, order, gnu, false) : plain;
            var spec = new Section(name, 1, flags, stored);
            var image = fixture(path, wide, order, List.of(spec));
            byte[] original = Files.readAllBytes(path);
            var result = OriginalFrameSources.inspect(image, () -> false);
            var source = result.sources().getFirst();
            require(result.sources().size() == 1 && source.decodedBytes() == plain.length && source.storedBytes() == stored.length,
                "wrong source sizes");
            require(source.records().frames().getFirst().address() == 0x1000 &&
                source.records().frames().getFirst().size() == 32 && !source.programHeaders(), "wrong source range");
            require(Arrays.equals(original, Files.readAllBytes(path)), "source reader changed input");
            try { result.sources().clear(); throw new AssertionError("mutable sources"); }
            catch (UnsupportedOperationException expected) { checks++; }
            int[] polls = {0};
            OriginalFrameSources.inspect(image, () -> { polls[0]++; return false; });
            for (int stop = 1; stop <= polls[0]; stop++) {
                int selected = stop; int[] seen = {0};
                try {
                    OriginalFrameSources.inspect(image, () -> ++seen[0] == selected);
                    throw new AssertionError("source inventory ignored cancellation");
                }
                catch (CancellationException expected) { checks++; }
            }
            require(OriginalFrameSources.inspect(image, () -> false).equals(result), "cancelled inventory poisoned retry");
            for (var invalid : List.of(
                    new Section(name, 8, flags, stored),
                    new Section(name, 1, flags | (packed ? 2 : 0), stored))) {
                if (invalid.type() == 1 && !packed) continue;
                reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order, List.of(invalid)), () -> false));
            }
            reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order, List.of(spec, spec)), () -> false));
            if (packed) {
                int header = gnu || !wide ? 12 : 24;
                for (String fault : List.of("short", "magic", "large", "size-small", "size-large", "checksum",
                        "truncated", "trailing", "dictionary", "alignment", "reserved", "mixed")) {
                    if (gnu && List.of("alignment", "reserved").contains(fault) || !wide && fault.equals("reserved")) continue;
                    byte[] bad = stored.clone();
                    var fields = ByteBuffer.wrap(bad).order(gnu ? ByteOrder.BIG_ENDIAN : order);
                    int sizeAt = gnu || !wide ? 4 : 8;
                    switch (fault) {
                        case "short" -> bad = Arrays.copyOf(bad, header - 1);
                        case "magic" -> bad[0] ^= 7;
                        case "large" -> { if (gnu || wide) fields.putLong(sizeAt, 0x4000001L); else fields.putInt(sizeAt, 0x4000001); }
                        case "size-small", "size-large" -> {
                            long count = plain.length + (fault.equals("size-small") ? -1 : 1);
                            if (gnu || wide) fields.putLong(sizeAt, count); else fields.putInt(sizeAt, (int) count);
                        }
                        case "checksum" -> bad[bad.length - 1] ^= 1;
                        case "truncated" -> bad = Arrays.copyOf(bad, bad.length - 1);
                        case "trailing" -> bad = Arrays.copyOf(bad, bad.length + 1);
                        case "dictionary" -> bad = compressed(plain, wide, order, gnu, true);
                        case "alignment" -> { if (wide) fields.putLong(16, 3); else fields.putInt(8, 3); }
                        case "reserved" -> fields.putInt(4, 1);
                        case "mixed" -> { }
                        default -> throw new AssertionError(fault);
                    }
                    Section invalid = new Section(fault.equals("mixed") ? ".zdebug_frame" : name, 1,
                        fault.equals("mixed") ? 0x800 : flags, bad);
                    reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order, List.of(invalid)), () -> false));
                }
            }
        }
        for (boolean gnu : List.of(false, true)) {
            var packedEmpty = new Section(gnu ? ".zdebug_frame" : ".debug_frame", 1, gnu ? 0 : 0x800,
                compressed(new byte[0], wide, order, gnu, false));
            require(OriginalFrameSources.inspect(fixture(path, wide, order, List.of(packedEmpty)), () -> false)
                .sources().getFirst().records().frames().isEmpty(), "empty compressed frame source invented records");
        }
        reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order, List.of(
            new Section(".debug_frame", 1, 0, plain),
            new Section(".zdebug_frame", 1, 0, compressed(plain, wide, order, true, false)))), () -> false));
        var relocating = fixture(path, wide, order, List.of(new Section(".debug_frame", 1, 0, plain)));
        byte[] unlinked = Files.readAllBytes(path);
        ByteBuffer.wrap(unlinked).order(order).putShort(16, (short) 1);
        Files.write(path, unlinked);
        reject(() -> OriginalFrameSources.inspect(ElfImage.read(path), () -> false));
        var changing = fixture(path, wide, order, List.of(new Section(".debug_frame", 1, 0, plain)));
        int[] observed = {0};
        OriginalFrameSources.inspect(changing, () -> { observed[0]++; return false; });
        int[] current = {0};
        try {
            OriginalFrameSources.inspect(changing, () -> {
                if (++current[0] == observed[0] - 1) {
                    try { Files.setLastModifiedTime(path, FileTime.fromMillis(Files.getLastModifiedTime(path).toMillis() + 10000)); }
                    catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
                }
                return false;
            });
            throw new AssertionError("change during source hashing accepted");
        }
        catch (java.io.IOException expected) { checks++; }
        var empty = fixture(path, wide, order, List.of());
        require(OriginalFrameSources.inspect(empty, () -> false).sources().isEmpty(), "invented absent source");
        var header = new Section(".eh_frame_hdr", 1, 2, new byte[] {1, 0, 0, 0});
        reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order, List.of(header)), () -> false));
        var stale = fixture(path, wide, order, List.of(new Section(".debug_frame", 1, 0, plain)));
        Files.setLastModifiedTime(path, FileTime.fromMillis(Files.getLastModifiedTime(path).toMillis() + 10000));
        try { OriginalFrameSources.inspect(stale, () -> false); throw new AssertionError("stale image accepted"); }
        catch (java.io.IOException expected) { checks++; }
        byte[] sectionless = SectionlessUnwindSmoke.fixture(wide, order, 0x3b);
        Files.write(path, sectionless);
        cancelEvery(ElfImage.read(path));
        var discovered = OriginalFrameSources.inspect(ElfImage.read(path), () -> false).sources().getFirst();
        require(discovered.programHeaders() && discovered.offset() == 0x300 &&
            discovered.records().frames().getFirst().address() == 0x4100, "wrong sectionless frame source");
        byte[] named = Arrays.copyOf(sectionless, 0x1000);
        var fields = ByteBuffer.wrap(named).order(order);
        byte[] names = "\0.eh_frame\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);
        fields.position(0xb00); fields.put(names);
        if (wide) fields.putLong(40, 0x900).putShort(58, (short) 64).putShort(60, (short) 3).putShort(62, (short) 2);
        else fields.putInt(32, 0x900).putShort(46, (short) 40).putShort(48, (short) 3).putShort(50, (short) 2);
        int shSize = wide ? 64 : 40;
        section(fields, 0x900 + shSize, wide, 1, 1, 2, 0x4300, 0x300, 44);
        section(fields, 0x900 + 2 * shSize, wide, 11, 3, 0, 0, 0xb00, names.length);
        Files.write(path, named);
        cancelEvery(ElfImage.read(path));
        require(SectionlessUnwind.find(ElfImage.read(path), () -> false, ignored -> { }) == null,
            "legacy sectionless API changed behavior");
        require(OriginalFrameSources.inspect(ElfImage.read(path), () -> false).sources().getFirst().programHeaders(),
            "named/program-header agreement missing");
        for (String fault : List.of("offset", "address", "short", "tail", "header", "header-pc")) {
            byte[] bad = named.clone(); var change = ByteBuffer.wrap(bad).order(order);
            if (fault.equals("tail")) bad[0x328] = 1;
            else if (fault.equals("header")) bad[0x200] = 2;
            else if (fault.equals("header-pc")) change.putInt(0x20c, 0x4101 - 0x4200);
            else section(change, 0x900 + shSize, wide, 1, 1, 2,
                fault.equals("address") ? 0x4301 : 0x4300, fault.equals("offset") ? 0x301 : 0x300,
                fault.equals("short") ? 39 : 44);
            Files.write(path, bad);
            reject(() -> OriginalFrameSources.inspect(ElfImage.read(path), () -> false));
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            var inventory = OriginalFrameSources.inspect(ElfImage.read(Path.of(args[0])), () -> false);
            for (var source : inventory.sources()) {
                System.out.printf("source %s %x %x %x %x %s %s %s%n", source.name(), source.offset(),
                    source.storedBytes(), source.decodedBytes(), source.address(), source.programHeaders(),
                    source.storedSha256(), source.decodedSha256());
                for (var frame : source.records().frames()) System.out.printf("frame %x %x %x %x %s%n",
                    frame.offset(), frame.cieOffset(), frame.address(), frame.size(), frame.signalFrame());
            }
            return;
        }
        Path root = Files.createTempDirectory("forge-frame-sources-");
        try {
            for (boolean wide : List.of(false, true)) for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                check(root.resolve("fixture"), wide, order);
            }
        }
        finally {
            try (var files = Files.walk(root)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("original-frame-sources-smoke=PASS checks=" + checks);
    }
}
