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
    private static OriginalFrameSources.Source identity(OriginalFrameSources.Source source,
            long offset, long stored, long decoded, String storedHash, String decodedHash) {
        return new OriginalFrameSources.Source(source.name(), offset, stored, decoded, source.address(),
            source.programHeaders(), storedHash, decodedHash, source.records());
    }

    private static void rejectRead(ElfImage image, OriginalFrameSources.Inventory inventory, String message)
            throws Exception {
        byte[] before = Files.readAllBytes(image.sourcePath());
        try {
            OriginalFrameSources.debugFrameBytes(image, inventory, () -> false);
            throw new AssertionError("accepted inconsistent original frame inventory: " + message);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(message), "wrong frame refusal: " + expected.getMessage());
        }
        require(Arrays.equals(before, Files.readAllBytes(image.sourcePath())), "frame refusal changed input");
    }

    /** Re-read exactly the inventoried bytes; filesystem metadata alone is insufficient. */
    private static void rereadControls(ElfImage image, OriginalFrameSources.Inventory inventory,
            byte[] expected, byte[] original) throws Exception {
        var source = inventory.sources().getFirst();
        require(Arrays.equals(expected, OriginalFrameSources.debugFrameBytes(image, inventory, () -> false)),
            "inventoried frame re-read changed decoded bytes");
        require(OriginalFrameSources.debugFrameBytes(image, new OriginalFrameSources.Inventory(List.of()),
            () -> false).length == 0, "absent inventoried frame acquired bytes");
        rejectRead(image, new OriginalFrameSources.Inventory(List.of(source, source)),
            "multiple original debug-frame sources");
        for (var changed : List.of(
                identity(source, source.offset() + 1, source.storedBytes(), source.decodedBytes(),
                    source.storedSha256(), source.decodedSha256()),
                identity(source, source.offset(), source.storedBytes() - 1, source.decodedBytes(),
                    source.storedSha256(), source.decodedSha256()))) {
            rejectRead(image, new OriginalFrameSources.Inventory(List.of(changed)),
                "original debug-frame section no longer matches inventory");
        }
        String wrongHash = (source.storedSha256().startsWith("0") ? "1" : "0") + source.storedSha256().substring(1);
        rejectRead(image, new OriginalFrameSources.Inventory(List.of(identity(source, source.offset(),
            source.storedBytes(), source.decodedBytes(), wrongHash, source.decodedSha256()))),
            "original stored frame bytes changed");
        wrongHash = (source.decodedSha256().startsWith("0") ? "1" : "0") + source.decodedSha256().substring(1);
        rejectRead(image, new OriginalFrameSources.Inventory(List.of(identity(source, source.offset(),
            source.storedBytes(), source.decodedBytes(), source.storedSha256(), wrongHash))),
            "original decoded frame bytes changed");
        for (long length : new long[] { source.decodedBytes() - 1, source.decodedBytes() + 1 }) {
            rejectRead(image, new OriginalFrameSources.Inventory(List.of(identity(source, source.offset(),
                source.storedBytes(), length, source.storedSha256(), source.decodedSha256()))),
                "original decoded frame bytes changed");
        }
        int[] visits = { 0 };
        OriginalFrameSources.debugFrameBytes(image, inventory, () -> { visits[0]++; return false; });
        for (int stop = 1; stop <= visits[0]; stop++) {
            int selected = stop;
            int[] current = { 0 };
            try {
                OriginalFrameSources.debugFrameBytes(image, inventory, () -> ++current[0] == selected);
                throw new AssertionError("frame re-read ignored cancellation at " + stop);
            }
            catch (CancellationException expectedCancellation) { checks++; }
            require(Arrays.equals(original, Files.readAllBytes(image.sourcePath())),
                "cancelled frame re-read changed input");
        }
        var attributes = Files.readAttributes(image.sourcePath(), java.nio.file.attribute.BasicFileAttributes.class);
        // A second real section header aliases exactly the original frame bytes.
        // Selecting the first matching header would hide the ambiguous inventory.
        byte[] ambiguous = original.clone();
        var fields = ByteBuffer.wrap(ambiguous).order(image.byteOrder());
        int table = Math.toIntExact(image.is64Bit() ? fields.getLong(40) : Integer.toUnsignedLong(fields.getInt(32)));
        int stride = Short.toUnsignedInt(fields.getShort(image.is64Bit() ? 58 : 46));
        require(Short.toUnsignedInt(fields.getShort(image.is64Bit() ? 60 : 48)) == 3,
            "ambiguity fixture requires null, strings and one frame section");
        System.arraycopy(ambiguous, table + 2 * stride, ambiguous, table + 3 * stride, stride);
        fields.putShort(image.is64Bit() ? 60 : 48, (short) 4);
        try {
            Files.write(image.sourcePath(), ambiguous);
            rejectRead(ElfImage.read(image.sourcePath()), inventory, "ambiguous original debug-frame section");
        }
        finally {
            Files.write(image.sourcePath(), original);
            Files.setLastModifiedTime(image.sourcePath(), attributes.lastModifiedTime());
        }
        byte[] changed = original.clone();
        changed[Math.toIntExact(source.offset() + source.storedBytes() - 1)] ^= 1;
        try {
            Files.write(image.sourcePath(), changed);
            Files.setLastModifiedTime(image.sourcePath(), attributes.lastModifiedTime());
            var after = Files.readAttributes(image.sourcePath(), java.nio.file.attribute.BasicFileAttributes.class);
            require(after.size() == attributes.size() && after.lastModifiedTime().equals(attributes.lastModifiedTime())
                && java.util.Objects.equals(after.fileKey(), attributes.fileKey()),
                "content-change fixture must retain metadata identity to exercise hashing");
            rejectRead(image, inventory, "original stored frame bytes changed");
        }
        finally {
            Files.write(image.sourcePath(), original);
            Files.setLastModifiedTime(image.sourcePath(), attributes.lastModifiedTime());
        }
        require(Arrays.equals(expected, OriginalFrameSources.debugFrameBytes(image, inventory, () -> false)),
            "restored source or cancelled re-read poisoned subsequent bytes");
        require(Arrays.equals(original, Files.readAllBytes(image.sourcePath())), "re-read controls changed original");
    }

    private static void compressionMetadata(Path path, boolean wide, ByteOrder order) throws Exception {
        byte[] frame = plain(wide ? 8 : 4, order);
        for (boolean gnu : List.of(false, true)) {
            String name = gnu ? ".zdebug_frame" : ".debug_frame";
            byte[] packed = compressed(frame, wide, order, gnu, false);
            // Every magic byte matters; GNU lengths are always big endian,
            // independently of the containing ELF's byte order and class.
            for (int fault = 0; fault < (gnu ? 5 : wide ? 2 : 0); fault++) {
                byte[] bad = packed.clone();
                var fields = ByteBuffer.wrap(bad).order(gnu ? ByteOrder.BIG_ENDIAN : order);
                String diagnostic;
                if (gnu && fault < 4) {
                    bad[fault] ^= 1;
                    diagnostic = "invalid GNU compressed frame header";
                }
                else if (gnu || fault == 0) {
                    fields.putLong(gnu ? 4 : 8, Long.MIN_VALUE);
                    diagnostic = "original frame decoded-byte budget exceeded";
                }
                else {
                    fields.putLong(16, Long.MIN_VALUE);
                    diagnostic = "invalid original frame uncompressed alignment";
                }
                var image = fixture(path, wide, order, List.of(new Section(name, 1, gnu ? 0 : 0x800, bad)));
                byte[] before = Files.readAllBytes(path);
                try {
                    OriginalFrameSources.inspect(image, () -> false);
                    throw new AssertionError("accepted invalid compression metadata: " + diagnostic);
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains(diagnostic), "wrong metadata refusal: " + expected);
                }
                require(Arrays.equals(before, Files.readAllBytes(path)), "metadata refusal changed original ELF");
            }
        }
        // Zero requests no alignment. ELF32 ch_addralign is unsigned, so its
        // highest power of two must not become a negative Java integer.
        for (long alignment : new long[] {0, 1, 2, 0x80000000L, wide ? 1L << 62 : 1L << 30}) {
            byte[] packed = compressed(frame, wide, order, false, false);
            var fields = ByteBuffer.wrap(packed).order(order);
            if (wide) fields.putLong(16, alignment);
            else fields.putInt(8, (int) alignment);
            var image = fixture(path, wide, order, List.of(new Section(".debug_frame", 1, 0x800, packed)));
            byte[] before = Files.readAllBytes(path);
            try {
                var inventory = OriginalFrameSources.inspect(image, () -> false);
                var records = inventory.sources().getFirst().records().frames();
                require(records.size() == 1 && records.getFirst().address() == 0x1000 &&
                    records.getFirst().size() == 32, "alignment changed frame inventory");
                require(Arrays.equals(frame, OriginalFrameSources.debugFrameBytes(image, inventory, () -> false)),
                    "alignment changed decoded frame bytes");
            }
            catch (IllegalArgumentException rejected) {
                throw new AssertionError("valid compression alignment rejected: " + alignment, rejected);
            }
            require(Arrays.equals(before, Files.readAllBytes(path)), "alignment inspection changed original ELF");
        }
        var eh = fixture(path, wide, order, List.of(new Section(".eh_frame", 1, 0x800,
            compressed(frame, wide, order, false, false))));
        try {
            OriginalFrameSources.inspect(eh, () -> false);
            throw new AssertionError("accepted compressed EH frame");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("compressed allocated/EH frame source is unsupported"),
                "compressed EH frame reached record parsing: " + expected);
        }
    }

    private static void check(Path path, boolean wide, ByteOrder order) throws Exception {
        compressionMetadata(path, wide, order);
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
            rereadControls(image, result, plain, original);
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
                    new Section(name, 0x70000001, flags, stored),
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
        if (wide && order == ByteOrder.LITTLE_ENDIAN) {
            for (String name : List.of(".extra_unwind", ".eh_frame.extra", "")) {
                reject(() -> OriginalFrameSources.inspect(fixture(path, wide, order,
                    List.of(new Section(name, 0x70000001, 2, new byte[] {0, 0, 0, 0}))), () -> false));
            }
        }
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
        require(OriginalFrameSources.debugFrameBytes(ElfImage.read(path),
            new OriginalFrameSources.Inventory(List.of(discovered)), () -> false).length == 0,
            "EH-only inventory acquired a debug-frame section");
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
        byte[] typed = named.clone();
        ByteBuffer.wrap(typed).order(order).putShort(18, (short) 62)
            .putInt(0x900 + shSize + 4, 0x70000001);
        Files.write(path, typed);
        if (wide && order == ByteOrder.LITTLE_ENDIAN) {
            var typedImage = ElfImage.read(path);
            var typedSource = OriginalFrameSources.inspect(typedImage, () -> false).sources().getFirst();
            require(typedSource.records().equals(discovered.records()) && typedSource.programHeaders(),
                "processor frame section type changed established runtime inventory");
            cancelEvery(typedImage);
            require(Arrays.equals(typed, Files.readAllBytes(path)), "typed frame inventory changed input");
            // A named source without a program-header search table is valid too.
            byte[] noHeader = typed.clone();
            var noHeaderFields = ByteBuffer.wrap(noHeader).order(order);
            noHeaderFields.putLong(32, 0).putShort(54, (short) 0).putShort(56, (short) 0);
            Files.write(path, noHeader);
            var namedOnly = OriginalFrameSources.inspect(ElfImage.read(path), () -> false).sources().getFirst();
            require(namedOnly.records().equals(discovered.records()) && !namedOnly.programHeaders(),
                "typed named-only frame source changed records");
            for (int machine : List.of(3, 8, 40, 183, 243)) {
                byte[] foreign = typed.clone();
                ByteBuffer.wrap(foreign).order(order).putShort(18, (short) machine);
                Files.write(path, foreign);
                reject(() -> OriginalFrameSources.inspect(ElfImage.read(path), () -> false));
            }
        }
        else reject(() -> OriginalFrameSources.inspect(ElfImage.read(path), () -> false));
        byte[] unknown = typed.clone();
        ByteBuffer.wrap(unknown).order(order).putInt(0x900 + shSize + 4, 0x70000002);
        Files.write(path, unknown);
        reject(() -> OriginalFrameSources.inspect(ElfImage.read(path), () -> false));
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
