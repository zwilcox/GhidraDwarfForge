package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;


/** Hand-built boundary cases; native compiler/loader cases are a separate oracle. */
public final class ElfRelocationEffectsSmoke {
    private static int checks;
    private interface Checked { void run() throws Exception; }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
    private static void reject(Checked action, String message) throws Exception {
        try { action.run(); throw new AssertionError("accepted: " + message); }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(message), "wrong rejection: " + expected.getMessage() + " expected " + message);
        }
    }
    private static ByteBuffer buffer(byte[] bytes) { return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN); }
    private static void segment(ByteBuffer b, int index, int type, long offset, long address, long file, long memory) {
        int at = 64 + 56 * index;
        b.putInt(at, type).putInt(at + 4, 6).putLong(at + 8, offset).putLong(at + 16, address)
            .putLong(at + 24, address).putLong(at + 32, file).putLong(at + 40, memory).putLong(at + 48, 1);
    }
    private static byte[] fixture(int machine, long type, long symbol, long address) {
        var b = ByteBuffer.allocate(0x1000).order(ByteOrder.LITTLE_ENDIAN);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0});
        b.putShort(16, (short) 2).putShort(18, (short) machine).putInt(20, 1).putLong(32, 64)
            .putShort(52, (short) 64).putShort(54, (short) 56).putShort(56, (short) 2).putShort(58, (short) 64);
        long[][] tags = {{7, 0x1400}, {8, 24}, {9, 24}, {6, 0x1500}, {11, 24}, {4, 0x1600},
            {0x6ffffffbL, 0}, {1, 0}, {0, 0}};
        for (int i = 0; i < tags.length; i++) b.putLong(0x200 + i * 16, tags[i][0]).putLong(0x208 + i * 16, tags[i][1]);
        segment(b, 0, 1, 0, 0x1000, 0x1000, 0x2000);
        segment(b, 1, 2, 0x200, 0x1200, tags.length * 16, tags.length * 16);
        b.putLong(0x400, address).putLong(0x408, (symbol << 32) | type).putLong(0x410, 0);
        b.put(0x51c, (byte) 0x11).putShort(0x51e, (short) 1).putLong(0x520, address).putLong(0x528, 37);
        b.putInt(0x600, 1).putInt(0x604, 2).putInt(0x608, 1); // SysV bucket and two terminated chains.
        return b.array();
    }
    private static ElfRelocationEffects inspect(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes);
        var identity = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class);
        try { return ElfRelocationEffects.inspect(ElfImage.read(path), () -> false); }
        finally {
            var after = Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class);
            require(Arrays.equals(bytes, Files.readAllBytes(path)) && identity.lastModifiedTime().equals(after.lastModifiedTime()) &&
                java.util.Objects.equals(identity.fileKey(), after.fileKey()), "inspection changed original input");
        }
    }
    private static OriginalFrameSources.Inventory frames(long offset, long size) {
        return new OriginalFrameSources.Inventory(List.of(new OriginalFrameSources.Source(".eh_frame", offset,
            size, size, 0x1000 + offset, false, "", "", null)));
    }
    private static void variants(Path path, int machine, long relative, long descriptor, long copy, long indirect) throws Exception {
        rangeAndMetadataBoundaries(path, machine, relative, copy);
        var effects = inspect(path, fixture(machine, relative, 0, 0x1800));
        require(effects.writes().size() == 1 && effects.writes().getFirst().size() == 8, "relative footprint");
        effects.requireUnchanged(0x17ff, 1, () -> false);
        effects.requireUnchanged(0x1808, 1, () -> false);
        reject(() -> effects.requireUnchanged(0x17ff, 2, () -> false), "overlaps a runtime relocation");
        reject(() -> effects.requireUnchanged(0x1807, 1, () -> false), "overlaps a runtime relocation");
        effects.requireUnchanged(frames(0x808, 1), () -> false);
        reject(() -> effects.requireUnchanged(frames(0x807, 1), () -> false), "frame source overlaps");
        var tls = inspect(path, fixture(machine, descriptor, 1, 0x1800));
        require(tls.writes().getFirst().size() == 16, "descriptor pair width");
        reject(() -> tls.requireUnchanged(0x180f, 1, () -> false), "overlaps a runtime relocation");
        tls.requireUnchanged(0x1810, 1, () -> false);
        var copied = inspect(path, fixture(machine, copy, 1, 0x1803));
        require(copied.writes().getFirst().size() == 37 && copied.writes().getFirst().fileOffset() == 0x803,
            "COPY byte-aligned symbol-sized footprint");
        reject(() -> copied.requireUnchanged(0x1827, 1, () -> false), "overlaps a runtime relocation");
        copied.requireUnchanged(0x1828, 1, () -> false);
        byte[] bytes = fixture(machine, copy, 1, 0x2100);
        var bss = inspect(path, bytes);
        require(bss.writes().getFirst().fileBytes() == 0 && bss.writes().getFirst().fileOffset() == -1, "BSS write file extent");
        bytes = fixture(machine, copy, 1, 0x1ff0);
        require(inspect(path, bytes).writes().getFirst().fileBytes() == 16, "partial file/BSS write");
        bytes = fixture(machine, copy, 1, 0x1800);
        buffer(bytes).putLong(0x410, 91); // COPY uses st_size, not the explicit addend.
        require(inspect(path, bytes).writes().getFirst().size() == 37, "COPY addend changed footprint");
        bytes = fixture(machine, copy, 1, 0x1800);
        buffer(bytes).putLong(0x200, 17).putLong(0x210, 18).putLong(0x218, 16).putLong(0x220, 19).putLong(0x228, 16);
        require(inspect(path, bytes).writes().getFirst().size() == 37, "REL COPY implicit addend rejected");
        bytes = fixture(machine, copy, 1, 0x1800);
        buffer(bytes).putShort(16, (short) 3).putLong(0x268, 0x08000000).putShort(56, (short) 3);
        segment(buffer(bytes), 2, 3, 0x380, 0x1380, 8, 8);
        require(inspect(path, bytes).writes().getFirst().size() == 37, "PIE COPY footprint");
        byte[] pie = bytes.clone(); buffer(pie).putLong(0x268, 0);
        reject(() -> inspect(path, pie), "COPY relocation is outside");
        byte[] noInterpreter = bytes.clone(); buffer(noInterpreter).putShort(56, (short) 2);
        reject(() -> inspect(path, noInterpreter), "COPY relocation is outside");
        for (String fault : List.of("unknown-type", "resolver", "ifunc", "bad-symbol", "copy-zero-symbol", "copy-value",
                "copy-undefined", "copy-function", "copy-too-big", "text", "table-write", "dynamic-write", "symbol-write",
                "unknown-tag", "unknown-flags", "unknown-mode", "unknown-segment", "unknown-profile", "past-load", "ambiguous")) {
            byte[] damaged = fixture(machine, copy, 1, 0x1800); var out = buffer(damaged);
            String diagnostic = switch (fault) {
                case "unknown-type" -> { out.putLong(0x408, 0xdead); yield "unsupported runtime relocation"; }
                case "resolver" -> { out.putLong(0x408, indirect); yield "resolver has unproved effects"; }
                case "ifunc" -> { out.put(0x51c, (byte) 0x1a); yield "IFUNC"; }
                case "bad-symbol" -> { out.putLong(0x408, (2L << 32) | copy); yield "symbol index exceeds"; }
                case "copy-zero-symbol" -> { out.putLong(0x408, copy); yield "COPY relocation is outside"; }
                case "copy-value" -> { out.putLong(0x520, 0x1810); yield "matching ordinary defined object"; }
                case "copy-undefined" -> { out.putShort(0x51e, (short) 0); yield "matching ordinary defined object"; }
                case "copy-function" -> { out.put(0x51c, (byte) 0x12); yield "matching ordinary defined object"; }
                case "copy-too-big" -> { out.putLong(0x528, Long.MAX_VALUE); yield "exceeds one allocated load extent"; }
                case "text" -> { out.putInt(68, 5); yield "non-writable storage"; }
                case "table-write" -> { out.putLong(0x400, 0x1400).putLong(0x520, 0x1400); yield "rewrite relocation/symbol metadata"; }
                case "dynamic-write" -> { out.putLong(0x400, 0x1200).putLong(0x520, 0x1200); yield "rewrite relocation/symbol metadata"; }
                case "symbol-write" -> { out.putLong(0x400, 0x1500).putLong(0x520, 0x1500); yield "rewrite relocation/symbol metadata"; }
                case "unknown-tag" -> { out.putLong(0x270, 0x70001234); yield "unknown unwind relocation metadata"; }
                case "unknown-flags" -> { out.putLong(0x270, 30).putLong(0x278, 0x80); yield "unknown dynamic flags"; }
                case "unknown-mode" -> { out.putLong(0x268, 0x80000000L); yield "unreviewed dynamic loader mode"; }
                case "unknown-segment" -> { out.putShort(56, (short) 3); segment(out, 2, 0x70000000, 0, 0, 0, 0); yield "unreviewed program-header"; }
                case "unknown-profile" -> { out.putShort(18, (short) 8); yield "no audited ordinary"; }
                case "past-load" -> { out.putLong(0x400, 0x2ff0).putLong(0x520, 0x2ff0); yield "exceeds one allocated load"; }
                case "ambiguous" -> { out.putShort(56, (short) 3); segment(out, 2, 1, 0x800, 0x1800, 0x100, 0x100); yield "ambiguous load mappings"; }
                default -> throw new AssertionError(fault);
            };
            reject(() -> inspect(path, damaged), diagnostic);
        }
        bytes = fixture(machine, relative, 0, 0x1800);
        buffer(bytes).putInt(68, 5).putLong(0x270, 22);
        require(inspect(path, bytes).writes().size() == 1, "declared text relocation rejected");
        var text = inspect(path, bytes);
        reject(() -> text.requireUnchanged(0x1800, 8, () -> false), "overlaps a runtime relocation");
        // Nested writes exercise the prefix maximum, not just the nearest start.
        bytes = fixture(machine, copy, 1, 0x1800);
        buffer(bytes).putLong(0x218, 48).putLong(0x418, 0x1808).putLong(0x420, relative);
        var nested = inspect(path, bytes);
        reject(() -> nested.requireUnchanged(0x1824, 1, () -> false), "overlaps a runtime relocation");
        nested.requireUnchanged(0x1825, 1, () -> false);
        bytes = fixture(machine, relative, 0, 0x1900);
        buffer(bytes).putLong(0x270, 3).putLong(0x278, 0x1800);
        var got = inspect(path, bytes);
        require(got.writes().stream().anyMatch(write -> write.type() == -2 && write.address() == 0x1808 && write.size() == 16),
            "reserved GOT loader footprint");
        reject(() -> got.requireUnchanged(0x1817, 1, () -> false), "overlaps a runtime relocation");
        got.requireUnchanged(0x1818, 1, () -> false);
        bytes = fixture(machine, relative, 0, 0x1900);
        buffer(bytes).putLong(0x270, 21).putLong(0x278, 0);
        var debug = inspect(path, bytes);
        require(debug.writes().stream().anyMatch(write -> write.role().equals("loader-DT_DEBUG") &&
            write.address() == 0x1278 && write.size() == 8 && write.recordOffset() == 0x278), "DT_DEBUG loader footprint");
        reject(() -> debug.requireUnchanged(0x127f, 1, () -> false), "overlaps a runtime relocation");
        debug.requireUnchanged(0x1280, 1, () -> false);
        if (machine == 62) {
            bytes = fixture(machine, relative, 0, 0x1900);
            buffer(bytes).putLong(0x270, 0x6ffffef7L).putLong(0x278, 0x1800);
            var resolverSlot = inspect(path, bytes);
            reject(() -> resolverSlot.requireUnchanged(0x1807, 1, () -> false), "overlaps a runtime relocation");
            resolverSlot.requireUnchanged(0x1808, 1, () -> false);
        }
        // Named dynsym size is independent count evidence when GNU hashing
        // supplies no definition chains; removing it must not invent a count.
        byte[] named = fixture(machine, descriptor, 1, 0x1800);
        var namedBuffer = buffer(named);
        namedBuffer.putLong(0x250, 1).putLong(40, 0x800).putShort(60, (short) 2);
        namedBuffer.putInt(0x844, 11).putLong(0x848, 2).putLong(0x850, 0x1500).putLong(0x858, 0x500)
            .putLong(0x860, 48).putLong(0x870, 8).putLong(0x878, 24);
        require(inspect(path, named).writes().getFirst().size() == 16, "named dynsym count missing");
        byte[] noCount = named.clone(); buffer(noCount).putLong(40, 0).putShort(60, (short) 0);
        reject(() -> inspect(path, noCount), "complete PT_DYNAMIC symbol count unavailable");
        byte[] disagree = named.clone(); buffer(disagree).putLong(0x250, 4).putLong(0x258, 0x1600).putLong(0x860, 72);
        reject(() -> inspect(path, disagree), "symbol count sources disagree");
        byte[] offsetDisagree = named.clone(); buffer(offsetDisagree).putLong(0x858, 0x501);
        reject(() -> inspect(path, offsetDisagree), "symbol section and tags disagree");
        byte[] relr = fixture(machine, relative, 0, 0x1800);
        buffer(relr).putLong(0x200, 36).putLong(0x210, 35).putLong(0x218, 16).putLong(0x220, 37)
            .putLong(0x228, 8).putLong(0x400, 0x1800).putLong(0x408, 3);
        var packed = inspect(path, relr);
        require(packed.writes().size() == 2 && packed.writes().get(1).address() == 0x1808 &&
            packed.writes().get(1).size() == 8, "RELR expanded write extent");
        byte[] counted = fixture(machine, relative, 0, 0x1800);
        buffer(counted).putLong(0x270, 0x6ffffff9L).putLong(0x278, 1);
        require(inspect(path, counted).writes().size() == 1, "valid RELACOUNT prefix");
        byte[] tooMany = counted.clone(); buffer(tooMany).putLong(0x278, 2);
        reject(() -> inspect(path, tooMany), "prefix count exceeds");
        byte[] wrongPrefix = counted.clone(); buffer(wrongPrefix).putLong(0x408, descriptor);
        reject(() -> inspect(path, wrongPrefix), "prefix contains a non-relative");
        byte[] none = fixture(machine, 0, 0xffffffffL, 0x1800);
        require(inspect(path, none).writes().isEmpty(), "NONE must not dereference its ignored symbol");
        byte[] empty = fixture(machine, relative, 0, 0x1800);
        buffer(empty).putShort(56, (short) 1);
        require(inspect(path, empty).writes().isEmpty(), "static absent dynamic table");
        Files.write(path, fixture(machine, descriptor, 1, 0x1800)); var image = ElfImage.read(path);
        int[] polls = {0};
        ElfRelocationEffects.inspect(image, () -> { polls[0]++; return false; });
        for (int at = 1; at <= polls[0]; at++) {
            final int stop = at; int[] current = {0};
            try { ElfRelocationEffects.inspect(image, () -> ++current[0] == stop); throw new AssertionError("missed cancellation " + at); }
            catch (CancellationException expected) { checks++; }
        }
        require(ElfRelocationEffects.inspect(image, () -> false).writes().size() == 1, "cancelled reader did not recover");
        int[] mutationPoll = {0};
        try {
            ElfRelocationEffects.inspect(image, () -> {
                if (++mutationPoll[0] == polls[0]) {
                    try {
                        Files.setLastModifiedTime(path, java.nio.file.attribute.FileTime.fromMillis(
                            Files.getLastModifiedTime(path).toMillis() + 1000));
                    }
                    catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
                }
                return false;
            });
            throw new AssertionError("late input identity mutation accepted");
        }
        catch (java.io.IOException expected) { require(expected.getMessage().contains("ELF input changed"), "wrong identity failure"); }
        try { effects.writes().clear(); throw new AssertionError("mutable write inventory"); }
        catch (UnsupportedOperationException expected) { checks++; }
        try { effects.requireUnchanged(new OriginalFrameSources.Inventory(List.of()), () -> true); throw new AssertionError("empty source cancellation"); }
        catch (CancellationException expected) { checks++; }
    }

    private static void rangeAndMetadataBoundaries(Path path, int machine, long relative, long copy) throws Exception {
        // The expected file intersection follows the fixture's independently
        // encoded LOAD [0x1000,0x3000), with file backing only to 0x2000.
        for (long address : List.of(0x1800L, 0x1ff8L, 0x2000L, 0x2100L)) {
            for (long size : List.of(0L, 1L, 7L, 8L, 37L, 256L)) {
                byte[] bytes = fixture(machine, copy, 1, address);
                buffer(bytes).putLong(0x528, size);
                var effects = inspect(path, bytes);
                long fileSize = Math.max(0, Math.min(address + size, 0x2000) - Math.min(address, 0x2000));
                long offset = address - 0x1000;
                if (size == 0) require(effects.writes().isEmpty(), "zero-size COPY invented a write");
                else {
                    var expected = new ElfRelocationEffects.Write("DT_RELA", 0x400, copy, 1, address, size,
                        fileSize == 0 ? -1 : offset, fileSize);
                    require(effects.writes().equals(List.of(expected)), "wrong file/BSS COPY extent");
                }
                for (long start : List.of(address - 1, address, address + size / 2, address + size, address + size + 1)) {
                    for (long length : List.of(1L, 2L, 257L)) {
                        boolean overlap = size > 0 && start < address + size && address < start + length;
                        if (overlap) reject(() -> effects.requireUnchanged(start, length, () -> false), "overlaps a runtime relocation");
                        else { effects.requireUnchanged(start, length, () -> false); checks++; }
                        long fileStart = start - 0x1000;
                        boolean fileOverlap = fileSize > 0 && fileStart < offset + fileSize && offset < fileStart + length;
                        if (fileOverlap) reject(() -> effects.requireFileUnchanged(fileStart, length, () -> false), "frame source overlaps");
                        else { effects.requireFileUnchanged(fileStart, length, () -> false); checks++; }
                    }
                    effects.requireFileUnchanged(start - 0x1000, 0, () -> false);
                    checks++;
                }
            }
        }
        var effects = inspect(path, fixture(machine, relative, 0, 0x1800));
        for (long[] extent : List.of(new long[] {0, 0}, new long[] {0, -1})) {
            reject(() -> effects.requireUnchanged(extent[0], extent[1], () -> false), "invalid protected address extent");
        }
        for (long[] extent : List.of(new long[] {-1, 1}, new long[] {0, -1})) {
            reject(() -> effects.requireFileUnchanged(extent[0], extent[1], () -> false), "negative relocation extent");
        }
        effects.requireUnchanged(Long.MAX_VALUE, 2, () -> false);
        effects.requireUnchanged(-1, 1, () -> false);
        reject(() -> effects.requireUnchanged(-1, 2, () -> false), "extent overflows");
        reject(() -> effects.requireFileUnchanged(Long.MAX_VALUE, 1, () -> false), "extent overflows");
        effects.requireUnchanged(Long.MAX_VALUE - 1, 1, () -> false);
        effects.requireFileUnchanged(Long.MAX_VALUE, 0, () -> false);

        for (int info : List.of(0x10, 0x11, 0x20, 0x21)) {
            byte[] bytes = fixture(machine, copy, 1, 0x1800);
            buffer(bytes).put(0x51c, (byte) info);
            require(inspect(path, bytes).writes().getFirst().size() == 37, "ordinary global/weak COPY omitted");
        }
        for (int info : List.of(0x00, 0x01, 0x30, 0x31)) {
            byte[] bytes = fixture(machine, copy, 1, 0x1800);
            buffer(bytes).put(0x51c, (byte) info);
            reject(() -> inspect(path, bytes), "matching ordinary defined object");
        }
        for (int section : List.of(0xff00, 0xfff1, 0xfff2, 0xffff)) {
            byte[] bytes = fixture(machine, copy, 1, 0x1800);
            buffer(bytes).putShort(0x51e, (short) section);
            reject(() -> inspect(path, bytes), "matching ordinary defined object");
        }
        byte[] unaligned = fixture(machine, relative, 0, 0x1801);
        if (machine == 183) reject(() -> inspect(path, unaligned), "violates the selected ABI alignment");
        else require(inspect(path, unaligned).writes().getFirst().address() == 0x1801, "AMD64 byte-aligned write omitted");

        for (boolean rela : List.of(false, true)) {
            byte[] counted = fixture(machine, relative, 0, 0x1800);
            if (!rela) buffer(counted).putLong(0x200, 17).putLong(0x210, 18).putLong(0x218, 16)
                .putLong(0x220, 19).putLong(0x228, 16);
            buffer(counted).putLong(0x270, rela ? 0x6ffffff9L : 0x6ffffffaL).putLong(0x278, 1);
            require(inspect(path, counted).writes().size() == 1, "valid relative prefix omitted");
            byte[] negative = counted.clone(); buffer(negative).putLong(0x278, -1);
            reject(() -> inspect(path, negative), "prefix count exceeds its table");
            // The opposite prefix tag has no corresponding table. A zero
            // count grants no writes; a positive count cannot claim a prefix.
            buffer(counted).putLong(0x270, rela ? 0x6ffffffaL : 0x6ffffff9L).putLong(0x278, 0);
            require(inspect(path, counted).writes().size() == 1, "empty absent-table prefix changed writes");
            buffer(counted).putLong(0x278, 1);
            reject(() -> inspect(path, counted), "prefix count exceeds its table");
        }
        byte[] repeated = fixture(machine, relative, 0, 0x1800);
        buffer(repeated).putLong(0x260, 1);
        require(inspect(path, repeated).writes().size() == 1, "repeated DT_NEEDED rejected");
        buffer(repeated).putLong(0x260, 30).putLong(0x270, 30);
        reject(() -> inspect(path, repeated), "duplicate ordinary loader metadata");
        byte[] text = fixture(machine, relative, 0, 0x1800);
        buffer(text).putInt(68, 5).putLong(0x270, 30).putLong(0x278, 4);
        require(inspect(path, text).writes().size() == 1, "DF_TEXTREL permission ignored");

        byte[] sframe = fixture(machine, relative, 0, 0x1800);
        var b = buffer(sframe);
        byte[] names = "\0.sframe\0.shstrtab\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        b.putLong(40, 0x900).putShort(60, (short) 3).putShort(62, (short) 2);
        b.putInt(0x940, 1).putInt(0x944, 1).putLong(0x958, 0xc00);
        b.putInt(0x980, 9).putInt(0x984, 3).putLong(0x998, 0xb00).putLong(0x9a0, names.length);
        b.put(0xb00, names);
        require(inspect(path, sframe).writes().size() == 1, "empty SFrame section changed writes");
        b.putLong(0x960, 1);
        reject(() -> inspect(path, sframe), "original SFrame coverage is not qualified");
        System.out.println("relocation-write-boundaries=PASS machine=" + machine);
    }
    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            var image = ElfImage.read(Path.of(args[0]));
            var effects = ElfRelocationEffects.inspect(image, () -> false);
            for (var write : effects.writes()) System.out.printf("WRITE %s %d %d %d %d %d %d %d%n", write.role(),
                write.recordOffset(), write.type(), write.symbol(), write.address(), write.size(), write.fileOffset(), write.fileBytes());
            return;
        }
        Path path = Files.createTempFile("forge-relocation-effects-", ".elf");
        try {
            variants(path, 62, 8, 36, 5, 37);
            variants(path, 183, 1027, 1031, 1024, 1032);
            System.out.println("elf-relocation-effects-checks=" + checks);
        }
        catch (IllegalArgumentException unexpected) {
            throw new AssertionError("valid relocation write fixture was rejected", unexpected);
        }
        finally { Files.deleteIfExists(path); }
    }
}
