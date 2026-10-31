package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Independent sectionless carriers, inventory oracles and publication/cancellation controls. */
public final class SectionlessDynamicSymbolsSmoke {
    private static final String NAMES = "\0local\0global\0weak\0V1\0V2\0";
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-sectionless-symbols-");
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (int hashes : List.of(1, 2, 3)) {
                    for (boolean versioned : List.of(false, true)) {
                        for (boolean extended : List.of(false, true)) {
                            positive(root, fixture(wide, order, hashes, versioned, extended), versioned);
                        }
                    }
                }
                byte[] valid = fixture(wide, order, 3, true, true);
                for (String mutation : List.of("width", "strings-zero", "strings-large", "strings-bss",
                        "name-offset", "name-boundary", "null-symbol", "local-order", "tls", "reserved",
                        "symbol-outside", "sysv-count", "sysv-index", "gnu-first", "gnu-bucket",
                        "missing-count", "duplicate-tag", "no-terminator", "missing-definition-count",
                        "definition-count", "definition-aux", "definition-chain", "aux-chain",
                        "unknown-version", "extended-index", "overlapping-load", "dynamic-mapping")) {
                    byte[] bad = valid.clone();
                    mutate(bad, mutation);
                    reject(root, bad, mutation);
                }
                cancellation(root, valid);
                if (!wide) {
                    mipsModes(root, order);
                    if (order == ByteOrder.LITTLE_ENDIAN) {
                        extendedLoadIndex(root);
                    }
                }
                byte[] noDynamic = valid.clone();
                bytes(noDynamic).putInt((wide ? 64 + 2 * 56 : 52 + 2 * 32), 0);
                Path path = root.resolve("no-dynamic");
                Files.write(path, noDynamic);
                var image = ElfImage.read(path);
                require(DynamicSymbolMirror.read(image, () -> false) == null, "absent dynamic segment invented inventory");
                require(plan(image, "alternate", new ArrayList<>()).size() == 1, "static sectionless alias omitted");
                byte[] mips = fixture(wide, order, 1, false, false);
                bytes(mips).putShort(18, (short) 8);
                tag(mips, 0x70000011L, 4);
                positive(root, mips, false);
                tag(mips, 0x70000011L, 5);
                reject(root, mips, "MIPS count disagreement");
                System.out.println("sectionless-symbol-format=PASS ELF" + (wide ? 64 : 32) + " " + order);
            }
        }
        System.out.println("sectionless-dynamic-symbols-smoke=PASS checks=" + checks);
    }

    static byte[] fixture(boolean wide, ByteOrder order, int hashes, boolean versioned, boolean extended) {
        byte[] data = new byte[0x1000];
        var b = ByteBuffer.wrap(data).order(order);
        b.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1), (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        b.putShort(16, (short) 2).putShort(18, (short) (wide ? 62 : 3)).putInt(20, 1);
        if (wide) {
            b.putLong(24, 0x4000).putLong(32, 64).putShort(52, (short) 64)
                .putShort(54, (short) 56).putShort(56, (short) 4).putShort(58, (short) 64);
        }
        else {
            b.putInt(24, 0x4000).putInt(28, 52).putShort(40, (short) 52)
                .putShort(42, (short) 32).putShort(44, (short) 4).putShort(46, (short) 40);
        }
        segment(data, 0, 1, 5, 0x400, 0x4000, 0x80, 0x80);
        segment(data, 1, 1, 6, 0x800, 0x8000, 0x800, 0x900);
        segment(data, 2, 2, 6, 0x900, 0x8100, 0x100, 0x100);
        b.put(0xb00, NAMES.getBytes(StandardCharsets.US_ASCII));
        int width = wide ? 24 : 16;
        symbol(data, 1, NAMES.indexOf("local"), 1, 7, 0x8080, 8);
        symbol(data, 2, NAMES.indexOf("global"), 0x12, extended ? 0xffff : 5, 0x4010, 16);
        symbol(data, 3, NAMES.indexOf("weak"), 0x22, 5, 0x4030, 16);
        tag(data, 5, 0x8300);
        tag(data, 6, 0x8200);
        tag(data, 10, NAMES.length());
        tag(data, 11, width);
        if ((hashes & 1) != 0) {
            tag(data, 4, 0x8380);
            b.position(0xb80);
            b.putInt(1).putInt(4).putInt(2).putInt(0).putInt(0).putInt(3).putInt(0);
        }
        if ((hashes & 2) != 0) {
            tag(data, 0x6ffffef5L, 0x8400);
            b.position(0xc00);
            b.putInt(1).putInt(2).putInt(1).putInt(5);
            if (wide) {
                b.putLong(0);
            }
            else {
                b.putInt(0);
            }
            b.putInt(2).putInt(0x100).putInt(0x101);
        }
        if (versioned) {
            tag(data, 0x6ffffff0L, 0x8480);
            tag(data, 0x6ffffffcL, 0x8500);
            tag(data, 0x6ffffffdL, 2);
            b.position(0xc80);
            b.putShort((short) 0).putShort((short) 0).putShort((short) 0x8002).putShort((short) 3);
            for (int index = 0; index < 2; index++) {
                b.position(0xd00 + index * 28);
                b.putShort((short) 1).putShort((short) 0).putShort((short) (index + 2)).putShort((short) 1)
                    .putInt(0).putInt(20).putInt(index == 0 ? 28 : 0).putInt(NAMES.indexOf(index == 0 ? "V1" : "V2")).putInt(0);
            }
        }
        if (extended) {
            tag(data, 34, 0x8580);
            b.putInt(0xd80 + 2 * 4, 5);
        }
        return data;
    }

    private static void positive(Path root, byte[] data, boolean versioned) throws Exception {
        Path path = root.resolve("original"), output = root.resolve("sidecar"), repeat = root.resolve("repeat");
        Files.write(path, data);
        var image = ElfImage.read(path);
        var mirror = DynamicSymbolMirror.read(image, () -> false);
        int width = image.is64Bit() ? 24 : 16;
        require(mirror.locals() == 2 && mirror.records().length == 4 * width && mirror.indices() == null,
            "count/local partition/extended remapping");
        require(mirror.versionedDefinitions() == versioned, "version observation");
        var rows = ByteBuffer.wrap(mirror.records()).order(image.byteOrder());
        for (int index = 0; index < 4; index++) {
            int at = index * width;
            int section = Short.toUnsignedInt(rows.getShort(at + (image.is64Bit() ? 6 : 14)));
            require(section == (index == 0 ? 0 : index == 1 ? 2 : 1), "wrong synthetic section index");
            byte[] before = Arrays.copyOfRange(data, 0xa00 + at, 0xa00 + at + width);
            byte[] after = Arrays.copyOfRange(mirror.records(), at, at + width);
            Arrays.fill(before, 0, 4, (byte) 0);
            Arrays.fill(after, 0, 4, (byte) 0);
            int field = image.is64Bit() ? 6 : 14;
            before[field] = before[field + 1] = after[field] = after[field + 1] = 0;
            require(Arrays.equals(before, after), "binding/value/size/visibility changed");
        }
        var diagnostics = new ArrayList<String>();
        var additions = plan(image, "alternate", diagnostics);
        require(additions.equals(List.of(new ElfLocalFunctionSymbol("alternate", 0x4040, 16, 1))), "alias planning");
        require(versioned ? diagnostics.toString().contains("loader default") : diagnostics.isEmpty(), "diagnostics");
        for (String name : versioned ? List.of("global", "global@V1", "weak@@V2") : List.of("global", "weak")) {
            diagnostics.clear();
            require(plan(image, name, diagnostics).isEmpty() && diagnostics.toString().contains("already exists"), "name collision");
        }
        var debug = Map.of(".debug_info", new byte[] { 1, 2, 3 });
        for (Path target : List.of(output, repeat)) {
            new MatchedElfSidecarWriter().write(image, target, debug, additions, () -> false);
        }
        require(Arrays.equals(Files.readAllBytes(path), data), "original changed");
        require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(repeat)), "nondeterministic mirror");
        var emitted = ElfImage.read(output);
        require(emitted.sections().get(1).name.equals(".forge.load.0") &&
            emitted.sections().get(2).name.equals(".forge.load.1"), "writer/planner index disagreement");
        var table = emitted.sections().stream().filter(s -> s.type == 2).findFirst().orElseThrow();
        require(table.info == 3 && table.size == 5 * width, "inserted local partition");
        byte[] records = emitted.sectionData(table);
        for (int index = 0; index < 4; index++) {
            int next = index < 2 ? index : index + 1;
            require(Arrays.equals(Arrays.copyOfRange(mirror.records(), index * width, (index + 1) * width),
                Arrays.copyOfRange(records, next * width, (next + 1) * width)), "mirrored record lost on writing");
        }
        require(Arrays.equals(Arrays.copyOf(emitted.sectionData(emitted.sections().get((int) table.link)), mirror.names().length),
            mirror.names()), "mirrored names changed on writing");
    }

    private static List<ElfLocalFunctionSymbol> plan(ElfImage image, String name, List<String> diagnostics) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[16]));
        return FunctionAliasSymbols.plan(image, List.of(new ElfFunctionAlias(name, "primary", 0x4040, 16, hash)),
            List.of(new FunctionSymbol("primary", 0x4040, 16)), List.of(), () -> false, diagnostics::add);
    }

    private static void reject(Path root, byte[] data, String label) throws Exception {
        Path path = root.resolve("bad"), output = root.resolve("prior-output");
        Files.write(path, data);
        Files.writeString(output, "prior output");
        var image = ElfImage.read(path);
        try {
            DynamicSymbolMirror.read(image, () -> false);
            throw new AssertionError("accepted " + label);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage() != null, "missing rejection diagnostic");
        }
        var diagnostics = new ArrayList<String>();
        require(plan(image, "alternate", diagnostics).isEmpty() && !diagnostics.isEmpty(), "planner guessed " + label);
        try {
            new MatchedElfSidecarWriter().write(image, output, Map.of(".debug_info", new byte[] { 1 }),
                List.of(new ElfLocalFunctionSymbol("alternate", 0x4040, 16, 1)), () -> false);
            throw new AssertionError("published " + label);
        }
        catch (IllegalArgumentException expected) {
            require(Files.readString(output).equals("prior output"), "prior output lost");
        }
        require(Arrays.equals(Files.readAllBytes(path), data), "rejection changed original");
    }

    private static void cancellation(Path root, byte[] data) throws Exception {
        Path path = root.resolve("cancel"), output = root.resolve("cancel-output");
        Files.write(path, data);
        var image = ElfImage.read(path);
        for (int stop : List.of(1, 10, 30, 60)) {
            AtomicInteger calls = new AtomicInteger();
            try {
                DynamicSymbolMirror.read(image, () -> calls.incrementAndGet() >= stop);
                throw new AssertionError("inventory ignored cancellation");
            }
            catch (CancellationException expected) {
                require(calls.get() == stop, "inventory continued after cancellation");
            }
            Files.writeString(output, "prior output");
            calls.set(0);
            try {
                new MatchedElfSidecarWriter().write(image, output, Map.of(".debug_info", new byte[] { 1 }),
                    List.of(new ElfLocalFunctionSymbol("alternate", 0x4040, 16, 1)),
                    () -> calls.incrementAndGet() >= stop);
                throw new AssertionError("writer ignored cancellation");
            }
            catch (CancellationException expected) {
                require(Files.readString(output).equals("prior output"), "cancellation lost prior output");
            }
        }
        require(Arrays.equals(Files.readAllBytes(path), data), "cancellation changed original");
    }

    private static void mipsModes(Path root, ByteOrder order) throws Exception {
        byte[] data = fixture(false, order, 1, false, false);
        bytes(data).putShort(18, (short) 8).putInt(36, 0x70001007);
        segment(data, 3, 0x70000003, 4, 0xe00, 0x8600, 24, 24);
        bytes(data).position(0xe00).putShort((short) 0).put((byte) 32).put((byte) 2)
            .put((byte) 1).put((byte) 1).put((byte) 0).put((byte) 5);
        Path input = root.resolve("mips-mode");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[16]));
        var aliases = List.of(new ElfFunctionAlias("alternate", "primary", 0x4040, 16, hash));
        var owners = List.of(new FunctionSymbol("primary", 0x4040, 16));
        for (int mode : List.of(0, 1, 2, 3, 0x80, 0xf0)) {
            data[0xa00 + 2 * 16 + 13] = (byte) mode;
            Files.write(input, data);
            var diagnostics = new ArrayList<String>();
            var planned = MipsFunctionAliasSymbols.plan(ElfImage.read(input), aliases, owners, List.of(),
                () -> false, diagnostics::add);
            require(mode <= 3 ? planned.size() == 1 && diagnostics.isEmpty() :
                planned.isEmpty() && diagnostics.toString().contains("unverified mode"), "sectionless MIPS mode policy");
        }
    }

    private static void extendedLoadIndex(Path root) throws Exception {
        int count = 0xff04;
        byte[] original = fixture(false, ByteOrder.LITTLE_ENDIAN, 1, false, false);
        byte[] data = Arrays.copyOf(original, 0x1000 + count * 32);
        var b = bytes(data);
        b.putInt(28, 0x1000).putShort(44, (short) count);
        // Move the code segment to the end, beyond the reserved direct-index range.
        System.arraycopy(original, 52 + 32, data, 0x1000, 64);
        for (int index = 2; index < count - 1; index++) {
            b.position(0x1000 + index * 32);
            b.putInt(1).putInt(0).putInt(0x100000 + index * 16).putInt(0)
                .putInt(0).putInt(1).putInt(0).putInt(1);
        }
        System.arraycopy(original, 52, data, 0x1000 + (count - 1) * 32, 32);
        Path path = root.resolve("high-load-index"), output = root.resolve("high-load-sidecar");
        Files.write(path, data);
        var image = ElfImage.read(path);
        var mirror = DynamicSymbolMirror.read(image, () -> false);
        require(mirror.indices() != null && ByteBuffer.wrap(mirror.indices()).order(ByteOrder.LITTLE_ENDIAN).getInt(8) == count - 1,
            "high synthetic load index was truncated");
        var planned = plan(image, "alternate", new ArrayList<>());
        require(planned.size() == 1 && planned.getFirst().sectionIndex() == count - 1, "high alias load index");
        new MatchedElfSidecarWriter().write(image, output, Map.of(".debug_info", new byte[] { 1 }), planned, () -> false);
        var result = ElfImage.read(output);
        var table = result.sections().stream().filter(section -> section.type == 2).findFirst().orElseThrow();
        var extended = result.sections().stream().filter(section -> section.type == 18).findFirst().orElseThrow();
        require(extended.link == table.originalIndex, "high-index table link");
        var records = ByteBuffer.wrap(result.sectionData(table)).order(ByteOrder.LITTLE_ENDIAN);
        var indices = ByteBuffer.wrap(result.sectionData(extended)).order(ByteOrder.LITTLE_ENDIAN);
        require(Short.toUnsignedInt(records.getShort(2 * 16 + 14)) == 0xffff && indices.getInt(2 * 4) == count - 1,
            "high alias index missing from output");
        require(Short.toUnsignedInt(records.getShort(3 * 16 + 14)) == 0xffff && indices.getInt(3 * 4) == count - 1,
            "high original index missing from output");
        require(Arrays.equals(Files.readAllBytes(path), data), "high-index input modified");
    }

    private static void mutate(byte[] data, String mutation) {
        var b = bytes(data);
        boolean wide = data[4] == 2;
        int width = wide ? 24 : 16;
        int global = 0xa00 + 2 * width;
        switch (mutation) {
            case "width" -> tag(data, 11, 1);
            case "strings-zero" -> tag(data, 10, 0);
            case "strings-large" -> tag(data, 10, 0x1000001);
            case "strings-bss" -> tag(data, 5, 0x8800);
            case "name-offset" -> b.putInt(global, -1);
            case "name-boundary" -> data[0xb00] = 1;
            case "null-symbol" -> data[0xa00] = 1;
            case "local-order" -> data[0xa00 + 3 * width + (wide ? 4 : 12)] = 2;
            case "tls" -> data[global + (wide ? 4 : 12)] = 0x16;
            case "reserved" -> { b.putShort(global + (wide ? 6 : 14), (short) 0xff20); b.putInt(0xd88, 0); }
            case "symbol-outside" -> { if (wide) b.putLong(global + 8, Long.MAX_VALUE); else b.putInt(global + 4, -1); }
            case "sysv-count" -> b.putInt(0xb84, 5);
            case "sysv-index" -> b.putInt(0xb88, 4);
            case "gnu-first" -> b.putInt(0xc04, 1);
            case "gnu-bucket" -> b.putInt(wide ? 0xc18 : 0xc14, -1);
            case "missing-count" -> { replaceTag(data, 4, 1); b.putInt(wide ? 0xc18 : 0xc14, 0); }
            case "duplicate-tag" -> replaceTag(data, 4, 11);
            case "no-terminator" -> {
                for (int at = 0x900; at < 0xa00; at += wide ? 16 : 8) {
                    if (wide) b.putLong(at, 1); else b.putInt(at, 1);
                }
            }
            case "missing-definition-count" -> replaceTag(data, 0x6ffffffdL, 1);
            case "definition-count" -> tag(data, 0x6ffffffdL, 0);
            case "definition-aux" -> b.putInt(0xd0c, 4);
            case "definition-chain" -> b.putInt(0xd10, 0);
            case "aux-chain" -> b.putInt(0xd18, 8);
            case "unknown-version" -> b.putShort(0xc84, (short) 99);
            case "extended-index" -> b.putInt(0xd88, 0);
            case "overlapping-load" -> segment(data, 3, 1, 6, 0xa00, 0x8200, 0x100, 0x100);
            case "dynamic-mapping" -> segment(data, 2, 2, 6, 0x900, 0x8108, 0x100, 0x100);
            default -> throw new AssertionError(mutation);
        }
    }

    private static void tag(byte[] data, long tag, long value) {
        var b = bytes(data);
        boolean wide = data[4] == 2;
        for (int at = 0x900; at < 0xa00; at += wide ? 16 : 8) {
            long current = wide ? b.getLong(at) : Integer.toUnsignedLong(b.getInt(at));
            if (current == 0 || current == tag) {
                if (wide) b.putLong(at, tag).putLong(at + 8, value);
                else b.putInt(at, (int) tag).putInt(at + 4, (int) value);
                return;
            }
        }
        throw new AssertionError("tag fixture overflow");
    }

    private static void replaceTag(byte[] data, long tag, long replacement) {
        var b = bytes(data);
        boolean wide = data[4] == 2;
        for (int at = 0x900; at < 0xa00; at += wide ? 16 : 8) {
            if ((wide ? b.getLong(at) : Integer.toUnsignedLong(b.getInt(at))) == tag) {
                if (wide) b.putLong(at, replacement); else b.putInt(at, (int) replacement);
                return;
            }
        }
        throw new AssertionError("missing tag fixture");
    }

    private static void symbol(byte[] data, int index, int name, int info, int section, long value, long size) {
        var b = bytes(data);
        boolean wide = data[4] == 2;
        b.position(0xa00 + index * (wide ? 24 : 16));
        if (wide) b.putInt(name).put((byte) info).put((byte) 0).putShort((short) section).putLong(value).putLong(size);
        else b.putInt(name).putInt((int) value).putInt((int) size).put((byte) info).put((byte) 0).putShort((short) section);
    }

    private static void segment(byte[] data, int index, int type, int flags, long file, long address, long size, long memory) {
        var b = bytes(data);
        boolean wide = data[4] == 2;
        b.position((wide ? 64 : 52) + index * (wide ? 56 : 32));
        if (wide) b.putInt(type).putInt(flags).putLong(file).putLong(address).putLong(address).putLong(size).putLong(memory).putLong(1);
        else b.putInt(type).putInt((int) file).putInt((int) address).putInt((int) address).putInt((int) size).putInt((int) memory).putInt(flags).putInt(1);
    }

    private static ByteBuffer bytes(byte[] data) {
        return ByteBuffer.wrap(data).order(data[5] == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
