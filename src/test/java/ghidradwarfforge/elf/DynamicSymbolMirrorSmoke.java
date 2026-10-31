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

/** Independent carriers, symbol-version chains and failure-before-publication controls. */
public final class DynamicSymbolMirrorSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-dynamic-mirror-");
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (boolean versioned : List.of(false, true)) {
                    for (boolean extended : List.of(false, true)) {
                        byte[] input = fixture(wide, order, versioned, extended);
                        positive(root, input, versioned);
                        for (String field : List.of("entsize", "size", "link", "info")) {
                            byte[] bad = input.clone();
                            LocalSymbolMergeSmoke.field(bad, 3, field, 0);
                            reject(root, bad);
                        }
                        byte[] bad = input.clone();
                        bytes(bad).putInt(0x200 + (wide ? 24 : 16), -1);
                        reject(root, bad);
                        bad = input.clone();
                        bad[0x200] = 1;
                        reject(root, bad);
                        bad = input.clone();
                        bad[0x180] = 1;
                        reject(root, bad);
                        bad = input.clone();
                        bad[0x200 + (wide ? 24 + 4 : 16 + 12)] = 0x12;
                        reject(root, bad);
                        bad = input.clone();
                        bytes(bad).putShort(0x200 + (wide ? 24 + 6 : 16 + 14), (short) 0xffff);
                        reject(root, bad);
                        if (versioned) {
                            for (int field : new int[] { 0, 2, 4, 6 }) {
                                bad = input.clone();
                                bytes(bad).putShort(0x280 + field, (short) 0xffff);
                                reject(root, bad);
                            }
                            for (int field : new int[] { 12, 16, 20, 24 }) {
                                bad = input.clone();
                                bytes(bad).putInt(0x280 + field, -1);
                                reject(root, bad);
                            }
                            bad = input.clone();
                            bytes(bad).putShort(0x280 + 28 + 4, (short) 2);
                            reject(root, bad);
                            bad = input.clone();
                            LocalSymbolMergeSmoke.field(bad, 6, "size", 6);
                            reject(root, bad);
                            bad = input.clone();
                            LocalSymbolMergeSmoke.field(bad, 6, "type", 1);
                            reject(root, bad);
                            bad = input.clone();
                            bytes(bad).putShort(0x270 + 6, (short) 99);
                            reject(root, bad);
                        }
                    }
                }
            }
        }
        System.out.println("dynamic-symbol-mirror-smoke=PASS checks=" + checks);
    }

    static byte[] fixture(boolean wide, ByteOrder order, boolean versioned, boolean extended) {
        byte[] original = LocalSymbolMergeSmoke.fixture(wide, order, extended, false);
        int headerWidth = wide ? 64 : 40;
        byte[] input = Arrays.copyOf(original, 0x400 + (versioned ? 8 : 6) * headerWidth);
        var b = bytes(input);
        String oldNames = new String(input, 0x310, (int) field(input, 5, "size"), StandardCharsets.US_ASCII);
        String names = oldNames.replace(".symtab", ".dynsym").replace(".strtab", ".dynstr");
        if (versioned) {
            names += ".gnu.version\0.gnu.version_d\0";
        }
        b.put(0x310, names.getBytes(StandardCharsets.US_ASCII));
        LocalSymbolMergeSmoke.field(input, 5, "size", names.length());
        LocalSymbolMergeSmoke.field(input, 3, "type", 11);
        LocalSymbolMergeSmoke.field(input, 3, "flags", 2);
        LocalSymbolMergeSmoke.field(input, 3, "address", 0x2200);
        LocalSymbolMergeSmoke.field(input, 2, "flags", 2);
        LocalSymbolMergeSmoke.field(input, 2, "address", 0x2180);
        if (versioned) {
            int end = (int) field(input, 2, "size");
            b.put(0x180 + end, new byte[] { 'V', '1', 0, 'V', '2', 0 });
            LocalSymbolMergeSmoke.field(input, 2, "size", end + 6);
            b.putShort(wide ? 60 : 48, (short) 8);
            long[] version = { names.indexOf(".gnu.version\0"), 0x6fffffffL, 2, 0x2270, 0x270, 8, 3, 0, 2, 2 };
            long[] definition = { names.indexOf(".gnu.version_d\0"), 0x6ffffffdL, 2, 0x2280, 0x280, 56, 2, 2, 4, 0 };
            String[] fields = { "name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entsize" };
            for (int i = 0; i < fields.length; i++) {
                LocalSymbolMergeSmoke.field(input, 6, fields[i], version[i]);
                LocalSymbolMergeSmoke.field(input, 7, fields[i], definition[i]);
            }
            b.position(0x270);
            b.putShort((short) 0).putShort((short) 0).putShort((short) 0x8002).putShort((short) 3);
            for (int index = 0; index < 2; index++) {
                b.position(0x280 + index * 28);
                b.putShort((short) 1).putShort((short) 0).putShort((short) (index + 2)).putShort((short) 1)
                    .putInt(0).putInt(20).putInt(index == 0 ? 28 : 0).putInt(end + index * 3).putInt(0);
            }
        }
        return input;
    }

    private static long field(byte[] input, int index, String name) {
        boolean wide = input[4] == 2;
        int offset = 0x400 + index * (wide ? 64 : 40) + (name.equals("size") ? wide ? 32 : 20 : 0);
        return wide ? bytes(input).getLong(offset) : Integer.toUnsignedLong(bytes(input).getInt(offset));
    }

    private static ByteBuffer bytes(byte[] input) {
        return ByteBuffer.wrap(input).order(input[5] == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
    }

    private static void positive(Path root, byte[] input, boolean versioned) throws Exception {
        Path path = root.resolve("original"), output = root.resolve("sidecar"), repeat = root.resolve("repeat");
        Files.write(path, input);
        var image = ElfImage.read(path);
        var mirror = DynamicSymbolMirror.read(image, () -> false);
        int width = image.is64Bit() ? 24 : 16;
        require(mirror.locals() == 2 && mirror.records().length == width * 4 &&
            mirror.versionedDefinitions() == versioned, "wrong inventory");
        require(mirror.existingNames().contains(ByteBuffer.wrap("old_global".getBytes(StandardCharsets.US_ASCII))),
            "lost original spelling");
        if (versioned) {
            for (String name : List.of("old_global@V1", "old_weak@@V2")) {
                require(mirror.existingNames().contains(ByteBuffer.wrap(name.getBytes(StandardCharsets.US_ASCII))),
                    "lost qualified spelling " + name);
            }
        }
        String codeHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[16]));
        var owner = new FunctionSymbol("primary", 0x1040, 16);
        var diagnostics = new ArrayList<String>();
        var planned = FunctionAliasSymbols.plan(image,
            List.of(new ElfFunctionAlias("alternate", "primary", 0x1040, 16, codeHash)),
            List.of(owner), List.of(), () -> false, diagnostics::add);
        require(planned.equals(List.of(new ElfLocalFunctionSymbol("alternate", 0x1040, 16, 1))),
            "planner rejected complete dynamic inventory");
        require(versioned ? diagnostics.size() == 1 && diagnostics.get(0).contains("loader default") :
            diagnostics.isEmpty(), "version limitation diagnostic missing or spurious");
        for (String occupied : versioned ? List.of("old_global", "old_global@V1", "old_weak@@V2") :
                List.of("old_global", "old_weak")) {
            diagnostics.clear();
            require(FunctionAliasSymbols.plan(image,
                List.of(new ElfFunctionAlias(occupied, "primary", 0x1040, 16, codeHash)),
                List.of(owner), List.of(), () -> false, diagnostics::add).isEmpty() &&
                diagnostics.toString().contains("already exists"), "dynamic spelling collision accepted");
        }
        var additions = List.of(new ElfLocalFunctionSymbol("alternate", 0x1040, 16, 1));
        var debug = Map.of(".debug_info", new byte[] { 1, 2, 3 });
        new MatchedElfSidecarWriter().write(image, output, debug, additions, () -> false);
        new MatchedElfSidecarWriter().write(image, repeat, debug, additions, () -> false);
        require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(repeat)), "nondeterministic writer");
        var result = ElfImage.read(output);
        for (int index : List.of(2, 3)) {
            require(Arrays.equals(image.sectionData(image.sections().get(index)),
                result.sectionData(result.sections().get(index))), "original dynamic bytes changed");
        }
        var table = result.sections().stream().filter(s -> s.type == 2).findFirst().orElseThrow();
        require(table.info == 3 && table.size == width * 5 && table.flags == 0 && table.address == 0,
            "static mirror framing");
        byte[] records = result.sectionData(table);
        require(Arrays.equals(Arrays.copyOfRange(records, 0, width * 2),
            Arrays.copyOfRange(mirror.records(), 0, width * 2)), "old locals changed");
        require(Arrays.equals(Arrays.copyOfRange(records, width * 3, width * 5),
            Arrays.copyOfRange(mirror.records(), width * 2, width * 4)), "old globals changed");
        if (mirror.indices() != null) {
            var extended = result.sections().stream().filter(s -> s.type == 18 && s.link == table.originalIndex)
                .findFirst().orElseThrow();
            byte[] indices = result.sectionData(extended);
            require(indices.length == 20 && Arrays.equals(Arrays.copyOfRange(indices, 0, 8),
                Arrays.copyOfRange(mirror.indices(), 0, 8)) &&
                Arrays.equals(Arrays.copyOfRange(indices, 12, 20), Arrays.copyOfRange(mirror.indices(), 8, 16)),
                "dynamic extended indices were not mirrored");
        }
        require(Arrays.equals(input, Files.readAllBytes(path)), "original mutated");
        AtomicInteger total = new AtomicInteger();
        DynamicSymbolMirror.read(image, () -> { total.incrementAndGet(); return false; });
        for (int limit : List.of(1, total.get() / 2, total.get())) {
            AtomicInteger current = new AtomicInteger();
            try {
                DynamicSymbolMirror.read(image, () -> current.incrementAndGet() >= limit);
                throw new AssertionError("cancellation ignored");
            }
            catch (CancellationException expected) {
                checks++;
            }
        }
    }

    private static void reject(Path root, byte[] bytes) throws Exception {
        Path path = root.resolve("bad"), output = root.resolve("sentinel");
        Files.write(path, bytes);
        byte[] sentinel = { 4, 3, 2, 1 };
        Files.write(output, sentinel);
        try {
            new MatchedElfSidecarWriter().write(ElfImage.read(path), output, Map.of(".debug_info", new byte[] { 1 }),
                List.of(new ElfLocalFunctionSymbol("alternate", 0x1040, 16, 1)), () -> false);
            throw new AssertionError("malformed dynamic inventory accepted");
        }
        catch (IllegalArgumentException expected) {
            checks++;
        }
        require(Arrays.equals(sentinel, Files.readAllBytes(output)), "prior output changed on failure");
        require(Arrays.equals(bytes, Files.readAllBytes(path)), "original changed on failure");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
