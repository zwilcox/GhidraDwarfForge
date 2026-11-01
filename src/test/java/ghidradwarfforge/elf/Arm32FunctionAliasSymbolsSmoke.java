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
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** ARM tagged values versus untagged ownership, body bytes and original mode maps. */
public final class Arm32FunctionAliasSymbolsSmoke {
    private static int checks;
    private static final long ENTRY = 0x1040;
    private static final String HASH = hash(16);
    private static final ElfFunctionAlias ALIAS = new ElfFunctionAlias("alternate", "primary", ENTRY, 16, HASH);

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-arm-alias-");
        dynamicBoundaries(root);
        recoveredModeLayouts(root);
        for (int mode : new int[] { 0, 1 }) {
            var cue = new ElfFunctionModeCue("primary", ENTRY, 16, ENTRY | mode, HASH);
            for (int type : new int[] { 2, 3 }) {
                byte[] original = fixture(mode, type);
                check(root, original, ALIAS, List.of(cue), List.of(), null, ENTRY | mode);
                check(root, original, ALIAS, List.of(), List.of(), "unique decoded mode", 0);
                check(root, original, ALIAS, List.of(cue, cue), List.of(), "unique decoded mode", 0);
                check(root, original, ALIAS, List.of(new ElfFunctionModeCue("other", ENTRY, 16, ENTRY | mode, HASH)),
                    List.of(), "unique decoded mode", 0);
                check(root, original, ALIAS, List.of(new ElfFunctionModeCue("primary", ENTRY, 16,
                    ENTRY | mode, "0".repeat(64))), List.of(), "unique decoded mode", 0);
                check(root, original, ALIAS, List.of(new ElfFunctionModeCue("primary", ENTRY, 16,
                    ENTRY + 2, HASH)), List.of(), "invalid mode value", 0);
                check(root, original, ALIAS, List.of(cue),
                    List.of(new ElfLocalFunctionSymbol("reserved", ENTRY | (mode ^ 1), 16, 1)),
                    "reserved function tag", 0);
                check(root, original, ALIAS, List.of(cue),
                    List.of(new ElfLocalFunctionSymbol("reserved", ENTRY | mode, 16, 1)), null, ENTRY | mode);
                for (int symbolMode : new int[] { 0, 1 }) {
                    byte[] changed = original.clone();
                    buffer(changed).putInt(0x214, (int) ENTRY | symbolMode);
                    check(root, changed, ALIAS, List.of(cue), List.of(),
                        symbolMode == mode ? null : "original function tag", ENTRY | mode);
                }
                for (int mapName : new int[] { 10, 13, 16 }) {
                    byte[] changed = original.clone();
                    buffer(changed).putInt(0x220, mapName);
                    check(root, changed, ALIAS, List.of(cue), List.of(),
                        mapName == (mode == 0 ? 10 : 13) ? null : "original mapping at entry", ENTRY | mode);
                }
                byte[] changed = original.clone();
                buffer(changed).putInt(0x234, (int) ENTRY + 4);
                check(root, changed, ALIAS, List.of(cue), List.of(), "mapping changes mode", 0);
                // A function's size may cover a mixed-mode veneer. Only its
                // tagged entry, not its entire size, asserts an instruction mode.
                changed = original.clone();
                buffer(changed).putInt(0x214, 0x1000 | (mode ^ 1)).putInt(0x218, 0x80);
                check(root, changed, ALIAS, List.of(cue), List.of(), null, ENTRY | mode);
                for (int field : new int[] { 12, 13 }) {
                    changed = original.clone();
                    changed[0x220 + field] = 1;
                    check(root, changed, ALIAS, List.of(cue), List.of(), "malformed mapping", 0);
                }
                changed = original.clone();
                buffer(changed).putInt(36, 0x04000400);
                check(root, changed, ALIAS, List.of(cue), List.of(), "EABI5", 0);
                changed = original.clone();
                buffer(changed).putInt(36, 0x05800400);
                rejectContradictoryEncoding(root, changed, cue);
                changed = original.clone();
                changed[0x140] ^= 1;
                check(root, changed, ALIAS, List.of(cue), List.of(), "code differs", 0);
                var split = new ElfFunctionAlias("alternate", "primary", ENTRY, List.of(
                    new ElfFunctionAlias.CodeRange(0x1010, 8, hash(8)),
                    new ElfFunctionAlias.CodeRange(ENTRY, 16, HASH)));
                check(root, original, split, List.of(cue), List.of(), null, ENTRY | mode);
                long interior = ENTRY + (mode == 0 ? 4 : 2);
                var below = new ElfFunctionAlias("alternate", "primary", interior, List.of(
                    new ElfFunctionAlias.CodeRange(ENTRY, 16, HASH),
                    new ElfFunctionAlias.CodeRange(0x1070, 8, hash(8))));
                check(root, original, below, List.of(cue), List.of(), null, interior | mode);
                changed = original.clone();
                LocalSymbolMergeSmoke.field(changed, 4, "type", 18);
                LocalSymbolMergeSmoke.field(changed, 4, "link", 3);
                LocalSymbolMergeSmoke.field(changed, 4, "entsize", 4);
                buffer(changed).putShort(0x21e, (short) 0xffff).putInt(0x2f4, 1);
                check(root, changed, ALIAS, List.of(cue), List.of(), null, ENTRY | mode);
                changed = original.clone();
                var bytes = buffer(changed);
                bytes.putInt(28, 52).putShort(42, (short) 32).putShort(44, (short) 1);
                bytes.putInt(52, 1).putInt(56, 0x100).putInt(60, 0x1000).putInt(64, 0x1000)
                    .putInt(68, 128).putInt(72, 128).putInt(76, 5).putInt(80, 1);
                bytes.putInt(32, 0).putShort(48, (short) 0).putShort(50, (short) 0);
                check(root, changed, ALIAS, List.of(cue), List.of(), null, ENTRY | mode);
                Path path = root.resolve("cancel.elf");
                Files.write(path, original);
                var image = ElfImage.read(path);
                for (int stop : new int[] { 1, 8, 25, 50 }) {
                    var count = new AtomicInteger();
                    try {
                        DwarfTarget.fromElf(image).planFunctionAliases(image, List.of(ALIAS),
                            functions(ALIAS), List.of(), List.of(cue), () -> count.incrementAndGet() >= stop, ignored -> { });
                        throw new AssertionError("ignored cancellation at " + stop);
                    }
                    catch (CancellationException expected) {
                        checks++;
                    }
                }
            }
        }
        System.out.println("arm32-function-alias-symbols-smoke=PASS checks=" + checks);
    }

    private static void recoveredModeLayouts(Path root) throws Exception {
        var cue = new ElfFunctionModeCue("primary", ENTRY, 16, ENTRY | 1, HASH);
        var owner = new FunctionSymbol("primary", ENTRY, 16);
        for (boolean sectionless : List.of(false, true)) {
            byte[] original = fixture(1, 3);
            if (sectionless) {
                var bytes = buffer(original);
                bytes.putInt(28, 52).putShort(42, (short) 32).putShort(44, (short) 1);
                bytes.putInt(52, 1).putInt(56, 0x100).putInt(60, 0x1000).putInt(64, 0x1000)
                    .putInt(68, 0x80).putInt(72, 0x80).putInt(76, 5).putInt(80, 4);
                bytes.putInt(32, 0).putShort(48, (short) 0).putShort(50, (short) 0);
            }
            Path input = root.resolve("recovered-layout.elf");
            Files.write(input, original);
            var image = ElfImage.read(input);
            var target = DwarfTarget.fromElf(image);
            var messages = new ArrayList<String>();
            var result = target.planFunctionModeSymbols(image, List.of(cue), List.of(owner),
                () -> false, messages::add);
            require(result.equals(List.of(new ElfLocalFunctionSymbol("__forge_arm_mode_00001040",
                ENTRY | 1, 16, 1))) && messages.isEmpty(), "extended mode binding " + messages);
            for (var definitions : List.of(List.<FunctionSymbol>of(),
                    List.of(new FunctionSymbol("other", ENTRY, 16)),
                    List.of(new FunctionSymbol("primary", ENTRY, 12)),
                    List.of(owner, new FunctionSymbol("uncued_overlap", ENTRY + 8, 16)))) {
                require(target.planFunctionModeSymbols(image, List.of(cue), definitions,
                    () -> false, ignored -> { }).isEmpty(), "unproved recovered ownership admitted");
            }
            for (var invalid : List.of(
                    new ElfFunctionModeCue("primary", ENTRY, 16, ENTRY | 1, "0".repeat(64)),
                    new ElfFunctionModeCue("primary", ENTRY, 16, ENTRY + 3, HASH))) {
                require(target.planFunctionModeSymbols(image, List.of(invalid), List.of(owner),
                    () -> false, ignored -> { }).isEmpty(), "bad original bytes/mode admitted");
            }
            require(target.planFunctionModeSymbols(image, List.of(cue, cue), List.of(owner),
                () -> false, ignored -> { }).isEmpty(), "duplicate mode evidence admitted");
            var arm = new ElfFunctionModeCue("primary", ENTRY, 16, ENTRY, HASH);
            require(target.planFunctionModeSymbols(image, List.of(arm), List.of(owner),
                () -> false, ignored -> { }).isEmpty(), "ARM-only behavior changed");
            Path output = root.resolve("recovered-layout.dbg");
            new MatchedElfSidecarWriter().write(image, output,
                java.util.Map.of(".debug_info", new byte[] {1}), result, () -> false);
            byte[] first = Files.readAllBytes(output);
            new MatchedElfSidecarWriter().write(image, output,
                java.util.Map.of(".debug_info", new byte[] {1}), result, () -> false);
            require(Arrays.equals(first, Files.readAllBytes(output)), "nondeterministic extended mode export");
            require(Arrays.equals(original, Files.readAllBytes(input)), "extended mode export changed input");
            try {
                target.planFunctionModeSymbols(image, List.of(cue), List.of(owner), () -> true, ignored -> { });
                throw new AssertionError("recovered mode cancellation ignored");
            }
            catch (CancellationException expected) {
                checks++;
            }
        }
    }

    private static byte[] fixture(int mode, int type) {
        byte[] data = LocalSymbolMergeSmoke.fixture(false, ByteOrder.LITTLE_ENDIAN, false, false);
        var bytes = buffer(data);
        bytes.putShort(16, (short) type).putShort(18, (short) 40).putInt(36, 0x05000400);
        byte[] names = "\0original\0$a\0$t\0$d\0".getBytes(StandardCharsets.US_ASCII);
        bytes.put(0x180, names);
        LocalSymbolMergeSmoke.field(data, 2, "size", names.length);
        LocalSymbolMergeSmoke.field(data, 3, "info", 4);
        Arrays.fill(data, 0x200, 0x240, (byte) 0);
        bytes.putInt(0x210, 1).putInt(0x214, (int) ENTRY | mode).putInt(0x218, 16)
            .put(0x21c, (byte) 2).putShort(0x21e, (short) 1);
        bytes.putInt(0x220, mode == 0 ? 10 : 13).putInt(0x224, 0x1000).putShort(0x22e, (short) 1);
        bytes.putInt(0x230, 16).putInt(0x234, 0x1060).putShort(0x23e, (short) 1);
        return data;
    }

    private static void rejectContradictoryEncoding(Path root, byte[] bytes, ElfFunctionModeCue cue) throws Exception {
        Path path = root.resolve("contradictory-encoding.elf");
        Files.write(path, bytes);
        var time = Files.getLastModifiedTime(path);
        var image = ElfImage.read(path);
        try {
            DwarfTarget.fromElf(image);
            throw new AssertionError("BE8 flag on little-endian input accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("contradicts little-endian ELF data"), "wrong preflight rejection");
        }
        var diagnostics = new ArrayList<String>();
        require(Arm32FunctionAliasSymbols.plan(image, List.of(ALIAS), functions(ALIAS), List.of(),
            List.of(cue), () -> false, diagnostics::add).isEmpty() && diagnostics.toString().contains("EABI5"),
            "direct alias policy admitted contradictory encoding");
        require(Arrays.equals(bytes, Files.readAllBytes(path)) && time.equals(Files.getLastModifiedTime(path)),
            "negative control changed original ELF");
    }

    private static void check(Path root, byte[] bytes, ElfFunctionAlias alias,
            List<ElfFunctionModeCue> cues, List<ElfLocalFunctionSymbol> reserved,
            String omission, long value) throws Exception {
        Path path = root.resolve("fixture.elf");
        Files.write(path, bytes);
        var time = Files.getLastModifiedTime(path);
        var image = ElfImage.read(path);
        var diagnostics = new ArrayList<String>();
        var target = DwarfTarget.fromElf(image);
        var actual = target.planFunctionAliases(image, List.of(alias), functions(alias), reserved,
            cues, () -> false, diagnostics::add);
        if (omission == null) {
            require(actual.equals(List.of(new ElfLocalFunctionSymbol("alternate", value, alias.size(), 1))) &&
                diagnostics.isEmpty(), "incorrect tagged alias " + actual + diagnostics);
        }
        else {
            require(actual.isEmpty() && diagnostics.toString().contains(omission),
                "missing restriction " + omission + diagnostics);
        }
        require(actual.equals(target.planFunctionAliases(image, List.of(alias), functions(alias), reserved,
            cues, () -> false, ignored -> { })), "nondeterministic alias mode policy");
        require(Arrays.equals(bytes, Files.readAllBytes(path)) && time.equals(Files.getLastModifiedTime(path)),
            "original ELF changed");
    }

    private static void dynamicBoundaries(Path root) throws Exception {
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (int machine : new int[] { 3, 40 }) {
                    for (int abi : new int[] { 4, 5 }) {
                        for (int kind : new int[] { 1, 2, 10 }) {
                            byte[] data = SectionlessDynamicSymbolsSmoke.fixture(wide, order, 3, false, false);
                            var bytes = ByteBuffer.wrap(data).order(order);
                            bytes.putShort(18, (short) machine).putInt(wide ? 48 : 36, abi << 24);
                            int at = 0xa00 + 2 * (wide ? 24 : 16);
                            bytes.put(at + (wide ? 4 : 12), (byte) (0x10 | kind));
                            if (wide) {
                                bytes.putLong(at + 8, 0x4071).putLong(at + 16, 16);
                            }
                            else {
                                bytes.putInt(at + 4, 0x4071).putInt(at + 8, 16);
                            }
                            Path input = root.resolve("dynamic-boundary");
                            Files.write(input, data);
                            var image = ElfImage.read(input);
                            boolean tagged = !wide && machine == 40 && abi == 5 && kind == 2;
                            require(Arm32SymbolValues.allocationAddress(image, kind, 0x4071) ==
                                (tagged ? 0x4070 : 0x4071), "unrelated symbol/profile lost its low bit");
                            require(Arm32SymbolValues.allocationAddress(image, kind, 0x4070) == 0x4070,
                                "untagged address changed");
                            if (!tagged) {
                                try {
                                    DynamicSymbolMirror.read(image, () -> false);
                                    throw new AssertionError("out-of-allocation definition was rounded into its load");
                                }
                                catch (IllegalArgumentException expected) {
                                    require(expected.getMessage().contains("crosses load"), "wrong boundary rejection");
                                }
                                continue;
                            }
                            var mirror = DynamicSymbolMirror.read(image, () -> false);
                            var records = ByteBuffer.wrap(mirror.records()).order(order);
                            require(records.getInt(2 * 16 + 4) == 0x4071 && records.getInt(2 * 16 + 8) == 16 &&
                                Short.toUnsignedInt(records.getShort(2 * 16 + 14)) == 1,
                                "tagged boundary definition lost its value, size or section");
                            Path output = root.resolve("dynamic-boundary.dbg");
                            new MatchedElfSidecarWriter().write(image, output,
                                java.util.Map.of(".debug_info", new byte[] {1}),
                                List.of(new ElfLocalFunctionSymbol("alternate", 0x4041, 16, 1)), () -> false);
                            var written = ElfImage.read(output);
                            var table = written.sections().stream().filter(section -> section.type == 2).findFirst().orElseThrow();
                            var emitted = ByteBuffer.wrap(written.sectionData(table)).order(order);
                            require(emitted.getInt(3 * 16 + 4) == 0x4071 && emitted.getInt(3 * 16 + 8) == 16,
                                "writer removed original entry mode");
                            require(Arrays.equals(Files.readAllBytes(input), data), "boundary export modified original");
                        }
                    }
                }
            }
        }
    }

    private static List<FunctionSymbol> functions(ElfFunctionAlias alias) {
        return List.of(new FunctionSymbol(alias.owner(), alias.address(), alias.ranges().stream()
            .map(r -> new FunctionRange(r.address(), r.size())).toList()));
    }

    private static ByteBuffer buffer(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static String hash(int size) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[size]));
        }
        catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
