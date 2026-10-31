package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Independent ELF32 carriers and contradictory instruction-mode controls. */
public final class MipsFunctionAliasSymbolsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-mips-alias-");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(new byte[16]));
        var alias = new ElfFunctionAlias("alternate", "primary", 0x1040, 16, hash);
        for (ByteOrder order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
            for (int fpAbi : List.of(1, 5)) {
                byte[] bytes = fixture(order, fpAbi);
                for (int flags = 0; flags <= 7; flags++) {
                    ByteBuffer.wrap(bytes).order(order).putInt(36, 0x70001000 | flags);
                    check(root, bytes, alias, null);
                }
                for (long flags : new long[] { 0, 0x70001027, 0x70001207, 0x74001007,
                        0x72001007, 0x70002007, 0x90001007 }) {
                    byte[] changed = bytes.clone();
                    ByteBuffer.wrap(changed).order(order).putInt(36, (int) flags);
                    check(root, changed, alias, "header profile");
                }
                for (int field : new int[] { 0, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20 }) {
                    byte[] changed = bytes.clone();
                    changed[0x2e0 + field] = (byte) 0xff;
                    check(root, changed, alias, "ABI");
                }
                for (int mode : new int[] { 0x04, 0x08, 0x20, 0x80, 0xf0 }) {
                    byte[] changed = bytes.clone();
                    changed[0x200 + 16 + 13] = (byte) mode;
                    check(root, changed, alias, "mode or tagged");
                }
                for (int visibility : new int[] { 1, 2, 3 }) {
                    byte[] changed = bytes.clone();
                    changed[0x200 + 16 + 13] = (byte) visibility;
                    check(root, changed, alias, null);
                }
                byte[] tagged = bytes.clone();
                ByteBuffer.wrap(tagged).order(order).putInt(0x200 + 16 + 4, 0x1001);
                check(root, tagged, alias, "mode or tagged");
                byte[] absent = bytes.clone();
                LocalSymbolMergeSmoke.field(absent, 4, "type", 1);
                check(root, absent, alias, "ABI record");
                for (String field : List.of("size", "entsize")) {
                    byte[] malformed = bytes.clone();
                    LocalSymbolMergeSmoke.field(malformed, 3, field, 17);
                    check(root, malformed, alias, "symbol inventory");
                }
                check(root, bytes, new ElfFunctionAlias("alternate", "primary", 0x1041, 16, hash), "word aligned");
                check(root, bytes, new ElfFunctionAlias("alternate", "primary", 0x1040, 15, hash), "word aligned");
                for (long start : new long[] { 0x1010, 0x1011 }) {
                    for (long size : new long[] { 16, 15 }) {
                        String lowerHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                            .digest(new byte[(int) size]));
                        var split = new ElfFunctionAlias("alternate", "primary", 0x1040, List.of(
                            new ElfFunctionAlias.CodeRange(start, size, lowerHash),
                            new ElfFunctionAlias.CodeRange(0x1040, 16, hash)));
                        check(root, bytes, split, start == 0x1010 && size == 16 ? null : "word aligned");
                    }
                }
                Path path = root.resolve("cancel.elf");
                Files.write(path, bytes);
                var image = ElfImage.read(path);
                for (int limit : List.of(1, 5, 12)) {
                    var count = new AtomicInteger();
                    try {
                        DwarfTarget.fromElf(image).planFunctionAliases(image, List.of(alias),
                            List.of(new FunctionSymbol("primary", 0x1040, 16)), List.of(),
                            () -> count.incrementAndGet() >= limit, ignored -> { });
                        throw new AssertionError("cancellation ignored");
                    }
                    catch (CancellationException expected) {
                        checks++;
                    }
                }
            }
        }
        System.out.println("mips-function-alias-symbols-smoke=PASS checks=" + checks);
    }

    private static byte[] fixture(ByteOrder order, int fpAbi) {
        byte[] bytes = LocalSymbolMergeSmoke.fixture(false, order, false, false);
        var record = ByteBuffer.wrap(bytes).order(order);
        record.putInt(36, 0x70001007);
        LocalSymbolMergeSmoke.field(bytes, 4, "type", 0x7000002aL);
        LocalSymbolMergeSmoke.field(bytes, 4, "flags", 2);
        LocalSymbolMergeSmoke.field(bytes, 4, "offset", 0x2e0);
        LocalSymbolMergeSmoke.field(bytes, 4, "size", 24);
        LocalSymbolMergeSmoke.field(bytes, 4, "alignment", 8);
        record.position(0x2e0);
        record.putShort((short) 0).put(new byte[] { 32, 2, 1, 1, 0, (byte) fpAbi })
            .putInt(0).putInt(0).putInt(0).putInt(0);
        return bytes;
    }

    private static void check(Path root, byte[] bytes, ElfFunctionAlias alias, String omission) throws Exception {
        Path path = root.resolve("fixture.elf");
        Files.write(path, bytes);
        var time = Files.getLastModifiedTime(path);
        var image = ElfImage.read(path);
        var diagnostics = new ArrayList<String>();
        var functions = List.of(new FunctionSymbol(alias.owner(), alias.address(), alias.ranges().stream()
            .map(range -> new FunctionRange(range.address(), range.size())).toList()));
        var actual = DwarfTarget.fromElf(image).planFunctionAliases(image, List.of(alias),
            functions, List.of(), () -> false, diagnostics::add);
        if (omission == null) {
            require(actual.equals(List.of(new ElfLocalFunctionSymbol("alternate", 0x1040, 16, 1))) &&
                diagnostics.isEmpty(), "unexpected plan " + actual + diagnostics);
        }
        else {
            require(actual.isEmpty() && diagnostics.toString().contains(omission),
                "missing restriction " + omission + diagnostics);
        }
        require(actual.equals(DwarfTarget.fromElf(image).planFunctionAliases(image, List.of(alias),
            functions, List.of(), () -> false, ignored -> { })), "nondeterministic policy");
        require(Arrays.equals(bytes, Files.readAllBytes(path)) && time.equals(Files.getLastModifiedTime(path)),
            "original changed");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
