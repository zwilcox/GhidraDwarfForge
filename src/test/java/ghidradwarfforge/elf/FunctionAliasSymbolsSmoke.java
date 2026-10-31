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

/** Original-byte and name-collision proof, independent of Ghidra/native production. */
public final class FunctionAliasSymbolsSmoke {
    private static int checks;
    private static final FunctionSymbol OWNER = new FunctionSymbol("primary", 0x1040, 16);
    private static final String HASH = hash(new byte[16]);
    private static final ElfFunctionAlias ALIAS = new ElfFunctionAlias("scope::alternate", "primary", 0x1040, 16, HASH);

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-alias-planner-");
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                byte[] bytes = LocalSymbolMergeSmoke.fixture(wide, order, false, false);
                rangeCases(root, bytes);
                check(root, bytes, List.of(ALIAS), List.of(OWNER), null);
                check(root, bytes, List.of(ALIAS, ALIAS), List.of(OWNER), "conflicts");
                check(root, bytes, List.of(alias("old_global", HASH)), List.of(OWNER), "already exists");
                check(root, bytes, List.of(alias("different", "0".repeat(64))), List.of(OWNER), "code differs");
                check(root, bytes, List.of(ALIAS), List.of(new FunctionSymbol("wrong", 0x1040, 16)), "primary definition");
                check(root, bytes, List.of(ALIAS), List.of(OWNER, new FunctionSymbol("overlap", 0x1048, 8)), "overlapping recovered");
                check(root, bytes, List.of(ALIAS), List.of(OWNER, OWNER), "primary definition");
                check(root, bytes, List.of(ALIAS), List.of(OWNER,
                    new FunctionSymbol(ALIAS.name(), 0x1060, 8)), "conflicts");
                for (String field : List.of("type", "flags", "size", "address")) {
                    byte[] changed = bytes.clone();
                    LocalSymbolMergeSmoke.field(changed, 1, field, switch (field) {
                        case "type" -> 8;
                        case "flags" -> 2;
                        case "size" -> 0x48;
                        default -> 0x1048;
                    });
                    check(root, changed, List.of(ALIAS), List.of(OWNER), "file-backed");
                }
                byte[] overlap = bytes.clone();
                LocalSymbolMergeSmoke.field(overlap, 4, "flags", 2);
                LocalSymbolMergeSmoke.field(overlap, 4, "address", 0x1048);
                check(root, overlap, List.of(ALIAS), List.of(OWNER), "overlapping original");
                for (String field : List.of("link", "size", "entsize")) {
                    byte[] changed = bytes.clone();
                    LocalSymbolMergeSmoke.field(changed, 3, field, 1);
                    check(root, changed, List.of(ALIAS), List.of(OWNER), "symbol");
                }
                byte[] badName = bytes.clone();
                ByteBuffer.wrap(badName).order(order).putInt(0x200 + (wide ? 24 : 16), -1);
                check(root, badName, List.of(ALIAS), List.of(OWNER), "name offset");
                byte[] badTerminator = bytes.clone();
                badTerminator[0x180 + 30] = 1;
                check(root, badTerminator, List.of(ALIAS), List.of(OWNER), "terminators");
                byte[] dynamic = DynamicSymbolMirrorSmoke.fixture(wide, order, false, false);
                check(root, dynamic, List.of(ALIAS), List.of(OWNER), null);
                check(root, dynamic, List.of(alias("old_global", HASH)), List.of(OWNER), "already exists");
                byte[] malformedDynamic = dynamic.clone();
                LocalSymbolMergeSmoke.field(malformedDynamic, 3, "info", 0);
                check(root, malformedDynamic, List.of(ALIAS), List.of(OWNER), "dynamic symbol framing");
                for (int row = 1; row < 4; row++) {
                    ByteBuffer.wrap(dynamic).order(order).putShort(0x200 + row * (wide ? 24 : 16) +
                        (wide ? 6 : 14), (short) 0);
                }
                check(root, dynamic, List.of(ALIAS), List.of(OWNER), null);
                check(root, dynamic, List.of(alias("old_weak", HASH)), List.of(OWNER), "already exists");
                byte[] rawName = bytes.clone();
                rawName[0x181] = (byte) 0xff;
                check(root, rawName, List.of(ALIAS), List.of(OWNER), null);
                byte[] shared = bytes.clone();
                ByteBuffer.wrap(shared).order(order).putShort(16, (short) 3);
                check(root, shared, List.of(ALIAS), List.of(OWNER), null);
                byte[] relocatable = bytes.clone();
                ByteBuffer.wrap(relocatable).order(order).putShort(16, (short) 1);
                check(root, relocatable, List.of(ALIAS), List.of(OWNER), "ET_EXEC");
                byte[] sectionless = bytes.clone();
                ByteBuffer header = ByteBuffer.wrap(sectionless).order(order);
                if (wide) {
                    header.putLong(40, 0).putShort(60, (short) 0).putShort(62, (short) 0);
                }
                else {
                    header.putInt(32, 0).putShort(48, (short) 0).putShort(50, (short) 0);
                }
                check(root, sectionless, List.of(ALIAS), List.of(OWNER), "file-backed executable allocation");
                Path path = Files.createTempFile(root, "cancel-", ".elf");
                Files.write(path, bytes);
                ElfImage image = ElfImage.read(path);
                var reservedDiagnostic = new ArrayList<String>();
                require(FunctionAliasSymbols.plan(image, List.of(ALIAS), List.of(OWNER),
                    List.of(new ElfLocalFunctionSymbol(ALIAS.name(), 0x1040, 16, 1)),
                    () -> false, reservedDiagnostic::add).isEmpty() &&
                    reservedDiagnostic.toString().contains("conflicts"), "reserved name collision lost");
                var budgetDiagnostic = new ArrayList<String>();
                require(FunctionAliasSymbols.plan(image, java.util.Collections.nCopies(65537, ALIAS),
                    List.of(OWNER), List.of(), () -> false, budgetDiagnostic::add).isEmpty() &&
                    budgetDiagnostic.toString().contains("budget"), "candidate budget ignored");
                for (int after : List.of(1, 12, 22)) {
                    AtomicInteger counter = new AtomicInteger();
                    try {
                        FunctionAliasSymbols.plan(image, List.of(ALIAS), List.of(OWNER), List.of(),
                            () -> counter.incrementAndGet() >= after, ignored -> { });
                        throw new AssertionError("cancel ignored at " + after);
                    }
                    catch (CancellationException expected) {
                        checks++;
                    }
                }
                if (!wide) {
                    var diagnostics = new ArrayList<String>();
                    require(DwarfTarget.fromElf(image).planFunctionAliases(image, List.of(ALIAS),
                        List.of(OWNER), List.of(), () -> false, diagnostics::add).isEmpty() &&
                        diagnostics.toString().contains("symbol-value policy"), "unproved target accepted");
                }
                if (order == ByteOrder.LITTLE_ENDIAN) {
                    for (int machine : wide ? List.of(62, 183) : List.of(3)) {
                        ByteBuffer.wrap(bytes).order(order).putShort(18, (short) machine);
                        Path target = Files.createTempFile(root, "target-", ".elf");
                        Files.write(target, bytes);
                        var elf = ElfImage.read(target);
                        require(DwarfTarget.fromElf(elf).planFunctionAliases(elf, List.of(ALIAS),
                            List.of(OWNER), List.of(), () -> false, ignored -> { }).size() == 1,
                            "direct target policy rejected");
                    }
                }
            }
        }
        for (String name : List.of("", "bad\0name", "bad\ud800", "λ".repeat(33000), "primary")) {
            try {
                alias(name, HASH);
                throw new AssertionError("invalid name accepted");
            }
            catch (IllegalArgumentException expected) {
                checks++;
            }
        }
        System.out.println("function-alias-symbols-smoke=PASS checks=" + checks);
    }

    private static void rangeCases(Path root, byte[] bytes) throws Exception {
        var lower = new ElfFunctionAlias.CodeRange(0x1010, 8, hash(new byte[8]));
        var upper = new ElfFunctionAlias.CodeRange(0x1060, 16, HASH);
        var alias = new ElfFunctionAlias("split_alias", "split", 0x1060, List.of(lower, upper));
        var owner = new FunctionSymbol("split", 0x1060,
            List.of(new FunctionRange(0x1010, 8), new FunctionRange(0x1060, 16)));
        rangeCheck(root, bytes, alias, List.of(owner), null);
        rangeCheck(root, bytes, alias, List.of(owner, new FunctionSymbol("gap_owner", 0x1030, 8)), null);
        rangeCheck(root, bytes, new ElfFunctionAlias("split_alias", "split", 0x1060,
            List.of(new ElfFunctionAlias.CodeRange(0x1010, 8, "0".repeat(64)), upper)), List.of(owner), "code differs");
        rangeCheck(root, bytes, new ElfFunctionAlias("split_alias", "split", 0x1060,
            List.of(upper)), List.of(owner), "primary definition");
        rangeCheck(root, bytes, alias, List.of(owner, new FunctionSymbol("overlap", 0x1014, 4)), "overlapping recovered");
        byte[] changed = bytes.clone();
        changed[0x110] = 1;
        rangeCheck(root, changed, alias, List.of(owner), "code differs");
        byte[] gap = bytes.clone();
        gap[0x130] = 1;
        rangeCheck(root, gap, alias, List.of(owner), null);
        var middle = new ElfFunctionAlias("middle_alias", "middle", 0x1050,
            List.of(new ElfFunctionAlias.CodeRange(0x1040, 32, hash(new byte[32]))));
        rangeCheck(root, bytes, middle, List.of(new FunctionSymbol("middle", 0x1050,
            List.of(new FunctionRange(0x1040, 32)))), null);
        for (var bad : List.of(List.of(upper, lower), List.of(lower, lower, upper), List.of(lower))) {
            try {
                new ElfFunctionAlias("invalid", "split", 0x1060, bad);
                throw new AssertionError("invalid alias ranges accepted");
            }
            catch (IllegalArgumentException expected) {
                checks++;
            }
        }
    }

    private static void rangeCheck(Path root, byte[] bytes, ElfFunctionAlias alias,
            List<FunctionSymbol> owners, String omitted) throws Exception {
        Path input = Files.createTempFile(root, "range-", ".elf");
        Files.write(input, bytes);
        var image = ElfImage.read(input);
        var diagnostics = new ArrayList<String>();
        var planned = FunctionAliasSymbols.plan(image, List.of(alias), owners, List.of(), () -> false, diagnostics::add);
        if (omitted == null) {
            require(planned.equals(List.of(new ElfLocalFunctionSymbol(alias.name(), alias.address(), 16, 1))) &&
                diagnostics.isEmpty(), "range plan invented coverage: " + planned + diagnostics);
            Path output = Files.createTempFile(root, "range-sidecar-", ".dbg");
            new MatchedElfSidecarWriter().write(image, output, java.util.Map.of(".debug_info", new byte[] { 1 }),
                planned, () -> false);
            require(Files.size(output) > 0 && Arrays.equals(bytes, Files.readAllBytes(input)), "range write changed input");
            AtomicInteger total = new AtomicInteger();
            FunctionAliasSymbols.plan(image, List.of(alias), owners, List.of(),
                () -> { total.incrementAndGet(); return false; }, ignored -> { });
            for (int limit : List.of(total.get() / 2, total.get())) {
                AtomicInteger counter = new AtomicInteger();
                try {
                    FunctionAliasSymbols.plan(image, List.of(alias), owners, List.of(),
                        () -> counter.incrementAndGet() >= limit, ignored -> { });
                    throw new AssertionError("range cancellation ignored");
                }
                catch (CancellationException expected) {
                    checks++;
                }
            }
        }
        else {
            require(planned.isEmpty() && diagnostics.toString().contains(omitted),
                "range omission lost: " + planned + diagnostics);
        }
    }

    private static ElfFunctionAlias alias(String name, String hash) {
        return new ElfFunctionAlias(name, "primary", 0x1040, 16, hash);
    }

    private static void check(Path root, byte[] bytes, List<ElfFunctionAlias> aliases,
            List<FunctionSymbol> owners, String omitted) throws Exception {
        Path input = Files.createTempFile(root, "case-", ".elf");
        Files.write(input, bytes);
        var diagnostics = new ArrayList<String>();
        var image = ElfImage.read(input);
        var result = FunctionAliasSymbols.plan(image, aliases, owners, List.of(), () -> false, diagnostics::add);
        if (omitted == null) {
            require(result.equals(List.of(new ElfLocalFunctionSymbol(ALIAS.name(), 0x1040, 16, 1))) &&
                diagnostics.isEmpty(), "unexpected plan/diagnostic " + result + diagnostics);
            require(result.equals(FunctionAliasSymbols.plan(image, aliases, owners, List.of(), () -> false,
                ignored -> { })), "nondeterministic plan");
            if (image.sections().stream().anyMatch(section -> section.type == 11)) {
                Path output = Files.createTempFile(root, "dynamic-alias-", ".dbg");
                new MatchedElfSidecarWriter().write(image, output,
                    java.util.Map.of(".debug_info", new byte[] { 1 }), result, () -> false);
                var written = ElfImage.read(output);
                var dynamic = image.sections().stream().filter(section -> section.type == 11)
                    .findFirst().orElseThrow();
                require(Arrays.equals(image.sectionData(dynamic),
                    written.sectionData(written.sections().get(dynamic.originalIndex))),
                    "planned alias damaged dynamic inventory");
                require(written.sections().stream().anyMatch(section -> section.type == 2 &&
                    section.size == dynamic.size + (image.is64Bit() ? 24 : 16)),
                    "planned alias did not retain complete inventory");
            }
        }
        else {
            require(result.isEmpty() && diagnostics.toString().contains(omitted),
                "missing omission " + omitted + ": " + diagnostics + result);
        }
        require(Arrays.equals(bytes, Files.readAllBytes(input)), "input modified");
    }


    private static String hash(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
