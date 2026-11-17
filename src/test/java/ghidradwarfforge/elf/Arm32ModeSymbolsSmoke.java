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
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Source-built ELF controls: no native producer, debugger, or compiler fixture dependency. */
public final class Arm32ModeSymbolsSmoke {
    private static final int TEXT = 0x10100;
    private static int checks;

    public static void main(String[] arguments) throws Exception {
        Path root = Files.createTempDirectory("arm-mode-symbols-");
        try {
            run(root);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void run(Path root) throws Exception {
        byte[] ordinary = fixture(1);
        Path input = root.resolve("input");
        Files.write(input, ordinary);
        ElfFunctionModeCue thumb = cue(ordinary, 0, 16, true);
        ElfFunctionModeCue arm = cue(ordinary, 16, 16, false);
        List<String> diagnostics = new ArrayList<>();
        ElfImage image = ElfImage.read(input);
        List<ElfLocalFunctionSymbol> symbols = Arm32ModeSymbols.plan(image,
            List.of(arm, thumb), () -> false, diagnostics::add);
        require(symbols.size() == 2, "both homogeneous modes planned");
        require(symbols.get(0).value() == TEXT + 1 && symbols.get(0).size() == 16,
            "Thumb tag and exact positive size");
        require(symbols.get(1).value() == TEXT + 16 && symbols.get(1).size() == 16,
            "ARM address and exact positive size");
        require(symbols.stream().allMatch(symbol -> symbol.sectionIndex() == 1),
            "original section indices retained");
        require(diagnostics.isEmpty(), "successful cues do not downgrade report status");
        Path output = root.resolve("symbols.dbg");
        Map<String, byte[]> dwarf = Map.of(".debug_info", new byte[] { 1, 2, 3 });
        new MatchedElfSidecarWriter().write(image, output, dwarf, symbols, () -> false);
        inspectOutput(output, 1, symbols, ordinary, false);
        require(Arrays.equals(ordinary, Files.readAllBytes(input)), "original bytes unchanged");
        Path repeat = root.resolve("repeat.dbg");
        new MatchedElfSidecarWriter().write(image, repeat, dwarf, symbols, () -> false);
        require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(repeat)),
            "symbol serialization is deterministic");

        diagnostics.clear();
        require(Arm32ModeSymbols.plan(image, List.of(arm), () -> false, diagnostics::add).isEmpty(),
            "ARM-only input has no supplement");
        require(diagnostics.isEmpty(), "ARM-only diagnostic compatibility");
        Path old = root.resolve("ordinary.dbg");
        Path same = root.resolve("empty-plan.dbg");
        new MatchedElfSidecarWriter().write(input, old, dwarf);
        new MatchedElfSidecarWriter().write(image, same, dwarf, List.of(), () -> false);
        require(Arrays.equals(Files.readAllBytes(old), Files.readAllBytes(same)),
            "empty plan retains byte-identical writer path");

        reject(root, ordinary, List.of(new ElfFunctionModeCue("wrong digest", TEXT, 16,
            TEXT + 1, "0".repeat(64))), "decoded instruction bytes differ");
        reject(root, ordinary, List.of(thumb, cue(ordinary, 8, 16, false)), "overlapping");
        reject(root, ordinary, List.of(thumb, thumb), "overlapping");
        reject(root, ordinary, List.of(new ElfFunctionModeCue("bad tag", TEXT, 16,
            TEXT + 3, thumb.codeSha256())), "encoded value");
        reject(root, ordinary, List.of(new ElfFunctionModeCue("odd code", TEXT + 1, 16,
            TEXT + 1, thumb.codeSha256())), "encoded value");
        reject(root, ordinary, List.of(new ElfFunctionModeCue("unbacked", TEXT + 128, 16,
            TEXT + 129, thumb.codeSha256())), "unique executable allocation");

        byte[] existing = ordinary.clone();
        put(existing, sectionOffset(existing, 2) + 4, 2);
        reject(root, existing, List.of(thumb), "existing SHT_SYMTAB");
        for (String name : List.of(".symtab", ".strtab", ".symtab_shndx")) {
            byte[] reserved = ordinary.clone();
            put(reserved, sectionOffset(reserved, 2), nameOffset(name));
            reject(root, reserved, List.of(thumb), "reserved section name collision " + name);
        }
        byte[] sectionless = ordinary.clone();
        put(sectionless, 32, 0);
        half(sectionless, 48, 0);
        half(sectionless, 50, 0);
        reject(root, sectionless, List.of(thumb), "sectionless");
        byte[] relocatable = ordinary.clone();
        half(relocatable, 16, 1);
        reject(root, relocatable, List.of(thumb), "only ET_EXEC");
        byte[] shared = ordinary.clone();
        half(shared, 16, 3);
        reject(root, shared, List.of(thumb), "only ET_EXEC");
        Files.write(input, shared);
        diagnostics.clear();
        require(Arm32ModeSymbols.plan(ElfImage.read(input), List.of(arm), () -> false,
            diagnostics::add).isEmpty() && diagnostics.isEmpty(),
            "ARM-only shared object keeps the existing no-cue path");
        byte[] noBits = ordinary.clone();
        put(noBits, sectionOffset(noBits, 1) + 4, 8);
        reject(root, noBits, List.of(thumb), "backed by original code bytes");
        byte[] overlap = ordinary.clone();
        int second = sectionOffset(overlap, 2);
        put(overlap, second + 8, 6);
        put(overlap, second + 12, TEXT + 8);
        put(overlap, second + 16, 0x108);
        put(overlap, second + 20, 16);
        reject(root, overlap, List.of(thumb), "unique executable allocation");

        // A defined dynamic function, an untyped code label, and a zero-sized
        // earlier label can all supply competing minimal-symbol information.
        reject(root, dynamic(ordinary, TEXT + 1, 16, 2, 1), List.of(thumb), "defined dynamic symbols");
        reject(root, dynamic(ordinary, TEXT + 8, 4, 0, 1), List.of(thumb), "defined dynamic symbols");
        reject(root, dynamic(ordinary, TEXT, 0, 0, 1), List.of(thumb), "defined dynamic symbols");
        reject(root, dynamic(ordinary, TEXT + 1, 16, 2, 0xfff1), List.of(thumb), "reserved index");
        reject(root, dynamic(ordinary, TEXT + 1, 16, 10, 0xff02), List.of(thumb), "reserved index");
        reject(root, dynamic(ordinary, TEXT + 1, 16, 2, 0xffff), List.of(thumb), "missing dynamic");
        reject(root, dynamic(ordinary, TEXT + 1, 16, 2, 10), List.of(thumb), "section index");
        byte[] malformed = dynamic(ordinary, 0, 0, 0, 0);
        put(malformed, sectionOffset(malformed, 2) + 36, 15);
        reject(root, malformed, List.of(thumb), "framing");
        malformed = dynamic(ordinary, 0, 0, 0, 0);
        malformed[0x180] = 1;
        reject(root, malformed, List.of(thumb), "row zero");
        // Even a nonoverlapping function or data/absolute definition would be
        // hidden by GDB's static-table precedence. Binding does not rescue it.
        for (int type : List.of(0, 1, 2, 3, 4, 6, 10)) {
            for (int binding : List.of(0, 1, 2, 10)) {
                byte[] defined = dynamic(ordinary, TEXT + 32, 16, type, 1);
                defined[0x19c] = (byte) ((binding << 4) | type);
                reject(root, defined, List.of(thumb), "defined dynamic symbols");
            }
        }
        reject(root, dynamic(ordinary, TEXT, 16, 1, 0xfff1), List.of(thumb),
            "defined dynamic symbols");
        reject(root, dynamic(ordinary, 0, 4, 1, 3), List.of(thumb),
            "defined dynamic symbols");
        for (byte[] harmless : List.of(dynamic(ordinary, 0, 0, 2, 0),
                dynamic(ordinary, TEXT + 32, 0, 2, 0))) {
            Files.write(input, harmless);
            diagnostics.clear();
            require(Arm32ModeSymbols.plan(ElfImage.read(input), List.of(thumb), () -> false,
                diagnostics::add).size() == 1, "undefined dynamic function remains available to GDB");
        }
        byte[] unnamed = dynamic(ordinary, TEXT + 8, 4, 0, 1);
        put(unnamed, 0x190, 0);
        reject(root, unnamed, List.of(thumb), "dynamic code symbol");
        unnamed = dynamic(ordinary, TEXT + 1, 80, 2, 1);
        put(unnamed, 0x190, 0);
        reject(root, unnamed, List.of(thumb), "exceeds its section");
        unnamedDynamicIntervals(root, ordinary);
        dynamicFramingBoundaries(root, ordinary);
        cueGeometryBoundaries(root, ordinary, thumb);
        inventoryLimits(root, ordinary, thumb);
        recoveredCueAdmission(root, ordinary, thumb);

        // Extended section counts and a high referenced index need SHNDX entries;
        // this is metadata-only scale, well below the actual 64 MiB smoke heap.
        byte[] extended = fixture(0xff00);
        Files.write(input, extended);
        image = ElfImage.read(input);
        symbols = Arm32ModeSymbols.plan(image, List.of(cue(extended, 0, 16, true)),
            () -> false, ignored -> { });
        require(symbols.size() == 1 && symbols.get(0).sectionIndex() == 0xff00,
            "high section index planned without narrowing");
        Path high = root.resolve("extended.dbg");
        new MatchedElfSidecarWriter().write(image, high, dwarf, symbols, () -> false);
        inspectOutput(high, 0xff00, symbols, extended, true);

        byte[] dynamicExtended = dynamic(extended, TEXT + 1, 16, 2, 0xffff);
        row(dynamicExtended, 5, ".opaque", 18, 0, 0, 0x220, 8, 2, 0, 4, 4);
        put(dynamicExtended, 0x224, 0xff00);
        reject(root, dynamicExtended, List.of(cue(extended, 0, 16, true)), "defined dynamic symbols");
        byte[] badExtended = dynamicExtended.clone();
        put(badExtended, 0x224, 1);
        reject(root, badExtended, List.of(cue(extended, 0, 16, true)), "invalid dynamic extended");
        badExtended = dynamicExtended.clone();
        half(badExtended, 0x19e, 1);
        reject(root, badExtended, List.of(cue(extended, 0, 16, true)), "nonzero unused dynamic");
        badExtended = dynamicExtended.clone();
        row(badExtended, 6, ".opaque", 18, 0, 0, 0x220, 8, 2, 0, 4, 4);
        reject(root, badExtended, List.of(cue(extended, 0, 16, true)), "duplicate dynamic extended");

        byte[] mixedIndices = extended.clone();
        put(mixedIndices, sectionOffset(mixedIndices, 0xff00) + 20, 16);
        row(mixedIndices, 1, ".opaque", 1, 6, TEXT + 32, 0x120, 16, 0, 0, 4, 0);
        Files.write(input, mixedIndices);
        image = ElfImage.read(input);
        symbols = Arm32ModeSymbols.plan(image, List.of(cue(mixedIndices, 0, 16, true),
            cue(mixedIndices, 32, 16, false)), () -> false, ignored -> { });
        require(symbols.size() == 2, "escaped and ordinary referenced indexes together");
        Path mixedOutput = root.resolve("mixed-indices.dbg");
        new MatchedElfSidecarWriter().write(image, mixedOutput, dwarf, symbols, () -> false);
        ElfImage mixedResult = ElfImage.read(mixedOutput);
        ByteBuffer mixedRows = ByteBuffer.wrap(mixedResult.sectionData(section(mixedResult,
            ".symtab_shndx"))).order(ByteOrder.LITTLE_ENDIAN);
        require(mixedRows.remaining() == 12 && mixedRows.getInt(0) == 0 &&
            mixedRows.getInt(4) == 0xff00 && mixedRows.getInt(8) == 0,
            "all unused extended rows are zero including ordinary function row");

        Files.write(input, ordinary);
        ElfImage limited = ElfImage.read(input);
        diagnostics.clear();
        require(Arm32ModeSymbols.plan(limited, java.util.Collections.nCopies(65537, thumb),
            () -> false, diagnostics::add).isEmpty() &&
            diagnostics.get(0).contains("cue count exceeds"), "cue count preallocation bound");
        require(Arm32ModeSymbols.plan(limited, java.util.Collections.nCopies(65536, thumb),
            () -> false, ignored -> { }).isEmpty(), "exact cue limit remains bounded with overlaps");
        List<ElfLocalFunctionSymbol> tooMany = java.util.Collections.nCopies(65537,
            new ElfLocalFunctionSymbol("x", TEXT + 1, 16, 1));
        Path overOutput = root.resolve("over-limit.dbg");
        expect(IllegalArgumentException.class, () -> new MatchedElfSidecarWriter().write(
            limited, overOutput, dwarf, tooMany, () -> false));
        require(!Files.exists(overOutput), "symbol count bound before final creation");

        // A two-chunk code interval exercises streamed hashing, not just the tiny
        // fixture hash path, and cancellation after the first actual code read.
        byte[] streamed = largeFixture();
        Files.write(input, streamed);
        ElfImage streamedImage = ElfImage.read(input);
        ElfFunctionModeCue streamedCue = cue(streamed, 0, 65552, true);
        require(Arm32ModeSymbols.plan(streamedImage, List.of(streamedCue), () -> false,
            ignored -> { }).size() == 1, "multi-chunk original code binding");
        AtomicInteger readPolls = new AtomicInteger();
        expect(CancellationException.class, () -> Arm32ModeSymbols.plan(streamedImage,
            List.of(streamedCue), () -> {
                boolean hashing = StackWalker.getInstance().walk(frames -> frames.anyMatch(
                    frame -> frame.getClassName().equals(Arm32ModeSymbols.class.getName()) &&
                        frame.getMethodName().equals("hash")));
                return hashing && readPolls.incrementAndGet() == 2;
            }, ignored -> { }));
        require(readPolls.get() == 2, "cancel after first hash chunk");
        byte[] foreign = ordinary.clone();
        half(foreign, 18, 62);
        Files.write(input, foreign);
        ElfImage foreignImage = ElfImage.read(input);
        expect(IllegalArgumentException.class, () -> Arm32ModeSymbols.plan(foreignImage,
            List.of(thumb), () -> false, ignored -> { }));

        Files.write(input, ordinary);
        ElfImage cancelImage = ElfImage.read(input);
        AtomicInteger calls = new AtomicInteger();
        expect(CancellationException.class, () -> Arm32ModeSymbols.plan(cancelImage,
            List.of(thumb), () -> calls.incrementAndGet() == 4, ignored -> { }));
        require(calls.get() == 4, "cancellation observed in metadata walk");
        IllegalArgumentException callback = new IllegalArgumentException("supplier identity");
        AtomicInteger dynamicPolls = new AtomicInteger();
        try {
            Arm32ModeSymbols.plan(cancelImage, List.of(thumb), () -> {
                boolean inDynamic = StackWalker.getInstance().walk(frames -> frames.anyMatch(
                    frame -> frame.getClassName().equals(Arm32ModeSymbols.class.getName()) &&
                        frame.getMethodName().equals("dynamicRanges")));
                if (inDynamic && dynamicPolls.incrementAndGet() == 2) {
                    throw callback;
                }
                return false;
            }, ignored -> { });
            throw new AssertionError("callback failure swallowed");
        }
        catch (IllegalArgumentException failure) {
            require(failure == callback && dynamicPolls.get() == 2,
                "supplier exception identity preserved through dynamic traversal");
        }
        Path cancelledOutput = root.resolve("cancelled.dbg");
        calls.set(0);
        expect(CancellationException.class, () -> new MatchedElfSidecarWriter().write(
            cancelImage, cancelledOutput, dwarf,
            List.of(new ElfLocalFunctionSymbol("synthetic", TEXT + 1, 16, 1)),
            () -> calls.incrementAndGet() == 3));
        require(!Files.exists(cancelledOutput), "cancelled planning leaves no final artifact");
        expect(IllegalArgumentException.class, () -> new MatchedElfSidecarWriter().write(
            cancelImage, input, dwarf, List.of(), () -> false));
        byte[] changed = ordinary.clone();
        changed[0x100] ^= 1;
        Files.write(input, changed);
        Files.setLastModifiedTime(input, java.nio.file.attribute.FileTime.fromMillis(
            Files.getLastModifiedTime(input).toMillis() + 5000));
        expect(java.io.IOException.class, () -> Arm32ModeSymbols.plan(cancelImage,
            List.of(thumb), () -> false, ignored -> { }));
        expect(IllegalArgumentException.class, () -> new ElfFunctionModeCue("bad", 1, 0, 1,
            thumb.codeSha256()));
        expect(IllegalArgumentException.class, () -> new ElfFunctionModeCue("bad", 1, 1, 1, "bad"));
        System.out.println("ARM32 mode symbols PASS checks=" + checks);
    }

    private static void dynamicFramingBoundaries(Path root, byte[] ordinary) throws Exception {
        for (int link : new int[] {0, 1, 6, -1}) {
            byte[] bytes = dynamic(ordinary, 0, 0, 0, 0);
            put(bytes, sectionOffset(bytes, 2) + 24, link);
            reject(root, bytes, List.of(cue(ordinary, 0, 16, true)), "table framing");
        }
        for (int size : new int[] {0, 31}) {
            byte[] bytes = dynamic(ordinary, 0, 0, 0, 0);
            put(bytes, sectionOffset(bytes, 2) + 20, size);
            reject(root, bytes, List.of(cue(ordinary, 0, 16, true)), "table framing");
        }
        for (int[] shape : new int[][] {{3, 8}, {4, 4}, {4, 12}}) {
            byte[] bytes = dynamic(ordinary, 0, 0, 0, 0);
            row(bytes, 4, ".opaque", 18, 0, 0, 0x220, shape[1], 2, 0, 4, shape[0]);
            reject(root, bytes, List.of(cue(ordinary, 0, 16, true)), "extended-index table");
        }
        // An unrelated SHNDX section must not be mistaken for this table's indices.
        for (int link : new int[] {0, 1, 6, -1}) {
            byte[] bytes = dynamic(ordinary, 0, 0, 0, 0);
            row(bytes, 4, ".opaque", 18, 0, 0, 0x220, 8, link, 0, 4, 4);
            accept(root, bytes, cue(ordinary, 0, 16, true), "unrelated index table");
        }
        for (int[] symbol : new int[][] {{TEXT - 2, 2, 1}, {TEXT + 66, 2, 1}}) {
            byte[] bytes = dynamic(ordinary, symbol[0], symbol[1], 2, symbol[2]);
            put(bytes, 0x190, 0);
            reject(root, bytes, List.of(cue(ordinary, 0, 16, true)), "exceeds its section");
        }
        for (int index : new int[] {3, 0xfff1}) {
            byte[] bytes = dynamic(ordinary, 0, 0, 1, index);
            put(bytes, 0x190, 0);
            accept(root, bytes, cue(ordinary, 0, 16, true), "unnamed non-code definition");
        }
        System.out.println("arm-mode-dynamic-framing=PASS");
    }

    private static void recoveredCueAdmission(Path root, byte[] bytes, ElfFunctionModeCue thumb)
            throws Exception {
        Path file = root.resolve("recovered-cue-admission");
        Files.write(file, bytes);
        var image = ElfImage.read(file);
        var owner = new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol(
            thumb.displayName(), thumb.address(), thumb.size());
        var messages = new ArrayList<String>();
        var result = Arm32ModeSymbols.planRecovered(image, List.of(thumb), List.of(owner),
            () -> false, messages::add);
        require(result.equals(List.of(new ElfLocalFunctionSymbol("__forge_arm_mode_00010100",
            TEXT + 1, 16, 1))) && messages.isEmpty(), "recovered cue positive ownership control: " + messages);
        messages.clear();
        require(Arm32ModeSymbols.planRecovered(image, java.util.Collections.nCopies(65537, thumb),
            List.of(owner), () -> false, messages::add).isEmpty() && messages.size() == 1 &&
            messages.getFirst().contains("cue count exceeds"), "recovered count refusal before alias allocation");
        messages.clear();
        var collision = new ElfFunctionModeCue("__forge_arm_mode_00010100", TEXT, 16,
            TEXT + 1, thumb.codeSha256());
        require(Arm32ModeSymbols.planRecovered(image, List.of(collision), List.of(owner),
            () -> false, messages::add).isEmpty() && messages.stream().anyMatch(s ->
                s.contains("synthetic name conflicts with owner")), "analyst name is not reused as a synthetic alias");
        messages.clear();
        var arm = cue(bytes, 32, 16, false);
        var armOwner = new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol(
            arm.displayName(), arm.address(), arm.size());
        var wrongThumb = new ElfFunctionModeCue(thumb.displayName(), TEXT, 16, TEXT + 1, "0".repeat(64));
        require(Arm32ModeSymbols.planRecovered(image, List.of(arm, wrongThumb), List.of(owner, armOwner),
            () -> false, messages::add).isEmpty() && messages.stream().anyMatch(s ->
                s.contains("no eligible Thumb cue remains")) && messages.stream().anyMatch(s ->
                s.contains("code differs")), "remaining ARM aliases cannot justify a Thumb supplement");
        require(Arrays.equals(bytes, Files.readAllBytes(file)), "recovered cue admission preserves original input");
        System.out.println("arm-mode-recovered-admission=PASS");
    }

    private static void cueGeometryBoundaries(Path root, byte[] ordinary,
            ElfFunctionModeCue thumb) throws Exception {
        for (long[] geometry : new long[][] {
                {0x1_0000_0000L, 2, 0x1_0000_0001L},
                {TEXT, 0x1_0000_0000L, TEXT + 1},
                {0xffff_fffeL, 4, 0xffff_ffffL},
                {TEXT, 3, TEXT + 1},
                {TEXT + 2, 4, TEXT + 2},
                {TEXT, 6, TEXT}}) {
            var invalid = new ElfFunctionModeCue("invalid geometry", geometry[0], geometry[1],
                geometry[2], thumb.codeSha256());
            // Keep an unrelated valid Thumb cue so ARM alignment is actually examined.
            var survivor = cue(ordinary, 32, 16, true);
            boolean arm = (geometry[2] & 1) == 0;
            Path file = root.resolve("geometry-" + checks);
            Files.write(file, ordinary);
            var messages = new ArrayList<String>();
            var result = Arm32ModeSymbols.plan(ElfImage.read(file),
                arm ? List.of(invalid, survivor) : List.of(invalid),
                () -> false, messages::add);
            require(arm ? result.size() == 1 && result.getFirst().value() == TEXT + 33 : result.isEmpty(),
                "invalid geometry is omitted while unrelated valid Thumb code survives");
            require(messages.getFirst().contains("encoded value, extent or alignment"),
                "geometry refusal precedes byte binding: " + messages);
            require(Arrays.equals(ordinary, Files.readAllBytes(file)), "geometry refusal preserves input");
        }
        reject(root, ordinary, List.of(new ElfFunctionModeCue("crosses section end", TEXT + 60,
            8, TEXT + 61, thumb.codeSha256())), "unique executable allocation");
        byte[] wrapping = ordinary.clone();
        put(wrapping, sectionOffset(wrapping, 1) + 12, -16);
        reject(root, wrapping, List.of(new ElfFunctionModeCue("wrapping allocation", 0xffff_fff0L,
            8, 0xffff_fff1L, thumb.codeSha256())), "backed by original code bytes");
        System.out.println("arm-mode-cue-geometry=PASS");
    }

    private static void inventoryLimits(Path root, byte[] ordinary,
            ElfFunctionModeCue thumb) throws Exception {
        for (int count : new int[] {262144, 262145}) {
            int offset = ordinary.length;
            byte[] bytes = Arrays.copyOf(ordinary, offset + count * 16);
            row(bytes, 2, ".opaque", 11, 0, 0, offset, count * 16, 3, 1, 4, 16);
            put(bytes, 68, bytes.length);
            put(bytes, 72, bytes.length);
            if (count == 262144) {
                accept(root, bytes, thumb, "exact dynamic inventory limit");
            }
            else {
                reject(root, bytes, List.of(thumb), "table framing");
            }
        }
        for (int count : new int[] {256, 257}) {
            byte[] bytes = fixture(260);
            for (int index = 1; index < count; index++) {
                row(bytes, index, ".opaque", 1, 6, TEXT, 0x100, 64, 0, 0, 4, 0);
            }
            Path file = root.resolve("allocation-budget-" + count);
            Files.write(file, bytes);
            var messages = new ArrayList<String>();
            var result = Arm32ModeSymbols.plan(ElfImage.read(file),
                java.util.Collections.nCopies(65536, thumb), () -> false, messages::add);
            require(result.isEmpty(), "ambiguous repeated cues never emit mode symbols");
            if (count == 256) {
                require(messages.stream().noneMatch(s -> s.contains("comparison budget")) &&
                    messages.stream().anyMatch(s -> s.contains("overlapping recovered")),
                    "exact allocation comparison budget reaches semantic rejection");
            }
            else {
                require(messages.size() == 1 && messages.getFirst().contains("comparison budget"),
                    "first allocation comparison excess is refused before traversal");
            }
            require(Arrays.equals(bytes, Files.readAllBytes(file)), "budget checking preserves input");
        }
        System.out.println("arm-mode-inventory-limits=PASS");
    }

    private static void accept(Path root, byte[] bytes, ElfFunctionModeCue cue, String reason)
            throws Exception {
        Path file = root.resolve("accepted-" + checks);
        Files.write(file, bytes);
        var messages = new ArrayList<String>();
        var result = Arm32ModeSymbols.plan(ElfImage.read(file), List.of(cue), () -> false, messages::add);
        require(result.size() == 1 && result.getFirst().value() == cue.symbolValue() &&
            result.getFirst().size() == cue.size() && result.getFirst().sectionIndex() == 1,
            "exact accepted cue: " + reason + " " + messages);
        require(messages.isEmpty(), "no diagnostic for " + reason);
        require(Arrays.equals(bytes, Files.readAllBytes(file)), "accepted planning preserves input");
    }

    /** An independent interval oracle: adjacency is harmless; any shared byte conflicts. */
    private static void unnamedDynamicIntervals(Path root, byte[] ordinary) throws Exception {
        int before = checks;
        int scenarios = 0;
        int[][][] inventories = {
            {{0, 8}, {16, 8}, {8, 8}},       // bridge two existing intervals
            {{0, 32}, {8, 8}, {16, 8}},     // nested intervals
            {{0, 8}, {16, 8}, {32, 8}},     // separated intervals
            {{16, 8}, {8, 8}, {0, 8}},      // reverse adjacency
            {{16, 0}, {0, 8}, {64, 0}},     // unknown size reaches section end; empty end label
            {{0, 8}, {0, 16}, {0, 4}}       // duplicate starts with different extents
        };
        int[][] permutations = {{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}};
        for (int type : new int[] {0, 2, 10}) {
            for (int[][] inventory : inventories) {
                for (int[] permutation : permutations) {
                    byte[] bytes = dynamic(ordinary, 0, 0, type, 0);
                    put(bytes, sectionOffset(bytes, 2) + 20, 64);
                    for (int i = 0; i < 3; i++) {
                        int[] interval = inventory[permutation[i]];
                        int at = 0x190 + i * 16;
                        put(bytes, at, 0); // deliberately unnamed; named definitions are refused separately
                        put(bytes, at + 4, (TEXT + interval[0]) | (type == 0 ? 0 : 1));
                        put(bytes, at + 8, interval[1]);
                        bytes[at + 12] = (byte) (0x10 | type);
                        bytes[at + 13] = 0;
                        half(bytes, at + 14, 1);
                    }
                    Path file = root.resolve("unnamed-dynamic-input");
                    Files.write(file, bytes);
                    var image = ElfImage.read(file);
                    for (int width : new int[] {2, 8}) {
                        for (int start = 0; start + width <= 64; start += 2) {
                            boolean occupied = false;
                            for (int[] interval : inventory) {
                                int end = interval[1] == 0 ? 64 : interval[0] + interval[1];
                                occupied |= interval[0] < start + width && start < end;
                            }
                            var messages = new ArrayList<String>();
                            var selected = cue(bytes, start, width, true);
                            var planned = Arm32ModeSymbols.plan(image, List.of(selected), () -> false, messages::add);
                            require(planned.size() == (occupied ? 0 : 1),
                                "dynamic interval conflict differs from byte-interval oracle at " + start + "/" + width);
                            if (occupied) {
                                require(messages.stream().anyMatch(message -> message.contains("existing dynamic code symbol")),
                                    "actual dynamic overlap requires its precise omission reason");
                            }
                            else {
                                require(messages.isEmpty() && planned.getFirst().value() == TEXT + start + 1 &&
                                    planned.getFirst().size() == width && planned.getFirst().sectionIndex() == 1,
                                    "adjacent or disjoint cue retains exact Thumb identity");
                            }
                            scenarios++;
                        }
                    }
                    require(Arrays.equals(bytes, Files.readAllBytes(file)), "range planning preserves the dynamic table");
                }
            }
        }
        System.out.println("arm-unnamed-dynamic-intervals=PASS scenarios=" + scenarios + " checks=" + (checks - before));
    }

    private static void inspectOutput(Path output, int textIndex,
            List<ElfLocalFunctionSymbol> expected, byte[] original, boolean extended) throws Exception {
        ElfImage result = ElfImage.read(output);
        ElfImage.Section sym = section(result, ".symtab");
        ElfImage.Section str = section(result, ".strtab");
        require(sym.type == 2 && sym.flags == 0 && sym.entrySize == 16 && sym.alignment == 4 &&
            sym.offset % 4 == 0 && sym.link == str.originalIndex && sym.info == expected.size() + 1,
            "canonical local symbol table header");
        require(str.type == 3 && str.flags == 0 && str.alignment == 1, "canonical string table");
        byte[] rows = result.sectionData(sym);
        byte[] names = result.sectionData(str);
        require(rows.length == (expected.size() + 1) * 16 && names[0] == 0,
            "table and string framing");
        require(Arrays.equals(Arrays.copyOf(rows, 16), new byte[16]), "null symbol row");
        ByteBuffer table = ByteBuffer.wrap(rows).order(ByteOrder.LITTLE_ENDIAN);
        for (int index = 0; index < expected.size(); index++) {
            int at = (index + 1) * 16;
            ElfLocalFunctionSymbol symbol = expected.get(index);
            require(Integer.toUnsignedLong(table.getInt(at + 4)) == symbol.value() &&
                Integer.toUnsignedLong(table.getInt(at + 8)) == symbol.size(), "exact symbol value/size");
            require(table.get(at + 12) == 2 && table.get(at + 13) == 0 &&
                Short.toUnsignedInt(table.getShort(at + 14)) == (extended ? 0xffff : textIndex),
                "local binding/function type/visibility/index");
            int name = table.getInt(at);
            int end = name;
            while (names[end] != 0) {
                end++;
            }
            require(new String(names, name, end - name, java.nio.charset.StandardCharsets.UTF_8)
                .equals(symbol.name()), "deterministic synthetic name");
        }
        if (extended) {
            ElfImage.Section xindex = section(result, ".symtab_shndx");
            ByteBuffer xrows = ByteBuffer.wrap(result.sectionData(xindex)).order(ByteOrder.LITTLE_ENDIAN);
            require(xindex.type == 18 && xindex.link == sym.originalIndex && xindex.entrySize == 4 &&
                xindex.alignment == 4 && xrows.getInt(0) == 0 && xrows.getInt(4) == textIndex,
                "proper full-width extended symbol index");
        }
        ElfImage.Section text = result.sections().get(textIndex);
        require(text.originalIndex == textIndex && text.address == TEXT && text.offset == 0x100 &&
            text.size == 64 && Arrays.equals(result.sectionData(text),
                Arrays.copyOfRange(original, 0x100, 0x140)), "original code section/index retained");
        ElfImage.Section relocation = result.sections().get(4);
        require(relocation.type == 8 && relocation.link == 0 && relocation.info == 0 &&
            relocation.size == 0, "relocation retirement remains unchanged");
        require(Arrays.equals(result.sectionData(section(result, ".debug_info")),
            new byte[] { 1, 2, 3 }), "DWARF payload unchanged");
    }

    private static ElfImage.Section section(ElfImage image, String name) {
        return image.sections().stream().filter(section -> section.name.equals(name)).findFirst().orElseThrow();
    }

    private static void reject(Path root, byte[] bytes, List<ElfFunctionModeCue> cues,
            String reason) throws Exception {
        Path file = root.resolve("negative-" + checks);
        Files.write(file, bytes);
        List<String> messages = new ArrayList<>();
        require(Arm32ModeSymbols.plan(ElfImage.read(file), cues, () -> false, messages::add).isEmpty(),
            "cue omitted: " + reason);
        require(messages.stream().anyMatch(message -> message.contains(reason)),
            "precise omission reason: " + reason + " " + messages);
        require(Arrays.equals(Files.readAllBytes(file), bytes), "omission preserves input");
    }

    private static byte[] dynamic(byte[] original, int value, int size, int type, int index) {
        byte[] bytes = original.clone();
        int section = sectionOffset(bytes, 2);
        put(bytes, section + 4, 11);
        put(bytes, section + 24, 3);
        put(bytes, section + 28, 1);
        put(bytes, section + 36, 16);
        put(bytes, 0x190, 1);
        put(bytes, 0x194, value);
        put(bytes, 0x198, size);
        bytes[0x19c] = (byte) (0x10 | type);
        half(bytes, 0x19e, index);
        return bytes;
    }

    private static ElfFunctionModeCue cue(byte[] bytes, int offset, int size, boolean thumb) throws Exception {
        return new ElfFunctionModeCue("curated " + offset, TEXT + offset, size,
            TEXT + offset + (thumb ? 1 : 0), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(Arrays.copyOfRange(bytes, 0x100 + offset, 0x100 + offset + size))));
    }

    private static final String NAMES = "\0.text\0.opaque\0.dynstr\0.rel.text\0.shstrtab\0.symtab\0.strtab\0.symtab_shndx\0";

    private static int nameOffset(String name) {
        return NAMES.indexOf(name + "\0");
    }

    static byte[] fixture(int textIndex) {
        int count = Math.max(6, textIndex + 2);
        int nameIndex = count - 1;
        byte[] bytes = new byte[0x300 + count * 40];
        bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
        bytes[4] = 1; bytes[5] = 1; bytes[6] = 1;
        half(bytes, 16, 2); half(bytes, 18, 40); put(bytes, 20, 1);
        put(bytes, 24, TEXT); put(bytes, 28, 52); put(bytes, 32, 0x300);
        put(bytes, 36, 0x5000400); half(bytes, 40, 52); half(bytes, 42, 32);
        half(bytes, 44, 1); half(bytes, 46, 40);
        half(bytes, 48, count >= 0xff00 ? 0 : count);
        half(bytes, 50, nameIndex >= 0xff00 ? 0xffff : nameIndex);
        put(bytes, 52, 1); put(bytes, 56, 0); put(bytes, 60, 0x10000); put(bytes, 64, 0x10000);
        put(bytes, 68, bytes.length); put(bytes, 72, bytes.length); put(bytes, 76, 5); put(bytes, 80, 4);
        if (count >= 0xff00) put(bytes, 0x300 + 20, count);
        if (nameIndex >= 0xff00) put(bytes, 0x300 + 24, nameIndex);
        for (int index = 0; index < 64; index++) bytes[0x100 + index] = (byte) (index + 1);
        byte[] names = NAMES.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(names, 0, bytes, 0x240, names.length);
        bytes[0x1c1] = 'x';
        row(bytes, textIndex, ".text", 1, 6, TEXT, 0x100, 64, 0, 0, 4, 0);
        row(bytes, 2, ".opaque", 1, 0, 0, 0x180, 32, 0, 0, 4, 0);
        row(bytes, 3, ".dynstr", 3, 0, 0, 0x1c0, 8, 0, 0, 1, 0);
        row(bytes, 4, ".rel.text", 9, 0, 0, 0x200, 8, 2, textIndex, 4, 8);
        row(bytes, nameIndex, ".shstrtab", 3, 0, 0, 0x240, names.length, 0, 0, 1, 0);
        return bytes;
    }

    private static byte[] largeFixture() {
        byte[] seed = fixture(1);
        byte[] bytes = new byte[0x10200 + 120];
        System.arraycopy(seed, 0, bytes, 0, 84);
        put(bytes, 32, 0x10200);
        put(bytes, 68, bytes.length); put(bytes, 72, bytes.length);
        half(bytes, 48, 3); half(bytes, 50, 2);
        for (int index = 0; index < 65552; index++) bytes[0x100 + index] = (byte) index;
        byte[] names = NAMES.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(names, 0, bytes, 0x10120, names.length);
        row(bytes, 1, ".text", 1, 6, TEXT, 0x100, 65552, 0, 0, 4, 0);
        row(bytes, 2, ".shstrtab", 3, 0, 0, 0x10120, names.length, 0, 0, 1, 0);
        return bytes;
    }

    private static void row(byte[] bytes, int index, String name, int type, int flags,
            int address, int offset, int size, int link, int info, int alignment, int entrySize) {
        int at = sectionOffset(bytes, index);
        int[] fields = { nameOffset(name), type, flags, address, offset, size, link, info, alignment, entrySize };
        for (int field = 0; field < fields.length; field++) put(bytes, at + field * 4, fields[field]);
    }

    private static int sectionOffset(byte[] bytes, int index) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(32) + index * 40;
    }

    private static void put(byte[] bytes, int offset, int value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, value);
    }

    private static void half(byte[] bytes, int offset, int value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putShort(offset, (short) value);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private interface Throwing {
        void run() throws Exception;
    }

    private static void expect(Class<? extends Throwable> type, Throwing action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            require(type.isInstance(failure), "expected " + type + ", got " + failure);
            return;
        }
        throw new AssertionError("expected " + type);
    }
}
