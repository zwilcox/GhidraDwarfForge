package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

/** Lossless local insertion and rejection before publication, in both ELF classes/orders. */
public final class LocalSymbolMergeSmoke {
    private static final String NAMES = "\0.text\0.strtab\0.symtab\0.spare\0.shstrtab\0.symtab_shndx\0.high\0";
    private static final byte[] STRINGS = "\0old_local\0old_global\0old_weak\0".getBytes(StandardCharsets.UTF_8);
    private static final Map<String, byte[]> DEBUG = Map.of(".debug_info", new byte[] { 1, 2, 3 });
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-symbol-merge-");
        try { run(root); }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void run(Path root) throws Exception {
        objectContracts();
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                byte[] original = fixture(wide, order, false, false);
                checkOriginalObjects(root, wide, order);
                List<ElfLocalFunctionSymbol> additions = List.of(
                    new ElfLocalFunctionSymbol("curated::alias", 0x1040, 16, 1),
                    new ElfLocalFunctionSymbol("curated::\u03bb", 0x1050, 16, 1));
                checkMerge(root, original, additions, 2, false);
                inventoryBoundaries(root, original, additions, wide, order);
                byte[] dataAllocation = original.clone();
                field(dataAllocation, 4, "flags", 3);
                field(dataAllocation, 4, "address", 0x2000);
                var object = new ElfLocalObjectSymbol("proved_object", 0x2000, 16, 4);
                checkMerge(root, dataAllocation, List.of(additions.get(0), object), 2, false);
                byte[] zeroFill = dataAllocation.clone();
                field(zeroFill, 4, "type", 8);
                checkMerge(root, zeroFill, List.of(object), 2, false);
                byte[] tls = dataAllocation.clone();
                field(tls, 4, "flags", 0x403);
                reject(root, tls, List.of(object), "ordinary allocation", () -> false);
                reject(root, original, List.of(object), "ordinary allocation", () -> false);
                for (var invalid : List.of(
                        new ElfLocalObjectSymbol("before", 0x1fff, 1, 4),
                        new ElfLocalObjectSymbol("after", 0x2010, 1, 4),
                        new ElfLocalObjectSymbol("past_end", 0x2008, 9, 4),
                        new ElfLocalObjectSymbol("overflow", Long.MAX_VALUE, Long.MAX_VALUE, 4))) {
                    reject(root, dataAllocation, List.of(invalid), "ordinary allocation", () -> false);
                }
                reject(root, dataAllocation, List.of(new ElfLocalObjectSymbol("old_global", 0x2000, 4, 4)),
                    "conflicts with existing symbol", () -> false);
                reject(root, dataAllocation, List.of(object, object), "duplicate", () -> false);
                byte[] allLocal = original.clone();
                field(allLocal, 3, "info", 4);
                symbolByte(allLocal, 2, wide ? 4 : 12, 2);
                symbolByte(allLocal, 3, wide ? 4 : 12, 2);
                checkMerge(root, allLocal, additions, 4, false);
                byte[] nullOnly = original.clone();
                field(nullOnly, 3, "size", wide ? 24 : 16);
                field(nullOnly, 3, "info", 1);
                checkMerge(root, nullOnly, additions, 1, false);
                byte[] alignedStrings = original.clone();
                field(alignedStrings, 2, "alignment", 16);
                checkMerge(root, alignedStrings, additions, 2, false);
                byte[] reservedSymbol = original.clone();
                bytes(reservedSymbol).putShort(symbolOffset(reservedSymbol, 3) + (wide ? 6 : 14), (short) 0xfff1);
                checkMerge(root, reservedSymbol, additions, 2, false);
                byte[] many = Arrays.copyOf(original, 0x1000 + 262144 * (wide ? 24 : 16));
                field(many, 3, "offset", 0x1000);
                field(many, 3, "size", 262144 * (wide ? 24 : 16));
                field(many, 3, "info", 262144);
                reject(root, many, additions, "merged symbol count", () -> false);
                byte[] hugeStrings = Arrays.copyOf(original, 0x1000 + 16 * 1024 * 1024 + 1);
                field(hugeStrings, 2, "offset", 0x1000);
                field(hugeStrings, 2, "size", 16 * 1024 * 1024 + 1);
                reject(root, hugeStrings, additions, "string table", () -> false);
                byte[] rawNames = original.clone();
                rawNames[0x181] = (byte) 0xff;
                checkMerge(root, rawNames, additions, 2, false);
                checkMerge(root, fixture(wide, order, true, false), additions, 2, true);
                byte[] extended = fixture(wide, order, true, true);
                List<ElfLocalFunctionSymbol> high = List.of(new ElfLocalFunctionSymbol("high_alias", 0x2000, 16, 0xff01));
                checkMerge(root, extended, high, 2, true);
                byte[] createExtended = fixture(wide, order, false, true);
                checkMerge(root, createExtended, high, 2, true);
                checkMerge(root, createExtended,
                    List.of(new ElfLocalObjectSymbol("high_object", 0x2000, 16, 0xff01)), 2, true);

                reject(root, original, List.of(new ElfLocalFunctionSymbol("old_global", 0x1040, 16, 1)),
                    "conflicts with existing symbol", () -> false);
                reject(root, original, List.of(additions.get(0), additions.get(0)), "duplicate", () -> false);
                reject(root, original, List.of(new ElfLocalFunctionSymbol("invalid\ud800", 0x1040, 16, 1)),
                    "valid Unicode", () -> false);
                reject(root, original, List.of(new ElfLocalFunctionSymbol("too_long_" + "\u03bb".repeat(33000), 0x1040, 16, 1)),
                    "names exceed", () -> false);
                reject(root, original, List.of(new ElfLocalFunctionSymbol("noncode", 0x1040, 16, 2)), "invalid", () -> false);
                reject(root, original, List.of(new ElfLocalFunctionSymbol("past_sections", 0x1040, 16, 20)), "invalid", () -> false);
                for (String field : List.of("link", "info", "entsize", "size", "flags", "address")) {
                    byte[] bad = original.clone();
                    field(bad, 3, field, switch (field) {
                        case "link" -> 1;
                        case "info" -> 0;
                        case "entsize" -> 1;
                        case "size" -> 1;
                        default -> 2;
                    });
                    reject(root, bad, additions, "symbol", () -> false);
                }
                for (String field : List.of("flags", "address", "type")) {
                    byte[] bad = original.clone();
                    field(bad, 2, field, 1);
                    reject(root, bad, additions, "string table", () -> false);
                }
                byte[] duplicate = original.clone();
                field(duplicate, 4, "type", 2);
                reject(root, duplicate, additions, "multiple static", () -> false);
                byte[] dependent = original.clone();
                field(dependent, 4, "type", 17);
                field(dependent, 4, "link", 3);
                reject(root, dependent, additions, "dependent symbol-index", () -> false);
                byte[] retired = dependent.clone();
                field(retired, 4, "type", 4);
                checkMerge(root, retired, additions, 2, false);
                byte[] badNull = original.clone();
                badNull[0x200] = 1;
                reject(root, badNull, additions, "null symbol", () -> false);
                byte[] badBinding = original.clone();
                symbolByte(badBinding, 1, wide ? 4 : 12, 0x12);
                reject(root, badBinding, additions, "binding order", () -> false);
                byte[] badName = original.clone();
                bytes(badName).putInt(symbolOffset(badName, 1), STRINGS.length);
                reject(root, badName, additions, "symbol name", () -> false);
                byte[] badTerminator = original.clone();
                badTerminator[0x180 + STRINGS.length - 1] = 1;
                reject(root, badTerminator, additions, "boundary terminators", () -> false);
                byte[] badSection = original.clone();
                bytes(badSection).putShort(symbolOffset(badSection, 1) + (wide ? 6 : 14), (short) 6);
                reject(root, badSection, additions, "section", () -> false);
                byte[] missingExtra = original.clone();
                bytes(missingExtra).putShort(symbolOffset(missingExtra, 1) + (wide ? 6 : 14), (short) 0xffff);
                reject(root, missingExtra, additions, "extended static", () -> false);
                for (String field : List.of("size", "entsize", "info", "flags")) {
                    byte[] bad = fixture(wide, order, true, false);
                    field(bad, 4, field, 8);
                    reject(root, bad, additions, "dependent symbol-index", () -> false);
                }
                byte[] unexpectedExtra = fixture(wide, order, true, false);
                bytes(unexpectedExtra).putInt(0x2f4, 1);
                reject(root, unexpectedExtra, additions, "extended static", () -> false);
                byte[] invalidExtra = extended.clone();
                bytes(invalidExtra).putInt(0x2f4, 0xff02);
                reject(root, invalidExtra, high, "extended static", () -> false);
                byte[] missingName = original.clone();
                bytes(missingName).putInt(symbolOffset(missingName, 1), -1);
                reject(root, missingName, additions, "symbol name", () -> false);
                if (!wide) {
                    reject(root, original, List.of(new ElfLocalFunctionSymbol("overflow", 0x1_0000_0000L, 16, 1)),
                        "ELF32 field", () -> false);
                }
                for (int at : List.of(1, 8, 20, 35)) {
                    AtomicInteger calls = new AtomicInteger();
                    reject(root, original, additions, "cancel", () -> calls.incrementAndGet() >= at);
                    AtomicInteger objectCalls = new AtomicInteger();
                    reject(root, dataAllocation, List.of(object), "cancel", () -> objectCalls.incrementAndGet() >= at);
                }
                System.out.println("local-symbol-merge-format=PASS ELF" + (wide ? 64 : 32) + " " + order);
            }
        }
        System.out.println("local-symbol-merge-smoke=PASS checks=" + checks);
    }

    private static void inventoryBoundaries(Path root, byte[] original,
            List<ElfLocalFunctionSymbol> additions, boolean wide, ByteOrder order) throws Exception {
        int width = wide ? 24 : 16;
        for (long link : new long[] { 0, 6, 0xffff_ffffL }) {
            byte[] bad = original.clone();
            field(bad, 3, "link", link);
            reject(root, bad, additions, "unsupported static symbol table metadata", () -> false);
        }
        for (long size : new long[] { width + 1, width * 4 - 1 }) {
            byte[] bad = original.clone();
            field(bad, 3, "size", size);
            reject(root, bad, additions, "unsupported static symbol table metadata", () -> false);
        }
        byte[] excessLocals = original.clone();
        field(excessLocals, 3, "info", 5);
        reject(root, excessLocals, additions, "unsupported static symbol table metadata", () -> false);
        byte[] emptyNames = original.clone();
        field(emptyNames, 2, "size", 0);
        reject(root, emptyNames, additions, "unsupported static symbol string table", () -> false);
        byte[] firstName = original.clone();
        firstName[0x180] = 1;
        reject(root, firstName, additions, "boundary terminators", () -> false);
        byte[] addressedIndices = fixture(wide, order, true, false);
        field(addressedIndices, 4, "address", 1);
        reject(root, addressedIndices, additions, "dependent symbol-index", () -> false);
        byte[] zeroIndex = fixture(wide, order, true, false);
        bytes(zeroIndex).putShort(symbolOffset(zeroIndex, 1) + (wide ? 6 : 14), (short) 0xffff);
        reject(root, zeroIndex, additions, "invalid extended static symbol index", () -> false);

        // A long raw ELF name is valid at the byte limit; the first excess is
        // rejected. This does not rely on Java UTF-8 decoding of original names.
        for (int length : new int[] { 65_536, 65_537 }) {
            byte[] names = Arrays.copyOf(original, 0x1000 + length + 2);
            Arrays.fill(names, 0x1001, 0x1001 + length, (byte) 'x');
            field(names, 2, "offset", 0x1000);
            field(names, 2, "size", length + 2);
            if (length == 65_536) checkMerge(root, names, additions, 2, false);
            else reject(root, names, additions, "static symbol names exceed supported bounds", () -> false);
        }
        // Overlapping string suffixes are legal. Bound decoded work as well as
        // stored bytes: the 257th distinct suffix crosses 16 MiB of name data.
        for (int names : new int[] { 256, 257 }) {
            byte[] suffixes = Arrays.copyOf(original, 0x4000 + 65_538);
            Arrays.fill(suffixes, 0x4001, 0x4001 + 65_536, (byte) 'x');
            field(suffixes, 2, "offset", 0x4000);
            field(suffixes, 2, "size", 65_538);
            field(suffixes, 3, "offset", 0x1000);
            field(suffixes, 3, "size", (long) (names + 1) * width);
            field(suffixes, 3, "info", names + 1);
            for (int index = 1; index <= names; index++) {
                bytes(suffixes).putInt(0x1000 + index * width, index);
            }
            if (names == 256) checkMerge(root, suffixes, additions, names + 1, false);
            else reject(root, suffixes, additions, "static symbol names exceed supported bounds", () -> false);
        }
    }

    /** Compare exact identities in independently encoded ELF32/64 symbol records. */
    private static void checkOriginalObjects(Path root, boolean wide, ByteOrder order) throws Exception {
        var match = MatchedElfSidecarWriter.OriginalObjectMatch.MATCH;
        var conflict = MatchedElfSidecarWriter.OriginalObjectMatch.CONFLICT;
        var absent = MatchedElfSidecarWriter.OriginalObjectMatch.ABSENT;
        byte[] original = fixture(wide, order, false, false);
        setObject(original, 2, 11, 0x1010, 4, 1);
        var requested = List.of(new ElfLocalObjectSymbol("old_global", 0x1010, 4, 1),
            new ElfLocalObjectSymbol("absent_object", 0x1010, 4, 1));
        Map<String, MatchedElfSidecarWriter.OriginalObjectMatch> wanted = Map.of("old_global", match, "absent_object", absent);
        checkObjectMatch(root, original, requested, wanted);
        for (String field : List.of("type", "value", "size", "section")) {
            byte[] changed = original.clone();
            int at = symbolOffset(changed, 2);
            switch (field) {
                case "type" -> symbolByte(changed, 2, wide ? 4 : 12, 0x12);
                case "value" -> setObject(changed, 2, 11, 0x1011, 4, 1);
                case "size" -> setObject(changed, 2, 11, 0x1010, 5, 1);
                case "section" -> bytes(changed).putShort(at + (wide ? 6 : 14), (short) 4);
                default -> throw new AssertionError(field);
            }
            checkObjectMatch(root, changed, requested, Map.of("old_global", conflict, "absent_object", absent));
        }
        // Repeated name offsets exercise the cache. A conflicting identity must
        // survive both later matches and changes in static symbol binding/order.
        for (boolean firstConflict : List.of(false, true)) {
            for (boolean lastConflict : List.of(false, true)) {
                byte[] duplicate = original.clone();
                setObject(duplicate, 1, 11, firstConflict ? 0x1011 : 0x1010, 4, 1);
                setObject(duplicate, 3, 11, lastConflict ? 0x1011 : 0x1010, 4, 1);
                checkObjectMatch(root, duplicate, requested, Map.of("old_global",
                    firstConflict || lastConflict ? conflict : match, "absent_object", absent));
            }
        }
        byte[] extended = fixture(wide, order, true, true);
        setObject(extended, 2, 11, 0x2000, 4, 0xffff);
        checkObjectMatch(root, extended, List.of(new ElfLocalObjectSymbol("old_global", 0x2000, 4, 0xff01)),
            Map.of("old_global", match));
        checkObjectMatch(root, extended, List.of(new ElfLocalObjectSymbol("old_global", 0x2000, 4, 1)),
            Map.of("old_global", conflict));

        // ELF32 values are unsigned; an address above INT_MAX must compare losslessly.
        byte[] highAddress = original.clone();
        field(highAddress, 1, "address", 0x80001000L);
        setObject(highAddress, 2, 11, 0x80001010L, 4, 1);
        checkObjectMatch(root, highAddress, List.of(new ElfLocalObjectSymbol("old_global", 0x80001010L, 4, 1)),
            Map.of("old_global", match));

        String longName = "long_object_" + "x".repeat(2048);
        byte[] names = ("\0" + longName + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] longTable = Arrays.copyOf(original, 0x1000 + names.length);
        System.arraycopy(names, 0, longTable, 0x1000, names.length);
        field(longTable, 2, "offset", 0x1000);
        field(longTable, 2, "size", names.length);
        for (int index = 1; index <= 3; index++) setObject(longTable, index, 1, 0x1010, 4, 1);
        Path dir = Files.createTempDirectory(root, "object-cancellation-");
        Path input = dir.resolve("input");
        Files.write(input, longTable);
        var image = ElfImage.read(input);
        var objects = List.of(new ElfLocalObjectSymbol(longName, 0x1010, 4, 1));
        var expected = Map.of(longName, match);
        AtomicInteger count = new AtomicInteger();
        require(MatchedElfSidecarWriter.originalObjectMatches(image, objects, () -> { count.incrementAndGet(); return false; })
            .equals(expected), "long repeated object name did not match");
        for (int boundary = 1; boundary <= count.get(); boundary++) {
            int stop = boundary;
            AtomicInteger calls = new AtomicInteger();
            try {
                MatchedElfSidecarWriter.originalObjectMatches(image, objects, () -> calls.incrementAndGet() == stop);
                throw new AssertionError("object matching ignored cancellation at " + stop);
            }
            catch (CancellationException expectedCancellation) {
                require(calls.get() == stop, "object matching passed cancellation boundary");
            }
            require(Arrays.equals(Files.readAllBytes(input), longTable), "cancelled matching changed input");
            require(MatchedElfSidecarWriter.originalObjectMatches(image, objects, () -> false).equals(expected),
                "cancelled matching corrupted a fresh retry");
        }
        try (var files = Files.list(dir)) { require(files.count() == 1, "object matching created unexpected files"); }
    }

    private static void checkObjectMatch(Path root, byte[] inputBytes, List<ElfLocalObjectSymbol> requested,
            Map<String, MatchedElfSidecarWriter.OriginalObjectMatch> expected) throws Exception {
        Path dir = Files.createTempDirectory(root, "object-match-");
        Path input = dir.resolve("input");
        Files.write(input, inputBytes);
        require(MatchedElfSidecarWriter.originalObjectMatches(ElfImage.read(input), requested, () -> false).equals(expected),
            "wrong original object identities: " + expected);
        require(Arrays.equals(Files.readAllBytes(input), inputBytes), "object matching changed input");
        try (var files = Files.list(dir)) { require(files.count() == 1, "object matching wrote an artifact"); }
    }

    private static void setObject(byte[] data, int index, int name, long value, long size, int section) {
        boolean wide = data[4] == 2;
        ByteBuffer b = bytes(data);
        int at = symbolOffset(data, index);
        b.putInt(at, name);
        b.put(at + (wide ? 4 : 12), (byte) ((index == 1 ? 0 : index == 2 ? 0x10 : 0x20) | 1));
        b.putShort(at + (wide ? 6 : 14), (short) section);
        if (wide) { b.putLong(at + 8, value); b.putLong(at + 16, size); }
        else { b.putInt(at + 4, (int) value); b.putInt(at + 8, (int) size); }
    }

    private static void checkMerge(Path root, byte[] inputBytes, List<? extends ElfLocalSymbol> additions,
            int locals, boolean extended) throws Exception {
        Path dir = Files.createTempDirectory(root, "positive-");
        Path input = dir.resolve("input");
        Path output = dir.resolve("output");
        Files.write(input, inputBytes);
        ElfImage original = ElfImage.read(input);
        new MatchedElfSidecarWriter().write(original, output, DEBUG, additions, () -> false);
        ElfImage result = ElfImage.read(output);
        ElfImage.Section oldTable = original.sections().get(3);
        ElfImage.Section table = result.sections().get(3);
        ElfImage.Section strings = result.sections().get(2);
        int width = original.is64Bit() ? 24 : 16;
        byte[] oldRecords = original.sectionData(oldTable);
        byte[] records = result.sectionData(table);
        byte[] oldNames = original.sectionData(original.sections().get(2));
        byte[] names = result.sectionData(strings);
        require(table.info == locals + additions.size() && table.link == 2 && table.entrySize == width,
            "local partition/string link/entry width");
        require(table.size == oldRecords.length + additions.size() * width, "merged record count");
        require(strings.alignment == 1 && table.offset % table.alignment == 0, "canonical nonallocated alignment");
        require(Arrays.equals(Arrays.copyOf(names, oldNames.length), oldNames), "original string bytes");
        for (int index = 0; index < oldRecords.length / width; index++) {
            int next = index < locals ? index : index + additions.size();
            require(Arrays.equals(Arrays.copyOfRange(records, next * width, (next + 1) * width),
                Arrays.copyOfRange(oldRecords, index * width, (index + 1) * width)), "original symbol record");
        }
        ByteBuffer values = ByteBuffer.wrap(records).order(original.byteOrder());
        for (int i = 0; i < additions.size(); i++) {
            int entry = (locals + i) * width;
            int name = values.getInt(entry);
            byte[] expected = additions.get(i).name().getBytes(StandardCharsets.UTF_8);
            require(Arrays.equals(Arrays.copyOfRange(names, name, name + expected.length), expected) &&
                names[name + expected.length] == 0, "appended exact name");
            require(records[entry + (original.is64Bit() ? 4 : 12)] == additions.get(i).type(), "local binding and type");
            long value = original.is64Bit() ? values.getLong(entry + 8) : Integer.toUnsignedLong(values.getInt(entry + 4));
            long size = original.is64Bit() ? values.getLong(entry + 16) : Integer.toUnsignedLong(values.getInt(entry + 8));
            require(value == additions.get(i).value() && size == additions.get(i).size(), "exact symbol address/size");
        }
        if (extended) {
            var indexSection = result.sections().stream().filter(s -> s.type == 18).findFirst().orElseThrow();
            require(indexSection.link == 3 && indexSection.size == records.length / width * 4L, "parallel index extent");
            ByteBuffer indices = ByteBuffer.wrap(result.sectionData(indexSection)).order(original.byteOrder());
            var oldIndex = original.sections().stream().filter(s -> s.type == 18).findFirst();
            for (int i = 0; i < oldRecords.length / width; i++) {
                int expected = oldIndex.isEmpty() ? 0 : ByteBuffer.wrap(original.sectionData(oldIndex.get()))
                    .order(original.byteOrder()).getInt(i * 4);
                require(indices.getInt((i < locals ? i : i + additions.size()) * 4) == expected,
                    "original extended indices move with original symbols");
            }
            for (int i = 0; i < additions.size(); i++) {
                int section = additions.get(i).sectionIndex();
                require(indices.getInt((locals + i) * 4) == (section >= 0xff00 ? section : 0), "new extended index");
            }
        }
        require(Arrays.equals(inputBytes, Files.readAllBytes(input)), "original unchanged");
        require(result.segments().isEmpty() && original.machine() == result.machine() &&
            original.byteOrder() == result.byteOrder() && original.flags() == result.flags(), "target identity");
        Path repeat = dir.resolve("repeat");
        new MatchedElfSidecarWriter().write(original, repeat, DEBUG, additions, () -> false);
        require(Arrays.equals(Files.readAllBytes(output), Files.readAllBytes(repeat)), "deterministic merge");
        Path empty = dir.resolve("empty");
        new MatchedElfSidecarWriter().write(original, empty, DEBUG, List.of(), () -> false);
        ElfImage untouched = ElfImage.read(empty);
        require(Arrays.equals(oldRecords, untouched.sectionData(untouched.sections().get(3))) &&
            untouched.sections().get(3).info == locals, "empty plan retains original table");
    }

    private static void reject(Path root, byte[] inputBytes, List<? extends ElfLocalSymbol> additions,
            String message, BooleanSupplier cancelled) throws Exception {
        Path dir = Files.createTempDirectory(root, "negative-");
        Path input = dir.resolve("input");
        Path output = dir.resolve("output");
        byte[] sentinel = { 9, 8, 7, 6 };
        Files.write(input, inputBytes);
        Files.write(output, sentinel);
        try {
            new MatchedElfSidecarWriter().write(ElfImage.read(input), output, DEBUG, additions, cancelled);
            throw new AssertionError("accepted " + message);
        }
        catch (IllegalArgumentException | CancellationException expected) {
            require(expected.getMessage().toLowerCase().contains(message.toLowerCase()), "rejection reason: " + expected);
        }
        require(Arrays.equals(inputBytes, Files.readAllBytes(input)), "rejection input preservation");
        require(Arrays.equals(sentinel, Files.readAllBytes(output)), "rejection destination preservation");
        try (var files = Files.list(dir)) {
            require(files.count() == 2, "no temporary residue");
        }
    }

    static byte[] fixture(boolean wide, ByteOrder order, boolean indices, boolean high) {
        int count = high ? 0xff02 : 6;
        int headerWidth = wide ? 64 : 40;
        byte[] data = new byte[0x400 + count * headerWidth];
        ByteBuffer b = ByteBuffer.wrap(data).order(order);
        b.put(new byte[] { 0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1 });
        b.putShort(16, (short) 2); b.putShort(18, (short) (wide ? 62 : 8)); b.putInt(20, 1);
        if (wide) {
            b.putLong(24, 0x1000); b.putLong(40, 0x400); b.putShort(52, (short) 64);
            b.putShort(58, (short) 64); b.putShort(60, (short) (high ? 0 : count)); b.putShort(62, (short) 5);
        }
        else {
            b.putInt(24, 0x1000); b.putInt(32, 0x400); b.putShort(40, (short) 52);
            b.putShort(46, (short) 40); b.putShort(48, (short) (high ? 0 : count)); b.putShort(50, (short) 5);
        }
        if (high) field(data, 0, "size", count);
        section(data, 1, ".text", 1, 6, 0x1000, 0x100, 128, 0, 0, 16, 0);
        section(data, 2, ".strtab", 3, 0, 0, 0x180, STRINGS.length, 0, 0, 1, 0);
        section(data, 3, ".symtab", 2, 0, 0, 0x200, (wide ? 24 : 16) * 4, 2, 2, wide ? 8 : 4, wide ? 24 : 16);
        section(data, 4, indices ? ".symtab_shndx" : ".spare", indices ? 18 : 1,
            0, 0, 0x2f0, 16, indices ? 3 : 0, 0, 4, indices ? 4 : 0);
        section(data, 5, ".shstrtab", 3, 0, 0, 0x310, NAMES.length(), 0, 0, 1, 0);
        if (high) section(data, 0xff01, ".high", 1, 6, 0x2000, 0x100, 128, 0, 0, 16, 0);
        b.put(0x180, STRINGS); b.put(0x310, NAMES.getBytes(StandardCharsets.US_ASCII));
        for (int index = 1; index < 4; index++) {
            int offset = symbolOffset(data, index);
            int name = index == 1 ? 1 : index == 2 ? 11 : 22;
            int info = index == 1 ? 2 : index == 2 ? 0x12 : 0x22;
            b.putInt(offset, name);
            if (wide) {
                b.put(offset + 4, (byte) info); b.putShort(offset + 6, (short) (indices && high ? 0xffff : 1));
                b.putLong(offset + 8, 0x1000 + (index - 1) * 16); b.putLong(offset + 16, 4);
            }
            else {
                b.putInt(offset + 4, 0x1000 + (index - 1) * 16); b.putInt(offset + 8, 4);
                b.put(offset + 12, (byte) info); b.putShort(offset + 14, (short) (indices && high ? 0xffff : 1));
            }
            if (indices && high) b.putInt(0x2f0 + index * 4, 0xff01);
        }
        return data;
    }

    private static void section(byte[] data, int index, String name, long type, long flags,
            long address, long offset, long size, long link, long info, long alignment, long entrySize) {
        ByteBuffer b = bytes(data);
        int base = 0x400 + index * (data[4] == 2 ? 64 : 40);
        b.putInt(base, NAMES.indexOf(name + "\0"));
        field(data, index, "type", type); field(data, index, "flags", flags);
        field(data, index, "address", address); field(data, index, "offset", offset);
        field(data, index, "size", size); field(data, index, "link", link);
        field(data, index, "info", info); field(data, index, "alignment", alignment);
        field(data, index, "entsize", entrySize);
    }

    static void field(byte[] data, int index, String name, long value) {
        boolean wide = data[4] == 2;
        int member = List.of("name", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entsize").indexOf(name);
        int[] offsets = wide ? new int[] { 0, 4, 8, 16, 24, 32, 40, 44, 48, 56 }
            : new int[] { 0, 4, 8, 12, 16, 20, 24, 28, 32, 36 };
        int offset = 0x400 + index * (wide ? 64 : 40) + offsets[member];
        if (wide && member != 0 && member != 1 && member != 6 && member != 7) bytes(data).putLong(offset, value);
        else bytes(data).putInt(offset, (int) value);
    }

    private static int symbolOffset(byte[] data, int index) {
        return 0x200 + index * (data[4] == 2 ? 24 : 16);
    }

    private static void symbolByte(byte[] data, int index, int field, int value) {
        data[symbolOffset(data, index) + field] = (byte) value;
    }

    private static ByteBuffer bytes(byte[] data) {
        return ByteBuffer.wrap(data).order(data[5] == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
    }

    private static void objectContracts() {
        for (String name : Arrays.asList(null, "", " \t", "bad\0name", "x".repeat(65537))) {
            objectRejected(() -> new ElfLocalObjectSymbol(name, 0, 1, 1));
        }
        objectRejected(() -> new ElfLocalObjectSymbol("object", -1, 1, 1));
        for (long size : new long[] {0, -1}) {
            objectRejected(() -> new ElfLocalObjectSymbol("object", 0, size, 1));
        }
        for (int section : new int[] {0, -1}) {
            objectRejected(() -> new ElfLocalObjectSymbol("object", 0, 1, section));
        }
        // Section membership and target width are checked by the writer; the
        // model must preserve large positive values for that decision.
        var object = new ElfLocalObjectSymbol("x".repeat(65536), 0x100000007L, 0x100000009L, 0xff01);
        require(object.name().length() == 65536 && object.value() == 0x100000007L &&
            object.size() == 0x100000009L && object.sectionIndex() == 0xff01 && object.type() == 1,
            "ordinary object identity was truncated or changed to a function");
    }

    private static void objectRejected(Runnable action) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid ordinary object symbol was accepted");
    }

    private static void require(boolean condition, String description) {
        checks++;
        if (!condition) throw new AssertionError(description);
    }
}
