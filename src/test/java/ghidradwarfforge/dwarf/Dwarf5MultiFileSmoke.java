package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.coverage.SourceCoverageIndex;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SourcePartitionPlan;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;

/** Decode real line bytes and resolve their file/local-line rows to source text. */
public final class Dwarf5MultiFileSmoke {
    private Dwarf5MultiFileSmoke() { }

    public static void run() {
        checkEncodingBoundaries();
        var source = SyntheticSourceFile.build("fixture", "test", List.of(
            new FunctionText("first", 0x1000, "int first(void)\n{\n    return 1;\n}\n", null,
                List.of(new RelativeLine(3, List.of(0x1004L, 0x2004L)))),
            new FunctionText("second", 0x3000, "int second(void)\n{\n    return 2;\n}\n", null,
                List.of(new RelativeLine(3, List.of(0x3004L))))));
        var functions = List.of(
            new FunctionSymbol("first", 0x1000, List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x2000, 8))),
            new FunctionSymbol("second", 0x3000, 8),
            new FunctionSymbol("wide", 0x1000, 0x2008));
        Map<Long, String> expected = Map.of(0x1000L, "int first(void)", 0x1004L, "    return 1;",
            0x2004L, "    return 1;", 0x3000L, "int second(void)", 0x3004L, "    return 2;");
        for (int limit : new int[] { 1, 10, 1000 }) {
            var plan = SourcePartitionPlan.build(source, limit, () -> false);
            var names = plan.parts().stream().map(part -> "generation/part-" + part.file() + ".c").toList();
            var files = Dwarf5LineTable.FileLayout.partitioned("fixture.dbg.c", names, plan);
            files.requireSource(source);
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (int width : new int[] { 4, 8 }) {
                    var emitted = Dwarf5LineTable.buildWithPlan(files, "/source λ", width, order,
                        functions, source.mappedLines(), true);
                    var decoded = decode(emitted.section(), width, order);
                    require(decoded.files().equals(files.names()), "file table differs from selected names");
                    require(decoded.rows().size() == 10, "missing/extra rows across overlapping bodies");
                    require(decoded.ends().equals(List.of(0x1008L, 0x2008L, 0x3008L, 0x3008L)),
                        "discontiguous range boundaries changed");
                    for (var row : decoded.rows()) {
                        require(row.file() > 0 && row.file() < decoded.files().size(), "index file acquired executable row");
                        var part = plan.parts().get(row.file() - 1);
                        String[] lines = new String(part.utf8(), StandardCharsets.UTF_8).split("\n", -1);
                        require(row.line() > 2 && row.line() < lines.length, "row references synthetic header or absent line");
                        require(lines[row.line() - 1].equals(expected.get(row.address())),
                            "decoded file/line refers to different source at " + Long.toHexString(row.address()));
                    }
                    var baseline = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/source λ", width,
                        order, functions, source.mappedLines(), true);
                    var before = new SourceCoverageIndex(baseline, () -> false);
                    var after = new SourceCoverageIndex(emitted, () -> false);
                    var first = functions.getFirst();
                    var starts = List.of(0x1000L, 0x1004L, 0x2000L, 0x2004L);
                    var tokens = source.functionTokens().getFirst().lines();
                    require(before.measurePoints(first, starts, tokens, () -> false).equals(
                        after.measurePoints(first, starts, tokens, () -> false)), "partitioning changed source evidence counts");
                }
            }
        }
        // More than 127 filenames exercises real ULEB file counts and indices.
        var many = new ArrayList<FunctionText>();
        for (int index = 0; index < 140; index++) {
            many.add(new FunctionText("f" + index, 0x1000L + 16L * index,
                "int f" + index + "(void) { return " + index + "; }\n", null));
        }
        var big = SyntheticSourceFile.build("many", "test", many);
        var partitions = SourcePartitionPlan.build(big, 1, () -> false);
        var layout = Dwarf5LineTable.FileLayout.partitioned("index.c",
            partitions.parts().stream().map(part -> "part-" + part.file() + ".c").toList(), partitions);
        var symbols = big.functions().stream().map(function -> new FunctionSymbol(function.name(), function.address(), 4)).toList();
        var decoded = decode(Dwarf5LineTable.buildWithPlan(layout, "/source", 8, ByteOrder.LITTLE_ENDIAN,
            symbols, big.mappedLines(), true).section(), 8, ByteOrder.LITTLE_ENDIAN);
        require(decoded.files().size() == 142 && decoded.rows().getLast().file() == 141,
            "multi-byte filename count/index truncated");
        try {
            layout.requireSource(source);
            throw new AssertionError("partition plan accepted different source bytes");
        }
        catch (IllegalArgumentException expectedFailure) { }
        System.out.println("dwarf-multifile-smoke=PASS widths=2 byte-orders=2 raw-line-and-source-oracle=PASS");
    }

    /** Decode complete programs; expected rows come directly from source evidence. */
    private static void checkEncodingBoundaries() {
        int[] lines = { 0, 1, 2, 63, 64, 65, 127, 128, 129, 8191, 8192, 8193,
            16383, 16384, Integer.MAX_VALUE };
        int cases = 0;
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : new int[] { 4, 8 }) {
                long base = width == 4 ? 0xfffffc00L : Long.MAX_VALUE - 1023;
                var functions = List.of(new FunctionSymbol("split", base, List.of(
                    new FunctionRange(base, 256), new FunctionRange(base + 512, 128))));
                for (int first : lines) {
                    for (int second : lines) {
                        var evidence = List.of(new SyntheticSourceFile.SourceLine(first,
                                List.of(base, base + 512)),
                            new SyntheticSourceFile.SourceLine(second, List.of(base + 127)),
                            new SyntheticSourceFile.SourceLine(1, List.of(base + 255)));
                        var emitted = Dwarf5LineTable.buildWithPlan("source.c", "/source", width,
                            order, functions, evidence);
                        var decoded = decode(emitted.section(), width, order);
                        require(decoded.rows().equals(List.of(new Row(base, 0, first),
                            new Row(base + 127, 0, second), new Row(base + 255, 0, 1),
                            new Row(base + 512, 0, first))),
                            "signed line transitions or sequence reset changed source evidence");
                        require(decoded.ends().equals(List.of(base + 256, base + 640)),
                            "line sequence end or wide address was truncated");
                        require(java.util.Arrays.equals(emitted.section(),
                            Dwarf5LineTable.build("source.c", "/source", width, order,
                                functions, evidence.reversed())), "line transition order changed bytes");
                        byte[] mutable = emitted.section();
                        mutable[0] ^= 0x7f;
                        require(mutable[0] != emitted.section()[0], "line bytes escaped mutable");
                        cases++;
                    }
                }
            }
        }
        for (String name : new String[] { null, "", " \t", "bad\0suffix" }) {
            reject(() -> Dwarf5LineTable.FileLayout.single(name), "invalid single filename");
        }
        reject(() -> new Dwarf5LineTable.FilePosition(-1, 1), "negative file index");
        reject(() -> new Dwarf5LineTable.FilePosition(0, -1), "negative source line");
        require(new Dwarf5LineTable.FilePosition(0, 0).line() == 0, "unknown line zero rejected");
        for (int width : new int[] { Integer.MIN_VALUE, 0, 1, 2, 3, 5, 7, 9, Integer.MAX_VALUE }) {
            reject(() -> Dwarf5LineTable.build("source.c", width, ByteOrder.LITTLE_ENDIAN,
                List.of(), List.of()), "unsupported line address width");
        }
        var source = SyntheticSourceFile.build("fixture", "test", List.of(
            new FunctionText("first", 0x1000, "int first(void) { return 1; }\n", null)));
        var plan = SourcePartitionPlan.build(source, 1, () -> false);
        var names = new ArrayList<>(plan.parts().stream().map(part -> "part-" + part.file() + ".c").toList());
        var layout = Dwarf5LineTable.FileLayout.partitioned("index.c", names, plan);
        List<String> expectedNames = List.copyOf(layout.names());
        names.set(0, "changed.c");
        require(layout.names().equals(expectedNames), "caller changed retained file table");
        try {
            layout.names().set(0, "changed.c");
            throw new AssertionError("line file table escaped mutable");
        }
        catch (UnsupportedOperationException expected) { }
        List<String> valid = expectedNames.subList(1, expectedNames.size());
        reject(() -> Dwarf5LineTable.FileLayout.partitioned(null, valid, plan), "null index name");
        reject(() -> Dwarf5LineTable.FileLayout.partitioned("index.c", null, plan), "null part names");
        reject(() -> Dwarf5LineTable.FileLayout.partitioned("index.c", valid, null), "null source plan");
        reject(() -> Dwarf5LineTable.FileLayout.partitioned("index.c", List.of(), plan), "part count mismatch");
        for (String invalid : new String[] { "", " ", "part\0suffix", "index.c" }) {
            var invalidNames = new ArrayList<>(valid);
            invalidNames.set(0, invalid);
            reject(() -> Dwarf5LineTable.FileLayout.partitioned("index.c", invalidNames, plan),
                "invalid or duplicate partition filename");
        }
        System.out.println("dwarf-line-boundaries=PASS programs=" + cases);
    }

    private static void reject(Runnable action, String message) {
        try {
            action.run();
            throw new AssertionError(message + " accepted");
        }
        catch (IllegalArgumentException expected) { }
    }

    private record Row(long address, int file, int line) { }
    private record Decoded(List<String> files, List<Row> rows, List<Long> ends) { }

    private static Decoded decode(byte[] bytes, int width, ByteOrder order) {
        ByteBuffer input = ByteBuffer.wrap(bytes).order(order);
        require(input.getInt() == bytes.length - 4 && input.getShort() == 5, "unit header");
        require(Byte.toUnsignedInt(input.get()) == width && input.get() == 0, "target metadata");
        int headerLength = input.getInt();
        int headerEnd = input.position() + headerLength;
        input.position(input.position() + 18);
        require(input.get() == 1 && uleb(input) == 1 && uleb(input) == 8 && uleb(input) == 1,
            "directory formats");
        string(input);
        require(input.get() == 2 && uleb(input) == 1 && uleb(input) == 8 &&
            uleb(input) == 2 && uleb(input) == 15, "file formats");
        long count = uleb(input);
        var files = new ArrayList<String>();
        for (long index = 0; index < count; index++) {
            files.add(string(input));
            require(uleb(input) == 0, "unexpected directory index");
        }
        require(input.position() == headerEnd, "header length");
        var rows = new ArrayList<Row>();
        var ends = new ArrayList<Long>();
        long address = 0;
        int line = 1;
        int file = 1;
        while (input.hasRemaining()) {
            int opcode = Byte.toUnsignedInt(input.get());
            switch (opcode) {
                case 0 -> {
                    int length = Math.toIntExact(uleb(input));
                    int end = input.position() + length;
                    int extended = Byte.toUnsignedInt(input.get());
                    if (extended == 1) {
                        ends.add(address);
                        address = 0;
                        line = 1;
                        file = 1;
                    }
                    else if (extended == 2) {
                        address = width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
                    }
                    else throw new AssertionError("unexpected extended opcode " + extended);
                    require(input.position() == end, "extended opcode length");
                }
                case 1 -> rows.add(new Row(address, file, line));
                case 2 -> address = Math.addExact(address, uleb(input));
                case 3 -> line = Math.toIntExact(Math.addExact(line, sleb(input)));
                case 4 -> file = Math.toIntExact(uleb(input));
                default -> throw new AssertionError("unexpected line opcode " + opcode);
            }
        }
        return new Decoded(files, rows, ends);
    }

    private static long uleb(ByteBuffer input) {
        long result = 0;
        int shift = 0;
        int value;
        do {
            value = Byte.toUnsignedInt(input.get());
            result |= (long) (value & 127) << shift;
            shift += 7;
        } while ((value & 128) != 0);
        return result;
    }

    private static long sleb(ByteBuffer input) {
        long result = 0;
        int shift = 0;
        int value;
        do {
            value = Byte.toUnsignedInt(input.get());
            result |= (long) (value & 127) << shift;
            shift += 7;
        } while ((value & 128) != 0);
        return (value & 64) == 0 ? result : result | (-1L << shift);
    }

    private static String string(ByteBuffer input) {
        int start = input.position();
        while (input.get() != 0) { }
        return new String(input.array(), start, input.position() - start - 1, StandardCharsets.UTF_8);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
