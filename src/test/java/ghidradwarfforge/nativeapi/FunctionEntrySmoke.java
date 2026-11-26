package ghidradwarfforge.nativeapi;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Native-free model checks, optionally followed by an isolated real producer. */
public final class FunctionEntrySmoke {
    private FunctionEntrySmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        modelBoundaries();
        declarationIndex();
        upperHalfEntryRanges();
        List<FunctionSymbol> functions = functions(0x1000);
        for (int width : new int[] { 4, 8 }) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var ranges = Dwarf5RangeLists.build(functions, width, order);
                if (ranges.empty() || ranges.functionOffsets().size() != 2) {
                    throw new AssertionError("split body lost its ranges");
                }
                checkRanges(ranges, ranges.functionOffsets().get(functions.get(0)), width, order,
                    new long[][] { { 0x1022, 0x1028 }, { 0x1000, 0x1008 },
                        { 0x1020, 0x1022 } });
                checkRanges(ranges, ranges.functionOffsets().get(functions.get(1)), width, order,
                    new long[][] { { 0x1044, 0x1050 }, { 0x1040, 0x1044 } });
                byte[] lines = Dwarf5LineTable.build("entry.c", width, order, functions,
                    List.of(new SourceLine(3, List.of(0x1000L, 0x1020L, 0x1040L))));
                if (lines.length == 0 || functions.get(0).contains(0x1010)) {
                    throw new AssertionError("missing lines or false gap coverage");
                }
            }
        }
        require(functions.get(0).ranges().getFirst().address() == 0x1000 &&
            functions.get(1).ranges().getFirst().address() == 0x1040,
            "encoding reordered the extraction model around the function entry");
        reject(0x1010); // A hole between real ranges is not an entry.
        reject(0x1028); // Nor is the exclusive range end.
        reject(0xfff);
        if (arguments.length == 4) {
            Path input = Path.of(arguments[2]);
            Path output = Path.of(arguments[3]);
            Files.createDirectories(output.toAbsolutePath().getParent());
            ElfImage elf = ElfImage.read(input);
            // Synthetic addresses exercise the producer and all relocation
            // widths. Executable code is independently checked by headless/GDB.
            long base = Math.addExact(elf.preferredImageBase(), 0x1000);
            var result = new MinimalDwarfSidecarExporter().export(input, output,
                Path.of(arguments[0]), Path.of(arguments[1]), functions(base));
            System.out.printf("entry-producer=PASS target=%s split-entry=0x%x " +
                "middle-entry=0x%x middle-low=0x%x%n", result.target().name(),
                base + 0x22, base + 0x44, base + 0x40);
        }
        else if (arguments.length != 0) {
            throw new IllegalArgumentException(
                "usage: FunctionEntrySmoke [<libdwarf> <libdwarfp> <input> <output>]");
        }
        System.out.println("function-entry-smoke=PASS");
    }

    private static void declarationIndex() {
        for (int count : List.of(16, 128, 512)) {
            var functions = new ArrayList<ghidradwarfforge.source.SyntheticSourceFile.FunctionLines>();
            var rows = new ArrayList<SourceLine>();
            for (int i = 0; i < count; i++) {
                long entry = 0x4000 + i * 8L;
                int start = i * 5 + 1;
                functions.add(new ghidradwarfforge.source.SyntheticSourceFile.FunctionLines("fn" + i, entry,
                    start, start + 4, true, null));
                // Rows can mention a neighboring entry and arrive out of line-number order.
                rows.add(new SourceLine(start + 3, List.of(entry + 8, entry + 1)));
                if (i % 3 != 0) {
                    rows.add(new SourceLine(start + 2, List.of(entry)));
                    rows.add(new SourceLine(start + 1, List.of(entry)));
                }
            }
            var source = new ghidradwarfforge.source.SyntheticSourceFile(new byte[0], functions, rows);
            var polls = new java.util.concurrent.atomic.AtomicInteger();
            var declarations = MinimalDwarfSidecarExporter.declarationLines(source, () -> {
                polls.incrementAndGet();
                return false;
            });
            for (var function : functions) {
                int reference = rows.stream().filter(row -> row.line() >= function.startLine() &&
                    row.line() <= function.endLine() && row.addresses().contains(function.address()))
                    .mapToInt(SourceLine::line).min().orElse(function.startLine());
                require(declarations.get(function) == reference, "indexed declaration lost earliest owned entry row or fallback");
            }
            require(polls.get() == rows.size() + 2 * count, "declaration planning exceeded one row pass");
        }
    }

    private static void modelBoundaries() {
        var body = List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x1020, 8));
        for (String name : Arrays.asList(null, "", " \t")) {
            invalid(() -> new FunctionSymbol(name, 0x1000, body),
                "function name is required");
        }
        List<List<String>> badNamespaces = Arrays.asList(null,
            Arrays.asList("outer", null), List.of("outer", ""), List.of(" "));
        for (var namespace : badNamespaces) {
            invalid(() -> new FunctionSymbol("f", 0x1000, body, namespace),
                "invalid function namespace path");
        }
        invalid(() -> new FunctionSymbol("f", -1, body), "entry is outside");
        invalid(() -> new FunctionSymbol("f", 0x1000, (List<FunctionRange>) null),
            "function ranges are required");
        invalid(() -> new FunctionSymbol("f", 0x1000, List.of()),
            "function ranges are required");
        invalid(() -> new FunctionSymbol("f", 0x1000,
            List.of(body.get(1), body.get(0))), "ranges overlap or are unsorted");
        invalid(() -> new FunctionSymbol("f", 0x1000,
            List.of(body.get(0), new FunctionRange(0x1007, 8))),
            "ranges overlap or are unsorted");
        invalid(() -> new FunctionRange(-1, 1), "exclusive range end 2^64");
        invalid(() -> new FunctionRange(-1, 2), "wraps through zero");
        invalid(() -> new FunctionRange(0, 0), "empty or unbounded");
        invalid(() -> new FunctionRange(0, -1), "empty or unbounded");

        for (long base : new long[] { 0, 0x1000, 0xffff_ffffL, Long.MAX_VALUE - 7, Long.MIN_VALUE, -17 }) {
            var range = new FunctionRange(base, 16);
            require(range.endExclusive() == base + 16, "wrong exclusive end");
            for (int offset = -1; offset <= 16; offset++) {
                require(range.contains(base + offset) == (offset >= 0 && offset < 16),
                    "incorrect half-open range membership");
            }
            var ordinary = new FunctionSymbol("f", base, List.of(range));
            var interior = new FunctionSymbol("f", base + 1, List.of(range));
            require(ordinary.contiguous() && ordinary.size() == 16 && !ordinary.usesRangeList(),
                "ordinary entry changed its representation");
            require(interior.contiguous() && interior.size() == 16 && interior.usesRangeList(),
                "interior entry lost its range-list requirement");
        }

        var mutableBody = new ArrayList<>(body);
        var mutableNamespace = new ArrayList<>(List.of("outer", "inner"));
        var split = new FunctionSymbol("f", 0x1022, mutableBody, mutableNamespace);
        mutableBody.clear();
        mutableNamespace.clear();
        require(split.ranges().equals(body) && split.namespacePath().equals(List.of("outer", "inner")),
            "caller mutation changed captured function identity");
        require(split.qualifiedDisplayName().equals("outer::inner::f") &&
            !split.contiguous() && split.usesRangeList(), "split function identity changed");
        for (long address = 0xfff; address <= 0x1028; address++) {
            require(split.contains(address) == ((address >= 0x1000 && address < 0x1008) ||
                (address >= 0x1020 && address < 0x1028)), "split body invented gap coverage");
        }
        try {
            split.size();
            throw new AssertionError("discontiguous body acquired a single size");
        }
        catch (IllegalStateException expected) {
            require(expected.getMessage().contains("discontiguous function"),
                "wrong discontiguous-size diagnostic");
        }
        var adjacent = new FunctionSymbol("adjacent", 0x1008,
            List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x1008, 8)));
        require(adjacent.contains(0x1008) && adjacent.usesRangeList(),
            "adjacent body ranges were rejected or lost");
        FunctionSymbol.validateDisplayNames(List.of(split,
            new FunctionSymbol("f", 0x2000, List.of(new FunctionRange(0x2000, 8)),
                List.of("outer", "inner"))));
        var delimiter = new FunctionSymbol("inner::f", 0x1000, body, List.of("outer"));
        invalid(() -> FunctionSymbol.validateDisplayNames(List.of(split, delimiter)),
            "ambiguous qualified function display");
        invalid(() -> FunctionSymbol.validateDisplayNames(List.of(delimiter, split)),
            "ambiguous qualified function display");
        System.out.println("function-model-boundaries=PASS");
    }

    private static void invalid(Runnable operation, String diagnostic) {
        try {
            operation.run();
            throw new AssertionError("accepted invalid function model: " + diagnostic);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage() != null && expected.getMessage().contains(diagnostic),
                "wrong function-model rejection: " + expected);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void upperHalfEntryRanges() {
        long low = 0x401000L;
        long entry = 0xffffffff81000000L;
        var function = new FunctionSymbol("split_entry", entry,
            List.of(new FunctionRange(low, 10), new FunctionRange(entry, 12)));
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            var ranges = Dwarf5RangeLists.build(List.of(function), Long.BYTES, order);
            checkRanges(ranges, ranges.compilationUnitOffset(), Long.BYTES, order,
                new long[][] { { low, low + 10 }, { entry, entry + 12 } });
            checkRanges(ranges, ranges.functionOffsets().get(function), Long.BYTES, order,
                new long[][] { { entry, entry + 12 }, { low, low + 10 } });
        }
        require(function.ranges().getFirst().address() == low && function.address() == entry,
            "upper-half entry or lower fragment moved during encoding");
    }

    private static void checkRanges(Dwarf5RangeLists.Result result, long listOffset,
            int width, ByteOrder order, long[][] expected) {
        ByteBuffer data = ByteBuffer.wrap(result.section()).order(order);
        data.position(Math.toIntExact(listOffset));
        for (long[] range : expected) {
            if (data.get() != 6) {
                throw new AssertionError("expected DW_RLE_start_end");
            }
            long start = width == 8 ? data.getLong() : Integer.toUnsignedLong(data.getInt());
            long end = width == 8 ? data.getLong() : Integer.toUnsignedLong(data.getInt());
            if (start != range[0] || end != range[1]) {
                throw new AssertionError("wrong entry/order/body interval");
            }
        }
        if (data.get() != 0) {
            throw new AssertionError("unterminated range list");
        }
    }

    private static List<FunctionSymbol> functions(long base) {
        return List.of(new FunctionSymbol("split_entry", base + 0x22,
                List.of(new FunctionRange(base, 8), new FunctionRange(base + 0x20, 8))),
            new FunctionSymbol("middle_entry", base + 0x44,
                List.of(new FunctionRange(base + 0x40, 16))),
            new FunctionSymbol("ordinary_entry", base + 0x80, 8));
    }

    private static void reject(long entry) {
        try {
            new FunctionSymbol("invalid", entry,
                List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x1020, 8)));
            throw new AssertionError("accepted entry outside body: " + entry);
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("outside its body ranges")) {
                throw expected;
            }
        }
    }
}
