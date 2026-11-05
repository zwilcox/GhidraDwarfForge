package ghidradwarfforge.coverage;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Decode emitted line bytes independently before checking source metrics. */
public final class SourceCoverageSmoke {
    private record Row(long address, long line, boolean end) {
    }

    public static void main(String[] args) {
        var split = new FunctionSymbol("split", 0x1000, List.of(
            new FunctionRange(0x1000, 0x10), new FunctionRange(0x2000, 0x10)));
        var overlap = new FunctionSymbol("overlap", 0x1004, 8);
        var gap = new FunctionSymbol("gap", 0x1800, 4);
        var empty = new FunctionSymbol("empty", 0x3000, 4);
        var failed = new FunctionSymbol("failed", 0x4000, 8);
        var declarationOnly = new FunctionSymbol("declaration", 0x5000, 8);
        var functions = List.of(split, overlap, gap, empty, failed, declarationOnly);
        var tokens = List.of(new SourceLine(20, List.of(0x1004L, 0x2008L)),
            new SourceLine(30, List.of(0x2004L)),
            new SourceLine(32, List.of(0x2005L)),
            new SourceLine(60, List.of(0x1804L, 0x2010L)));
        var emittedLines = new ArrayList<>(tokens);
        emittedLines.add(new SourceLine(10, List.of(0x1000L)));
        emittedLines.add(new SourceLine(19, List.of(0x1004L)));
        emittedLines.add(new SourceLine(50, List.of(0x5000L)));
        var starts = List.of(0x1000L, 0x1004L, 0x1008L, 0x100cL,
            0x2000L, 0x2004L, 0x2008L, 0x200cL, 0x1004L);
        for (int width : new int[] {4, 8}) {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var result = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/fixture",
                    width, order, functions, emittedLines);
                var raw = decode(result.section(), width, order);
                require(raw.contains(new Row(0x1004, 19, false)), "earliest row survives collision");
                require(!raw.contains(new Row(0x1004, 20, false)), "later token row not serialized");
                Set<Long> rawVisible = new HashSet<>();
                Set<Long> rawAnchored = new HashSet<>();
                for (int i = 0; i + 1 < raw.size(); i++) {
                    Row row = raw.get(i);
                    if (row.end()) continue;
                    for (long pc : starts) {
                        if (pc >= row.address() && pc < raw.get(i + 1).address()) rawVisible.add(pc);
                        if (pc == row.address() && tokens.stream().anyMatch(token ->
                                token.line() == row.line() && token.addresses().contains(pc))) {
                            rawAnchored.add(pc);
                        }
                    }
                }
                require(rawVisible.size() == 7 && rawAnchored.size() == 2, "independent decoded-byte oracle");
                var index = new SourceCoverageIndex(result, () -> false);
                var measured = index.measure(split, starts, tokens, () -> false);
                require(measured.equals(new SourceCoverage(8, 2, 7)), "split/duplicate/collision counts");
                require(index.measure(split, starts.reversed(), tokens.reversed(), () -> false)
                    .equals(measured), "inventory order independence");
                require(index.measure(overlap, List.of(0x1004L, 0x1008L),
                    List.of(new SourceLine(19, List.of(0x1004L))), () -> false)
                    .equals(new SourceCoverage(2, 1, 2)), "overlap retains its own token provenance");
                require(index.measure(gap, List.of(0x1800L), List.of(), () -> false)
                    .equals(new SourceCoverage(1, 0, 0)), "no gap carry-forward");
                require(!index.measure(empty, List.of(), List.of(), () -> false).applicable(),
                    "zero denominator not applicable");
                require(index.measure(failed, List.of(0x4000L, 0x4004L), List.of(), () -> false)
                    .equals(new SourceCoverage(2, 0, 0)), "symbol-only denominator survives");
                require(index.measure(declarationOnly, List.of(0x5000L, 0x5004L), List.of(), () -> false)
                    .equals(new SourceCoverage(2, 0, 2)), "declaration visibility is not a token anchor");
                byte[] snapshot = result.section();
                snapshot[0] ^= 0x7f;
                require(!Arrays.equals(snapshot, result.section()), "encoded result owns immutable bytes");
                require(Arrays.equals(result.section(), Dwarf5LineTable.build("fixture.dbg.c", "/fixture",
                    width, order, functions, emittedLines)), "legacy byte output unchanged");
                var repeated = new ArrayList<>(functions);
                repeated.add(new FunctionSymbol("alias", split.address(), split.ranges()));
                var duplicate = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/fixture",
                    width, order, repeated, emittedLines);
                require(new SourceCoverageIndex(duplicate, () -> false).measure(split, starts,
                    tokens, () -> false).equals(measured), "duplicate sequences do not inflate counts");
                reject(() -> index.measure(split, List.of(0x2010L), tokens, () -> false));
                reject(() -> index.measure(split, List.of(-1L), tokens, () -> false));
                cancelled(() -> new SourceCoverageIndex(result, () -> true));
                AtomicInteger calls = new AtomicInteger();
                cancelled(() -> index.measure(split, starts, tokens, () -> calls.incrementAndGet() == 4));
                require(calls.get() == 4, "prompt inventory cancellation");
            }
        }
        reject(() -> new SourceCoverage(1, 2, 2));
        reject(() -> new SourceCoverage(1, 1, 0));
        reject(() -> new SourceCoverage(-1, 0, 0));
        System.out.println("source-coverage-smoke=PASS widths=2 byte-orders=2 raw-line-byte-oracle=PASS");
    }

    /** Only the encoder's documented standard opcodes; unknown bytes fail closed. */
    private static List<Row> decode(byte[] section, int width, ByteOrder order) {
        ByteBuffer bytes = ByteBuffer.wrap(section).order(order);
        require(bytes.getInt() == section.length - 4, "line unit length");
        require(bytes.getShort() == 5 && bytes.get() == width && bytes.get() == 0, "DWARF5 target header");
        int headerSize = bytes.getInt();
        bytes.position(bytes.position() + headerSize);
        long address = 0;
        long line = 1;
        List<Row> rows = new ArrayList<>();
        while (bytes.hasRemaining()) {
            int opcode = Byte.toUnsignedInt(bytes.get());
            switch (opcode) {
                case 0 -> {
                    int length = Math.toIntExact(uleb(bytes));
                    int end = bytes.position() + length;
                    int extended = Byte.toUnsignedInt(bytes.get());
                    if (extended == 2) address = width == 4 ? Integer.toUnsignedLong(bytes.getInt()) : bytes.getLong();
                    else if (extended == 1) {
                        rows.add(new Row(address, line, true));
                        address = 0;
                        line = 1;
                    }
                    else throw new AssertionError("unexpected extended opcode");
                    require(bytes.position() == end, "extended opcode length");
                }
                case 1 -> rows.add(new Row(address, line, false));
                case 2 -> address += uleb(bytes);
                case 3 -> line += sleb(bytes);
                case 4 -> require(uleb(bytes) == 0, "synthetic file index");
                default -> throw new AssertionError("unexpected standard opcode");
            }
        }
        return rows;
    }

    private static long uleb(ByteBuffer bytes) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            int next = Byte.toUnsignedInt(bytes.get());
            value |= (long) (next & 0x7f) << shift;
            if ((next & 0x80) == 0) return value;
        }
        throw new AssertionError("overlong ULEB");
    }

    private static long sleb(ByteBuffer bytes) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            int next = Byte.toUnsignedInt(bytes.get());
            value |= (long) (next & 0x7f) << shift;
            if ((next & 0x80) == 0) {
                int bits = shift + 7;
                return (next & 0x40) != 0 && bits < 64 ? value | (-1L << bits) : value;
            }
        }
        throw new AssertionError("overlong SLEB");
    }

    private static void reject(Runnable action) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid metric input accepted");
    }

    private static void cancelled(Runnable action) {
        try { action.run(); }
        catch (CancellationException expected) { return; }
        throw new AssertionError("cancellation not honored");
    }

    private static void require(boolean condition, String detail) {
        if (!condition) throw new AssertionError(detail);
    }
}
