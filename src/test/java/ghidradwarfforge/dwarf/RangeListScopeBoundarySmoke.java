package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.LexicalScopeModel.Block;
import ghidradwarfforge.types.LexicalScopeModel.Key;

/** Independent decoding of discontiguous lexical ranges inside contiguous functions. */
public final class RangeListScopeBoundarySmoke {
    private static int checks;

    private RangeListScopeBoundarySmoke() { }

    public static void main(String[] args) {
        for (int width : new int[] {4, 8}) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                long[] bases = width == 4 ? new long[] {0, 0x1000, 0xffff_ff80L} :
                    new long[] {0, 0x1000, 0x1_0000_0080L, Long.MAX_VALUE - 128};
                for (long base : bases) {
                    for (int gap = 1; gap <= 16; gap++) {
                        checkLayout(base, width, order, gap);
                    }
                }
            }
        }
        var function = new FunctionSymbol("owner", 0x1000, 64);
        var scope = scope(function, 4);
        for (int invalid : new int[] {-1, 0, 1, 2, 3, 5, 7, 9, 16}) {
            rejects(() -> Dwarf5RangeLists.build(List.of(function), List.of(scope), invalid,
                ByteOrder.LITTLE_ENDIAN), "unsupported address size");
        }
        rejects(() -> Dwarf5RangeLists.build(List.of(), List.of(scope), 8,
            ByteOrder.LITTLE_ENDIAN), "different function body");
        rejects(() -> Dwarf5RangeLists.build(List.of(new FunctionSymbol("other", 0x2000, 64)),
            List.of(scope), 8, ByteOrder.LITTLE_ENDIAN), "different function body");
        rejects(() -> Dwarf5RangeLists.build(List.of(function, function), List.of(scope), 8,
            ByteOrder.LITTLE_ENDIAN), "different function body");
        rejects(() -> Dwarf5RangeLists.build(List.of(new FunctionSymbol("wrong", 0x1000, 32)),
            List.of(scope), 8, ByteOrder.LITTLE_ENDIAN), "different function body");
        rejects(() -> Dwarf5RangeLists.build(List.of(function), List.of(scope, scope), 8,
            ByteOrder.LITTLE_ENDIAN), "duplicate lexical range identity");
        check(Dwarf5RangeLists.build(List.of(), 8, ByteOrder.LITTLE_ENDIAN).empty(),
            "empty function inventory should not create ranges");
        var simple = new LexicalScopeModel(function.address(), function.ranges(),
            List.of(new Block("one", "", List.of(new FunctionRange(0x1008, 8)))),
            List.of(), "explicit contiguous lexical block");
        check(Dwarf5RangeLists.build(List.of(function), List.of(simple), 8,
            ByteOrder.LITTLE_ENDIAN).empty(), "contiguous lexical block needs no range list");
        System.out.println("range-list-scope-boundaries=PASS checks=" + checks);
    }

    private static LexicalScopeModel scope(FunctionSymbol function, int gap) {
        long base = function.address();
        return new LexicalScopeModel(base, function.ranges(), List.of(
            new Block("split", "", List.of(new FunctionRange(base + 8, 4),
                new FunctionRange(base + 12 + gap, 8))),
            new Block("simple", "", List.of(new FunctionRange(base + 48, 8)))),
            List.of(), "explicit lexical ranges with an excluded visibility gap");
    }

    private static void checkLayout(long base, int width, ByteOrder order, int gap) {
        var function = new FunctionSymbol("owner", base, 64);
        var scope = scope(function, gap);
        var result = Dwarf5RangeLists.build(List.of(function), List.of(scope), width, order);
        check(!result.empty(), "discontiguous lexical scope requires a range list");
        byte[] bytes = result.section();
        var header = ByteBuffer.wrap(bytes).order(order);
        check(Integer.toUnsignedLong(header.getInt()) == bytes.length - 4L, "unit length");
        check(Short.toUnsignedInt(header.getShort()) == 5, "DWARF version");
        check(Byte.toUnsignedInt(header.get()) == width && header.get() == 0, "address/segment widths");
        check(header.getInt() == 0 && result.compilationUnitOffset() == header.position(), "direct-offset header");
        check(result.functionOffsets().isEmpty(), "contiguous function must retain its simple range");
        check(result.lexicalOffsets().keySet().equals(java.util.Set.of(new Key(base, "split"))),
            "only the discontiguous lexical block needs a list");
        List<long[]> unit = decode(bytes, result.compilationUnitOffset(), width, order);
        check(unit.size() == 1 && unit.getFirst()[0] == base && unit.getFirst()[1] == base + 64,
            "CU should retain all function code");
        long offset = result.lexicalOffsets().get(new Key(base, "split"));
        List<long[]> blocks = decode(bytes, offset, width, order);
        check(blocks.size() == 2, "lexical ranges must retain both intervals");
        check(blocks.get(0)[0] == base + 8 && blocks.get(0)[1] == base + 12,
            "first lexical interval");
        check(blocks.get(1)[0] == base + 12 + gap && blocks.get(1)[1] == base + 20 + gap,
            "second lexical interval");
        for (int displacement = 0; displacement < 64; displacement++) {
            long address = base + displacement;
            boolean actual = blocks.stream().anyMatch(range -> range[0] <= address && address < range[1]);
            boolean expected = (displacement >= 8 && displacement < 12) ||
                (displacement >= 12 + gap && displacement < 20 + gap);
            check(actual == expected, "lexical visibility must neither fill gaps nor lose endpoints");
        }
        bytes[0] ^= 0x7f;
        check(!Arrays.equals(bytes, result.section()), "section bytes must be defensive copies");
        check(Arrays.equals(result.section(), Dwarf5RangeLists.build(List.of(function), List.of(scope),
            width, order).section()), "repeat encoding must be deterministic");
        rejectsMutation(() -> result.lexicalOffsets().clear());
    }

    private static List<long[]> decode(byte[] bytes, long offset, int width, ByteOrder order) {
        ByteBuffer input = ByteBuffer.wrap(bytes).order(order);
        input.position(Math.toIntExact(offset));
        var ranges = new ArrayList<long[]>();
        while (input.hasRemaining()) {
            int opcode = Byte.toUnsignedInt(input.get());
            if (opcode == 0) return ranges;
            check(opcode == 6, "unsupported range-list opcode");
            long start = width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
            long end = width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
            check(start < end, "decoded interval must have positive extent");
            ranges.add(new long[] {start, end});
        }
        throw new AssertionError("unterminated range list");
    }

    private static void rejects(Runnable action, String diagnostic) {
        try {
            action.run();
            throw new AssertionError("accepted invalid range model: " + diagnostic);
        }
        catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains(diagnostic), "wrong rejection diagnostic");
        }
    }

    private static void rejectsMutation(Runnable action) {
        try {
            action.run();
            throw new AssertionError("range offsets are mutable");
        }
        catch (UnsupportedOperationException expected) {
            checks++;
        }
    }

    private static void check(boolean valid, String message) {
        checks++;
        if (!valid) throw new AssertionError(message);
    }
}
