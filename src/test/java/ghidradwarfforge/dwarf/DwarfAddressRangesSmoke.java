package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Native-free, independent address-table decoding and boundary checks. */
public final class DwarfAddressRangesSmoke {
    private record Interval(long start, long length) {
        boolean contains(long address) {
            return start <= address && address - start < length;
        }
    }

    private DwarfAddressRangesSmoke() {
    }

    public static void main(String[] args) {
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : List.of(4, 8)) {
                checkUnion(width, order);
                checkBoundaries(width, order);
                require(DwarfAddressRanges.build(List.of(), width, order).length == 0,
                    "empty model must not emit a fake CU contribution");
            }
        }
        // Fixed externally readable encodings catch shared offset/alignment mistakes.
        FunctionSymbol simple = new FunctionSymbol("simple", 0x12345678, 0x10);
        require(Arrays.equals(DwarfAddressRanges.build(List.of(simple), 4,
                ByteOrder.BIG_ENDIAN), HexFormat.of().parseHex(
                    "0000001c000200000000040000000000" +
                    "12345678000000100000000000000000")), "ELF32 golden bytes");
        require(Arrays.equals(DwarfAddressRanges.build(List.of(simple), 8,
                ByteOrder.LITTLE_ENDIAN), HexFormat.of().parseHex(
                    "2c000000020000000000080000000000" +
                    "78563412000000001000000000000000" +
                    "00000000000000000000000000000000")), "ELF64 golden bytes");
        rejects(() -> DwarfAddressRanges.build(List.of(simple), 2, ByteOrder.LITTLE_ENDIAN));
        rejects(() -> DwarfAddressRanges.build(List.of(simple), 16, ByteOrder.BIG_ENDIAN));
        rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
            "overflow", Long.MAX_VALUE, 1)), 8, ByteOrder.LITTLE_ENDIAN));
        rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
            "negative", -1, 1)), 8, ByteOrder.BIG_ENDIAN));
        rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
            "empty", 0, 0)), 4, ByteOrder.LITTLE_ENDIAN));
        System.out.println("dwarf-address-ranges-smoke=PASS");
    }

    private static void checkUnion(int width, ByteOrder order) {
        FunctionSymbol split = new FunctionSymbol("interior_entry", 0x3005, List.of(
            new FunctionRange(0x1000, 0x10), new FunctionRange(0x3000, 0x10)));
        List<FunctionSymbol> functions = new ArrayList<>(List.of(
            new FunctionSymbol("last", 0x4000, 8), split,
            new FunctionSymbol("overlap", 0x1008, 0x18),
            new FunctionSymbol("adjacent", 0x1020, 0x10),
            new FunctionSymbol("duplicate_body", 0x3000, 0x10)));
        byte[] bytes = DwarfAddressRanges.build(functions, width, order);
        List<Interval> intervals = decode(bytes, width, order);
        require(intervals.equals(List.of(new Interval(0x1000, 0x30),
            new Interval(0x3000, 0x10), new Interval(0x4000, 8))), "exact body union");
        for (long excluded : new long[] { 0xfff, 0x1030, 0x2000, 0x3010, 0x4008, 0x420028 }) {
            require(intervals.stream().noneMatch(range -> range.contains(excluded)),
                "invented gap/data coverage at " + Long.toHexString(excluded));
        }
        require(intervals.stream().anyMatch(range -> range.contains(0x3005)),
            "true interior entry must remain covered");
        Collections.reverse(functions);
        require(Arrays.equals(bytes, DwarfAddressRanges.build(functions, width, order)),
            "model ordering changed serialized bytes");
        require(Arrays.equals(bytes, DwarfAddressRanges.build(functions, width, order)),
            "repeated build changed serialized bytes");
    }

    private static void checkBoundaries(int width, ByteOrder order) {
        List<FunctionSymbol> edges = List.of(new FunctionSymbol("zero", 0, 1),
            new FunctionSymbol("last_32_bit_byte", 0xffff_ffffL, 1));
        require(decode(DwarfAddressRanges.build(edges, width, order), width, order)
            .equals(List.of(new Interval(0, 1), new Interval(0xffff_ffffL, 1))),
            "zero address or exact 2^32 endpoint changed");
        require(decode(DwarfAddressRanges.build(List.of(new FunctionSymbol(
            "large_length", 1, 0xffff_ffffL)), width, order), width, order)
            .equals(List.of(new Interval(1, 0xffff_ffffL))), "unsigned32 length truncated");
        if (width == 4) {
            rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
                "large_address", 0x1_0000_0000L, 1)), width, order));
            rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
                "end_overflow", 0xffff_ffffL, 2)), width, order));
            rejects(() -> DwarfAddressRanges.build(List.of(new FunctionSymbol(
                "length_overflow", 0, 0x1_0000_0000L)), width, order));
            // Individually valid words can merge into an unencodable 2^32 length.
            rejects(() -> DwarfAddressRanges.build(List.of(
                new FunctionSymbol("almost_all", 0, 0xffff_ffffL),
                new FunctionSymbol("last", 0xffff_ffffL, 1)), width, order));
        }
        else {
            List<FunctionSymbol> wide = List.of(
                new FunctionSymbol("wide_address", 0x1_0000_0000L, 0x1_0000_0000L),
                new FunctionSymbol("model_upper_bound", Long.MAX_VALUE - 16, 16));
            require(decode(DwarfAddressRanges.build(wide, width, order), width, order)
                .equals(List.of(new Interval(0x1_0000_0000L, 0x1_0000_0000L),
                    new Interval(Long.MAX_VALUE - 16, 16))), "ELF64 words truncated");
        }
    }

    private static List<Interval> decode(byte[] bytes, int width, ByteOrder order) {
        ByteBuffer input = ByteBuffer.wrap(bytes).order(order);
        require(Integer.toUnsignedLong(input.getInt()) == bytes.length - 4,
            "DWARF32 length");
        require(Short.toUnsignedInt(input.getShort()) == 2, "address-table version");
        require(input.getInt() == 0, "CU header offset must be zero, not first DIE");
        require(Byte.toUnsignedInt(input.get()) == width, "target address size");
        require(input.get() == 0, "segment selector");
        // Both supported formats have four padding bytes and start tuples at16.
        for (int i = 0; i < 4; i++) {
            require(input.get() == 0, "header padding");
        }
        require(input.position() == 16 && input.position() % (2 * width) == 0,
            "tuple alignment");
        List<Interval> result = new ArrayList<>();
        while (input.hasRemaining()) {
            long address = width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
            long length = width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
            if (address == 0 && length == 0) {
                require(!input.hasRemaining(), "bytes after terminating tuple");
                return List.copyOf(result);
            }
            require(address >= 0 && length > 0, "invalid nonterminal tuple");
            result.add(new Interval(address, length));
        }
        throw new AssertionError("missing terminating tuple");
    }

    private static void rejects(Runnable operation) {
        try {
            operation.run();
        }
        catch (IllegalArgumentException | ArithmeticException expected) {
            return;
        }
        throw new AssertionError("invalid address table was accepted");
    }

    private static void require(boolean condition, String detail) {
        if (!condition) {
            throw new AssertionError("invalid address lookup: " + detail);
        }
    }
}
