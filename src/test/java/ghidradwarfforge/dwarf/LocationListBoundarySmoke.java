package ghidradwarfforge.dwarf;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import ghidradwarfforge.locations.VariableStorageModel.*;

/** Independent decoding of address and LEB boundaries, including fail-closed narrowing. */
public final class LocationListBoundarySmoke {
    private static final Evidence EVIDENCE = new Evidence(Confidence.USER_DEFINED, "explicit encoding fixture");
    private static int checks;

    public static void main(String[] args) {
        for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : List.of(4, 8)) {
                long highest = width == 4 ? 0xffff_ffffL : Long.MAX_VALUE;
                for (long address : new long[] {0, 0x7fff_ffffL, 0x8000_0000L, highest}) {
                    checkAddresses(width, order, address, false);
                    checkAddresses(width, order, address, true);
                }
                for (long offset : new long[] {Long.MIN_VALUE, -8193, -8192, -65, -64, -1,
                        0, 63, 64, 8191, 8192, Long.MAX_VALUE}) {
                    var storage = new RegisterRelativeStorage(new DwarfRegister("fixture", 128), offset);
                    for (byte[] expression : expressions(variable(0x1000, 4, storage), width, order)) {
                        var bytes = ByteBuffer.wrap(expression);
                        require((bytes.get() & 255) == 0x92, "missing bregx");
                        require(leb(bytes, false).intValueExact() == 128, "register ULEB differs");
                        require(leb(bytes, true).longValueExact() == offset, "signed offset narrowed");
                        require(!bytes.hasRemaining(), "extra register-relative operands");
                    }
                }
                var pieces = new ArrayList<Piece>();
                for (int index = 0; index < 64; index++) {
                    pieces.add(new Piece(new RegisterStorage(new DwarfRegister("fixture", 128 + index), 128, 8), 8));
                }
                var variable = variable(0x1000, 64, new CompositeStorage(pieces));
                for (byte[] expression : expressions(variable, width, order)) {
                    require(expression.length > 127, "fixture must exercise multi-byte expression length");
                    var bytes = ByteBuffer.wrap(expression);
                    for (int index = 0; index < 64; index++) {
                        require((bytes.get() & 255) == 0x90, "piece register opcode");
                        require(leb(bytes, false).intValueExact() == 128 + index, "piece register number");
                        require((bytes.get() & 255) == 0x9d, "piece bit-offset opcode");
                        require(leb(bytes, false).intValueExact() == 8, "piece bit size");
                        require(leb(bytes, false).intValueExact() == 128, "piece bit offset");
                    }
                    require(!bytes.hasRemaining(), "trailing composite bytes");
                }
                cancellation(variable, width, order);
            }
            for (long address : new long[] {0x1_0000_0000L, 0x1_0000_0007L, Long.MAX_VALUE}) {
                rejects(() -> Dwarf5LocationLists.build(List.of(variable(0x1000, 1,
                    new MemoryStorage(address))), 4, order));
                rejects(() -> Dwarf5LocationLists.build(List.of(variable(0x1000, 1,
                    new IndirectMemoryStorage(new MemoryStorage(address)))), 4, order));
            }
            // The storage address fits, but a live-range bound does not.
            rejects(() -> Dwarf5LocationLists.build(List.of(variable(0x1_0000_0000L, 1,
                new MemoryStorage(7))), 4, order));
            rejects(() -> Dwarf5LocationLists.build(List.of(variable(0xffff_fffcL, 1,
                new MemoryStorage(7))), 4, order));
            var edge = variable(0xffff_fffbL, 1, new MemoryStorage(7));
            var encoded = Dwarf5LocationLists.build(List.of(edge), 4, order);
            var edgeBytes = ByteBuffer.wrap(encoded.section()).order(order);
            edgeBytes.position(Math.toIntExact(encoded.offsets().get(edge)) + 15);
            require(edgeBytes.get() == 8 && Integer.toUnsignedLong(edgeBytes.getInt()) == 0xffff_fffeL &&
                edgeBytes.get() == 2, "last ELF32 location needs start and length");
            var high = variable(0x1_0000_0000L, 1, new MemoryStorage(0x1_0000_0007L));
            require(expressions(high, 8, order).size() == 2, "64-bit address was wrongly rejected");
        }
        System.out.println("location-list-boundaries=PASS checks=" + checks);
    }

    private static VariableLocation variable(long start, long size, Storage storage) {
        return new VariableLocation("fixture", start, "value", VariableKind.LOCAL, size, List.of(
            new LocationRange(start, start + 2, storage, EVIDENCE),
            new LocationRange(start + 3, start + 5, storage, EVIDENCE)));
    }

    private static void checkAddresses(int width, ByteOrder order, long address, boolean indirect) {
        Storage storage = new MemoryStorage(address);
        if (indirect) storage = new IndirectMemoryStorage(storage);
        for (byte[] expression : expressions(variable(0x1000, 1, storage), width, order)) {
            var bytes = ByteBuffer.wrap(expression).order(order);
            require((bytes.get() & 255) == 3, "missing absolute-address operation");
            require(unsigned(bytes, width) == address, "storage address narrowed");
            if (indirect) require((bytes.get() & 255) == 6, "missing dereference");
            require(!bytes.hasRemaining(), "unexpected address-expression operands");
        }
    }

    private static List<byte[]> expressions(VariableLocation variable, int width, ByteOrder order) {
        var result = Dwarf5LocationLists.build(List.of(variable), width, order);
        byte[] encoded = result.section();
        var bytes = ByteBuffer.wrap(encoded).order(order);
        require(Integer.toUnsignedLong(bytes.getInt()) == encoded.length - 4, "section length");
        require(Short.toUnsignedInt(bytes.getShort()) == 5, "section version");
        require((bytes.get() & 255) == width && bytes.get() == 0 && bytes.getInt() == 0, "section header");
        require(result.offsets().get(variable) == bytes.position(), "list offset");
        var expressions = new ArrayList<byte[]>();
        for (var range : variable.locations()) {
            require((bytes.get() & 255) == 7, "missing start/end entry");
            require(unsigned(bytes, width) == range.start() && unsigned(bytes, width) == range.end(),
                "live range narrowed or gap bridged");
            byte[] expression = new byte[leb(bytes, false).intValueExact()];
            bytes.get(expression);
            expressions.add(expression);
        }
        require(bytes.get() == 0 && !bytes.hasRemaining(), "list terminator");
        encoded[0] ^= 127;
        require(!Arrays.equals(encoded, result.section()), "caller changed retained section");
        return expressions;
    }

    private static long unsigned(ByteBuffer bytes, int width) {
        return width == 4 ? Integer.toUnsignedLong(bytes.getInt()) : bytes.getLong();
    }

    private static BigInteger leb(ByteBuffer bytes, boolean signed) {
        BigInteger value = BigInteger.ZERO;
        int octet, bits = 0;
        do {
            require(bits < 70, "unbounded LEB operand");
            octet = bytes.get() & 255;
            value = value.or(BigInteger.valueOf(octet & 127).shiftLeft(bits));
            bits += 7;
        } while ((octet & 128) != 0);
        return signed && (octet & 64) != 0 ? value.subtract(BigInteger.ONE.shiftLeft(bits)) : value;
    }

    private static void cancellation(VariableLocation variable, int width, ByteOrder order) {
        var calls = new AtomicInteger();
        var result = Dwarf5LocationLists.build(List.of(variable), width, order,
            () -> { calls.incrementAndGet(); return false; });
        for (int boundary = 1; boundary <= calls.get(); boundary++) {
            int selected = boundary;
            var observed = new AtomicInteger();
            try {
                Dwarf5LocationLists.build(List.of(variable), width, order,
                    () -> observed.incrementAndGet() == selected);
                throw new AssertionError("cancellation returned a partial/final result");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(Arrays.equals(result.section(), Dwarf5LocationLists.build(List.of(variable), width, order).section()),
            "retry differs after cancelled planning");
    }

    private static void rejects(Runnable action) {
        try {
            action.run();
            throw new AssertionError("location address overflow was silently accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().equals("location-list value exceeds serialized width"), "wrong refusal");
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
