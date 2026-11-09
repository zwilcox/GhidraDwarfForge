package ghidradwarfforge.calls;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.function.BiFunction;

import com.google.gson.GsonBuilder;
import ghidradwarfforge.calls.CallValue.*;

/** Numeric expectations use unbounded arithmetic, independent of DWARF serialization. */
public final class CallValueSmoke {
    private record Case(String name, CallValue value, BiFunction<BigInteger, BigInteger, BigInteger> expected) { }
    private record Vector(String name, int addressBytes, String order, String register5, String register6,
            String expression, String expected) { }
    private static int rejected;
    private static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("invalid expression was admitted"); }
        catch (IllegalArgumentException expected) { rejected++; }
    }
    private static BigInteger unsigned(long value) { return new BigInteger(Long.toUnsignedString(value)); }
    private static BigInteger mask(int bytes) { return BigInteger.ONE.shiftLeft(bytes * 8).subtract(BigInteger.ONE); }

    public static void main(String[] args) throws Exception {
        var vectors = new ArrayList<Vector>();
        var samples = new ArrayList<Long>(List.of(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE,
            0x7fffffffL, 0x80000000L, 0xffffffffL, 0x100000000L));
        var random = new Random(117);
        for (int index = 0; index < 12; index++) samples.add(random.nextLong());
        for (int addressBytes : List.of(4, 8)) {
            for (int bytes = 1; bytes <= addressBytes; bytes++) {
                int width = bytes;
                var x = CallValue.slice(new Incoming(5, addressBytes), 0, width);
                var y = CallValue.slice(new Incoming(6, addressBytes), 0, width);
                var one = new Literal(1, width);
                var zero = new Literal(0, width);
                var sum = CallValue.binary(Op.ADD, x, one, width);
                var condition = CallValue.binary(Op.EQUAL, y, zero, 1);
                List<Case> cases = List.of(
                    new Case("incoming", x, (a, b) -> a),
                    new Case("constant-high", new Literal(-1, width), (a, b) -> mask(width)),
                    new Case("increment", sum, (a, b) -> a.add(BigInteger.ONE)),
                    new Case("subtract", CallValue.binary(Op.SUBTRACT, x, y, width), BigInteger::subtract),
                    new Case("multiply", CallValue.binary(Op.MULTIPLY, x, y, width), BigInteger::multiply),
                    new Case("xor", CallValue.binary(Op.XOR, x, y, width), BigInteger::xor),
                    new Case("and", CallValue.binary(Op.AND, x, y, width), BigInteger::and),
                    new Case("or", CallValue.binary(Op.OR, x, y, width), BigInteger::or),
                    new Case("shift-left", CallValue.binary(Op.SHIFT_LEFT, x, new Literal(3, 1), width), (a, b) -> a.shiftLeft(3)),
                    new Case("shift-right", CallValue.binary(Op.SHIFT_RIGHT, x, new Literal(3, 1), width), (a, b) -> a.shiftRight(3)),
                    new Case("overshift", CallValue.binary(Op.SHIFT_LEFT, x, new Literal(width * 8, 1), width), (a, b) -> BigInteger.ZERO),
                    new Case("select", CallValue.select(condition, sum, x), (a, b) -> b.signum() == 0 ? a.add(BigInteger.ONE) : a),
                    new Case("nested-select", CallValue.select(condition, sum, CallValue.select(
                        CallValue.binary(Op.NOT_EQUAL, x, zero, 1), x, one)),
                        (a, b) -> b.signum() == 0 ? a.add(BigInteger.ONE) : a.signum() != 0 ? a : BigInteger.ONE),
                    new Case("zero-extend", CallValue.extend(x, false, addressBytes), (a, b) -> a),
                    new Case("sign-extend", CallValue.extend(x, true, addressBytes),
                        (a, b) -> a.testBit(width * 8 - 1) ? a.subtract(BigInteger.ONE.shiftLeft(width * 8)) : a)
                );
                for (int index = 0; index < samples.size(); index++) {
                    long input = samples.get(index);
                    long second = index % 3 == 0 ? 0 : samples.get((index + 1) % samples.size());
                    BigInteger a = unsigned(input).and(mask(width));
                    BigInteger b = unsigned(second).and(mask(width));
                    for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        for (var test : cases) {
                            byte[] code = test.value().dwarf(addressBytes, order);
                            if (!java.util.Arrays.equals(code, test.value().dwarf(addressBytes, order))) throw new AssertionError("unstable bytecode");
                            vectors.add(new Vector(test.name() + "-" + width, addressBytes, order.toString(),
                                unsigned(input).and(mask(addressBytes)).toString(16), unsigned(second).and(mask(addressBytes)).toString(16),
                                HexFormat.of().formatHex(code), test.expected().apply(a, b).and(mask(test.value().bytes())).toString(16)));
                        }
                        if (width < addressBytes) {
                            var high = CallValue.slice(new Incoming(5, addressBytes), (addressBytes - width) * 8, width);
                            vectors.add(new Vector("high-slice-" + width, addressBytes, order.toString(),
                                unsigned(input).and(mask(addressBytes)).toString(16), "0", HexFormat.of().formatHex(high.dwarf(addressBytes, order)),
                                unsigned(input).and(mask(addressBytes)).shiftRight((addressBytes - width) * 8).toString(16)));
                        }
                    }
                }
            }
        }
        reject(() -> new Literal(0, 0));
        reject(() -> new Incoming(-1, 8));
        reject(() -> CallValue.slice(new Incoming(0, 4), 1, 4));
        reject(() -> CallValue.extend(new Incoming(0, 8), false, 4));
        reject(() -> CallValue.binary(Op.ADD, new Literal(1, 4), new Incoming(0, 8), 4));
        reject(() -> CallValue.select(new Incoming(0, 8), new Literal(1, 4), new Literal(0, 4)));
        reject(() -> new Incoming(0, 8).dwarf(4, ByteOrder.LITTLE_ENDIAN));
        reject(() -> CallValue.binary(Op.SHIFT_LEFT, new Incoming(0, 8), new Incoming(1, 8), 8).dwarf(8, ByteOrder.LITTLE_ENDIAN));
        reject(() -> {
            CallValue value = new Incoming(0, 8);
            for (int index = 0; index < 40; index++) value = new Binary(Op.ADD, value, new Literal(1, 8), 8);
        });
        reject(() -> {
            CallValue value = new Incoming(0, 8);
            for (int index = 0; index < 9; index++) value = new Binary(Op.ADD, value, value, 8);
        });
        Path output = Path.of(args[0]); Files.createDirectories(output.getParent());
        Files.writeString(output, new GsonBuilder().create().toJson(vectors) + "\n");
        System.out.println("call-value-smoke=PASS vectors=" + vectors.size() + " rejected=" + rejected);
    }
}
