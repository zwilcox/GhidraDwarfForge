package ghidradwarfforge.calls;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.BiFunction;

import ghidradwarfforge.calls.CallValue.*;

/** Independent numeric expectations; the Python DWARF VM must validate the generated vectors. */
final class CallValueBoundarySmoke {
    private record Case(String name, CallValue value, BiFunction<BigInteger, BigInteger, BigInteger> expected) { }
    private static int rejected;

    private CallValueBoundarySmoke() { }

    static int append(List<CallValueSmoke.Vector> vectors, List<Long> samples) {
        int initial = vectors.size();
        for (int addressBytes : List.of(4, 8)) {
            for (int bytes = 1; bytes <= addressBytes; bytes++) {
                int width = bytes;
                var x = new Incoming(5, width);
                var y = new Incoming(6, width);
                var zero = new Literal(0, width);
                var one = new Literal(1, width);
                var cases = new ArrayList<Case>();
                for (var op : Op.values()) {
                    int resultBytes = comparison(op) ? 1 : width;
                    if (op != Op.SHIFT_LEFT && op != Op.SHIFT_RIGHT) {
                        cases.add(new Case("same-" + op, CallValue.binary(op, x, x, resultBytes), (a, b) -> numeric(op, a, a, width)));
                        cases.add(new Case("left-zero-" + op, CallValue.binary(op, zero, x, resultBytes), (a, b) -> numeric(op, BigInteger.ZERO, a, width)));
                        cases.add(new Case("left-one-" + op, CallValue.binary(op, one, x, resultBytes), (a, b) -> numeric(op, BigInteger.ONE, a, width)));
                    }
                    cases.add(new Case("right-zero-" + op, CallValue.binary(op, x, zero, resultBytes), (a, b) -> numeric(op, a, BigInteger.ZERO, width)));
                    cases.add(new Case("right-one-" + op, CallValue.binary(op, x, one, resultBytes), (a, b) -> numeric(op, a, BigInteger.ONE, width)));
                }
                cases.add(new Case("equal-select-arms", CallValue.select(new Incoming(6, 1), x, x), (a, b) -> a));
                for (int condition : List.of(0, 1, 255)) {
                    cases.add(new Case("literal-select-" + condition, CallValue.select(new Literal(condition, 1), x, y),
                        (a, b) -> condition == 0 ? b : a));
                }
                if (width < addressBytes) {
                    var whole = new Incoming(5, addressBytes);
                    cases.add(new Case("slice-raw-extension", CallValue.slice(new Extend(x, false, addressBytes), 0, width), (a, b) -> a));
                    if (width + 1 < addressBytes) {
                        cases.add(new Case("nested-unaligned-slice", CallValue.slice(new Slice(whole, 1, addressBytes - 1), 2, width),
                            (a, b) -> a.shiftRight(3)));
                    }
                    for (var op : List.of(Op.AND, Op.OR, Op.XOR, Op.ADD)) {
                        var raw = new Binary(op, whole, new Incoming(6, addressBytes), addressBytes);
                        cases.add(new Case("slice-" + op, CallValue.slice(raw, 3, width), (a, b) -> numeric(op, a, b, addressBytes).and(mask(addressBytes)).shiftRight(3)));
                    }
                    // The extracted byte crosses into an extension's added high bytes.
                    var narrow = new Incoming(5, 1);
                    for (boolean signed : List.of(false, true)) {
                        cases.add(new Case("slice-extension-high-" + signed,
                            CallValue.slice(new Extend(narrow, signed, addressBytes), 8, width),
                            (a, b) -> signed && a.testBit(7) ? mask(width) : BigInteger.ZERO));
                    }
                }
                for (int index = 0; index < samples.size(); index++) {
                    long first = samples.get(index), second = samples.get((index + 1) % samples.size());
                    for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        for (var test : cases) {
                            // Slice cases deliberately consume the full entry registers.
                            int inputWidth = test.name().startsWith("slice-") || test.name().startsWith("nested-") ? addressBytes : width;
                            BigInteger a = unsigned(first).and(mask(inputWidth)), b = unsigned(second).and(mask(inputWidth));
                            add(vectors, test.name(), test.value(), addressBytes, order, first, second, test.expected().apply(a, b));
                        }
                    }
                }
                constants(vectors, addressBytes, width);
            }
            limits(vectors, addressBytes);
        }
        invalid();
        System.out.println("call-value-boundaries=GENERATED vectors=" + (vectors.size() - initial) + " rejected=" + rejected);
        return rejected;
    }

    private static void constants(List<CallValueSmoke.Vector> vectors, int addressBytes, int width) {
        List<BigInteger> values = List.of(BigInteger.ZERO, BigInteger.ONE, mask(width),
            BigInteger.ONE.shiftLeft(width * 8 - 1), BigInteger.ONE.shiftLeft(width * 8 - 1).subtract(BigInteger.ONE),
            new BigInteger("a55a0123fedcba98", 16).and(mask(width)));
        for (var op : Op.values()) {
            boolean shift = op == Op.SHIFT_LEFT || op == Op.SHIFT_RIGHT;
            var operands = shift ? List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(width * 8L - 1),
                BigInteger.valueOf(width * 8L), BigInteger.valueOf(width * 8L + 1), mask(addressBytes)) : values;
            for (var a : values) {
                for (var b : operands) {
                    var left = new Literal(a.longValue(), width);
                    var right = new Literal(b.longValue(), shift ? addressBytes : width);
                    int resultBytes = comparison(op) ? 1 : width;
                    var folded = CallValue.binary(op, left, right, resultBytes);
                    var raw = new Binary(op, left, right, resultBytes);
                    BigInteger expected = numeric(op, a, b, width);
                    for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                        add(vectors, "constant-folded-" + op, folded, addressBytes, order, 0, 0, expected);
                        add(vectors, "constant-raw-" + op, raw, addressBytes, order, 0, 0, expected);
                    }
                }
            }
        }
        for (var a : values) {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (boolean signed : List.of(false, true)) {
                    var literal = new Literal(a.longValue(), width);
                    var expected = signed && a.testBit(width * 8 - 1) ? a.subtract(BigInteger.ONE.shiftLeft(width * 8)) : a;
                    add(vectors, "constant-extension-" + signed, CallValue.extend(literal, signed, addressBytes), addressBytes, order, 0, 0, expected);
                    add(vectors, "raw-constant-extension-" + signed, new Extend(literal, signed, addressBytes), addressBytes, order, 0, 0, expected);
                }
                if (width > 1) {
                    add(vectors, "constant-slice", CallValue.slice(new Literal(a.longValue(), width), 3, width - 1),
                        addressBytes, order, 0, 0, a.shiftRight(3));
                }
            }
        }
    }

    private static void limits(List<CallValueSmoke.Vector> vectors, int addressBytes) {
        CallValue depth = new Incoming(5, addressBytes);
        for (int i = 1; i < 32; i++) depth = new Slice(depth, 0, addressBytes);
        if (depth.depth() != 32 || depth.nodes() != 32) throw new AssertionError("incorrect exact-depth fixture");
        CallValue maxDepth = depth;
        reject(() -> new Slice(maxDepth, 0, addressBytes));
        reject(() -> CallValue.slice(maxDepth, 0, addressBytes));
        reject(() -> new Extend(maxDepth, false, addressBytes));
        reject(() -> new Binary(Op.ADD, maxDepth, new Literal(0, addressBytes), addressBytes));
        reject(() -> new Select(new Literal(0, 1), maxDepth, new Incoming(6, addressBytes)));
        CallValue tree = new Incoming(5, addressBytes);
        for (int i = 0; i < 7; i++) tree = new Binary(Op.ADD, tree, tree, addressBytes);
        if (tree.nodes() != 255 || tree.depth() != 8) throw new AssertionError("incorrect 255-node fixture");
        CallValue maxNodes = new Extend(tree, false, addressBytes);
        if (maxNodes.nodes() != 256) throw new AssertionError("incorrect exact-node fixture");
        CallValue fullTree = tree;
        reject(() -> new Slice(maxNodes, 0, addressBytes));
        reject(() -> new Binary(Op.ADD, fullTree, new Literal(1, addressBytes), addressBytes));
        reject(() -> new Select(new Literal(1, 1), fullTree, new Literal(0, addressBytes)));
        for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            add(vectors, "exact-depth-32", depth, addressBytes, order, -1L, 0, mask(addressBytes));
            add(vectors, "exact-nodes-256", maxNodes, addressBytes, order, -1L, 0, mask(addressBytes).multiply(BigInteger.valueOf(128)));
        }
    }

    private static void invalid() {
        for (int width : List.of(-1, 0, 9)) reject(() -> new Literal(1, width));
        reject(() -> CallValue.slice(new Incoming(5, 4), -1, 1));
        reject(() -> CallValue.binary(Op.ADD, new Incoming(5, 4), new Literal(0, 4), 1));
        reject(() -> CallValue.binary(Op.EQUAL, new Incoming(5, 4), new Incoming(5, 4), 4));
        reject(() -> CallValue.binary(Op.NOT_EQUAL, new Literal(0, 4), new Literal(0, 4), 2));
        reject(() -> CallValue.binary(Op.MULTIPLY, new Literal(0, 4), new Incoming(5, 8), 4));
        reject(() -> CallValue.select(new Literal(0, 1), new Incoming(5, 4), new Incoming(6, 8)));
        for (int addressBytes : List.of(0, 1, 2, 16)) reject(() -> new Literal(1, 1).dwarf(addressBytes, ByteOrder.LITTLE_ENDIAN));
    }

    private static BigInteger numeric(Op op, BigInteger a, BigInteger b, int width) {
        return switch (op) {
            case ADD -> a.add(b);
            case SUBTRACT -> a.subtract(b);
            case MULTIPLY -> a.multiply(b);
            case AND -> a.and(b);
            case OR -> a.or(b);
            case XOR -> a.xor(b);
            case EQUAL -> a.equals(b) ? BigInteger.ONE : BigInteger.ZERO;
            case NOT_EQUAL -> a.equals(b) ? BigInteger.ZERO : BigInteger.ONE;
            case SHIFT_LEFT -> b.compareTo(BigInteger.valueOf(width * 8L)) >= 0 ? BigInteger.ZERO : a.shiftLeft(b.intValueExact());
            case SHIFT_RIGHT -> b.compareTo(BigInteger.valueOf(width * 8L)) >= 0 ? BigInteger.ZERO : a.shiftRight(b.intValueExact());
        };
    }

    private static void add(List<CallValueSmoke.Vector> vectors, String name, CallValue value, int addressBytes,
            ByteOrder order, long first, long second, BigInteger expected) {
        byte[] code = value.dwarf(addressBytes, order);
        if (!Arrays.equals(code, value.dwarf(addressBytes, order))) throw new AssertionError("nondeterministic boundary expression");
        vectors.add(new CallValueSmoke.Vector(name + "-" + value.bytes(), addressBytes, order.toString(),
            unsigned(first).and(mask(addressBytes)).toString(16), unsigned(second).and(mask(addressBytes)).toString(16),
            HexFormat.of().formatHex(code), expected.and(mask(value.bytes())).toString(16)));
    }

    private static boolean comparison(Op op) { return op == Op.EQUAL || op == Op.NOT_EQUAL; }
    private static BigInteger unsigned(long value) { return new BigInteger(Long.toUnsignedString(value)); }
    private static BigInteger mask(int bytes) { return BigInteger.ONE.shiftLeft(bytes * 8).subtract(BigInteger.ONE); }
    private static void reject(Runnable operation) {
        try { operation.run(); throw new AssertionError("invalid boundary expression admitted"); }
        catch (IllegalArgumentException expected) { rejected++; }
    }
}
