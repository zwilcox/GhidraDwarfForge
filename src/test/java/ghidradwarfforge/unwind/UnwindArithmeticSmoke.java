package ghidradwarfforge.unwind;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidradwarfforge.unwind.UnwindFlow.*;

/** Independent integer arithmetic oracle for bounded affine caller-state facts. */
public final class UnwindArithmeticSmoke {
    private static int cases;

    private UnwindArithmeticSmoke() { }

    public static void main(String[] args) { check(); }

    static void check() {
        cases = 0;
        for (int bytes = 1; bytes <= 8; bytes++) {
            BigInteger modulus = BigInteger.ONE.shiftLeft(bytes * 8);
            BigInteger min = modulus.shiftRight(1).negate(), max = modulus.shiftRight(1).subtract(BigInteger.ONE);
            long[] numbers = { min.longValueExact(), -1, 0, 1, max.longValueExact() };
            for (long first : numbers) {
                for (long second : numbers) {
                    for (boolean subtract : List.of(false, true)) {
                        BigInteger sum = subtract ? BigInteger.valueOf(first).subtract(BigInteger.valueOf(second)) :
                            BigInteger.valueOf(first).add(BigInteger.valueOf(second));
                        // The abstract machine deliberately drops subtraction
                        // requiring an unrepresentable signed 64-bit negation.
                        boolean omittedNegation = subtract && bytes == 8 && second == Long.MIN_VALUE;
                        Value affine = !omittedNegation && sum.compareTo(min) >= 0 && sum.compareTo(max) <= 0
                            ? new StackAddress(sum.longValueExact(), bytes) : null;
                        Value constant = omittedNegation ? null : new Constant(sum.mod(modulus).longValue(), bytes);
                        verify(bytes, new StackAddress(first, bytes), new Constant(second, bytes), subtract, affine);
                        verify(bytes, new Constant(first, bytes), new Constant(second, bytes), subtract, constant);
                        verify(bytes, new Constant(second, bytes), new StackAddress(first, bytes), subtract,
                            subtract ? null : affine);
                    }
                }
                for (Value identity : List.of(new Incoming(19, bytes), new ReturnAddress(bytes))) {
                    for (boolean subtract : List.of(false, true)) {
                        verify(bytes, identity, new Constant(first, bytes), subtract, first == 0 ? identity : null);
                        verify(bytes, new Constant(first, bytes), identity, subtract,
                            !subtract && first == 0 ? identity : null);
                    }
                }
            }
            for (int other = 1; other <= 8; other++) {
                if (other == bytes) continue;
                for (boolean subtract : List.of(false, true)) {
                    verify(bytes, new StackAddress(0, other), new Constant(0, bytes), subtract, null);
                    verify(bytes, new StackAddress(0, bytes), new Constant(0, other), subtract, null);
                }
            }
            for (boolean subtract : List.of(false, true)) {
                verify(bytes, null, new Constant(0, bytes), subtract, null);
                verify(bytes, new StackAddress(0, bytes), null, subtract, null);
                verify(bytes, new StackAddress(0, bytes), new StackAddress(0, bytes), subtract, null);
                verify(bytes, new Incoming(19, bytes), new ReturnAddress(bytes), subtract, null);
            }
        }
        System.out.println("unwind-arithmetic=PASS cases=" + cases + " widths=1..8 oracle=BigInteger");
    }

    private static void verify(int bytes, Value left, Value right, boolean subtract, Value expected) {
        Cell stack = new Cell(Bank.REGISTER, 0, bytes);
        Cell first = new Cell(Bank.REGISTER, 16, left == null ? bytes : left.bytes());
        Cell second = new Cell(Bank.REGISTER, 32, right == null ? bytes : right.bytes());
        Cell destination = new Cell(Bank.REGISTER, 48, bytes);
        var values = new LinkedHashMap<Cell, Value>();
        values.put(stack, new StackAddress(0, bytes));
        values.put(destination, new Incoming(31, bytes));
        if (left != null) values.put(first, left);
        if (right != null) values.put(second, right);
        var memory = Map.<Slot, Value>of(new Slot(0, bytes), new ReturnAddress(bytes));
        var seed = new State(values, memory);
        var graph = Map.of(0, new Node<Integer>(List.of(new Add(destination, first, second, subtract)), List.of()));
        State actual = UnwindFlow.analyze(graph, 0, seed, stack, () -> false).after().get(0);
        String label = "width=" + bytes + " left=" + left + " right=" + right + " subtract=" + subtract;
        require(Objects.equals(actual.values().get(destination), expected), label + " invented or lost arithmetic fact: " + actual);
        for (var entry : values.entrySet()) {
            if (!entry.getKey().equals(destination)) require(entry.getValue().equals(actual.values().get(entry.getKey())),
                label + " changed unrelated register");
        }
        require(actual.memory().equals(memory) && seed.values().equals(values) && seed.memory().equals(memory),
            label + " changed memory ownership or seed");
        cases++;
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
}
