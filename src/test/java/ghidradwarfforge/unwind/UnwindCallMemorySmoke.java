package ghidradwarfforge.unwind;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidradwarfforge.unwind.UnwindFlow.*;

/** Supplied call summaries must not exceed their memory or preservation proof. */
public final class UnwindCallMemorySmoke {
    private static int cases;

    private UnwindCallMemorySmoke() { }

    public static void main(String[] args) { check(); }

    static void check() {
        cases = 0;
        for (int bytes = 1; bytes <= 8; bytes++) {
            BigInteger half = BigInteger.ONE.shiftLeft(bytes * 8 - 1);
            long min = half.negate().longValueExact(), max = half.subtract(BigInteger.ONE).longValueExact();
            for (long offset : new long[] { min, -1, 0, 1, max }) {
                for (long adjustment : new long[] { min, -1, 0, 1, max }) {
                    for (Long bound : Arrays.asList(null, Long.MIN_VALUE, -16L, 0L, 16L, Long.MAX_VALUE)) {
                        for (boolean preserve : List.of(false, true)) verify(bytes, offset, adjustment, bound, preserve);
                    }
                }
            }
            unknownAndAliases(bytes);
            if (bytes < 8) {
                for (long adjustment : new long[] { min - 1, max + 1 }) {
                    Cell sp = new Cell(Bank.REGISTER, 0, bytes);
                    State seed = new State(Map.of(sp, new StackAddress(0, bytes)), Map.of());
                    try {
                        UnwindFlow.analyze(Map.of(0, new Node<Integer>(List.of(new Call(Set.of(), adjustment, 0L,
                            "deliberately oversized summary")), List.of())), 0, seed, sp, () -> false);
                        throw new AssertionError("call accepted adjustment outside target signed width " + bytes);
                    }
                    catch (IllegalArgumentException expected) { cases++; }
                }
            }
        }
        System.out.println("unwind-call-memory=PASS cases=" + cases + " oracle=BigInteger-and-byte-ownership");
    }

    private static void verify(int bytes, long offset, long adjustment, Long bound, boolean preserve) {
        Cell sp = new Cell(Bank.REGISTER, 0, bytes), saved = new Cell(Bank.REGISTER, 16, bytes);
        Cell returned = new Cell(Bank.REGISTER, 32, bytes), clobbered = new Cell(Bank.REGISTER, 48, bytes);
        var values = Map.<Cell, Value>of(sp, new StackAddress(offset, bytes), saved, new Incoming(19, bytes),
            returned, new ReturnAddress(bytes), clobbered, new Incoming(20, bytes));
        var memory = new LinkedHashMap<Slot, Value>();
        for (long address : new long[] { -16, 0, 16 }) memory.put(new Slot(address, bytes),
            address == 0 ? new ReturnAddress(bytes) : new Incoming(address < 0 ? 21 : 22, bytes));
        State seed = new State(values, memory);
        BigInteger next = BigInteger.valueOf(offset).add(BigInteger.valueOf(adjustment));
        BigInteger half = BigInteger.ONE.shiftLeft(bytes * 8 - 1);
        boolean stackKnown = next.compareTo(half.negate()) >= 0 && next.compareTo(half) < 0;
        Value expectedSp = stackKnown ? new StackAddress(next.longValueExact(), bytes) : null;
        BigInteger limit = bound == null ? null : BigInteger.valueOf(offset).add(BigInteger.valueOf(bound));
        boolean bounded = limit != null && limit.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) >= 0 &&
            limit.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0;
        var expectedMemory = new LinkedHashMap<Slot, Value>();
        if (stackKnown && bounded) {
            for (var item : memory.entrySet()) {
                boolean owned = true;
                for (int index = 0; index < item.getKey().bytes(); index++) {
                    BigInteger address = BigInteger.valueOf(item.getKey().offset()).add(BigInteger.valueOf(index));
                    if (address.compareTo(limit) < 0 || (adjustment > 0 && address.compareTo(next) < 0)) owned = false;
                }
                if (owned) expectedMemory.put(item.getKey(), item.getValue());
            }
        }
        var effect = new Call(preserve ? Set.of(saved, returned) : Set.of(), adjustment, bound,
            "test-supplied exact register preservation and stack-write bound");
        var actual = UnwindFlow.analyze(Map.of(0, new Node<Integer>(List.of(effect), List.of())),
            0, seed, sp, () -> false).after().get(0);
        String label = "width=" + bytes + " offset=" + offset + " adjustment=" + adjustment + " bound=" + bound + " preserve=" + preserve;
        var expectedValues = new LinkedHashMap<Cell, Value>();
        if (preserve) { expectedValues.put(saved, values.get(saved)); expectedValues.put(returned, values.get(returned)); }
        if (expectedSp != null) expectedValues.put(sp, expectedSp);
        require(actual.values().equals(expectedValues), label + " incorrect preserved registers/stack relation: " + actual);
        require(actual.memory().equals(expectedMemory), label + " retained clobbered or released memory: " + actual);
        require(seed.values().equals(values) && seed.memory().equals(memory), label + " modified seed");
        cases++;
    }

    private static void unknownAndAliases(int bytes) {
        Cell sp = new Cell(Bank.REGISTER, 0, bytes), saved = new Cell(Bank.REGISTER, 16, bytes);
        Cell alias = new Cell(Bank.REGISTER, bytes == 1 ? 17 : 16, bytes == 1 ? 1 : bytes - 1);
        for (Value stack : Arrays.asList(null, new Constant(0, bytes), new Incoming(40, bytes), new ReturnAddress(bytes))) {
            var values = new LinkedHashMap<Cell, Value>();
            if (stack != null) values.put(sp, stack);
            values.put(saved, new Incoming(19, bytes));
            State seed = new State(values, Map.of(new Slot(0, bytes), new ReturnAddress(bytes)));
            var effect = new Call(Set.of(alias), 0, 0L, "partial physical alias is not full preservation");
            State actual = UnwindFlow.analyze(Map.of(0, new Node<Integer>(List.of(effect), List.of())),
                0, seed, sp, () -> false).after().get(0);
            require(Objects.equals(actual.values().get(sp), stack), "zero adjustment changed non-affine pointer value");
            require(!actual.values().containsKey(saved) && actual.memory().isEmpty(),
                "non-affine stack or partial preservation retained caller state");
            require(seed.values().equals(values) && seed.memory().size() == 1, "unknown-anchor proof changed seed");
            cases++;
        }
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
}
