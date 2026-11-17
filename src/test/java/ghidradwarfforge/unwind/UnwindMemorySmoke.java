package ghidradwarfforge.unwind;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidradwarfforge.unwind.UnwindFlow.*;

/** Byte-by-byte alias oracle; a partial store invalidates the whole saved fact. */
public final class UnwindMemorySmoke {
    private static int cases;

    private UnwindMemorySmoke() { }

    public static void main(String[] args) { check(); }

    static void check() {
        cases = 0;
        for (long base : new long[] { Long.MIN_VALUE + 32, -32, 0, Long.MAX_VALUE - 64 }) {
            for (int offset = -24; offset <= 24; offset++) {
                long address = Math.addExact(base, offset);
                for (int bytes = 1; bytes <= 8; bytes++) {
                    for (int value = 0; value < 3; value++) {
                        Value source = value == 0 ? new Incoming(40, bytes) :
                            value == 1 ? new ReturnAddress(bytes == 8 ? 4 : 8) : null;
                        verify(base, new StackAddress(address, 8), address, source, bytes);
                    }
                }
            }
        }
        for (int bytes = 1; bytes <= 8; bytes++) {
            for (long offset : new long[] { Long.MIN_VALUE, Long.MAX_VALUE - 7, Long.MAX_VALUE }) {
                verify(0, new StackAddress(offset, 8), offset, new Incoming(40, bytes), bytes);
            }
            for (Value address : List.of(new Constant(0, 8), new Incoming(9, 8), new ReturnAddress(8))) {
                verify(0, address, null, new Incoming(40, bytes), bytes);
            }
            verify(0, null, null, new Incoming(40, bytes), bytes);
        }
        System.out.println("unwind-memory=PASS cases=" + cases + " oracle=byte-overlap");
    }

    private static void verify(long base, Value address, Long knownOffset, Value source, int bytes) {
        Cell stack = new Cell(Bank.REGISTER, 0, 8);
        Cell pointer = new Cell(Bank.REGISTER, 16, 8);
        Cell input = new Cell(Bank.REGISTER, 32, source == null ? bytes : source.bytes());
        var values = new LinkedHashMap<Cell, Value>();
        values.put(stack, new StackAddress(base, 8));
        if (address != null) values.put(pointer, address);
        if (source != null) values.put(input, source);
        var memory = new LinkedHashMap<Slot, Value>();
        for (int index = 0; index < 3; index++) {
            memory.put(new Slot(Math.addExact(base, (index - 1) * 16L), 8),
                index == 1 ? new ReturnAddress(8) : new Incoming(12 + index, 8));
        }
        var expected = new LinkedHashMap<>(memory);
        boolean bounded = knownOffset != null && BigInteger.valueOf(knownOffset).add(BigInteger.valueOf(bytes - 1))
            .compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0;
        if (!bounded) expected.clear();
        else {
            // Enumerating individual bytes avoids repeating the production
            // interval inequality and its overflow/boundary assumptions.
            for (Slot slot : memory.keySet()) {
                boolean overlaps = false;
                for (int oldByte = 0; oldByte < slot.bytes(); oldByte++) {
                    for (int newByte = 0; newByte < bytes; newByte++) {
                        if (BigInteger.valueOf(slot.offset()).add(BigInteger.valueOf(oldByte)).equals(
                                BigInteger.valueOf(knownOffset).add(BigInteger.valueOf(newByte)))) overlaps = true;
                    }
                }
                if (overlaps) expected.remove(slot);
            }
            if (source != null && source.bytes() == bytes) expected.put(new Slot(knownOffset, bytes), source);
        }
        var loads = new ArrayList<Effect>();
        var expectedRegisters = new LinkedHashMap<Cell, Value>();
        int index = 0;
        for (var slot : memory.keySet()) {
            Cell loadPointer = new Cell(Bank.REGISTER, 64 + index * 16, 8);
            Cell destination = new Cell(Bank.REGISTER, 128 + index * 16, 8);
            values.put(loadPointer, new StackAddress(slot.offset(), 8));
            values.put(destination, new Incoming(50 + index, 8));
            loads.add(new Load(destination, loadPointer));
            expectedRegisters.put(destination, expected.get(slot));
            index++;
        }
        Cell reloaded = new Cell(Bank.REGISTER, 192, bytes);
        values.put(reloaded, new Incoming(60, bytes));
        loads.add(new Load(reloaded, pointer));
        expectedRegisters.put(reloaded, bounded ? expected.get(new Slot(knownOffset, bytes)) : null);
        State seed = new State(values, memory);
        var graph = Map.of(0, new Node<Integer>(List.of(new Store(pointer, input, bytes)), List.of(1)),
            1, new Node<Integer>(loads, List.of()));
        String label = "base=" + base + " address=" + address + " source=" + source + " bytes=" + bytes;
        UnwindFlow.Result<Integer> result;
        try { result = UnwindFlow.analyze(graph, 0, seed, stack, () -> false); }
        catch (IllegalArgumentException failure) { throw new AssertionError(label + " rejected valid effect graph", failure); }
        require(result.after().get(0).memory().equals(expected), label + " incorrect store ownership");
        State after = result.after().get(1);
        require(after.memory().equals(expected), label + " load changed memory facts");
        for (var item : expectedRegisters.entrySet()) require(Objects.equals(after.values().get(item.getKey()), item.getValue()),
            label + " invented or lost saved identity at " + item.getKey());
        for (var item : values.entrySet()) {
            if (!expectedRegisters.containsKey(item.getKey())) require(item.getValue().equals(after.values().get(item.getKey())),
                label + " changed unrelated input register");
        }
        require(seed.values().equals(values) && seed.memory().equals(memory), label + " changed caller seed");
        cases++;
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
}
