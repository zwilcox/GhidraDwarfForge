package ghidradwarfforge.calls;

import java.util.LinkedHashMap;
import java.util.Map;

import ghidradwarfforge.unwind.UnwindFlow.Bank;
import ghidradwarfforge.unwind.UnwindFlow.Cell;

/** Exact byte containment and immutable bounded value snapshots; no new ABI claim. */
final class ArgumentValueStorageSmoke {
    private static int checks;

    private ArgumentValueStorageSmoke() { }

    static void run() {
        long bits = 0xfedcba9876543210L;
        for (Bank bank : Bank.values()) {
            for (int ownerBytes = 1; ownerBytes <= 8; ownerBytes++) {
                var owner = new Cell(bank, 0x100, ownerBytes);
                var input = new LinkedHashMap<Cell, CallValue>();
                input.put(owner, new CallValue.Literal(bits, ownerBytes));
                var state = new GhidraCallArgumentFlow.State(input);
                input.clear();
                require(state.values().size() == 1, "state retained a mutable input map");
                for (Bank queryBank : Bank.values()) {
                    for (int offset = -1; offset <= ownerBytes; offset++) {
                        for (int bytes = 1; bytes <= 8; bytes++) {
                            var actual = GhidraCallArgumentFlow.read(state.values(), new Cell(queryBank, 0x100 + offset, bytes));
                            boolean contained = queryBank == bank && offset >= 0 && offset + bytes <= ownerBytes;
                            if (!contained) {
                                require(actual == null, "value escaped its bank/byte extent");
                            }
                            else {
                                long mask = bytes == 8 ? -1L : (1L << (8 * bytes)) - 1;
                                long expected = (bits >>> (8 * offset)) & mask;
                                require(actual instanceof CallValue.Literal value && value.bytes() == bytes && value.value() == expected,
                                    "register byte order or slice extent changed: " + actual);
                            }
                        }
                    }
                }
                try { state.values().clear(); throw new AssertionError("state map is mutable"); }
                catch (UnsupportedOperationException expected) { checks++; }
            }
        }
        var budget = new LinkedHashMap<Cell, CallValue>();
        for (int index = 0; index < 1024; index++) {
            budget.put(new Cell(Bank.REGISTER, index * 8L, 8), new CallValue.Literal(index, 8));
        }
        GhidraCallArgumentFlow.State exact;
        try { exact = new GhidraCallArgumentFlow.State(budget); }
        catch (IllegalArgumentException failure) {
            throw new AssertionError("exact state budget must be accepted", failure);
        }
        require(exact.values().size() == 1024, "exact state budget was refused");
        budget.put(new Cell(Bank.REGISTER, 8192, 8), new CallValue.Literal(1024, 8));
        try { new GhidraCallArgumentFlow.State(budget); throw new AssertionError("excess state budget accepted"); }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().equals("call-value state budget exceeded"), "wrong state-budget refusal");
        }
        require(exact.values().size() == 1024 && !exact.values().containsKey(new Cell(Bank.REGISTER, 8192, 8)),
            "excess state changed prior snapshot");
        // A claimed physical extent alone cannot widen the expression's known value.
        var carrier = new Cell(Bank.REGISTER, 0x100, 8);
        var narrow = Map.<Cell, CallValue>of(carrier, new CallValue.Literal(0x12, 1));
        require(GhidraCallArgumentFlow.read(narrow, carrier) == null, "narrow expression fabricated whole-register bits");
        require(new CallValue.Literal(0x12, 1).equals(GhidraCallArgumentFlow.read(narrow, new Cell(Bank.REGISTER, 0x100, 1))),
            "known byte was discarded with unsupported wider read");
        // A full-depth expression cannot grow another slice node beyond the
        // budget. No truncated approximation is acceptable.
        CallValue deep = new CallValue.Incoming(0, 8);
        for (int level = 1; level < 32; level++) {
            deep = new CallValue.Binary(CallValue.Op.ADD, deep, new CallValue.Literal(level, 8), 8);
        }
        require(deep.depth() == 32, "expression-depth control is not exact");
        var deepState = Map.of(carrier, deep);
        require(GhidraCallArgumentFlow.read(deepState, new Cell(Bank.REGISTER, 0x100, 4)) == null,
            "oversized derived expression acquired a partial value");
        require(deepState.get(carrier).equals(deep), "refused slice changed its source expression");
        System.out.println("argument-value-storage=PASS checks=" + checks);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
