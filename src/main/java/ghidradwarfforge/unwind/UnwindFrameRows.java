package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.unwind.CallFramePlan.*;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Projection of final identity evidence only; no ABI defaults or instruction inference. */
public final class UnwindFrameRows {
    public record Policy(Map<Integer, Cell> registers, int stack, int returnColumn, int counter,
            long entryCfaOffset, long returnedStackOffset) {
        public Policy {
            registers = Collections.unmodifiableMap(new TreeMap<>(registers));
            if (registers.isEmpty() || registers.size() > CallFramePlan.MAX_REGISTERS ||
                    !registers.keySet().containsAll(List.of(stack, returnColumn, counter)) ||
                    stack == returnColumn || stack == counter) throw new IllegalArgumentException("incomplete frame projection policy");
            var physical = new ArrayList<Cell>();
            for (var item : registers.entrySet()) {
                if (item.getKey() < 0 || item.getKey() > CallFramePlan.MAX_REGISTER || item.getValue().bank() != Bank.REGISTER ||
                        item.getValue().bytes() != registers.get(stack).bytes() || physical.stream().anyMatch(prior ->
                            prior.offset() <= item.getValue().offset() + item.getValue().bytes() - 1 &&
                            item.getValue().offset() <= prior.offset() + prior.bytes() - 1)) {
                    throw new IllegalArgumentException("invalid or overlapping projection registers");
                }
                physical.add(item.getValue());
            }
        }
    }
    public record Projected(Cfa cfa, Map<Integer, Rule> rules, Map<Integer, String> unavailable, String omission) {
        public Projected {
            rules = Collections.unmodifiableMap(new TreeMap<>(rules));
            unavailable = Collections.unmodifiableMap(new TreeMap<>(unavailable));
            Objects.requireNonNull(omission);
        }
        public boolean covered() { return omission.isEmpty(); }
    }
    private UnwindFrameRows() { }

    /**
     * Debuggers commonly bias a suspended caller's return address into its call
     * instruction. The selected row must also work at a live pre-call stop, so
     * require the same recovery locations on both sides of the verified call.
     */
    public static Projected projectCall(State before, State after, Policy policy, BooleanSupplier cancelled) {
        check(cancelled);
        if (before == null || after == null) return omitted("call boundary has no complete reachable state");
        var values = new LinkedHashMap<Cell, Value>();
        for (var item : before.values().entrySet()) {
            check(cancelled);
            if (item.getValue().equals(after.values().get(item.getKey()))) values.put(item.getKey(), item.getValue());
        }
        var memory = new LinkedHashMap<Slot, Value>();
        for (var item : before.memory().entrySet()) {
            check(cancelled);
            if (item.getValue().equals(after.memory().get(item.getKey()))) memory.put(item.getKey(), item.getValue());
        }
        return project(new State(values, memory), policy, cancelled);
    }

    public static Projected project(State state, Policy policy, BooleanSupplier cancelled) {
        check(cancelled);
        if (state == null) return omitted("instruction is unreachable from the selected entry");
        var candidates = new ArrayList<>(policy.registers().keySet());
        candidates.remove(Integer.valueOf(policy.stack()));
        candidates.addFirst(policy.stack());
        Cfa cfa = null;
        for (int number : candidates) {
            check(cancelled);
            if (state.values().get(policy.registers().get(number)) instanceof StackAddress anchor) {
                try { cfa = new Cfa(number, Math.subtractExact(policy.entryCfaOffset(), anchor.offset())); break; }
                catch (ArithmeticException overflow) { /* Try another proven anchor. */ }
            }
        }
        if (cfa == null) return omitted("no proved current-register relation to entry CFA");
        int width = policy.registers().get(policy.stack()).bytes();
        var rules = new LinkedHashMap<Integer, Rule>();
        var unavailable = new LinkedHashMap<Integer, String>();
        for (int number : policy.registers().keySet()) {
            check(cancelled);
            Rule rule;
            if (number == policy.stack()) {
                try { rule = new CfaValue(Math.subtractExact(policy.returnedStackOffset(), policy.entryCfaOffset())); }
                catch (ArithmeticException overflow) { return omitted("caller stack/CFA relation overflows"); }
            }
            else {
                Value identity = number == policy.returnColumn() || number == policy.counter() ?
                    new ReturnAddress(width) : new Incoming(number, width);
                rule = locate(identity, number, state, policy, cancelled);
                if (rule == null) {
                    if (number == policy.returnColumn() || number == policy.counter()) {
                        return omitted("caller return address has no proved current location");
                    }
                    rule = new Undefined();
                    unavailable.put(number, "incoming register identity has no proved current location");
                }
            }
            rules.put(number, rule);
        }
        check(cancelled);
        return new Projected(cfa, rules, unavailable, "");
    }

    private static Rule locate(Value identity, int number, State state, Policy policy, BooleanSupplier cancelled) {
        if (identity.equals(state.values().get(policy.registers().get(number)))) return new SameValue();
        for (var register : policy.registers().entrySet()) {
            check(cancelled);
            if (identity.equals(state.values().get(register.getValue()))) return new InRegister(register.getKey());
        }
        var slots = new ArrayList<>(state.memory().entrySet());
        slots.sort(Comparator.comparingLong(item -> item.getKey().offset()));
        for (var slot : slots) {
            check(cancelled);
            if (identity.equals(slot.getValue())) {
                try { return new AtCfaOffset(Math.subtractExact(slot.getKey().offset(), policy.entryCfaOffset())); }
                catch (ArithmeticException overflow) { /* Another duplicate save may be representable. */ }
            }
        }
        return null;
    }
    private static Projected omitted(String reason) { return new Projected(null, Map.of(), Map.of(), reason); }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("frame projection cancelled");
    }
}
