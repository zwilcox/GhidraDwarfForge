package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.unwind.UnwindFlow.*;

/**
 * Simultaneous verification of a closed group of ordinary, stack-writing callees.
 * Contracts are hypotheses until every body's effects and returns are checked.
 * Decoded target identity and ABI selection remain the native caller's obligation.
 */
public final class UnwindCalls {
    private static final int MAX_FUNCTIONS = 1024;
    private static final int MAX_NODES = 65_536;

    private UnwindCalls() { }

    public record Site<K>(K instruction, int effect) {
        public Site {
            Objects.requireNonNull(instruction);
            if (effect < 0) throw new IllegalArgumentException("negative call effect index");
        }
    }
    public record Body<K>(K entry, Map<K, Node<K>> graph, Map<Site<K>, K> calls, Set<K> returns) {
        public Body {
            Objects.requireNonNull(entry);
            graph = Collections.unmodifiableMap(new LinkedHashMap<>(graph));
            calls = Collections.unmodifiableMap(new LinkedHashMap<>(calls));
            returns = Set.copyOf(returns);
            if (!graph.containsKey(entry) || returns.isEmpty() || !graph.keySet().containsAll(returns)) {
                throw new IllegalArgumentException("incomplete callee entry/return graph");
            }
        }
    }
    public record Contract(State entry, Cell stackPointer, Cell returnTarget,
            Map<Cell, Incoming> preserved, long returnAdjustment) {
        public Contract {
            Objects.requireNonNull(entry);
            Objects.requireNonNull(stackPointer);
            Objects.requireNonNull(returnTarget);
            preserved = Collections.unmodifiableMap(new LinkedHashMap<>(preserved));
            if (stackPointer.bank() != Bank.REGISTER || returnTarget.bank() != Bank.REGISTER ||
                    stackPointer.equals(returnTarget) || stackPointer.bytes() != returnTarget.bytes() ||
                    !new StackAddress(0, stackPointer.bytes()).equals(entry.values().get(stackPointer))) {
                throw new IllegalArgumentException("invalid callee entry stack/return target");
            }
            new StackAddress(returnAdjustment, stackPointer.bytes());
            for (var item : preserved.entrySet()) {
                if (item.getKey().bank() != Bank.REGISTER || item.getKey().equals(stackPointer) ||
                        item.getKey().equals(returnTarget) || !item.getValue().equals(entry.values().get(item.getKey()))) {
                    throw new IllegalArgumentException("callee preservation hypothesis differs from its entry identity");
                }
            }
        }
        private Call hypothesis() {
            return new Call(preserved.keySet(), returnAdjustment, 0L, "closed-group hypothesis; not yet verified");
        }
    }
    public static final class Verified<K> {
        private final Contract contract;
        private final Map<K, Body<K>> bodies;
        private final Map<K, Result<K>> flows;

        private Verified(Contract contract, Map<K, Body<K>> bodies, Map<K, Result<K>> flows) {
            this.contract = contract;
            this.bodies = Collections.unmodifiableMap(new LinkedHashMap<>(bodies));
            this.flows = Collections.unmodifiableMap(new LinkedHashMap<>(flows));
        }
        public Map<K, Body<K>> bodies() { return bodies; }
        public Map<K, Result<K>> flows() { return flows; }
        public Call summary(K callee) {
            if (!bodies.containsKey(callee)) throw new IllegalArgumentException("callee is outside the verified group");
            return new Call(contract.preserved().keySet(), contract.returnAdjustment(), 0L,
                "verified closed stack-writing group: " + callee);
        }
    }

    /**
     * All stores must end at or below the function's entry stack address. Calls
     * must enter at or below that address and target another member of the group.
     * This supports finite recursive executions by induction on call depth; it
     * does not prove termination or authorize unknown/image-relative writes.
     */
    public static <K> Verified<K> verify(Map<K, Body<K>> input, Contract contract, BooleanSupplier cancelled) {
        Objects.requireNonNull(contract);
        Objects.requireNonNull(cancelled);
        check(cancelled);
        if (input.isEmpty() || input.size() > MAX_FUNCTIONS) throw new IllegalArgumentException("callee group budget exceeded");
        var group = new LinkedHashMap<>(input);
        var bodies = new LinkedHashMap<K, Body<K>>();
        var owned = new LinkedHashSet<K>();
        // Replace every supplied call summary with our own hypothesis. A caller
        // cannot smuggle a stronger preserved set, write bound or stack effect.
        for (var item : group.entrySet()) {
            check(cancelled);
            K key = Objects.requireNonNull(item.getKey());
            Body<K> body = Objects.requireNonNull(item.getValue());
            if (!key.equals(body.entry())) throw new IllegalArgumentException("callee key differs from entry");
            var graph = new LinkedHashMap<K, Node<K>>();
            var bound = new LinkedHashSet<Site<K>>();
            for (var instruction : body.graph().entrySet()) {
                check(cancelled);
                if (!owned.add(instruction.getKey()) || owned.size() > MAX_NODES) {
                    throw new IllegalArgumentException("overlapping or unbounded callee instruction group");
                }
                Node<K> node = instruction.getValue();
                if (body.returns().contains(instruction.getKey()) != node.successors().isEmpty()) {
                    throw new IllegalArgumentException("callee terminal is not a declared return");
                }
                var effects = new ArrayList<Effect>();
                for (int index = 0; index < node.effects().size(); index++) {
                    check(cancelled);
                    Effect effect = node.effects().get(index);
                    if (effect instanceof Call) {
                        var site = new Site<>(instruction.getKey(), index);
                        K target = body.calls().get(site);
                        if (target == null || !group.containsKey(target)) {
                            throw new IllegalArgumentException("call target is not in the closed group");
                        }
                        bound.add(site);
                        effect = contract.hypothesis();
                    }
                    effects.add(effect);
                }
                graph.put(instruction.getKey(), new Node<>(effects, node.successors()));
            }
            if (!bound.equals(body.calls().keySet())) throw new IllegalArgumentException("call binding has no matching decoded effect");
            bodies.put(key, new Body<>(body.entry(), graph, body.calls(), body.returns()));
        }
        var flows = new LinkedHashMap<K, Result<K>>();
        for (var item : bodies.entrySet()) {
            check(cancelled);
            Body<K> body = item.getValue();
            Result<K> flow = UnwindFlow.analyze(body.graph(), body.entry(), contract.entry(), contract.stackPointer(), cancelled,
                (instruction, index, effect, before) -> verifyEffect(effect, before, contract));
            int returns = 0;
            for (K terminal : body.returns()) {
                check(cancelled);
                State after = flow.after().get(terminal);
                if (after == null) continue;
                returns++;
                if (!new ReturnAddress(contract.returnTarget().bytes()).equals(after.values().get(contract.returnTarget())) ||
                        !new StackAddress(contract.returnAdjustment(), contract.stackPointer().bytes())
                            .equals(after.values().get(contract.stackPointer()))) {
                    throw new IllegalArgumentException("callee return target or stack restoration is unproved at " + terminal);
                }
                for (var preserved : contract.preserved().entrySet()) {
                    check(cancelled);
                    if (!preserved.getValue().equals(after.values().get(preserved.getKey()))) {
                        throw new IllegalArgumentException("callee register restoration is unproved at " + terminal);
                    }
                }
            }
            if (returns == 0) throw new IllegalArgumentException("callee has no reachable ordinary return");
            flows.put(item.getKey(), flow);
        }
        check(cancelled);
        return new Verified<>(contract, bodies, flows);
    }

    private static void verifyEffect(Effect effect, State before, Contract contract) {
        if (effect instanceof Opaque) throw new IllegalArgumentException("callee contains opaque reachable effects");
        if (effect instanceof Store store) {
            Value address = store.address() instanceof Constant constant ? constant : before.values().get((Cell) store.address());
            if (!(address instanceof StackAddress stack) || stack.offset() > -store.bytes()) {
                throw new IllegalArgumentException("callee store is not proved below entry stack");
            }
        }
        if (effect instanceof Call) {
            if (!(before.values().get(contract.stackPointer()) instanceof StackAddress stack) || stack.offset() > 0) {
                throw new IllegalArgumentException("nested callee entry exceeds caller's proved write boundary");
            }
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("callee verification cancelled");
    }
}
