package ghidradwarfforge.unwind;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Must-analysis over explicitly supplied instruction effects, not an instruction
 * decoder or ABI recognizer. Unknown facts are absent; an unvisited node has no
 * State at all. Only final fixed-point states may be used for recovery rules.
 */
public final class UnwindFlow {
    private static final int MAX_NODES = 65_536;
    private static final int MAX_OPERATIONS = 4096;
    private static final int MAX_FACTS = 1024;
    private static final int MAX_TRANSFERS = 1_000_000;

    private UnwindFlow() { }

    public enum Bank { REGISTER, TEMPORARY }

    /** Physical byte coordinates, supplied by the decoder, not DWARF numbers. */
    public record Cell(Bank bank, long offset, int bytes) implements Operand {
        public Cell {
            Objects.requireNonNull(bank);
            extent(offset, bytes);
        }
    }
    public sealed interface Operand permits Cell, Constant { }
    public sealed interface Value permits Incoming, ReturnAddress, StackAddress, Constant {
        int bytes();
    }
    public record Incoming(int register, int bytes) implements Value {
        public Incoming { if (register < 0) throw new IllegalArgumentException("negative register"); width(bytes); }
    }
    public record ReturnAddress(int bytes) implements Value {
        public ReturnAddress { width(bytes); }
    }
    public record StackAddress(long offset, int bytes) implements Value {
        public StackAddress {
            width(bytes);
            if (bytes < 8 && (offset < -(1L << (bytes * 8 - 1)) || offset >= (1L << (bytes * 8 - 1)))) {
                throw new IllegalArgumentException("stack relation exceeds target signed offset width");
            }
        }
    }
    public record Constant(long value, int bytes) implements Value, Operand {
        public Constant {
            width(bytes);
            if (bytes < 8) value &= (1L << (bytes * 8)) - 1;
        }
        long signed() { return bytes == 8 ? value : (value << (64 - bytes * 8)) >> (64 - bytes * 8); }
    }
    public record Slot(long offset, int bytes) {
        public Slot { extent(offset, bytes); }
    }

    public sealed interface Effect permits Copy, Add, Load, Store, Kill, Opaque, Call { }
    public record Copy(Cell output, Operand input) implements Effect {
        public Copy { Objects.requireNonNull(output); Objects.requireNonNull(input); }
    }
    /** Subtraction is explicit; arithmetic must have the destination width. */
    public record Add(Cell output, Operand left, Operand right, boolean subtract) implements Effect {
        public Add { Objects.requireNonNull(output); Objects.requireNonNull(left); Objects.requireNonNull(right); }
    }
    public record Load(Cell output, Operand address) implements Effect {
        public Load { Objects.requireNonNull(output); Objects.requireNonNull(address); }
    }
    public record Store(Operand address, Operand input, int bytes) implements Effect {
        public Store { Objects.requireNonNull(address); Objects.requireNonNull(input); width(bytes); }
    }
    public record Kill(Cell output) implements Effect {
        public Kill { Objects.requireNonNull(output); }
    }
    /** An unmodeled instruction may affect registers and arbitrary memory. */
    public record Opaque(String reason) implements Effect {
        public Opaque { if (reason == null || reason.isBlank()) throw new IllegalArgumentException("missing reason"); }
    }
    /**
     * A separately proved call summary. A null write bound means arbitrary memory
     * writes. Otherwise all writes are strictly below the pre-call stack pointer plus the
     * bound, except writes to explicitly separated absolute regions when a condition
     * is attached. Neither bounds, separation nor preserved cells are inferred from an ABI name.
     * stackAdjustment describes post-return stack pointer relative to the state at this
     * effect (which may already include the instruction's return-address push).
     */
    public record Call(Set<Cell> preserved, long stackAdjustment, Long writeBound, String evidence,
            UnwindStackSeparation separation) implements Effect {
        public Call(Set<Cell> preserved, long stackAdjustment, Long writeBound, String evidence) {
            this(preserved, stackAdjustment, writeBound, evidence, UnwindStackSeparation.NONE);
        }
        public Call {
            Objects.requireNonNull(separation);
            preserved = Set.copyOf(preserved);
            if (preserved.stream().anyMatch(cell -> cell.bank() != Bank.REGISTER) ||
                    evidence == null || evidence.isBlank()) throw new IllegalArgumentException("invalid call proof");
        }
    }
    public record Node<K>(List<Effect> effects, List<K> successors) {
        public Node {
            effects = List.copyOf(effects);
            successors = List.copyOf(successors);
            if (effects.size() > MAX_OPERATIONS || successors.size() > 2 ||
                    new LinkedHashSet<>(successors).size() != successors.size()) {
                throw new IllegalArgumentException("instruction effects or edges exceed bounds");
            }
        }
    }
    public record State(Map<Cell, Value> values, Map<Slot, Value> memory) {
        public State {
            if (values.size() + memory.size() > MAX_FACTS) throw new IllegalArgumentException("unwind fact budget exceeded");
            var cells = new LinkedHashMap<Cell, Value>();
            for (var entry : values.entrySet()) {
                Cell cell = Objects.requireNonNull(entry.getKey());
                Value value = Objects.requireNonNull(entry.getValue());
                if (cell.bytes() != value.bytes() || cells.keySet().stream().anyMatch(prior -> overlaps(prior, cell))) {
                    throw new IllegalArgumentException("overlapping or mismatched register facts");
                }
                cells.put(cell, value);
            }
            var slots = new LinkedHashMap<Slot, Value>();
            for (var entry : memory.entrySet()) {
                Slot slot = Objects.requireNonNull(entry.getKey());
                Value value = Objects.requireNonNull(entry.getValue());
                if (slot.bytes() != value.bytes() || slots.keySet().stream().anyMatch(prior ->
                        overlaps(prior.offset(), prior.bytes(), slot.offset(), slot.bytes()))) {
                    throw new IllegalArgumentException("overlapping or mismatched memory facts");
                }
                slots.put(slot, value);
            }
            values = Collections.unmodifiableMap(cells);
            memory = Collections.unmodifiableMap(slots);
        }
    }
    public record Result<K>(Map<K, State> before, Map<K, State> after, int transfers, UnwindStackSeparation separation) { }

    @FunctionalInterface
    public interface EffectObserver<K> {
        /** Called only during replay of converged, reachable states; snapshots include instruction temporaries. */
        void observe(K instruction, int index, Effect effect, State before);
    }
    @FunctionalInterface
    private interface StepObserver {
        void observe(int index, Effect effect, State before);
    }

    public static <K> Result<K> analyze(Map<K, Node<K>> graph, K entry, State seed,
            Cell stackPointer, BooleanSupplier cancelled) {
        return analyzeInternal(graph, entry, seed, stackPointer, cancelled, null, UnwindStackSeparation.NONE);
    }

    /** A verifier may reject a final effect; no result is returned after rejection or cancellation. */
    public static <K> Result<K> analyze(Map<K, Node<K>> graph, K entry, State seed,
            Cell stackPointer, BooleanSupplier cancelled, EffectObserver<K> observer) {
        return analyzeInternal(graph, entry, seed, stackPointer, cancelled, Objects.requireNonNull(observer), UnwindStackSeparation.NONE);
    }

    public static <K> Result<K> analyze(Map<K, Node<K>> graph, K entry, State seed,
            Cell stackPointer, BooleanSupplier cancelled, EffectObserver<K> observer,
            UnwindStackSeparation separation) {
        return analyzeInternal(graph, entry, seed, stackPointer, cancelled, observer, separation);
    }

    private static <K> Result<K> analyzeInternal(Map<K, Node<K>> graph, K entry, State seed,
            Cell stackPointer, BooleanSupplier cancelled, EffectObserver<K> observer,
            UnwindStackSeparation separation) {
        Objects.requireNonNull(separation);
        if (separation.conditional() && separation.addressBytes() != stackPointer.bytes()) {
            throw new IllegalArgumentException("stack separation address width differs from analysis");
        }
        Objects.requireNonNull(cancelled);
        check(cancelled);
        Objects.requireNonNull(stackPointer);
        if (stackPointer.bank() != Bank.REGISTER || graph.isEmpty() || graph.size() > MAX_NODES || !graph.containsKey(entry)) {
            throw new IllegalArgumentException("invalid unwind graph or stack pointer");
        }
        var nodes = new LinkedHashMap<K, Node<K>>();
        for (var item : graph.entrySet()) {
            check(cancelled);
            K key = Objects.requireNonNull(item.getKey());
            Node<K> node = Objects.requireNonNull(item.getValue());
            if (!graph.keySet().containsAll(node.successors())) throw new IllegalArgumentException("unresolved instruction edge");
            nodes.put(key, node);
        }
        if (seed.values().keySet().stream().anyMatch(cell -> cell.bank() == Bank.TEMPORARY)) {
            throw new IllegalArgumentException("temporary identity cannot cross an instruction boundary");
        }
        var before = new LinkedHashMap<K, State>();
        var after = new LinkedHashMap<K, State>();
        var queue = new ArrayDeque<K>();
        var queued = new LinkedHashSet<K>();
        before.put(entry, seed);
        queue.add(entry);
        queued.add(entry);
        int transfers = 0;
        while (!queue.isEmpty()) {
            check(cancelled);
            if (++transfers > MAX_TRANSFERS) throw new IllegalArgumentException("unwind fixed-point budget exceeded");
            K key = queue.removeFirst();
            queued.remove(key);
            State out = transfer(before.get(key), nodes.get(key).effects(), stackPointer, cancelled, null, separation);
            if (out.equals(after.put(key, out))) continue;
            for (K target : nodes.get(key).successors()) {
                check(cancelled);
                State old = before.get(target);
                State merged = old == null ? out : intersect(old, out, cancelled);
                if (!merged.equals(old)) {
                    before.put(target, merged);
                    if (queued.add(target)) queue.addLast(target);
                }
            }
        }
        if (observer != null) {
            // Verifiers must never authorize writes from optimistic first-visit states.
            // Replay each reachable instruction once after all joins have converged.
            for (var item : nodes.entrySet()) {
                check(cancelled);
                K key = item.getKey();
                if (!before.containsKey(key)) continue;
                State replayed = transfer(before.get(key), item.getValue().effects(), stackPointer, cancelled,
                    (index, effect, state) -> observer.observe(key, index, effect, state), separation);
                if (!replayed.equals(after.get(key))) throw new IllegalStateException("unwind replay differs from fixed point");
            }
        }
        check(cancelled);
        return new Result<>(Collections.unmodifiableMap(before), Collections.unmodifiableMap(after), transfers, separation);
    }

    private static State intersect(State left, State right, BooleanSupplier cancelled) {
        var values = new LinkedHashMap<Cell, Value>();
        for (var entry : left.values().entrySet()) {
            check(cancelled);
            if (entry.getValue().equals(right.values().get(entry.getKey()))) values.put(entry.getKey(), entry.getValue());
        }
        var memory = new LinkedHashMap<Slot, Value>();
        for (var entry : left.memory().entrySet()) {
            check(cancelled);
            if (entry.getValue().equals(right.memory().get(entry.getKey()))) memory.put(entry.getKey(), entry.getValue());
        }
        return new State(values, memory);
    }

    private static State transfer(State input, List<Effect> effects, Cell stackPointer, BooleanSupplier cancelled,
            StepObserver observer, UnwindStackSeparation separation) {
        var values = new LinkedHashMap<>(input.values());
        var memory = new LinkedHashMap<>(input.memory());
        boolean stackWritten = false;
        for (int index = 0; index < effects.size(); index++) {
            check(cancelled);
            Effect effect = effects.get(index);
            if (observer != null) observer.observe(index, effect, new State(values, memory));
            if (effect instanceof Store store) {
                Value address = read(store.address(), values);
                Value value = read(store.input(), values);
                if (address instanceof StackAddress stack && fits(stack.offset(), store.bytes())) {
                    Slot slot = new Slot(stack.offset(), store.bytes());
                    memory.keySet().removeIf(prior -> overlaps(prior.offset(), prior.bytes(), slot.offset(), slot.bytes()));
                    if (value != null && value.bytes() == store.bytes()) memory.put(slot, value);
                }
                else if (!separation.permits(address, store.bytes())) memory.clear();
            }
            else if (effect instanceof Opaque) {
                values.clear();
                memory.clear();
            }
            else if (effect instanceof Call call) {
                if (!separation.admits(call.separation())) {
                    throw new IllegalArgumentException("call summary requires an unaccepted stack separation condition");
                }
                stackWritten = true;
                if (new Constant(call.stackAdjustment(), stackPointer.bytes()).signed() != call.stackAdjustment()) {
                    throw new IllegalArgumentException("call stack adjustment exceeds target width");
                }
                Value stack = values.get(stackPointer);
                values.keySet().removeIf(cell -> !call.preserved().contains(cell));
                if (stack instanceof StackAddress address && call.writeBound() != null) {
                    try {
                        long bound = Math.addExact(address.offset(), call.writeBound());
                        memory.keySet().removeIf(slot -> slot.offset() < bound);
                    }
                    catch (ArithmeticException overflow) { memory.clear(); }
                }
                else memory.clear();
                Value restored = plus(stack, new Constant(call.stackAdjustment(), stackPointer.bytes()), false, stackPointer.bytes());
                write(stackPointer, restored, values);
            }
            else {
                Cell output;
                Value value;
                switch (effect) {
                    case Copy copy -> { output = copy.output(); value = read(copy.input(), values); }
                    case Add add -> {
                        output = add.output();
                        value = plus(read(add.left(), values), read(add.right(), values), add.subtract(), output.bytes());
                    }
                    case Load load -> {
                        output = load.output();
                        Value address = read(load.address(), values);
                        value = address instanceof StackAddress stack && fits(stack.offset(), output.bytes()) ?
                            memory.get(new Slot(stack.offset(), output.bytes())) : null;
                    }
                    case Kill kill -> { output = kill.output(); value = null; }
                    default -> throw new IllegalStateException("unhandled instruction effect");
                }
                write(output, value, values);
                stackWritten |= overlaps(output, stackPointer);
            }
            if (values.size() + memory.size() > MAX_FACTS) throw new IllegalArgumentException("unwind fact budget exceeded");
        }
        // Ownership changes at the machine-instruction boundary. A decoder may
        // update stack pointer before a post-increment load through a temporary old address.
        // The memory value remains valid for that load within the instruction.
        if (stackWritten) {
            if (input.values().get(stackPointer) instanceof StackAddress old && values.get(stackPointer) instanceof StackAddress next) {
                if (next.offset() > old.offset()) memory.keySet().removeIf(slot -> slot.offset() < next.offset());
            }
            else memory.clear();
        }
        values.keySet().removeIf(cell -> cell.bank() == Bank.TEMPORARY);
        check(cancelled);
        return new State(values, memory);
    }

    private static Value read(Operand operand, Map<Cell, Value> values) {
        return operand instanceof Constant constant ? constant : values.get((Cell) operand);
    }

    private static void write(Cell output, Value value, Map<Cell, Value> values) {
        values.keySet().removeIf(cell -> overlaps(cell, output));
        if (value != null && value.bytes() == output.bytes()) values.put(output, value);
    }

    private static Value plus(Value left, Value right, boolean subtract, int bytes) {
        if (left == null || right == null || left.bytes() != bytes || right.bytes() != bytes) return null;
        if (!subtract && left instanceof Constant && !(right instanceof Constant)) return plus(right, left, false, bytes);
        if (!(right instanceof Constant constant)) return null;
        try {
            long offset = subtract ? Math.negateExact(constant.signed()) : constant.signed();
            if (left instanceof StackAddress stack) return new StackAddress(Math.addExact(stack.offset(), offset), bytes);
            if (left instanceof Constant value) return new Constant(value.value() + offset, bytes);
            return offset == 0 ? left : null;
        }
        catch (ArithmeticException | IllegalArgumentException overflow) { return null; }
    }

    private static boolean overlaps(Cell left, Cell right) {
        return left.bank() == right.bank() && overlaps(left.offset(), left.bytes(), right.offset(), right.bytes());
    }
    private static boolean overlaps(long left, int leftBytes, long right, int rightBytes) {
        return left <= right + rightBytes - 1 && right <= left + leftBytes - 1;
    }
    private static boolean fits(long offset, int bytes) { return offset <= Long.MAX_VALUE - bytes + 1; }
    private static void extent(long offset, int bytes) {
        width(bytes);
        if (!fits(offset, bytes)) throw new IllegalArgumentException("physical extent overflows");
    }
    private static void width(int bytes) {
        if (bytes < 1 || bytes > 8) throw new IllegalArgumentException("unsupported symbolic value width");
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("unwind analysis cancelled");
    }
}
