package ghidradwarfforge.unwind;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.unwind.UnwindCalls.*;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Conditions must remain explicit across stores, joins, recursion and call summaries. */
public final class UnwindStackSeparationSmoke {
    private static final Cell STACK = new Cell(Bank.REGISTER, 0, 8);
    private static final Cell SAVED = new Cell(Bank.REGISTER, 8, 8);
    private static final Cell TARGET = new Cell(Bank.REGISTER, 16, 8);
    private static final Cell ADDRESS = new Cell(Bank.REGISTER, 24, 8);
    private static final Incoming ID = new Incoming(1, 8);
    private static final State ENTRY = new State(Map.of(STACK, new StackAddress(0, 8), SAVED, ID),
        Map.of(new Slot(0, 8), new ReturnAddress(8)));
    private static final UnwindStackSeparation CONDITION = new UnwindStackSeparation(8,
        List.of(new UnwindStackSeparation.Region(0x600000, 0x600007)), "explicit test condition; not inferred");
    private static int checks;

    private static void require(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
        checks++;
    }
    private static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("invalid or unconditional proof accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static Node<Integer> node(List<Effect> effects, Integer... successors) {
        return new Node<>(effects, List.of(successors));
    }
    private static Contract contract(UnwindStackSeparation separation) {
        return new Contract(ENTRY, STACK, TARGET, Map.of(SAVED, ID), 8, separation);
    }
    private static Body<Integer> leaf(Operand address, int bytes) {
        return new Body<>(0, Map.of(0, node(List.of(new Store(address, SAVED, bytes),
            new Load(TARGET, STACK), new Add(STACK, STACK, new Constant(8, 8), false)))), Map.of(), Set.of(0));
    }
    public static void main(String[] args) {
        var body = leaf(new Constant(0x600000, 8), 8);
        reject(() -> UnwindCalls.verify(Map.of(0, body), contract(UnwindStackSeparation.NONE), () -> false));
        var proof = UnwindCalls.verify(Map.of(0, body), contract(CONDITION), () -> false);
        require(proof.separation().equals(CONDITION), "verified group lost its condition");
        require(proof.flows().get(0).separation().equals(CONDITION), "flow lost its condition");
        require(proof.summary(0).separation().equals(CONDITION), "summary lost its condition");
        require(proof.flows().get(0).after().get(0).values().get(TARGET).equals(new ReturnAddress(8)),
            "separated write lost return identity");
        var call = Map.of(0, node(List.of(proof.summary(0))));
        reject(() -> UnwindFlow.analyze(call, 0, ENTRY, STACK, () -> false));
        require(UnwindFlow.analyze(call, 0, ENTRY, STACK, () -> false, null, CONDITION).separation().equals(CONDITION),
            "explicit caller condition not retained");
        var different = new UnwindStackSeparation(8, CONDITION.regions(), "different external evidence");
        reject(() -> UnwindFlow.analyze(call, 0, ENTRY, STACK, () -> false, null, different));
        var unconditional = Map.of(0, node(List.of(new Call(Set.of(SAVED), 0, 0L, "unconditional fixture"))));
        require(UnwindFlow.analyze(unconditional, 0, ENTRY, STACK, () -> false, null, CONDITION)
            .after().get(0).memory().equals(ENTRY.memory()), "unconditional call unusable under stronger condition");
        for (Operand address : List.of(new Constant(0x5fffff, 8), new Constant(0x600001, 8),
                new Constant(0x600000, 4), ADDRESS)) {
            reject(() -> UnwindCalls.verify(Map.of(0, leaf(address, 8)), contract(CONDITION), () -> false));
        }
        require(CONDITION.permits(new Constant(0x600007, 8), 1), "last byte rejected");
        require(!CONDITION.permits(new Constant(0x600007, 8), 2), "partially covered write accepted");
        require(!CONDITION.permits(new Constant(-1, 8), 2), "wrapping write accepted");
        var high = new UnwindStackSeparation(8,
            List.of(new UnwindStackSeparation.Region(Long.MIN_VALUE, -1)), "high address condition");
        require(high.permits(new Constant(-8, 8), 8) && !high.permits(new Constant(-7, 8), 8), "unsigned range boundary");
        var narrow = new UnwindStackSeparation(4,
            List.of(new UnwindStackSeparation.Region(0xfffffff8L, 0xffffffffL)), "narrow condition");
        require(narrow.permits(new Constant(0xfffffff8L, 4), 8) && !narrow.permits(new Constant(0xffffffffL, 4), 2),
            "target-width wrap accepted");
        reject(() -> contract(narrow));
        reject(() -> new UnwindStackSeparation(8, CONDITION.regions(), " "));
        reject(() -> new UnwindStackSeparation(8, List.of(), "condition without regions"));
        reject(() -> new UnwindStackSeparation(4, high.regions(), "outside width"));
        reject(() -> new UnwindStackSeparation(8, List.of(CONDITION.regions().getFirst(), CONDITION.regions().getFirst()), "overlap"));
        reject(() -> new UnwindStackSeparation.Region(-1, 0));
        reject(() -> new UnwindStackSeparation(8, CONDITION.regions(), "x".repeat(4097)));
        reject(() -> new UnwindStackSeparation(8, java.util.Collections.nCopies(129, CONDITION.regions().getFirst()), "budget"));
        try { CONDITION.regions().clear(); throw new AssertionError("mutable separation condition"); }
        catch (UnsupportedOperationException expected) { checks++; }
        // A late predecessor invalidates a tempting absolute address. Neither
        // first-visit facts nor a caller-supplied summary may authorize it.
        var joined = new Body<>(0, Map.of(
            0, node(List.of(new Copy(ADDRESS, new Constant(0x600000, 8))), 1, 2),
            1, node(List.of(new Kill(ADDRESS)), 2),
            2, node(List.of(new Store(ADDRESS, SAVED, 8), new Load(TARGET, STACK),
                new Add(STACK, STACK, new Constant(8, 8), false)))), Map.of(), Set.of(2));
        reject(() -> UnwindCalls.verify(Map.of(0, joined), contract(CONDITION), () -> false));
        // An invalid store in a recursive group cannot bootstrap a conditional
        // summary into an unconditional hypothesis.
        var recursive = new Body<>(0, Map.of(
            0, node(List.of(), 1, 2),
            1, node(List.of(new Add(STACK, STACK, new Constant(-8, 8), false),
                new Store(STACK, new Constant(123, 8), 8), proof.summary(0)), 2),
            2, node(List.of(new Store(new Constant(0x600000, 8), SAVED, 8), new Load(TARGET, STACK),
                new Add(STACK, STACK, new Constant(8, 8), false)))), Map.of(new Site<>(1, 2), 0), Set.of(2));
        reject(() -> UnwindCalls.verify(Map.of(0, recursive), contract(UnwindStackSeparation.NONE), () -> false));
        require(UnwindCalls.verify(Map.of(0, recursive), contract(CONDITION), () -> false).separation().equals(CONDITION),
            "conditional recursive proof failed");
        var shifted = new java.util.LinkedHashMap<Integer, Node<Integer>>();
        recursive.graph().forEach((key, value) -> shifted.put(key + 100,
            new Node<>(value.effects(), value.successors().stream().map(next -> next + 100).toList())));
        var first = new Body<>(0, recursive.graph(), Map.of(new Site<>(1, 2), 100), Set.of(2));
        var second = new Body<>(100, shifted, Map.of(new Site<>(101, 2), 0), Set.of(102));
        var mutual = UnwindCalls.verify(Map.of(0, first, 100, second), contract(CONDITION), () -> false);
        require(mutual.summary(0).separation().equals(CONDITION) && mutual.summary(100).separation().equals(CONDITION),
            "mutual recursion lost its shared condition");
        reject(() -> UnwindCalls.verify(Map.of(0, first, 100, second), contract(UnwindStackSeparation.NONE), () -> false));
        fixedPointers();
        int[] polls = {0};
        UnwindCalls.verify(Map.of(0, recursive), contract(CONDITION), () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop; int[] count = {0};
            try {
                UnwindCalls.verify(Map.of(0, recursive), contract(CONDITION), () -> ++count[0] == selected);
                throw new AssertionError("conditional proof ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        System.out.println("unwind-stack-separation=PASS checks=" + checks + " cancellation-points=" + polls[0]);
    }
    private static void fixedPointers() {
        var regions = List.of(new UnwindStackSeparation.Region(0x500000, 0x500007), CONDITION.regions().getFirst());
        var pointer = new UnwindStackSeparation.Pointer(0x500000, 0x600000);
        var condition = new UnwindStackSeparation(8, regions, "external immutable pointer test condition", List.of(pointer));
        var loaded = new Body<>(0, Map.of(0, node(List.of(new Load(ADDRESS, new Constant(0x500000, 8)),
            new Store(ADDRESS, SAVED, 8), new Load(TARGET, STACK), new Add(STACK, STACK, new Constant(8, 8), false)))),
            Map.of(), Set.of(0));
        reject(() -> UnwindCalls.verify(Map.of(0, loaded), contract(CONDITION), () -> false));
        var proof = UnwindCalls.verify(Map.of(0, loaded), contract(condition), () -> false);
        require(proof.separation().equals(condition) && proof.summary(0).separation().equals(condition), "fixed pointer provenance lost");
        require(new Constant(0x600000, 8).equals(proof.flows().get(0).after().get(0).values().get(ADDRESS)), "pointer load not recovered");
        var without = new UnwindStackSeparation(8, regions, condition.basis());
        reject(() -> UnwindFlow.analyze(Map.of(0, node(List.of(proof.summary(0)))), 0, ENTRY, STACK, () -> false, null, without));
        require(condition.readPointer(new Constant(0x500000, 8), 4) == null &&
            condition.readPointer(new Constant(0x500001, 8), 8) == null &&
            condition.readPointer(new Constant(0x500000, 4), 8) == null, "partial/wrong-width pointer read accepted");
        for (Effect effect : List.of(new Store(new Constant(0x500000, 8), SAVED, 8),
                new Store(new Constant(0x4fffff, 8), SAVED, 2), new Store(new Constant(0x500007, 8), SAVED, 1),
                new Store(ADDRESS, SAVED, 8), new Opaque("unknown memory effect"),
                new Call(Set.of(SAVED), 0, null, "unknown memory call"))) {
            reject(() -> UnwindFlow.analyze(Map.of(0, node(List.of(effect, new Load(ADDRESS, new Constant(0x500000, 8))))),
                0, ENTRY, STACK, () -> false, null, condition));
        }
        for (var pointers : List.of(List.of(pointer, pointer), List.of(new UnwindStackSeparation.Pointer(0x500001, 0x600000)),
                List.of(new UnwindStackSeparation.Pointer(-4, 0x600000)))) {
            reject(() -> new UnwindStackSeparation(8, regions, condition.basis(), pointers));
        }
        reject(() -> new UnwindStackSeparation(0, List.of(), "", List.of(pointer)));
        reject(() -> new UnwindStackSeparation(4, regions, condition.basis(), List.of(new UnwindStackSeparation.Pointer(0x500000, 0x100000000L))));
        var flow = UnwindFlow.analyze(Map.of(0, node(List.of(new Store(new Constant(0x500008, 8), SAVED, 1),
            new Load(ADDRESS, new Constant(0x500000, 8))))), 0, ENTRY, STACK, () -> false, null, condition);
        require(new Constant(0x600000, 8).equals(flow.after().get(0).values().get(ADDRESS)), "nonoverlapping write invalidated fixed pointer");
        int[] polls = {0};
        UnwindCalls.verify(Map.of(0, loaded), contract(condition), () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop; int[] count = {0};
            try {
                UnwindCalls.verify(Map.of(0, loaded), contract(condition), () -> ++count[0] == selected);
                throw new AssertionError("fixed pointer proof ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
    }

}
