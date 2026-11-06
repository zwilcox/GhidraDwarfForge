package ghidradwarfforge.unwind;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.unwind.UnwindCalls.*;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Closed-group obligations, recursive counterexamples and adversarial summaries. */
public final class UnwindCallsSmoke {
    private static final Cell STACK = new Cell(Bank.REGISTER, 0, 8);
    private static final Cell SAVED = new Cell(Bank.REGISTER, 8, 8);
    private static final Cell TARGET = new Cell(Bank.REGISTER, 16, 8);
    private static final Cell UNKNOWN = new Cell(Bank.REGISTER, 24, 8);
    private static final Incoming IDENTITY = new Incoming(12, 8);
    private static final State ENTRY = new State(Map.of(STACK, new StackAddress(0, 8), SAVED, IDENTITY),
        Map.of(new Slot(0, 8), new ReturnAddress(8)));
    private static final Contract CONTRACT = new Contract(ENTRY, STACK, TARGET, Map.of(SAVED, IDENTITY), 8);
    private static int checks;

    private static void require(boolean test, String reason) {
        if (!test) throw new AssertionError(reason);
        checks++;
    }
    private static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("unproved closed callee group accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static Add adjust(long offset) { return new Add(STACK, STACK, new Constant(offset, 8), false); }
    private static Node<Integer> node(List<Effect> effects, Integer... successors) { return new Node<>(effects, List.of(successors)); }
    private static Body<Integer> leaf(int base, List<Effect> extra) {
        var effects = new java.util.ArrayList<>(extra);
        effects.add(new Load(TARGET, STACK));
        effects.add(adjust(8));
        return new Body<>(base, Map.of(base, node(effects)), Map.of(), Set.of(base));
    }
    private static Body<Integer> calling(int base, int target) {
        var graph = new LinkedHashMap<Integer, Node<Integer>>();
        graph.put(base, node(List.of(adjust(-8), new Store(STACK, SAVED, 8), new Copy(SAVED, new Constant(73, 8))), base + 1));
        graph.put(base + 1, node(List.of(), base + 2, base + 3));
        // An adversarial supplied summary promises every register and no writes.
        // The verifier must replace it, not use those unsupported assertions.
        graph.put(base + 2, node(List.of(adjust(-8), new Store(STACK, new Constant(456, 8), 8),
            new Call(Set.of(SAVED, TARGET, UNKNOWN), -999, Long.MIN_VALUE, "untrusted summary")), base + 3));
        graph.put(base + 3, node(List.of(new Load(SAVED, STACK), adjust(8)), base + 4));
        graph.put(base + 4, node(List.of(new Load(TARGET, STACK), adjust(8))));
        return new Body<>(base, graph, Map.of(new Site<>(base + 2, 2), target), Set.of(base + 4));
    }
    private static Body<Integer> replace(Body<Integer> body, int instruction, Node<Integer> replacement) {
        var graph = new LinkedHashMap<>(body.graph());
        graph.put(instruction, replacement);
        return new Body<>(body.entry(), graph, body.calls(), body.returns());
    }
    private static Verified<Integer> verify(Map<Integer, Body<Integer>> group) {
        return UnwindCalls.verify(group, CONTRACT, () -> false);
    }

    public static void main(String[] args) {
        var direct = Map.of(0, calling(0, 100), 100, leaf(100, List.of()));
        var proof = verify(direct);
        require(proof.summary(100).preserved().equals(Set.of(SAVED)), "untrusted preserved set escaped verification");
        require(proof.summary(100).stackAdjustment() == 8 && proof.summary(100).writeBound() == 0,
            "untrusted stack/write effects escaped verification");
        require(proof.flows().get(0).after().get(4).values().get(SAVED).equals(IDENTITY), "caller identity not restored");
        require(proof.flows().get(0).before().get(3).memory().get(new Slot(-8, 8)).equals(IDENTITY),
            "verified callee destroyed caller-owned saved slot");
        require(proof.flows().get(0).before().get(3).values().get(SAVED).equals(new Constant(73, 8)),
            "callee preserved value was confused with incoming identity");
        reject(() -> proof.summary(200));
        var recursive = Map.of(0, calling(0, 0));
        require(verify(recursive).flows().get(0).after().get(4).values().get(TARGET).equals(new ReturnAddress(8)),
            "self-recursive return target unproved");
        var mutual = new LinkedHashMap<Integer, Body<Integer>>();
        mutual.put(0, calling(0, 100)); mutual.put(100, calling(100, 0));
        var forward = verify(mutual);
        var reverse = new LinkedHashMap<Integer, Body<Integer>>();
        reverse.put(100, mutual.get(100)); reverse.put(0, mutual.get(0));
        require(verify(reverse).flows().equals(forward.flows()), "recursive proof depends on traversal order");
        for (List<Effect> invalid : List.of(
                List.<Effect>of(new Kill(SAVED)),
                List.<Effect>of(new Store(UNKNOWN, SAVED, 8)),
                List.<Effect>of(new Store(new Constant(0x600000, 8), SAVED, 8)),
                List.<Effect>of(new Store(STACK, SAVED, 8)),
                List.<Effect>of(adjust(-4), new Store(STACK, SAVED, 8), adjust(4)),
                List.<Effect>of(new Opaque("unmodeled callee operation")),
                List.<Effect>of(new Kill(new Cell(Bank.REGISTER, SAVED.offset(), 1))))) {
            reject(() -> verify(Map.of(0, calling(0, 100), 100, leaf(100, invalid))));
        }
        reject(() -> verify(Map.of(0, calling(0, 100))));
        var corruptedReturn = replace(mutual.get(100), 104, node(List.of(new Load(TARGET, STACK), adjust(8), new Kill(SAVED))));
        reject(() -> verify(Map.of(0, mutual.get(0), 100, corruptedReturn)));
        reject(() -> verify(Map.of(0, replace(calling(0, 0), 4, node(List.of(new Load(TARGET, STACK), adjust(16)))))));
        reject(() -> verify(Map.of(0, replace(calling(0, 0), 4, node(List.of(new Copy(TARGET, new Constant(42, 8)), adjust(8)))))));
        var missingBinding = new Body<>(0, calling(0, 100).graph(), Map.of(), Set.of(4));
        reject(() -> verify(Map.of(0, missingBinding, 100, leaf(100, List.of()))));
        var extraBinding = new Body<>(100, leaf(100, List.of()).graph(), Map.of(new Site<>(100, 0), 0), Set.of(100));
        reject(() -> verify(Map.of(0, calling(0, 100), 100, extraBinding)));
        var earlyTerminal = replace(calling(0, 100), 1, node(List.of()));
        reject(() -> verify(Map.of(0, earlyTerminal, 100, leaf(100, List.of()))));
        // A call from above entry stack violates the transitive write bound even
        // if a synthetic later instruction could restore stack/return values.
        var highCall = replace(calling(0, 100), 2, node(List.of(adjust(32), new Copy(SAVED, SAVED),
            new Call(Set.of(), 0, null, "untrusted")), 3));
        try {
            verify(Map.of(0, highCall, 100, leaf(100, List.of())));
            throw new AssertionError("nested callee write boundary accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("nested callee entry exceeds"), "call boundary failed for unrelated reason");
        }
        // Unknown stores remain invalid after a join, even if one path has an
        // initially plausible stack-relative address.
        var varying = new LinkedHashMap<Integer, Node<Integer>>();
        varying.put(100, node(List.of(new Copy(UNKNOWN, STACK)), 101, 102));
        varying.put(101, node(List.of(new Kill(UNKNOWN)), 102));
        varying.put(102, node(List.of(new Store(UNKNOWN, SAVED, 8), new Load(TARGET, STACK), adjust(8))));
        reject(() -> verify(Map.of(100, new Body<>(100, varying, Map.of(), Set.of(102)))));
        reject(() -> verify(Map.of()));
        reject(() -> new Contract(ENTRY, STACK, STACK, Map.of(SAVED, IDENTITY), 8));
        reject(() -> new Contract(ENTRY, STACK, TARGET, Map.of(SAVED, new Incoming(13, 8)), 8));
        var tooMany = new LinkedHashMap<Integer, Body<Integer>>();
        for (int index = 0; index <= 1024; index++) tooMany.put(index, leaf(index, List.of()));
        reject(() -> verify(tooMany));
        try { proof.flows().clear(); throw new AssertionError("verified result mutable"); }
        catch (UnsupportedOperationException expected) { checks++; }
        int[] polls = {0};
        UnwindCalls.verify(mutual, CONTRACT, () -> { polls[0]++; return false; });
        for (int limit = 1; limit <= polls[0]; limit++) {
            int stop = limit; int[] seen = {0};
            try {
                UnwindCalls.verify(mutual, CONTRACT, () -> ++seen[0] == stop);
                throw new AssertionError("callee verification ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(verify(mutual).flows().equals(forward.flows()), "cancelled proof contaminated retry");
        System.out.println("unwind-calls-smoke=PASS checks=" + checks + " cancellation=" + polls[0]);
    }
}
