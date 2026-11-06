package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.unwind.UnwindFlow.*;

/** Effect-level proofs; native instruction extraction has its own acceptance. */
public final class UnwindFlowSmoke {
    private static final Cell SP = new Cell(Bank.REGISTER, 0, 8);
    private static final Cell FP = new Cell(Bank.REGISTER, 8, 8);
    private static final Cell SAVED = new Cell(Bank.REGISTER, 16, 8);
    private static final Cell RA = new Cell(Bank.REGISTER, 24, 8);
    private static final Cell TEMP = new Cell(Bank.TEMPORARY, 0, 8);
    private static final Incoming CALLER = new Incoming(12, 8);
    private static final ReturnAddress RETURN = new ReturnAddress(8);
    private static int checks;

    private static State seed() {
        return new State(Map.of(SP, new StackAddress(0, 8), FP, new Incoming(6, 8),
            SAVED, CALLER, RA, RETURN), Map.of(new Slot(0, 8), RETURN));
    }
    private static Node<Integer> node(List<Effect> effects, Integer... successors) {
        return new Node<>(effects, List.of(successors));
    }
    private static Add add(Cell output, Operand input, long amount) {
        return new Add(output, input, new Constant(amount, output.bytes()), false);
    }
    private static void require(boolean condition, String description) {
        if (!condition) throw new AssertionError(description);
        checks++;
    }
    private static void rejected(Runnable action) {
        try { action.run(); throw new AssertionError("invalid symbolic flow accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static State after(List<Effect> effects) {
        return UnwindFlow.analyze(Map.of(0, node(effects)), 0, seed(), SP, () -> false).after().get(0);
    }

    public static void main(String[] args) {
        var graph = new LinkedHashMap<Integer, Node<Integer>>();
        graph.put(0, node(List.of(add(SP, SP, -16), add(TEMP, SP, 8), new Store(TEMP, SAVED, 8)), 1));
        graph.put(1, node(List.of(new Copy(FP, SP), new Copy(SAVED, new Constant(77, 8))), 2));
        graph.put(2, node(List.of(new Call(Set.of(FP, SAVED), 0, 0L, "fixture closed stack-only callee")), 3));
        graph.put(3, node(List.of(add(TEMP, FP, 8), new Load(SAVED, TEMP), add(SP, SP, 16)), 4));
        graph.put(4, node(List.of()));
        var result = UnwindFlow.analyze(graph, 0, seed(), SP, () -> false);
        require(result.before().get(0).equals(seed()), "entry state was changed by future effects");
        require(result.before().get(1).memory().get(new Slot(-8, 8)).equals(CALLER), "saved identity missing");
        require(result.before().get(3).memory().get(new Slot(-8, 8)).equals(CALLER), "proved call lost caller-owned slot");
        require(result.before().get(3).values().get(SAVED).equals(new Constant(77, 8)), "callee preservation confused with caller identity");
        require(!result.before().get(3).values().containsKey(RA), "call preserved unproved incoming return register");
        require(result.before().get(4).values().get(SAVED).equals(CALLER), "restore lost saved identity");
        require(result.before().get(4).values().get(SP).equals(new StackAddress(0, 8)), "epilogue stack relation wrong");
        require(!result.before().get(4).memory().containsKey(new Slot(-8, 8)), "deallocated slot remained live");
        require(result.before().get(4).memory().get(new Slot(0, 8)).equals(RETURN), "return address overwritten by unrelated store");
        require(result.before().values().stream().noneMatch(s -> s.values().containsKey(TEMP)), "temporary crossed instruction boundary");

        // Different predecessor orders must not let the first, optimistic path
        // establish a fact that the eventual join cannot prove.
        for (boolean reverse : List.of(false, true)) {
            for (boolean conflict : List.of(false, true)) {
                var diamond = new LinkedHashMap<Integer, Node<Integer>>();
                diamond.put(0, node(List.of(), reverse ? 2 : 1, reverse ? 1 : 2));
                diamond.put(1, node(List.of(add(TEMP, SP, -8), new Store(TEMP, SAVED, 8)), 3));
                diamond.put(2, node(List.of(add(TEMP, SP, -8), new Store(TEMP,
                    conflict ? new Constant(91, 8) : SAVED, 8)), 3));
                diamond.put(3, node(List.of(add(TEMP, SP, -8), new Load(SAVED, TEMP)), 4));
                diamond.put(4, node(List.of()));
                State join = UnwindFlow.analyze(diamond, 0, seed(), SP, () -> false).before().get(4);
                require(join.values().containsKey(SAVED) != conflict, "join trusted only one predecessor");
                if (!conflict) require(join.values().get(SAVED).equals(CALLER), "identical split saves did not merge");
            }
        }
        var loop = Map.of(0, node(List.of(), 1),
            1, node(List.of(), 2, 3), 2, node(List.of(new Kill(SAVED)), 1), 3, node(List.of()));
        var loopResult = UnwindFlow.analyze(loop, 0, seed(), SP, () -> false);
        require(!loopResult.before().get(1).values().containsKey(SAVED), "loop backedge did not invalidate header");
        require(!loopResult.before().get(3).values().containsKey(SAVED), "loop exit retained speculative first iteration");
        var stackLoop = Map.of(0, node(List.of(), 1), 1, node(List.of(add(SP, SP, -8)), 1, 2), 2, node(List.of()));
        require(!UnwindFlow.analyze(stackLoop, 0, seed(), SP, () -> false).before().get(2).values().containsKey(SP),
            "varying loop stack offset failed to converge to unknown");
        var unreachable = Map.of(0, node(List.of(), 2), 1, node(List.of(new Opaque("unreachable partial instruction")), 2), 2, node(List.of()));
        require(UnwindFlow.analyze(unreachable, 0, seed(), SP, () -> false).before().get(2).equals(seed()),
            "unreachable predecessor poisoned valid path");
        require(after(List.of(new Opaque("partial instruction"))).values().isEmpty(), "opaque effect retained registers");
        require(after(List.of(new Opaque("partial instruction"))).memory().isEmpty(), "opaque effect retained memory");
        require(after(List.of(new Kill(new Cell(Bank.REGISTER, SAVED.offset() + 3, 1)))).values().get(SAVED) == null,
            "partial register alias write retained whole caller identity");
        require(!after(List.of(add(TEMP, SP, 3), new Store(TEMP, new Constant(1, 1), 1))).memory().containsValue(RETURN),
            "partial overlapping store retained return address");
        require(after(List.of(new Store(new Constant(0x1000, 8), SAVED, 8))).memory().isEmpty(),
            "unproved absolute store assumed not to alias stack");
        require(after(List.of(new Call(Set.of(SAVED), 0, null, "unknown memory effect"))).memory().isEmpty(),
            "call with unknown memory effect retained saved slot");
        require(after(List.of(new Call(Set.of(SAVED), 8, 0L, "stack-only return"))).memory().isEmpty(),
            "call return retained released stack slot");
        require(after(List.of(new Load(SAVED, SP))).values().get(SAVED).equals(RETURN),
            "return-address identity conflated with incoming register identity");
        State postIncrement = after(List.of(new Copy(TEMP, SP), add(SP, SP, 8), new Load(SAVED, TEMP)));
        require(postIncrement.values().get(SAVED).equals(RETURN), "post-increment load lost old-address memory");
        require(postIncrement.memory().isEmpty(), "post-increment retained released memory after instruction");
        var snapshots = new ArrayList<State>();
        var postIncrementGraph = Map.of(0, node(List.of(new Copy(TEMP, SP), add(SP, SP, 8), new Load(SAVED, TEMP))));
        var observed = UnwindFlow.analyze(postIncrementGraph, 0, seed(), SP, () -> false,
            (instruction, index, effect, before) -> {
                require(instruction == 0 && index == snapshots.size(), "replay effect order changed");
                snapshots.add(before);
            });
        require(observed.after().get(0).equals(postIncrement), "observation changed post-increment semantics");
        require(snapshots.get(2).values().get(TEMP).equals(new StackAddress(0, 8)), "replay lost temporary old stack address");
        require(snapshots.get(2).memory().get(new Slot(0, 8)).equals(RETURN), "replay prematurely expired old stack slot");
        require(snapshots.get(0).equals(seed()), "later effects mutated an earlier snapshot");
        try {
            snapshots.get(0).values().clear();
            throw new AssertionError("observer snapshot is mutable");
        }
        catch (UnsupportedOperationException expected) { checks++; }
        var seenInstructions = new ArrayList<Integer>();
        var finalLoop = UnwindFlow.analyze(loop, 0, seed(), SP, () -> false,
            (instruction, index, effect, before) -> {
                seenInstructions.add(instruction);
                require(!before.values().containsKey(SAVED), "observer saw speculative first-loop identity");
            });
        require(seenInstructions.equals(List.of(2)), "replay repeated an effect during convergence");
        require(finalLoop.equals(loopResult), "observation changed loop fixed point or transfer accounting");
        UnwindFlow.analyze(unreachable, 0, seed(), SP, () -> false,
            (instruction, index, effect, before) -> { throw new AssertionError("unreachable effect was observed"); });
        checks++;
        rejected(() -> UnwindFlow.analyze(postIncrementGraph, 0, seed(), SP, () -> false,
            (instruction, index, effect, before) -> { throw new IllegalArgumentException("callee effect rejected"); }));
        int[] replayPolls = {0};
        UnwindFlow.analyze(postIncrementGraph, 0, seed(), SP, () -> { replayPolls[0]++; return false; },
            (instruction, index, effect, before) -> { });
        for (int limit = 1; limit <= replayPolls[0]; limit++) {
            int stop = limit; int[] poll = {0};
            try {
                UnwindFlow.analyze(postIncrementGraph, 0, seed(), SP, () -> ++poll[0] == stop,
                    (instruction, index, effect, before) -> { });
                throw new AssertionError("replay ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(UnwindFlow.analyze(postIncrementGraph, 0, seed(), SP, () -> false).after().get(0).equals(postIncrement),
            "replay cancellation contaminated retry");
        require(after(List.of(new Copy(SAVED, new Constant(1, 4)))).values().get(SAVED) == null,
            "width-changing copy fabricated a full caller value");
        require(after(List.of(new Kill(SP))).memory().isEmpty(), "lost stack anchor retained stack ownership");
        require(after(List.of(add(TEMP, SP, 0), new Copy(FP, TEMP))).values().get(FP).equals(new StackAddress(0, 8)),
            "frame-pointer copy lost affine entry stack relation");
        require(after(List.of(new Copy(SP, new Constant(0, 8)))).memory().isEmpty(), "stack switch retained old frame memory");
        require(after(List.of(new Add(SP, SP, new Constant(Long.MIN_VALUE, 8), true))).values().get(SP) == null,
            "negation overflow fabricated stack relation");

        int[] polls = {0};
        var counted = UnwindFlow.analyze(graph, 0, seed(), SP, () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop;
            int[] count = {0};
            try {
                UnwindFlow.analyze(graph, 0, seed(), SP, () -> ++count[0] == selected);
                throw new AssertionError("cancellation ignored at poll " + stop);
            }
            catch (CancellationException expected) { checks++; }
        }
        require(counted.equals(UnwindFlow.analyze(graph, 0, seed(), SP, () -> false)), "cancelled run contaminated retry");
        rejected(() -> UnwindFlow.analyze(Map.of(0, node(List.of(), 1)), 0, seed(), SP, () -> false));
        rejected(() -> new Cell(Bank.REGISTER, Long.MAX_VALUE, 8));
        rejected(() -> new State(Map.of(SAVED, CALLER, new Cell(Bank.REGISTER, 17, 1), new Constant(0, 1)), Map.of()));
        rejected(() -> new State(Map.of(), Map.of(new Slot(0, 8), RETURN, new Slot(3, 1), new Constant(1, 1))));
        rejected(() -> new Call(Set.of(TEMP), 0, 0L, "not a physical preserved register"));
        rejected(() -> new StackAddress(0x80000000L, 4));
        Cell narrowStack = new Cell(Bank.REGISTER, 0, 4);
        rejected(() -> UnwindFlow.analyze(Map.of(0, node(List.of(new Call(Set.of(), 0x1_0000_0000L, 0L,
            "invalid width summary")))), 0, new State(Map.of(narrowStack, new StackAddress(0, 4)), Map.of()),
            narrowStack, () -> false));
        var effects = new ArrayList<Effect>(List.of(new Kill(SAVED)));
        var immutable = node(effects);
        effects.clear();
        require(immutable.effects().size() == 1, "mutable effects leaked into graph");
        require(seed().values().get(SAVED).equals(CALLER), "analysis mutated seed");
        System.out.println("unwind-flow-smoke=PASS checks=" + checks + " cancellation=" + polls[0]);
    }
}
