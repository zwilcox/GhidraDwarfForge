package ghidradwarfforge.unwind;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.unwind.CallFramePlan.*;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Identity-to-rule oracle with unknown/overflow/anchor/alias controls. */
public final class UnwindFrameRowsSmoke {
    private static final Cell STACK = new Cell(Bank.REGISTER, 0, 8);
    private static final Cell ANCHOR = new Cell(Bank.REGISTER, 8, 8);
    private static final Cell SAVED = new Cell(Bank.REGISTER, 16, 8);
    private static final Cell LINK = new Cell(Bank.REGISTER, 24, 8);
    private static final Cell COUNTER = new Cell(Bank.REGISTER, 32, 8);
    private static final Map<Integer, Cell> REGISTERS = Map.of(0, STACK, 1, ANCHOR, 2, SAVED, 3, LINK, 4, COUNTER);
    private static final UnwindFrameRows.Policy POLICY = new UnwindFrameRows.Policy(REGISTERS, 0, 3, 4, 8, 8);
    private static int checks;
    private static void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); checks++; }
    private static UnwindFrameRows.Projected project(Map<Cell, Value> values, Map<Slot, Value> slots) {
        return UnwindFrameRows.project(new State(values, slots), POLICY, () -> false);
    }
    public static void main(String[] args) {
        var entry = project(Map.of(STACK, new StackAddress(0, 8), ANCHOR, new Incoming(1, 8),
            SAVED, new Incoming(2, 8), LINK, new ReturnAddress(8)), Map.of());
        require(entry.covered() && entry.cfa().equals(new Cfa(0, 8)), "entry CFA differs from evidence");
        require(entry.rules().equals(Map.of(0, new CfaValue(0), 1, new SameValue(), 2, new SameValue(),
            3, new SameValue(), 4, new InRegister(3))), "entry identities/return alias conflated");
        var callBefore = new State(Map.of(STACK, new StackAddress(-16, 8), LINK, new ReturnAddress(8)),
            Map.of(new Slot(-8, 8), new ReturnAddress(8)));
        var callAfter = new State(Map.of(STACK, new StackAddress(-16, 8)), callBefore.memory());
        var call = UnwindFrameRows.projectCall(callBefore, callAfter, POLICY, () -> false);
        require(call.rules().get(3).equals(new AtCfaOffset(-16)) && call.rules().get(4).equals(new AtCfaOffset(-16)),
            "biased caller lookup used a link value invalidated by the call");
        require(!UnwindFrameRows.projectCall(callBefore, new State(Map.of(STACK, new StackAddress(-16, 8)), Map.of()),
            POLICY, () -> false).covered(), "call row used a location proved on only one side");
        var saved = project(Map.of(STACK, new StackAddress(-16, 8), ANCHOR, new Incoming(1, 8)),
            Map.of(new Slot(-16, 8), new Incoming(2, 8), new Slot(-8, 8), new ReturnAddress(8)));
        require(saved.cfa().equals(new Cfa(0, 24)), "allocated stack CFA offset wrong");
        require(saved.rules().get(2).equals(new AtCfaOffset(-24)), "saved register offset wrong");
        require(saved.rules().get(3).equals(new AtCfaOffset(-16)) && saved.rules().get(4).equals(new AtCfaOffset(-16)),
            "saved return aliases differ");
        var moved = project(Map.of(ANCHOR, new StackAddress(-16, 8), SAVED, new ReturnAddress(8), LINK, new Incoming(2, 8)), Map.of());
        require(moved.cfa().equals(new Cfa(1, 24)), "surviving frame anchor was ignored");
        require(moved.rules().get(2).equals(new InRegister(3)) && moved.rules().get(3).equals(new InRegister(2)),
            "register identities assumed to be current names");
        require(moved.rules().get(1) instanceof Undefined && moved.unavailable().containsKey(1), "lost anchor identity invented");
        require(!project(Map.of(STACK, new StackAddress(0, 8)), Map.of()).covered(), "missing return address covered");
        require(!project(Map.of(LINK, new ReturnAddress(8)), Map.of()).covered(), "missing CFA covered");
        require(!UnwindFrameRows.project(null, POLICY, () -> false).covered(), "unreachable state covered");
        require(!project(Map.of(STACK, new StackAddress(Long.MIN_VALUE, 8), LINK, new ReturnAddress(8)), Map.of()).covered(),
            "overflowing CFA relation covered");
        var alternate = project(Map.of(STACK, new StackAddress(Long.MIN_VALUE, 8), ANCHOR, new StackAddress(0, 8),
            LINK, new ReturnAddress(8)), Map.of());
        require(alternate.cfa().equals(new Cfa(1, 8)), "representable alternate anchor ignored");
        require(!project(Map.of(STACK, new StackAddress(0, 8)), Map.of(new Slot(Long.MIN_VALUE, 8), new ReturnAddress(8))).covered(),
            "overflowing saved-return offset covered");
        var orderA = new LinkedHashMap<Cell, Value>();
        orderA.put(STACK, new StackAddress(-16, 8)); orderA.put(LINK, new ReturnAddress(8)); orderA.put(ANCHOR, new Incoming(2, 8));
        var orderB = new LinkedHashMap<Cell, Value>();
        orderB.put(ANCHOR, new Incoming(2, 8)); orderB.put(LINK, new ReturnAddress(8)); orderB.put(STACK, new StackAddress(-16, 8));
        require(project(orderA, Map.of()).equals(project(orderB, Map.of())), "map insertion order changed selected rules");
        var duplicate = project(Map.of(STACK, new StackAddress(0, 8)),
            Map.of(new Slot(-24, 8), new ReturnAddress(8), new Slot(-16, 8), new ReturnAddress(8)));
        require(duplicate.rules().get(3).equals(new AtCfaOffset(-32)), "duplicate saves chosen nondeterministically");
        try { entry.rules().clear(); throw new AssertionError("mutable projection"); }
        catch (UnsupportedOperationException expected) { checks++; }
        try { new UnwindFrameRows.Policy(Map.of(0, STACK, 1, STACK, 2, LINK), 0, 1, 2, 0, 0); throw new AssertionError("aliased policy"); }
        catch (IllegalArgumentException expected) { checks++; }
        int[] polls = {0};
        var state = new State(orderA, Map.of());
        var reference = UnwindFrameRows.project(state, POLICY, () -> { polls[0]++; return false; });
        for (int limit = 1; limit <= polls[0]; limit++) {
            int stop = limit; int[] seen = {0};
            try {
                UnwindFrameRows.project(state, POLICY, () -> ++seen[0] == stop);
                throw new AssertionError("projection ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(UnwindFrameRows.project(state, POLICY, () -> false).equals(reference), "cancelled projection changed retry");
        int[] callPolls = {0};
        UnwindFrameRows.projectCall(callBefore, callAfter, POLICY, () -> { callPolls[0]++; return false; });
        for (int limit = 1; limit <= callPolls[0]; limit++) {
            int stop = limit; int[] seen = {0};
            try {
                UnwindFrameRows.projectCall(callBefore, callAfter, POLICY, () -> ++seen[0] == stop);
                throw new AssertionError("call projection ignored cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(UnwindFrameRows.projectCall(callBefore, callAfter, POLICY, () -> false).equals(call), "call projection retry changed rules");
        System.out.println("unwind-frame-rows-smoke=PASS checks=" + checks + " cancellation=" + polls[0]);
    }
}
