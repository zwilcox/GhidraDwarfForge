package ghidradwarfforge.calls;

import java.util.List;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Rejects stale call/formal identities before the native producer is entered. */
public final class CallSitePlanSmoke {
    private static int checks;

    public static void main(String[] args) {
        var integer = new TypeGraph.TypeRef("int");
        var graph = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var signature = new ProgramTypeModel.FunctionSignature("callee", 0x200, integer,
            List.of(new TypeGraph.Parameter("value", integer, false)), List.of(), false, false, "default", "USER_DEFINED");
        var model = new ProgramTypeModel(graph, List.of(signature), List.of());
        var symbols = List.of(new FunctionSymbol("caller", 0x100, 0x20), new FunctionSymbol("callee", 0x200, 0x20));
        var argument = new CallSitePlan.Argument(0, "value", "int", 5, new CallValue.Literal(42, 8));
        var site = new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(argument));
        var owner = new CallSitePlan.FunctionCalls(0x100, CallSitePlan.Completeness.PARTIAL, List.of(site));
        var plan = new CallSitePlan(List.of(owner));
        plan.validate(symbols, model, 8);
        CallSitePlan.EMPTY.validate(symbols, null, 8);
        reject(() -> plan.validate(List.of(symbols.get(1)), model, 8));
        reject(() -> plan.validate(List.of(symbols.get(0)), model, 8));
        reject(() -> plan.validate(symbols, null, 8));
        reject(() -> plan.validate(symbols, model, 4)); // an eight-byte actual value cannot fit this target
        reject(() -> new CallSitePlan(List.of(owner, owner)));
        reject(() -> new CallSitePlan.Site(0x110, 0x115, false, null, List.of(argument)));
        reject(() -> new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(argument, argument)));
        reject(() -> new CallSitePlan(List.of(new CallSitePlan.FunctionCalls(0x100,
            CallSitePlan.Completeness.ALL_TAILS, List.of(new CallSitePlan.Site(0x110, 0x115, true, 0x100L, List.of()))))));
        reject(() -> new CallSitePlan(List.of(new CallSitePlan.FunctionCalls(0x100,
            CallSitePlan.Completeness.PARTIAL, List.of(new CallSitePlan.Site(0x120, 0x125, false, 0x200L, List.of())))))
            .validate(symbols, model, 8));
        for (var bad : List.of(new CallSitePlan.Argument(1, "value", "int", 5, argument.value()),
                new CallSitePlan.Argument(0, "renamed", "int", 5, argument.value()),
                new CallSitePlan.Argument(0, "value", "changed-type", 5, argument.value()))) {
            reject(() -> new CallSitePlan(List.of(new CallSitePlan.FunctionCalls(0x100,
                CallSitePlan.Completeness.PARTIAL, List.of(new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(bad))))))
                .validate(symbols, model, 8));
        }
        // Input order cannot affect serialization order, and external collection changes cannot alter the plan.
        var mutable = new java.util.ArrayList<>(List.of(new CallSitePlan.Site(0x118, 0x11d, false, 0x200L, List.of()), site));
        var sorted = new CallSitePlan.FunctionCalls(0x100, CallSitePlan.Completeness.PARTIAL, mutable);
        mutable.clear();
        if (sorted.sites().size() != 2 || sorted.sites().get(0) != site) throw new AssertionError("unstable plan");
        boundaries(graph, symbols, model, argument);
        System.out.println("PASS_CALL_SITE_PLAN checks=" + checks + " deterministic-order-and-ownership=PASS");
    }

    private static void boundaries(TypeGraph graph, List<FunctionSymbol> symbols,
            ProgramTypeModel model, CallSitePlan.Argument argument) {
        int before = checks;
        for (Runnable invalid : List.<Runnable>of(
                () -> new CallSitePlan.Argument(-1, "value", "int", 5, argument.value()),
                () -> new CallSitePlan.Argument(0, "value", "int", -1, argument.value()),
                () -> new CallSitePlan.Argument(0, null, "int", 5, argument.value()),
                () -> new CallSitePlan.Argument(0, "value", null, 5, argument.value()),
                () -> new CallSitePlan.Argument(0, "value", " \t", 5, argument.value()),
                () -> new CallSitePlan.Argument(0, "value", "int", 5, null),
                () -> new CallSitePlan.Site(-1, 4, false, null, List.of()),
                () -> new CallSitePlan.Site(4, 4, false, null, List.of()),
                () -> new CallSitePlan.Site(4, 3, false, null, List.of()),
                () -> new CallSitePlan.Site(0, 4, false, null, null),
                () -> new CallSitePlan.FunctionCalls(0, null, List.of()),
                () -> new CallSitePlan.FunctionCalls(0, CallSitePlan.Completeness.PARTIAL, null))) {
            reject(invalid);
        }
        var highCall = new CallSitePlan.Site(Long.MAX_VALUE - 2, Long.MIN_VALUE, false, -1L, List.of());
        var highInventory = new CallSitePlan.FunctionCalls(-1L, CallSitePlan.Completeness.PARTIAL, List.of(highCall));
        equal(-1L, highInventory.caller());
        equal(-1L, highCall.callee());
        equal(Long.MIN_VALUE, highCall.returnPc());
        var otherOrdinal = new CallSitePlan.Argument(1, "other", "int", argument.dwarfRegister(), argument.value());
        reject(() -> new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(argument, otherOrdinal)));
        // Distinct normal-call owners cannot share either global lookup key.
        var first = new CallSitePlan.FunctionCalls(0x100, CallSitePlan.Completeness.PARTIAL,
            List.of(new CallSitePlan.Site(0x110, 0x115, false, null, List.of())));
        for (var conflict : List.of(new CallSitePlan.Site(0x110, 0x116, false, null, List.of()),
                new CallSitePlan.Site(0x111, 0x115, false, null, List.of()))) {
            reject(() -> new CallSitePlan(List.of(first,
                new CallSitePlan.FunctionCalls(0x200, CallSitePlan.Completeness.PARTIAL, List.of(conflict)))));
        }
        // Unknown destinations carry no invented argument binding. Ordinary recursion remains legal;
        // only a self-tail entry is deliberately excluded from the serialization plan.
        for (var completeness : CallSitePlan.Completeness.values()) {
            for (Long callee : new Long[] {null, 0x100L, 0x200L}) {
                var normal = plan(0x100, completeness, new CallSitePlan.Site(0x110, 0x115, false, callee, List.of()));
                normal.validate(symbols, null, 4);
                normal.validate(symbols, null, 8);
                checks += 2;
                if (callee == null || callee != 0x100L) {
                    plan(0x100, completeness, new CallSitePlan.Site(0x110, 0x115, true, callee, List.of()))
                        .validate(symbols, null, 8);
                    checks++;
                }
            }
        }

        var split = List.of(new FunctionSymbol("split", 0x100,
            List.of(new FunctionRange(0x100, 8), new FunctionRange(0x180, 8))), symbols.get(1));
        for (long address : new long[] {0x100, 0x107, 0x180, 0x187}) {
            plan(0x100, CallSitePlan.Completeness.PARTIAL,
                new CallSitePlan.Site(address, address + 1, false, 0x200L, List.of(argument))).validate(split, model, 8);
            checks++;
        }
        for (long address : new long[] {0xff, 0x108, 0x17f, 0x188}) {
            reject(() -> plan(0x100, CallSitePlan.Completeness.PARTIAL,
                new CallSitePlan.Site(address, address + 1, false, 0x200L, List.of(argument))).validate(split, model, 8));
        }
        var high = List.of(new FunctionSymbol("high", 0xfffffff0L, 16));
        plan(0xfffffff0L, CallSitePlan.Completeness.PARTIAL,
            new CallSitePlan.Site(0xfffffffaL, 0xffffffffL, false, null, List.of())).validate(high, null, 4);
        checks++;
        var overflow = plan(0xfffffff0L, CallSitePlan.Completeness.PARTIAL,
            new CallSitePlan.Site(0xfffffffbL, 0x100000000L, false, null, List.of()));
        reject(() -> overflow.validate(high, null, 4));
        overflow.validate(high, null, 8);
        checks++;

        var integer = new TypeGraph.TypeRef("int");
        var hidden = new ProgramTypeModel.FunctionSignature("callee", 0x200, integer,
            List.of(new TypeGraph.Parameter("value", integer, true, true)), List.of(), false, false, "default", "USER_DEFINED");
        var hiddenModel = new ProgramTypeModel(graph, List.of(hidden), List.of());
        reject(() -> plan(0x100, CallSitePlan.Completeness.PARTIAL,
            new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(argument))).validate(symbols, hiddenModel, 8));
        var narrow = new CallSitePlan.Argument(0, "value", "int", 5, new CallValue.Literal(42, 4));
        plan(0x100, CallSitePlan.Completeness.PARTIAL,
            new CallSitePlan.Site(0x110, 0x115, false, 0x200L, List.of(narrow))).validate(symbols, model, 4);
        checks++;

        var mutableArguments = new java.util.ArrayList<>(List.of(
            new CallSitePlan.Argument(1, "second", "int", 4, argument.value()), argument));
        var ordered = new CallSitePlan.Site(0x210, 0x215, false, 0x300L, mutableArguments);
        mutableArguments.clear();
        equal(List.of(0, 1), ordered.arguments().stream().map(CallSitePlan.Argument::ordinal).toList());
        var mutableFunctions = new java.util.ArrayList<>(List.of(
            new CallSitePlan.FunctionCalls(0x200, CallSitePlan.Completeness.ALL_CALLS, List.of(ordered)), first));
        var sorted = new CallSitePlan(mutableFunctions);
        mutableFunctions.clear();
        equal(List.of(0x100L, 0x200L), sorted.functions().stream().map(CallSitePlan.FunctionCalls::caller).toList());
        equal(2, sorted.functions().get(1).sites().getFirst().arguments().size());
        System.out.println("call-site-plan-boundaries=PASS checks=" + (checks - before));
    }

    private static CallSitePlan plan(long owner, CallSitePlan.Completeness completeness, CallSitePlan.Site site) {
        return new CallSitePlan(List.of(new CallSitePlan.FunctionCalls(owner, completeness, List.of(site))));
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }

    private static void reject(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid plan accepted");
        }
        catch (IllegalArgumentException expected) {
            // Admission failures must stay outside native production.
            checks++;
        }
    }
}
