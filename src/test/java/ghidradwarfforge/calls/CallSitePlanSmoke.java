package ghidradwarfforge.calls;

import java.util.List;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Rejects stale call/formal identities before the native producer is entered. */
public final class CallSitePlanSmoke {
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
        System.out.println("PASS_CALL_SITE_PLAN rejected=12 deterministic-order-and-ownership=PASS");
    }

    private static void reject(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid plan accepted");
        }
        catch (IllegalArgumentException expected) {
            // Admission failures must stay outside native production.
        }
    }
}
