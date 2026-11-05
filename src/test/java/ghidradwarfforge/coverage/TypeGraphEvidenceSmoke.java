package ghidradwarfforge.coverage;

import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Individual state transitions, exact edge multiplicity and bounded iterative graph work. */
public final class TypeGraphEvidenceSmoke {
    private static int checks;
    public static void main(String[] args) {
        var before = graph(false);
        var after = graph(true);
        var old = TypeGraphEvidence.capture(before, actual(before), () -> false);
        var next = TypeGraphEvidence.capture(after, actual(after), () -> false);
        var roots = List.of(new TypeRef("root"));
        var a = old.inspect(roots, roots, () -> false);
        var b = next.inspect(roots, roots, () -> false);
        require(a.totals().equals(b.totals()), "fixture must have equal aggregate counts");
        require(a.states().get("a") == TypeGraphEvidence.State.RESOLVED && b.states().get("a") == TypeGraphEvidence.State.OPAQUE &&
            a.states().get("b") == TypeGraphEvidence.State.OPAQUE && b.states().get("b") == TypeGraphEvidence.State.RESOLVED,
            "offsetting type changes hid individual regression");
        require(a.totals().equals(new TypeCoverage(1, 1, 0, 3, 2, 1, 0, 0, 0)), "hand-counted node populations");
        require(old.nodes().get("root").recoveredReferences().equals(Map.of("a", 2, "b", 1)), "duplicate member edges lost");
        var omitted = actual(before);
        omitted.put("root", List.of(new TypeRef("a"), new TypeRef("b")));
        var fewerEdges = TypeGraphEvidence.capture(before, omitted, () -> false);
        require(fewerEdges.nodes().get("root").emittedReferences().get("a") == 1 &&
            fewerEdges.inspect(roots, roots, () -> false).states().equals(a.states()), "missing repeated edge lost from evidence");
        omitted.put("root", List.of(new TypeRef("a")));
        omitted.remove("b");
        var missing = TypeGraphEvidence.capture(before, omitted, () -> false).inspect(roots, roots, () -> false);
        require(missing.states().get("b") == TypeGraphEvidence.State.NOT_EMITTED && missing.totals().notEmittedNodes() == 1,
            "unrepresented type counted as emitted opaque");
        var unattached = old.inspect(roots, List.of(), () -> false);
        require(unattached.totals().notEmittedNodes() == 3 && unattached.totals().emittedRoots() == 0,
            "globally allocated nodes credited to symbol-only function");
        var voidRoots = List.of(new TypeRef("void"));
        require(old.inspect(voidRoots, voidRoots, () -> false).states().get("void") == TypeGraphEvidence.State.IMPLICIT_VOID,
            "implicit void fabricated a DIE");
        require(old.inspect(voidRoots, List.of(), () -> false).states().get("void") == TypeGraphEvidence.State.VOID_NOT_EMITTED,
            "unattached void counted as represented");
        var cycle = List.of(new TypeRef("cycle"));
        require(old.inspect(cycle, cycle, () -> false).totals().equals(new TypeCoverage(1, 1, 1, 1, 1, 0, 0, 0, 0)), "cycle did not terminate");
        for (var selected : List.of(roots, voidRoots, cycle, List.<TypeRef>of())) {
            require(old.inspect(selected, selected, () -> false).totals().equals(
                new TypeCoverageIndex(before, actual(before), () -> false).measure(selected, selected, () -> false)), "existing metric contract changed");
        }
        reject(() -> old.inspect(List.of(new TypeRef("missing")), List.of(), () -> false));
        reject(() -> old.inspect(roots, voidRoots, () -> false));
        reject(() -> TypeGraphEvidence.capture(before, Map.of("missing", List.of()), () -> false));
        var dangling = actual(before);
        dangling.remove("a");
        reject(() -> TypeGraphEvidence.capture(before, dangling, () -> false));
        var extra = actual(before);
        extra.put("root", List.of(new TypeRef("a"), new TypeRef("a"), new TypeRef("a"), new TypeRef("b")));
        reject(() -> TypeGraphEvidence.capture(before, extra, () -> false));
        reject(() -> TypeGraphEvidence.of(List.of(old.nodes().get("a"), old.nodes().get("a")), () -> false));
        var counts = new AtomicInteger();
        TypeGraphEvidence.capture(before, actual(before), () -> { counts.incrementAndGet(); return false; });
        for (int i = 1; i <= counts.get(); i++) {
            int stop = i;
            var position = new AtomicInteger();
            cancel(() -> TypeGraphEvidence.capture(before, actual(before), () -> position.incrementAndGet() >= stop));
        }
        int constructionPoints = counts.get();
        counts.set(0);
        old.inspect(roots, roots, () -> { counts.incrementAndGet(); return false; });
        for (int i = 1; i <= counts.get(); i++) {
            int stop = i;
            var position = new AtomicInteger();
            cancel(() -> old.inspect(roots, roots, () -> position.incrementAndGet() >= stop));
        }
        int viewPoints = counts.get();
        var nodes = new ArrayList<TypeNode>();
        var allRoots = new ArrayList<TypeRef>();
        int depth = 20000;
        nodes.add(new BaseType("end", "int", 4, BaseEncoding.SIGNED));
        for (int i = 0; i < depth; i++) {
            String key = "node" + i;
            nodes.add(new IndirectionType(key, key, 8, IndirectionKind.POINTER, new TypeRef(i + 1 == depth ? "end" : "node" + (i + 1))));
            allRoots.add(new TypeRef(key));
        }
        var deep = new TypeGraph(nodes);
        var deepEvidence = TypeGraphEvidence.capture(deep, actual(deep), () -> false);
        counts.set(0);
        var deepView = deepEvidence.inspect(allRoots, allRoots, () -> {
            if (counts.incrementAndGet() > 40 * depth) throw new AssertionError("rescanned shared subgraphs per root");
            return false;
        });
        require(deepView.states().size() == depth + 1 && deepView.totals().resolvedEmittedNodes() == depth + 1, "deep shared graph counts");
        try { old.nodes().clear(); throw new AssertionError("mutable node dictionary"); }
        catch (UnsupportedOperationException expected) { }
        try { old.nodes().get("root").emittedReferences().clear(); throw new AssertionError("mutable references"); }
        catch (UnsupportedOperationException expected) { }
        System.out.println("type-graph-evidence=PASS checks=" + checks + " cancellation-points=" + constructionPoints + "/" + viewPoints +
            " deep-checkpoints=" + counts.get());
    }

    private static TypeGraph graph(boolean swap) {
        TypeNode a = swap ? new OpaqueType("a", "A", 4, "new unresolved layout") : new BaseType("a", "A", 4, BaseEncoding.SIGNED);
        TypeNode b = swap ? new BaseType("b", "B", 4, BaseEncoding.SIGNED) : new OpaqueType("b", "B", 4, "old unresolved layout");
        return new TypeGraph(List.of(a, b, new VoidType("void"),
            new IndirectionType("cycle", "recursive pointer", 8, IndirectionKind.POINTER, new TypeRef("cycle")),
            new AggregateType("root", "Root", 12, AggregateKind.STRUCTURE, List.of(
                new Member("first", new TypeRef("a"), 0), new Member("second", new TypeRef("a"), 4), new Member("third", new TypeRef("b"), 8)))));
    }
    private static Map<String, List<TypeRef>> actual(TypeGraph graph) {
        var result = new HashMap<String, List<TypeRef>>();
        for (TypeNode node : graph.nodes()) result.put(node.key(), node.references());
        return result;
    }
    private static void reject(Runnable action) {
        try { action.run(); } catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("inconsistent type evidence admitted");
    }
    private static void cancel(Runnable action) {
        try { action.run(); } catch (CancellationException expected) { return; }
        throw new AssertionError("type evidence cancellation ignored");
    }
    private static void require(boolean value, String message) { checks++; if (!value) throw new AssertionError(message); }
}
