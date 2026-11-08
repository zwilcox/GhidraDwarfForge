package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Hand-counted graph fixtures. Serialized DIE/GDB evidence remains a separate gate. */
public final class TypeCoverageSmoke {
    private static int checks;

    public static void main(String[] args) {
        TypeGraph graph = new TypeGraph(List.of(
            new VoidType("void"),
            new BaseType("int", "int", 4, BaseEncoding.SIGNED),
            new OpaqueType("opaque", "missing", 0, "unresolved target"),
            pointer("pointer", "opaque"),
            new TypedefType("alias", "alias", 8, ref("pointer")),
            new AggregateType("recursive", "node", 16, AggregateKind.STRUCTURE,
                List.of(new Member("value", ref("int"), 0), new Member("next", ref("next"), 8))),
            pointer("next", "recursive"),
            pointer("voidPointer", "void"),
            new QualifiedType("qualified", "const volatile int", 4,
                List.of(Qualifier.CONST, Qualifier.VOLATILE), ref("int")),
            new ArrayType("array", "int[3]", 12, ref("qualified"), 3),
            new EnumType("enum", "choice", 4, true, List.of(new Enumerator("one", 1))),
            new AggregateType("pair", "pair", 8, AggregateKind.STRUCTURE,
                List.of(new Member("first", ref("int"), 0), new Member("second", ref("int"), 4))),
            new SubroutineType("callback", "callback", 0, ref("void"),
                List.of(new Parameter("array", ref("array"), false),
                    new Parameter("choice", ref("enum"), false)), false)));
        Map<String, List<TypeRef>> all = allReferences(graph);
        var index = new TypeCoverageIndex(graph, all, () -> false);
        List<TypeRef> roots = refs("pointer", "alias", "recursive", "void", "alias");
        var mixed = index.measure(roots, roots, () -> false);
        require(mixed.equals(new TypeCoverage(4, 4, 2, 6, 5, 1, 0, 1, 1)),
            "opaque pointer/alias do not hide the unresolved target; cycles terminate");
        require(mixed.emittedNodes() == 6 && mixed.applicable(), "canonical node denominator");
        require(index.measure(roots.reversed(), roots.reversed(), () -> false).equals(mixed),
            "ordering and duplicate roots do not affect counts");
        require(index.measure(roots, List.of(), () -> false)
            .equals(new TypeCoverage(4, 0, 0, 6, 0, 0, 6, 1, 0)),
            "global type allocation does not give a symbol-only function emitted roots");
        require(index.measure(roots, refs("recursive"), () -> false)
            .equals(new TypeCoverage(4, 1, 1, 6, 3, 0, 3, 1, 0)),
            "signature filtering retains recovered type denominator");
        var voidOnly = index.measure(refs("void"), refs("void"), () -> false);
        require(voidOnly.equals(new TypeCoverage(1, 1, 1, 0, 0, 0, 0, 1, 1)) && !voidOnly.applicable(),
            "void is represented implicitly, not invented as a DIE or 100 percent node coverage");
        require(index.measure(refs("voidPointer"), refs("voidPointer"), () -> false)
            .equals(new TypeCoverage(1, 1, 1, 1, 1, 0, 0, 1, 1)), "pointer-to-void semantics");
        require(!index.measure(List.of(), List.of(), () -> false).applicable(), "empty population N/A");
        require(index.measure(refs("callback"), refs("callback"), () -> false)
            .equals(new TypeCoverage(1, 1, 1, 5, 5, 0, 0, 1, 1)),
            "subroutine, array, qualifiers and enum counted as canonical nodes, not auxiliary DIEs");

        Map<String, List<TypeRef>> missingEdge = allReferences(graph);
        missingEdge.put("next", List.of());
        var broken = new TypeCoverageIndex(graph, missingEdge, () -> false);
        require(broken.measure(refs("recursive"), refs("recursive"), () -> false)
            .equals(new TypeCoverage(1, 1, 0, 3, 3, 0, 0, 0, 0)),
            "all nodes present does not hide a missing edge in a cycle");
        missingEdge.put("pointer", List.of());
        missingEdge.remove("opaque");
        var omitted = new TypeCoverageIndex(graph, missingEdge, () -> false);
        require(omitted.measure(refs("alias"), refs("alias"), () -> false)
            .equals(new TypeCoverage(1, 1, 0, 3, 2, 0, 1, 0, 0)),
            "missing pointee counted separately from an emitted opaque pointee");
        missingEdge.put("pair", refs("int"));
        require(new TypeCoverageIndex(graph, missingEdge, () -> false)
            .measure(refs("pair"), refs("pair"), () -> false)
            .equals(new TypeCoverage(1, 1, 0, 2, 2, 0, 0, 0, 0)),
            "a missing repeated member reference cannot disappear during node deduplication");
        Map<String, List<TypeRef>> snapshot = allReferences(graph);
        var mutableReferences = new ArrayList<>(snapshot.get("pointer"));
        snapshot.put("pointer", mutableReferences);
        var owned = new TypeCoverageIndex(graph, snapshot, () -> false);
        mutableReferences.clear();
        snapshot.clear();
        require(owned.measure(roots, roots, () -> false).equals(mixed), "index owns deep snapshots");

        reject(() -> index.measure(refs("unknown"), List.of(), () -> false));
        reject(() -> index.measure(refs("int"), refs("recursive"), () -> false));
        reject(() -> new TypeCoverageIndex(graph, Map.of(), () -> false)
            .measure(refs("int"), refs("int"), () -> false));
        reject(() -> new TypeCoverageIndex(graph, Map.of("unknown", List.of()), () -> false));
        reject(() -> new TypeCoverageIndex(graph, Map.of("pointer", refs("opaque")), () -> false));
        reject(() -> new TypeCoverageIndex(graph,
            Map.of("pointer", refs("int"), "int", List.of()), () -> false));
        reject(() -> new TypeCoverageIndex(graph,
            Map.of("pair", refs("int", "int", "int"), "int", List.of()), () -> false));
        reject(() -> new TypeCoverage(1, 1, 1, 1, 1, 1, 0, 0, 0));
        reject(() -> new TypeCoverage(1, 1, 1, Long.MAX_VALUE, Long.MAX_VALUE, 1, 0, 0, 0));
        cancel(() -> new TypeCoverageIndex(graph, all, () -> true));
        cancel(() -> index.measure(roots, roots, () -> true));
        AtomicInteger constructTicks = new AtomicInteger();
        cancel(() -> new TypeCoverageIndex(graph, all, () -> constructTicks.incrementAndGet() == 30));
        require(constructTicks.get() == 30, "construction cancels inside graph traversal");
        AtomicInteger measureTicks = new AtomicInteger();
        cancel(() -> index.measure(roots, roots, () -> measureTicks.incrementAndGet() == 25));
        require(measureTicks.get() == 25, "measurement cancels inside graph traversal");

        // More depth than the Java stack can safely traverse; many roots share a tail.
        List<TypeNode> deepNodes = new ArrayList<>();
        List<TypeRef> deepRoots = new ArrayList<>();
        int depth = 20_000;
        deepNodes.add(new BaseType("leaf", "int", 4, BaseEncoding.SIGNED));
        for (int i = depth - 1; i >= 0; i--) {
            String key = "chain" + i;
            deepNodes.add(pointer(key, i + 1 == depth ? "leaf" : "chain" + (i + 1)));
            deepRoots.add(ref(key));
        }
        var deep = new TypeGraph(deepNodes);
        var deepIndex = new TypeCoverageIndex(deep, allReferences(deep), () -> false);
        AtomicInteger linearWork = new AtomicInteger();
        require(deepIndex.measure(deepRoots, deepRoots, () -> {
            if (linearWork.incrementAndGet() > 20 * depth) {
                throw new AssertionError("coverage rescans shared subgraphs per root");
            }
            return false;
        }).equals(new TypeCoverage(depth, depth, depth, depth + 1, depth + 1, 0, 0, 0, 0)),
            "deep shared graph uses bounded iterative work");
        System.out.println("type coverage smoke passed: " + checks + " checks; deep traversal checkpoints=" +
            linearWork.get());
    }

    private static TypeRef ref(String key) {
        return new TypeRef(key);
    }

    private static List<TypeRef> refs(String... keys) {
        return java.util.Arrays.stream(keys).map(TypeCoverageSmoke::ref).toList();
    }

    private static IndirectionType pointer(String key, String target) {
        return new IndirectionType(key, key, 8, IndirectionKind.POINTER, ref(target));
    }

    private static Map<String, List<TypeRef>> allReferences(TypeGraph graph) {
        Map<String, List<TypeRef>> result = new HashMap<>();
        graph.nodes().forEach(node -> result.put(node.key(), node.references()));
        return result;
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        }
        catch (IllegalArgumentException expected) {
            checks++;
            return;
        }
        throw new AssertionError("invalid coverage evidence accepted");
    }

    private static void cancel(Runnable action) {
        try {
            action.run();
        }
        catch (CancellationException expected) {
            checks++;
            return;
        }
        throw new AssertionError("cancellation ignored");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
