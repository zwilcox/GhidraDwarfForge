package ghidradwarfforge.output;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission;
import ghidradwarfforge.coverage.TypeGraphEvidence;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Definition two: shared graph plus roots, avoiding repeated per-function graph serialization. */
public record CoverageTypeEvidence(TypeGraphEvidence graph, Map<Long, Roots> functions) {
    public record Roots(List<TypeRef> recovered, List<TypeRef> emitted) {
        public Roots {
            recovered = List.copyOf(recovered);
            emitted = List.copyOf(emitted);
        }
    }

    public CoverageTypeEvidence {
        java.util.Objects.requireNonNull(graph);
        functions = Collections.unmodifiableMap(new TreeMap<>(functions));
    }

    public static CoverageTypeEvidence capture(ProgramTypeModel model, ExportEmission actual,
            ExportCoverage coverage, BooleanSupplier cancelled) {
        check(cancelled);
        var graph = TypeGraphEvidence.capture(model == null ? new TypeGraph(List.of()) : model.types(),
            actual.typeReferences(), cancelled);
        var signatures = new HashMap<Long, ProgramTypeModel.FunctionSignature>();
        if (model != null) {
            for (var signature : model.functions()) { check(cancelled); signatures.put(signature.address(), signature); }
        }
        var emitted = new HashMap<Long, ExportEmission.FunctionEmission>();
        for (var function : actual.functions()) { check(cancelled); emitted.put(function.function().address(), function); }
        var roots = new TreeMap<Long, Roots>();
        for (var function : coverage.functions()) {
            check(cancelled);
            var recovered = new ArrayList<TypeRef>();
            var signature = signatures.get(function.function().address());
            if (signature != null) {
                recovered.add(signature.returnType());
                for (var variable : function.variables().variables()) { check(cancelled); recovered.add(variable.recoveredType()); }
            }
            roots.put(function.function().address(), new Roots(unique(recovered, cancelled),
                unique(emitted.get(function.function().address()).typeRoots(), cancelled)));
        }
        var evidence = new CoverageTypeEvidence(graph, roots);
        evidence.validate(coverage, cancelled);
        return evidence;
    }

    /** Counts must follow the reported graph, without authenticating its claims against artifacts. */
    public void validate(ExportCoverage coverage, BooleanSupplier cancelled) {
        check(cancelled);
        if (functions.size() != coverage.functions().size()) throw new IllegalArgumentException("type root owner count differs");
        var allRecovered = new ArrayList<TypeRef>();
        var allEmitted = new ArrayList<TypeRef>();
        for (var function : coverage.functions()) {
            check(cancelled);
            Roots roots = functions.get(function.function().address());
            if (roots == null) throw new IllegalArgumentException("missing type root owner");
            requireCanonical(roots.recovered(), cancelled);
            requireCanonical(roots.emitted(), cancelled);
            if (function.types() == null) {
                if (!roots.recovered().isEmpty() || !roots.emitted().isEmpty()) {
                    throw new IllegalArgumentException("unknown signature supplies type roots");
                }
                continue;
            }
            if (!graph.inspect(roots.recovered(), roots.emitted(), cancelled).totals().equals(function.types())) {
                throw new IllegalArgumentException("function type counts differ from graph");
            }
            var recovered = new java.util.HashSet<>(roots.recovered());
            var attached = new java.util.HashSet<>(roots.emitted());
            for (var variable : function.variables().variables()) {
                check(cancelled);
                if (!recovered.contains(variable.recoveredType()) ||
                        variable.emittedType() != null && !attached.contains(variable.emittedType())) {
                    throw new IllegalArgumentException("variable type missing from function roots");
                }
            }
            allRecovered.addAll(roots.recovered());
            allEmitted.addAll(roots.emitted());
        }
        if (!graph.inspect(allRecovered, allEmitted, cancelled).totals().equals(coverage.functionTypeUnion())) {
            throw new IllegalArgumentException("type union differs from graph");
        }
        for (var global : coverage.recoveredGlobals()) {
            check(cancelled);
            if (!graph.nodes().containsKey(global.type().key())) throw new IllegalArgumentException("unknown global type root");
        }
    }

    private static List<TypeRef> unique(List<TypeRef> supplied, BooleanSupplier cancelled) {
        var roots = new TreeMap<String, TypeRef>();
        for (TypeRef root : supplied) { check(cancelled); roots.put(root.key(), root); }
        return List.copyOf(roots.values());
    }
    private static void requireCanonical(List<TypeRef> roots, BooleanSupplier cancelled) {
        String previous = null;
        for (TypeRef root : roots) {
            check(cancelled);
            if (previous != null && previous.compareTo(root.key()) >= 0) throw new IllegalArgumentException("noncanonical type roots");
            previous = root.key();
        }
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("type report evidence cancelled");
    }
}
