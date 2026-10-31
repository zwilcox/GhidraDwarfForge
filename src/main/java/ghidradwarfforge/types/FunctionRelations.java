package ghidradwarfforge.types;

import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import ghidradwarfforge.types.ClassScopeModel.FunctionReference;

/** Saved control-transfer identity; it does not inherit source, locals or parameter locations. */
public record FunctionRelations(List<Thunk> thunks) {
    public record Thunk(long id, FunctionReference function, long targetId,
            FunctionReference target, String evidence) {
        public Thunk {
            if (id <= 0 || targetId <= 0 || id == targetId || function == null || target == null ||
                    !function.declarationKey().isEmpty() || function.equals(target) ||
                    (target.declarationKey().isEmpty() && function.address() == target.address()) ||
                    evidence == null || evidence.isBlank()) throw invalid("invalid thunk identity");
        }
    }

    public static FunctionRelations empty() { return new FunctionRelations(List.of()); }

    public FunctionRelations {
        if (thunks == null || thunks.size() > 65536) throw invalid("missing or excessive thunk relationships");
        var identities = new HashMap<Long, FunctionReference>();
        var inverse = new HashMap<FunctionReference, Long>();
        var edges = new HashMap<FunctionReference, FunctionReference>();
        for (var thunk : thunks) {
            if (thunk == null) throw invalid("null thunk");
            for (var item : List.of(java.util.Map.entry(thunk.id(), thunk.function()),
                    java.util.Map.entry(thunk.targetId(), thunk.target()))) {
                var old = identities.putIfAbsent(item.getKey(), item.getValue());
                var oldId = inverse.putIfAbsent(item.getValue(), item.getKey());
                if ((old != null && !old.equals(item.getValue())) || (oldId != null && !oldId.equals(item.getKey()))) {
                    throw invalid("conflicting saved function identity");
                }
            }
            if (edges.put(thunk.function(), thunk.target()) != null) throw invalid("duplicate thunk origin");
        }
        var done = new HashSet<FunctionReference>();
        for (var start : edges.keySet()) {
            var path = new HashSet<FunctionReference>();
            var current = start;
            while (current != null && !done.contains(current)) {
                if (!path.add(current)) throw invalid("cyclic thunk graph");
                current = edges.get(current);
            }
            done.addAll(path);
        }
        thunks = thunks.stream().sorted(Comparator.comparingLong((Thunk t) -> t.function().address())
            .thenComparingLong(Thunk::id)).toList();
    }

    public void validate(List<ProgramTypeModel.FunctionSignature> functions,
            List<ProgramTypeModel.FunctionDeclaration> declarations) {
        var available = new HashSet<FunctionReference>();
        for (var function : functions) available.add(FunctionReference.definition(function.name(), function.address()));
        for (var declaration : declarations) available.add(FunctionReference.declaration(declaration.name(), declaration.key()));
        for (var thunk : thunks) {
            if (!available.contains(thunk.function()) || !available.contains(thunk.target())) {
                throw invalid("thunk relationship references an absent function");
            }
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}
