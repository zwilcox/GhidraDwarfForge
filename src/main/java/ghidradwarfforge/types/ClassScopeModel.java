package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Saved ownership and separately evidenced class layout; never a location proof. */
public record ClassScopeModel(List<Scope> scopes, List<Binding> bindings, List<Method> methods) {
    public enum Kind { NAMESPACE, CLASS }

    /** An inference is a current snapshot, not a durable class/type identity. */
    public enum BindingSource { EXPLICIT_SAVED, CURRENT_AUTO_THIS }

    /** Zero parent denotes the CU/global namespace. Names are not identity keys. */
    public record Scope(long id, long parent, String name, Kind kind) {
        public Scope {
            if (id <= 0 || parent < 0 || id == parent || kind == null) throw invalid("invalid scope identity");
            text(name);
        }
    }

    public record Binding(long classId, TypeRef type, BindingSource source, String evidence) {
        public Binding {
            if (classId <= 0 || type == null || source == null) throw invalid("invalid class binding");
            text(evidence);
        }
    }

    /** External declarations have an explicit key and no image address. */
    public record FunctionReference(String name, long address, String declarationKey) {
        public FunctionReference {
            text(name);
            if (declarationKey == null || (declarationKey.isEmpty() ? address < 0 :
                    address != -1 || declarationKey.isBlank())) throw invalid("invalid method target");
        }

        public static FunctionReference definition(String name, long address) {
            return new FunctionReference(name, address, "");
        }

        public static FunctionReference declaration(String name, String key) {
            return new FunctionReference(name, -1, key);
        }
    }

    /** The saved function ID ties the class declaration to its exact definition. */
    public record Method(long id, long classId, String name, FunctionReference function) {
        public Method {
            if (id <= 0 || classId <= 0 || function == null) throw invalid("invalid method identity");
            text(name);
        }
    }

    public static ClassScopeModel empty() {
        return new ClassScopeModel(List.of(), List.of(), List.of());
    }

    public ClassScopeModel {
        if (scopes == null || bindings == null || methods == null) throw invalid("missing class model lists");
        var byId = new HashMap<Long, Scope>();
        for (Scope scope : scopes) {
            if (scope == null || byId.put(scope.id(), scope) != null) throw invalid("duplicate scope identity");
        }
        // Iterative topological ordering also detects cycles without recursing
        // through arbitrarily deep namespace/class hierarchies.
        var children = new HashMap<Long, List<Scope>>();
        var ready = new PriorityQueue<Scope>(Comparator.comparing(Scope::name).thenComparingLong(Scope::id));
        for (Scope scope : scopes) {
            if (scope.parent() == 0) ready.add(scope);
            else {
                if (!byId.containsKey(scope.parent())) throw invalid("missing scope parent");
                children.computeIfAbsent(scope.parent(), ignored -> new ArrayList<>()).add(scope);
            }
        }
        var ordered = new ArrayList<Scope>();
        while (!ready.isEmpty()) {
            var scope = ready.remove();
            ordered.add(scope);
            ready.addAll(children.getOrDefault(scope.id(), List.of()));
        }
        if (ordered.size() != scopes.size()) throw invalid("cyclic scope ownership");
        scopes = List.copyOf(ordered);
        var boundClasses = new HashSet<Long>();
        var boundTypes = new HashSet<String>();
        for (Binding binding : bindings) {
            if (binding == null) throw invalid("null class binding");
            requireClass(byId, binding.classId());
            if (!boundClasses.add(binding.classId()) || !boundTypes.add(binding.type().key())) {
                throw invalid("conflicting class/type identity");
            }
        }
        bindings = bindings.stream().sorted(Comparator.comparingLong(Binding::classId)).toList();
        var methodIds = new HashSet<Long>();
        var targets = new HashSet<FunctionReference>();
        for (Method method : methods) {
            if (method == null) throw invalid("null method");
            requireClass(byId, method.classId());
            if (byId.containsKey(method.id()) || !methodIds.add(method.id()) || !targets.add(method.function())) {
                throw invalid("conflicting saved method identity");
            }
        }
        methods = methods.stream().sorted(Comparator.comparingLong(Method::classId)
            .thenComparing(Method::name).thenComparingLong(Method::id)).toList();
    }

    /** Validate actual referenced signatures/types, without matching their spellings. */
    public void validate(TypeGraph graph, List<ProgramTypeModel.FunctionSignature> functions,
            List<ProgramTypeModel.FunctionDeclaration> declarations) {
        var types = graph.byKey();
        var byClass = new HashMap<Long, Binding>();
        for (Binding binding : bindings) {
            var type = types.get(binding.type().key());
            if (!(type instanceof TypeGraph.AggregateType aggregate) ||
                    aggregate.kind() != TypeGraph.AggregateKind.STRUCTURE) {
                throw invalid("class binding requires a canonical structure type");
            }
            byClass.put(binding.classId(), binding);
        }
        var signatures = new HashMap<FunctionReference, List<TypeGraph.Parameter>>();
        var ambiguous = new HashSet<FunctionReference>();
        if (!methods.isEmpty()) {
            for (var function : functions) {
                var reference = FunctionReference.definition(function.name(), function.address());
                if (signatures.putIfAbsent(reference, function.parameters()) != null) ambiguous.add(reference);
            }
            for (var declaration : declarations) {
                var reference = FunctionReference.declaration(declaration.name(), declaration.key());
                if (signatures.putIfAbsent(reference, declaration.parameters()) != null) ambiguous.add(reference);
            }
        }
        var witnessed = new HashSet<Long>();
        for (Method method : methods) {
            FunctionReference reference = method.function();
            List<TypeGraph.Parameter> parameters = signatures.get(reference);
            if (parameters == null || ambiguous.contains(reference)) throw invalid("method has no unique signature");
            Binding binding = byClass.get(method.classId());
            if (binding == null) continue; // Ownership alone cannot establish a class layout.
            for (var parameter : parameters) {
                if (!parameter.objectPointer()) continue;
                var pointer = unqualified(parameter.type(), types);
                if (!(pointer instanceof TypeGraph.IndirectionType indirection)) {
                    throw invalid("method object has no pointer/reference type");
                }
                var object = unqualified(indirection.target(), types);
                if (!object.key().equals(binding.type().key())) {
                    throw invalid("class layout conflicts with current object parameter type");
                }
                witnessed.add(binding.classId());
            }
        }
        for (Binding binding : bindings) {
            if (binding.source() == BindingSource.CURRENT_AUTO_THIS && !witnessed.contains(binding.classId())) {
                throw invalid("inferred class layout has no current object parameter witness");
            }
        }
    }

    private static TypeGraph.TypeNode unqualified(TypeRef reference, Map<String, TypeGraph.TypeNode> types) {
        var visited = new HashSet<String>();
        while (visited.add(reference.key())) {
            var node = types.get(reference.key());
            if (node instanceof TypeGraph.QualifiedType qualified) reference = qualified.target();
            else if (node instanceof TypeGraph.TypedefType typedef) reference = typedef.target();
            else if (node != null) return node;
            else throw invalid("missing object type");
        }
        throw invalid("cyclic object type qualifiers");
    }

    private static void requireClass(Map<Long, Scope> scopes, long id) {
        if (!scopes.containsKey(id) || scopes.get(id).kind() != Kind.CLASS) throw invalid("owner is not a recorded class");
    }

    private static void text(String value) {
        if (value == null || value.isBlank() || value.indexOf('\0') >= 0) throw invalid("missing or invalid class text");
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}
