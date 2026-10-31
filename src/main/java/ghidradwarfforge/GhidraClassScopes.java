package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.ClassScopeModel.Binding;
import ghidradwarfforge.types.ClassScopeModel.BindingSource;
import ghidradwarfforge.types.ClassScopeModel.FunctionReference;
import ghidradwarfforge.types.ClassScopeModel.Kind;
import ghidradwarfforge.types.ClassScopeModel.Method;
import ghidradwarfforge.types.ClassScopeModel.Scope;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Collect saved ownership without treating current THIS inference as durable identity. */
final class GhidraClassScopes {
    private final Program program;
    private final TaskMonitor monitor;
    private final Consumer<String> diagnostic;
    private final Map<Long, Scope> scopes = new LinkedHashMap<>();
    private final List<Method> methods = new ArrayList<>();
    private final Map<Long, List<TypeGraph.Parameter>> parameters = new HashMap<>();
    private final Map<Long, Binding> explicit = new HashMap<>();
    private final HashSet<Long> rejected = new HashSet<>();

    GhidraClassScopes(Program program, TaskMonitor monitor, Consumer<String> diagnostic) {
        this.program = program;
        this.monitor = monitor;
        this.diagnostic = diagnostic;
    }

    void record(Function function, FunctionReference reference, List<TypeGraph.Parameter> signature)
            throws CancelledException {
        monitor.checkCancelled();
        if (!(function.getParentNamespace() instanceof GhidraClass owner)) return;
        if (!retain(owner)) return;
        methods.add(new Method(function.getID(), owner.getID(), function.getName(), reference));
        parameters.put(function.getID(), List.copyOf(signature));
    }

    /** Reserve explicit layouts before draining the canonical type graph. */
    void prepare(java.util.function.Function<DataType, TypeRef> reserve) throws CancelledException {
        var classes = program.getSymbolTable().getClassNamespaces();
        while (classes.hasNext()) {
            monitor.checkCancelled();
            var owner = classes.next();
            var result = GhidraClassBindings.read(program, owner.getID(), monitor, diagnostic);
            if (result.status() == GhidraClassBindings.Status.REJECTED) rejected.add(owner.getID());
            if (result.status() != GhidraClassBindings.Status.VALID || !retain(owner)) continue;
            explicit.put(owner.getID(), new Binding(owner.getID(), reserve.apply(result.binding().type()),
                BindingSource.EXPLICIT_SAVED, result.binding().evidence()));
        }
    }

    ClassScopeModel finish(TypeGraph graph) throws CancelledException {
        var types = graph.byKey();
        var witnesses = new HashMap<Long, HashSet<TypeRef>>();
        var invalidObjects = new HashSet<Long>();
        for (Method method : methods) {
            monitor.checkCancelled();
            for (var parameter : parameters.get(method.id())) {
                monitor.checkCancelled();
                if (!parameter.objectPointer()) continue;
                var pointer = unqualified(parameter.type(), types);
                var object = pointer instanceof TypeGraph.IndirectionType indirection
                    ? unqualified(indirection.target(), types) : null;
                if (!(object instanceof TypeGraph.AggregateType aggregate) ||
                        aggregate.kind() != TypeGraph.AggregateKind.STRUCTURE) {
                    invalidObjects.add(method.classId());
                    continue;
                }
                witnesses.computeIfAbsent(method.classId(), ignored -> new HashSet<>()).add(new TypeRef(object.key()));
            }
        }
        var candidates = new ArrayList<Binding>();
        for (Scope scope : scopes.values()) {
            monitor.checkCancelled();
            if (scope.kind() != Kind.CLASS || rejected.contains(scope.id())) continue;
            var objects = witnesses.getOrDefault(scope.id(), new HashSet<>());
            Binding binding = explicit.get(scope.id());
            if (invalidObjects.contains(scope.id()) || objects.size() > 1 ||
                    (binding != null && !objects.isEmpty() && !objects.contains(binding.type()))) {
                omit(scope.id(), "current method object types contradict the class layout");
                continue;
            }
            if (binding != null) candidates.add(binding);
            else if (objects.size() == 1) {
                TypeRef type = objects.iterator().next();
                var aggregate = (TypeGraph.AggregateType) types.get(type.key());
                // Empty/generated placeholder structures do not establish a layout.
                // An explicit binding can still intentionally describe an empty class.
                if (aggregate.byteSize() <= 0 || aggregate.members().isEmpty()) {
                    omit(scope.id(), "automatic object type has no evidenced member layout");
                    continue;
                }
                candidates.add(new Binding(scope.id(), type, BindingSource.CURRENT_AUTO_THIS,
                    "Current Ghidra automatic THIS type; inferred, not a saved class/type identity"));
            }
        }
        var byType = new HashMap<String, List<Binding>>();
        for (Binding candidate : candidates) {
            byType.computeIfAbsent(candidate.type().key(), ignored -> new ArrayList<>()).add(candidate);
        }
        var uniqueExplicit = new HashMap<String, Binding>();
        for (var entry : byType.entrySet()) {
            monitor.checkCancelled();
            var saved = entry.getValue().stream().filter(b -> b.source() == BindingSource.EXPLICIT_SAVED).toList();
            if (saved.size() == 1) uniqueExplicit.put(entry.getKey(), saved.getFirst());
        }
        var bindings = new ArrayList<Binding>();
        for (Binding candidate : candidates) {
            monitor.checkCancelled();
            var owners = byType.get(candidate.type().key());
            if (owners.size() == 1) bindings.add(candidate);
            else {
                if (candidate == uniqueExplicit.get(candidate.type().key())) bindings.add(candidate);
                else omit(candidate.classId(), "canonical layout is claimed by multiple classes");
            }
        }
        var result = new ClassScopeModel(new ArrayList<>(scopes.values()), bindings, methods);
        for (String message : ghidradwarfforge.types.ClassScopeNames.build(graph, result).diagnostics()) {
            monitor.checkCancelled();
            diagnostic.accept(message);
        }
        return result;
    }

    /** Keep actual namespace ancestry; a library is a linkage container, not a source namespace. */
    private boolean retain(Namespace owner) throws CancelledException {
        var pending = new ArrayList<Namespace>();
        var visited = new HashSet<Long>();
        Namespace current = owner;
        while (!current.isGlobal() && !current.isLibrary() && !scopes.containsKey(current.getID())) {
            monitor.checkCancelled();
            if (!visited.add(current.getID()) || current.getSymbol().getProgram() != program ||
                    (current.getSymbol().getSymbolType() != SymbolType.NAMESPACE &&
                    current.getSymbol().getSymbolType() != SymbolType.CLASS)) {
                omit(owner.getID(), "unsupported or cyclic saved namespace ancestry");
                return false;
            }
            pending.add(current);
            current = current.getParentNamespace();
            if (current == null) {
                omit(owner.getID(), "missing saved namespace parent");
                return false;
            }
        }
        long parent = current.isGlobal() || current.isLibrary() ? 0 : current.getID();
        for (int index = pending.size() - 1; index >= 0; index--) {
            monitor.checkCancelled();
            Namespace scope = pending.get(index);
            scopes.put(scope.getID(), new Scope(scope.getID(), parent, scope.getName(),
                scope instanceof GhidraClass ? Kind.CLASS : Kind.NAMESPACE));
            parent = scope.getID();
        }
        return true;
    }

    private TypeGraph.TypeNode unqualified(TypeRef reference, Map<String, TypeGraph.TypeNode> types)
            throws CancelledException {
        var visited = new HashSet<String>();
        while (visited.add(reference.key())) {
            monitor.checkCancelled();
            var type = types.get(reference.key());
            if (type instanceof TypeGraph.TypedefType alias) reference = alias.target();
            else if (type instanceof TypeGraph.QualifiedType qualified) reference = qualified.target();
            else return type;
        }
        return null;
    }

    private void omit(long classId, String reason) {
        diagnostic.accept("Omitted class layout for symbol " + classId + ": " + reason +
            "; saved ownership and current method types are retained");
    }
}
