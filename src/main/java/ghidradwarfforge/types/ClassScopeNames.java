package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Synthetic C lookup aliases must never replace another curated type identity. */
public final class ClassScopeNames {
    public record Alias(long classId, String name) { }
    public record Plan(Map<Long, String> names, List<Alias> aliases, List<String> diagnostics) {
        public Plan {
            names = Map.copyOf(names);
            aliases = List.copyOf(aliases);
            diagnostics = List.copyOf(diagnostics);
        }
    }

    private record TypeIdentity(String key) { }
    private record UnboundIdentity(long classId) { }

    private ClassScopeNames() { }

    public static Plan build(TypeGraph graph, ClassScopeModel scopes) {
        var types = graph.byKey();
        var bindings = new HashMap<Long, ClassScopeModel.Binding>();
        for (var binding : scopes.bindings()) bindings.put(binding.classId(), binding);
        var occupied = new HashMap<String, HashSet<Object>>();
        for (var type : graph.nodes()) {
            if (!type.name().isBlank()) occupied.computeIfAbsent(type.name(), ignored -> new HashSet<>()).add(new TypeIdentity(type.key()));
        }
        var paths = new HashMap<Long, String>();
        paths.put(0L, "");
        var names = new LinkedHashMap<Long, String>();
        var candidates = new ArrayList<Alias>();
        var diagnostics = new ArrayList<String>();
        for (var scope : scopes.scopes()) {
            String prefix = paths.get(scope.parent());
            String qualified = prefix.isEmpty() ? scope.name() : prefix + "::" + scope.name();
            paths.put(scope.id(), qualified);
            if (scope.kind() != ClassScopeModel.Kind.CLASS) continue;
            var binding = bindings.get(scope.id());
            String name;
            if (binding == null) {
                name = qualified;
                if (occupied.containsKey(name)) {
                    name = "__ghidra_class_scope_" + scope.id();
                    while (occupied.containsKey(name)) name += "_";
                    diagnostics.add("Unbound class symbol " + scope.id() + " uses synthetic lookup name " + name +
                        ": its scope spelling conflicts with a curated type; no layout is inferred");
                }
                occupied.computeIfAbsent(name, ignored -> new HashSet<>()).add(unboundKey(scope.id()));
            }
            else name = types.get(binding.type().key()).name();
            names.put(scope.id(), name);
            if (binding != null && !scope.name().equals(name)) candidates.add(new Alias(scope.id(), scope.name()));
            if (!qualified.equals(name) && (binding == null || !qualified.equals(scope.name()))) {
                candidates.add(new Alias(scope.id(), qualified));
            }
        }
        var claims = new HashMap<String, HashSet<Long>>();
        for (Alias alias : candidates) claims.computeIfAbsent(alias.name(), ignored -> new HashSet<>()).add(alias.classId());
        var aliases = new ArrayList<Alias>();
        for (Alias alias : candidates.stream().sorted(Comparator.comparing(Alias::name).thenComparingLong(Alias::classId)).toList()) {
            var binding = bindings.get(alias.classId());
            Object key = binding == null ? unboundKey(alias.classId()) : new TypeIdentity(binding.type().key());
            var existing = occupied.get(alias.name());
            if (claims.get(alias.name()).size() > 1 || (existing != null && !existing.equals(java.util.Set.of(key)))) {
                diagnostics.add("Omitted class lookup alias " + alias.name() + " for symbol " + alias.classId() +
                    ": spelling conflicts with another type/class identity; canonical types and saved ownership are retained");
            }
            else if (existing == null) aliases.add(alias);
        }
        return new Plan(names, aliases, diagnostics);
    }

    private static UnboundIdentity unboundKey(long id) { return new UnboundIdentity(id); }
}
