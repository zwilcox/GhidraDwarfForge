package ghidradwarfforge.coverage;

import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import ghidradwarfforge.types.TypeGraph.VoidType;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Canonical recovered nodes and successful producer references, retained once per graph.
 * Keys identify reported definitions, not proof of historical identity across database forks.
 * Retained in metric definition two as one shared graph plus function roots.
 */
public final class TypeGraphEvidence {
    private static final Set<String> RESOLVED_DEFINITIONS = Set.of("BaseType", "IndirectionType", "QualifiedType",
        "ArrayType", "TypedefType", "EnumType", "AggregateType", "SubroutineType");
    public enum Kind { RESOLVED, OPAQUE, IMPLICIT_VOID }
    public enum State { RESOLVED, OPAQUE, NOT_EMITTED, IMPLICIT_VOID, VOID_NOT_EMITTED }

    public record Node(String key, String name, String definitionKind, long byteSize, Kind kind,
            boolean emitted, Map<String, Integer> recoveredReferences,
            Map<String, Integer> emittedReferences, String diagnostic) {
        public Node {
            if (key == null || key.isBlank() || name == null || name.isBlank() ||
                    definitionKind == null || definitionKind.isBlank() || byteSize < 0 || kind == null || diagnostic == null) {
                throw new IllegalArgumentException("invalid type evidence node");
            }
            boolean validKind = switch (kind) {
                case RESOLVED -> RESOLVED_DEFINITIONS.contains(definitionKind);
                case OPAQUE -> definitionKind.equals("OpaqueType");
                case IMPLICIT_VOID -> definitionKind.equals("VoidType") && byteSize == 0;
            };
            if (!validKind) throw new IllegalArgumentException("type kind differs from definition");
            recoveredReferences = owned(recoveredReferences);
            emittedReferences = owned(emittedReferences);
            if ((!emitted && !emittedReferences.isEmpty()) ||
                    (kind != Kind.RESOLVED && (!recoveredReferences.isEmpty() || !emittedReferences.isEmpty())) ||
                    (kind == Kind.OPAQUE ? diagnostic.isBlank() : !diagnostic.isEmpty())) {
                throw new IllegalArgumentException("inconsistent type node evidence");
            }
        }
        private static Map<String, Integer> owned(Map<String, Integer> references) {
            var copy = new TreeMap<String, Integer>();
            references.forEach((key, count) -> {
                if (key == null || key.isBlank() || count == null || count <= 0) {
                    throw new IllegalArgumentException("invalid type reference multiplicity");
                }
                copy.put(key, count);
            });
            return Collections.unmodifiableMap(copy);
        }
    }

    public record View(TypeCoverage totals, Map<String, State> states) {
        public View { states = Collections.unmodifiableMap(new TreeMap<>(states)); }
    }

    private final Map<String, Node> nodes;
    private final Set<String> incomplete;

    private TypeGraphEvidence(Map<String, Node> nodes, Set<String> incomplete) {
        this.nodes = Collections.unmodifiableMap(nodes);
        this.incomplete = Set.copyOf(incomplete);
    }

    public Map<String, Node> nodes() { return nodes; }
    @Override public boolean equals(Object other) {
        return other instanceof TypeGraphEvidence evidence && nodes.equals(evidence.nodes);
    }
    @Override public int hashCode() { return nodes.hashCode(); }

    public static TypeGraphEvidence capture(TypeGraph recovered, Map<String, List<TypeRef>> actual,
            BooleanSupplier cancelled) {
        check(cancelled);
        var nodes = new ArrayList<Node>();
        var keys = new HashSet<String>();
        for (var node : recovered.nodes()) {
            check(cancelled);
            keys.add(node.key());
            Kind kind = node instanceof VoidType ? Kind.IMPLICIT_VOID : node instanceof OpaqueType ? Kind.OPAQUE : Kind.RESOLVED;
            nodes.add(new Node(node.key(), node.name(), node.getClass().getSimpleName(), node.byteSize(), kind,
                actual.containsKey(node.key()), counts(node.references(), cancelled),
                counts(actual.getOrDefault(node.key(), List.of()), cancelled), node instanceof OpaqueType opaque ? opaque.diagnostic() : ""));
        }
        for (String key : actual.keySet()) {
            check(cancelled);
            if (!keys.contains(key)) throw new IllegalArgumentException("unrecovered emitted type " + key);
        }
        return of(nodes, cancelled);
    }

    /** Validate graph consistency without reading any artifact or inventing absent edges. */
    public static TypeGraphEvidence of(List<Node> supplied, BooleanSupplier cancelled) {
        check(cancelled);
        var nodes = new TreeMap<String, Node>();
        for (Node node : supplied) {
            check(cancelled);
            if (nodes.put(node.key(), node) != null) throw new IllegalArgumentException("duplicate type definition " + node.key());
        }
        var parents = new HashMap<String, List<String>>();
        var incomplete = new HashSet<String>();
        var pending = new ArrayDeque<String>();
        for (Node node : nodes.values()) {
            check(cancelled);
            for (String child : node.recoveredReferences().keySet()) {
                check(cancelled);
                if (!nodes.containsKey(child)) throw new IllegalArgumentException("unknown recovered type reference " + child);
                parents.computeIfAbsent(child, ignored -> new ArrayList<>()).add(node.key());
            }
            for (var edge : node.emittedReferences().entrySet()) {
                check(cancelled);
                Node child = nodes.get(edge.getKey());
                if (child == null || !child.emitted() || edge.getValue() > node.recoveredReferences().getOrDefault(edge.getKey(), 0)) {
                    throw new IllegalArgumentException("unexpected or dangling emitted type reference " + edge.getKey());
                }
            }
            if (!node.emitted() || node.kind() == Kind.OPAQUE || !node.recoveredReferences().equals(node.emittedReferences())) {
                incomplete.add(node.key());
                pending.addLast(node.key());
            }
        }
        while (!pending.isEmpty()) {
            check(cancelled);
            for (String parent : parents.getOrDefault(pending.removeFirst(), List.of())) {
                check(cancelled);
                if (incomplete.add(parent)) pending.addLast(parent);
            }
        }
        check(cancelled);
        return new TypeGraphEvidence(nodes, incomplete);
    }

    /** An allocated type elsewhere does not establish that a declaration actually uses it. */
    public View inspect(List<TypeRef> recoveredRoots, List<TypeRef> attachedRoots, BooleanSupplier cancelled) {
        check(cancelled);
        Set<String> roots = roots(recoveredRoots, cancelled);
        Set<String> attached = roots(attachedRoots, cancelled);
        long complete = 0;
        for (String key : attached) {
            check(cancelled);
            if (!roots.contains(key) || !nodes.get(key).emitted()) throw new IllegalArgumentException("unrepresented attached type root " + key);
            if (!incomplete.contains(key)) complete++;
        }
        Set<String> recovered = reachable(roots, false, cancelled);
        Set<String> emitted = reachable(attached, true, cancelled);
        var states = new TreeMap<String, State>();
        long resolved = 0, opaque = 0, missing = 0, voids = 0, emittedVoids = 0;
        for (String key : recovered) {
            check(cancelled);
            Node node = nodes.get(key);
            boolean present = emitted.contains(key);
            State state;
            if (node.kind() == Kind.IMPLICIT_VOID) {
                voids++;
                if (present) emittedVoids++;
                state = present ? State.IMPLICIT_VOID : State.VOID_NOT_EMITTED;
            }
            else if (!present) { missing++; state = State.NOT_EMITTED; }
            else if (node.kind() == Kind.OPAQUE) { opaque++; state = State.OPAQUE; }
            else { resolved++; state = State.RESOLVED; }
            states.put(key, state);
        }
        check(cancelled);
        return new View(new TypeCoverage(roots.size(), attached.size(), complete,
            recovered.size() - voids, resolved, opaque, missing, voids, emittedVoids), states);
    }

    private Set<String> roots(List<TypeRef> supplied, BooleanSupplier cancelled) {
        var result = new TreeSet<String>();
        for (TypeRef root : supplied) {
            check(cancelled);
            if (!nodes.containsKey(root.key())) throw new IllegalArgumentException("unknown recovered root " + root.key());
            result.add(root.key());
        }
        return result;
    }

    private Set<String> reachable(Set<String> roots, boolean emitted, BooleanSupplier cancelled) {
        var result = new TreeSet<String>();
        var pending = new ArrayDeque<String>();
        for (String key : roots) { check(cancelled); result.add(key); pending.addLast(key); }
        while (!pending.isEmpty()) {
            check(cancelled);
            var node = nodes.get(pending.removeFirst());
            var edges = emitted ? node.emittedReferences() : node.recoveredReferences();
            for (String child : edges.keySet()) { check(cancelled); if (result.add(child)) pending.addLast(child); }
        }
        return result;
    }

    private static Map<String, Integer> counts(List<TypeRef> references, BooleanSupplier cancelled) {
        var result = new TreeMap<String, Integer>();
        for (TypeRef reference : references) { check(cancelled); result.merge(Objects.requireNonNull(reference).key(), 1, Math::addExact); }
        return result;
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("type graph evidence cancelled");
    }
}
