package ghidradwarfforge.coverage;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import ghidradwarfforge.types.TypeGraph.VoidType;

/** Reusable canonical graph index; no recursive walks or per-root graph rescans. */
public final class TypeCoverageIndex {
    private final Map<String, TypeNode> nodes;
    private final Map<String, Set<String>> recoveredEdges;
    private final Map<String, Set<String>> emittedEdges;
    private final Set<String> incompleteRoots;

    /**
     * The emission map must come from successful type emission, not allocation or
     * extraction alone. Keys identify represented canonical types; values identify
     * their actually represented semantic references. A represented VoidType has
     * an empty entry: its deliberate absence of DW_AT_type is not a missing DIE.
     * Qualifier chains and member/parameter DIEs retain their one canonical node.
     * Reference lists preserve multiplicity (two members with the same type are
     * two references), although the reachable node population is deduplicated.
     * Missing edges are allowed and prevent a complete-root claim. Unknown edges
     * and dangling references are rejected as inconsistent emission evidence.
     */
    public TypeCoverageIndex(TypeGraph recovered,
            Map<String, List<TypeRef>> emittedReferences, BooleanSupplier cancelled) {
        Objects.requireNonNull(recovered);
        Objects.requireNonNull(emittedReferences);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        Map<String, TypeNode> nodeIndex = new HashMap<>();
        Map<String, Set<String>> expected = new HashMap<>();
        Map<String, Map<String, Integer>> expectedCounts = new HashMap<>();
        Map<String, List<String>> parents = new HashMap<>();
        for (TypeNode node : recovered.nodes()) {
            checkCancelled(cancelled);
            nodeIndex.put(node.key(), node);
            Map<String, Integer> counts = referenceCounts(node.references(), cancelled);
            expectedCounts.put(node.key(), counts);
            Set<String> references = counts.keySet();
            expected.put(node.key(), references);
            for (String child : references) {
                checkCancelled(cancelled);
                parents.computeIfAbsent(child, unused -> new ArrayList<>()).add(node.key());
            }
        }
        Map<String, Set<String>> actual = new HashMap<>();
        Set<String> incomplete = new HashSet<>();
        for (var entry : emittedReferences.entrySet()) {
            checkCancelled(cancelled);
            if (!nodeIndex.containsKey(entry.getKey())) {
                throw new IllegalArgumentException("unknown emitted type " + entry.getKey());
            }
            Map<String, Integer> counts = referenceCounts(entry.getValue(), cancelled);
            Set<String> references = counts.keySet();
            for (String child : references) {
                checkCancelled(cancelled);
                if (!expected.get(entry.getKey()).contains(child) ||
                        !emittedReferences.containsKey(child) ||
                        counts.get(child) > expectedCounts.get(entry.getKey()).get(child)) {
                    throw new IllegalArgumentException("unexpected or dangling emitted type reference");
                }
            }
            actual.put(entry.getKey(), references);
            if (!counts.equals(expectedCounts.get(entry.getKey()))) {
                incomplete.add(entry.getKey());
            }
        }
        ArrayDeque<String> pending = new ArrayDeque<>();
        for (TypeNode node : recovered.nodes()) {
            checkCancelled(cancelled);
            if (node instanceof OpaqueType || !actual.containsKey(node.key()) ||
                    incomplete.contains(node.key())) {
                incomplete.add(node.key());
                pending.addLast(node.key());
            }
        }
        // Propagate once over reverse edges, including strongly connected cycles.
        while (!pending.isEmpty()) {
            checkCancelled(cancelled);
            for (String parent : parents.getOrDefault(pending.removeFirst(), List.of())) {
                checkCancelled(cancelled);
                if (incomplete.add(parent)) {
                    pending.addLast(parent);
                }
            }
        }
        // All maps/sets are private, owned snapshots and never mutated after construction.
        nodes = nodeIndex;
        recoveredEdges = expected;
        emittedEdges = actual;
        incompleteRoots = incomplete;
    }

    /**
     * Roots are distinct canonical identities, not declaration counts. Emitted
     * roots must be attached to this function's actual declarations: types that
     * exist elsewhere in the CU cannot make a symbol-only function look complete.
     */
    public TypeCoverage measure(List<TypeRef> recoveredRoots, List<TypeRef> emittedRoots,
            BooleanSupplier cancelled) {
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        Set<String> recovered = keys(recoveredRoots, cancelled);
        Set<String> emitted = keys(emittedRoots, cancelled);
        for (String root : recovered) {
            checkCancelled(cancelled);
            if (!nodes.containsKey(root)) {
                throw new IllegalArgumentException("unknown recovered type root " + root);
            }
        }
        long complete = 0;
        for (String root : emitted) {
            checkCancelled(cancelled);
            if (!recovered.contains(root) || !emittedEdges.containsKey(root)) {
                throw new IllegalArgumentException("unrecovered or unrepresented emitted type root " + root);
            }
            if (!incompleteRoots.contains(root)) {
                complete++;
            }
        }
        Set<String> recoveredReachable = reachable(recovered, recoveredEdges, cancelled);
        Set<String> emittedReachable = reachable(emitted, emittedEdges, cancelled);
        long resolved = 0;
        long opaque = 0;
        long missing = 0;
        long voids = 0;
        long emittedVoids = 0;
        for (String key : recoveredReachable) {
            checkCancelled(cancelled);
            TypeNode node = nodes.get(key);
            boolean present = emittedReachable.contains(key);
            if (node instanceof VoidType) {
                voids++;
                if (present) emittedVoids++;
            }
            else if (!present) {
                missing++;
            }
            else if (node instanceof OpaqueType) {
                opaque++;
            }
            else {
                resolved++;
            }
        }
        return new TypeCoverage(recovered.size(), emitted.size(), complete,
            recoveredReachable.size() - voids, resolved, opaque, missing, voids, emittedVoids);
    }

    private static Set<String> keys(List<TypeRef> references, BooleanSupplier cancelled) {
        Objects.requireNonNull(references);
        Set<String> result = new HashSet<>();
        for (TypeRef reference : references) {
            checkCancelled(cancelled);
            result.add(Objects.requireNonNull(reference).key());
        }
        return result;
    }

    private static Map<String, Integer> referenceCounts(List<TypeRef> references,
            BooleanSupplier cancelled) {
        Objects.requireNonNull(references);
        Map<String, Integer> result = new HashMap<>();
        for (TypeRef reference : references) {
            checkCancelled(cancelled);
            result.merge(Objects.requireNonNull(reference).key(), 1, Math::addExact);
        }
        return result;
    }

    private static Set<String> reachable(Set<String> roots, Map<String, Set<String>> edges,
            BooleanSupplier cancelled) {
        Set<String> result = new HashSet<>();
        ArrayDeque<String> pending = new ArrayDeque<>();
        for (String root : roots) {
            checkCancelled(cancelled);
            if (result.add(root)) pending.addLast(root);
        }
        while (!pending.isEmpty()) {
            checkCancelled(cancelled);
            for (String child : edges.get(pending.removeFirst())) {
                checkCancelled(cancelled);
                if (result.add(child)) pending.addLast(child);
            }
        }
        return result;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("type coverage cancelled");
        }
    }
}
