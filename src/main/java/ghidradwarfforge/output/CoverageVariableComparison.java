package ghidradwarfforge.output;

import com.google.gson.JsonPrimitive;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.VariableCoverageInventory.FunctionInventory;
import ghidradwarfforge.coverage.VariableCoverageInventory.StorageEvidence;
import ghidradwarfforge.coverage.VariableCoverageInventory.Variable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Differences at explicitly reported bindings, never proof of declaration lineage.
 * Inputs have passed the strict report reader, including canonical interval unions.
 */
final class CoverageVariableComparison {
    private CoverageVariableComparison() { }

    private record Binding(Kind kind, int ordinal, String name, String block, Long address) {
        static Binding of(Variable variable) {
            var id = variable.identity();
            return new Binding(id.kind(), id.parameterOrdinal(), id.kind() == Kind.PARAMETER ? "" : id.internalName(),
                id.block(), id.staticAddress());
        }
        String label() {
            return kind == Kind.PARAMETER ? "reported parameter ordinal=" + ordinal :
                "reported " + kind + " name=" + quote(name) + " block=" + quote(block) +
                    (address == null ? "" : " address=0x" + Long.toHexString(address));
        }
    }
    private static final Comparator<Binding> BINDINGS = Comparator.comparing(Binding::kind)
        .thenComparingInt(Binding::ordinal).thenComparing(Binding::name).thenComparing(Binding::block)
        .thenComparing(Binding::address, Comparator.nullsFirst(Comparator.naturalOrder()));
    private static final Comparator<StorageEvidence> STORAGE = Comparator.comparingLong(StorageEvidence::start)
        .thenComparingLong(StorageEvidence::end).thenComparing(StorageEvidence::category).thenComparing(StorageEvidence::source)
        .thenComparing(StorageEvidence::omissionReason).thenComparing(StorageEvidence::diagnostic);

    static void compare(FunctionInventory before, FunctionInventory after,
            Consumer<CoverageComparison.Change> output, BooleanSupplier cancelled) {
        long entry = before.function().address();
        var sink = new Sink(entry, output, cancelled);
        sink.different("VARIABLE_POPULATION_EVIDENCE_CHANGED", "declaration population known",
            before.recoveredSignatureKnown(), after.recoveredSignatureKnown());
        if (!before.recoveredSignatureKnown() || !after.recoveredSignatureKnown()) return;
        var left = index(before.variables(), cancelled);
        var right = index(after.variables(), cancelled);
        var bindings = new TreeSet<Binding>(BINDINGS);
        for (var binding : left.keySet()) { check(cancelled); bindings.add(binding); }
        for (var binding : right.keySet()) { check(cancelled); bindings.add(binding); }
        for (var binding : bindings) {
            check(cancelled);
            var old = left.get(binding);
            var next = right.get(binding);
            String label = binding.label();
            if (old == null || next == null) {
                sink.add(old == null ? "VARIABLE_BINDING_ADDED" : "VARIABLE_BINDING_REMOVED", label +
                    "; no declaration identity inferred; display=" + quote((old == null ? next : old).displayName()));
                continue;
            }
            sink.different("VARIABLE_DISPLAY_NAME_CHANGED", label, old.displayName(), next.displayName());
            sink.different("VARIABLE_INTERNAL_NAME_CHANGED", label, old.identity().internalName(), next.identity().internalName());
            sink.different("VARIABLE_RECOVERED_TYPE_CHANGED", label, old.recoveredType(), next.recoveredType());
            sink.different("VARIABLE_EMITTED_TYPE_CHANGED", label, old.emittedType(), next.emittedType());
            sink.different("VARIABLE_DECLARATION_PROVENANCE_CHANGED", label, old.declarationProvenance(), next.declarationProvenance());
            sink.different("VARIABLE_OMISSION_CHANGED", label, old.omissionReason(), next.omissionReason());
            sink.different("VARIABLE_DIAGNOSTIC_CHANGED", label, old.diagnostic(), next.diagnostic());
            var a = old.location();
            var b = next.location();
            sink.different("VARIABLE_DECLARATION_EMISSION_CHANGED", label, a.declarationEmitted(), b.declarationEmitted());
            sink.different("VARIABLE_SCOPE_COMPLETENESS_CHANGED", label, a.scopeComplete(), b.scopeComplete());
            sink.different("VARIABLE_SCOPE_EVIDENCE_CHANGED", label, a.scopeEvidence(), b.scopeEvidence());
            difference(a.knownScopeRanges(), b.knownScopeRanges(), range -> sink.range("VARIABLE_SCOPE_RANGE_REMOVED", label, range), cancelled);
            difference(b.knownScopeRanges(), a.knownScopeRanges(), range -> sink.range("VARIABLE_SCOPE_RANGE_ADDED", label, range), cancelled);
            difference(a.locatedRanges(), b.locatedRanges(), range -> sink.range("VARIABLE_LOCATION_RANGE_REMOVED", label, range), cancelled);
            difference(b.locatedRanges(), a.locatedRanges(), range -> sink.range("VARIABLE_LOCATION_RANGE_ADDED", label, range), cancelled);
            // Actual locations and scope population changes remain separate. Unknown
            // portions cannot become denominators; only common evidenced scope is compared.
            var common = intersection(a.knownScopeRanges(), b.knownScopeRanges(), cancelled);
            var oldCovered = intersection(a.locatedRanges(), common, cancelled);
            var newCovered = intersection(b.locatedRanges(), common, cancelled);
            difference(oldCovered, newCovered, range -> sink.range("VARIABLE_COMMON_SCOPE_COVERAGE_LOST", label, range), cancelled);
            difference(newCovered, oldCovered, range -> sink.range("VARIABLE_COMMON_SCOPE_COVERAGE_GAINED", label, range), cancelled);
            storage(label, old.storageEvidence(), next.storageEvidence(), sink);
        }
    }

    private static Map<Binding, Variable> index(List<Variable> variables, BooleanSupplier cancelled) {
        var result = new TreeMap<Binding, Variable>(BINDINGS);
        for (var variable : variables) {
            check(cancelled);
            if (result.put(Binding.of(variable), variable) != null) throw new IllegalArgumentException("ambiguous reported variable binding");
        }
        return result;
    }

    private static void storage(String label, List<StorageEvidence> before, List<StorageEvidence> after, Sink sink) {
        var left = storageIndex(before, sink.cancelled);
        var right = storageIndex(after, sink.cancelled);
        var keys = new TreeSet<StorageEvidence>(STORAGE);
        for (var key : left.keySet()) { check(sink.cancelled); keys.add(key); }
        for (var key : right.keySet()) { check(sink.cancelled); keys.add(key); }
        for (var key : keys) {
            check(sink.cancelled);
            int a = left.getOrDefault(key, 0), b = right.getOrDefault(key, 0);
            if (a == b) continue;
            sink.add("VARIABLE_STORAGE_EVIDENCE_CHANGED", label + "; [0x" + Long.toHexString(key.start()) +
                ",0x" + Long.toHexString(key.end()) + ") category=" + quote(key.category()) + " source=" + quote(key.source()) +
                " omission=" + quote(key.omissionReason()) + " diagnostic=" + quote(key.diagnostic()) + " count=" + a + " -> " + b);
        }
    }

    private static Map<StorageEvidence, Integer> storageIndex(List<StorageEvidence> supplied, BooleanSupplier cancelled) {
        var result = new TreeMap<StorageEvidence, Integer>(STORAGE);
        for (var evidence : supplied) { check(cancelled); result.merge(evidence, 1, Math::addExact); }
        return result;
    }

    /** Linear interval subtraction; never enumerates bytes or fills discontiguous gaps. */
    static void difference(List<FunctionRange> from, List<FunctionRange> other,
            Consumer<FunctionRange> output, BooleanSupplier cancelled) {
        check(cancelled);
        int index = 0;
        for (var range : from) {
            check(cancelled);
            long cursor = range.address(), end = range.endExclusive();
            while (index < other.size() && other.get(index).endExclusive() <= cursor) { check(cancelled); index++; }
            while (index < other.size() && other.get(index).address() < end) {
                check(cancelled);
                var removed = other.get(index);
                if (removed.address() > cursor) output.accept(new FunctionRange(cursor, removed.address() - cursor));
                cursor = Math.max(cursor, removed.endExclusive());
                if (cursor >= end) break;
                index++;
            }
            if (cursor < end) { check(cancelled); output.accept(new FunctionRange(cursor, end - cursor)); }
        }
        check(cancelled);
    }

    private static List<FunctionRange> intersection(List<FunctionRange> a, List<FunctionRange> b, BooleanSupplier cancelled) {
        var result = new ArrayList<FunctionRange>();
        int left = 0, right = 0;
        while (left < a.size() && right < b.size()) {
            check(cancelled);
            var first = a.get(left);
            var second = b.get(right);
            long start = Math.max(first.address(), second.address()), end = Math.min(first.endExclusive(), second.endExclusive());
            if (start < end) result.add(new FunctionRange(start, end - start));
            if (first.endExclusive() <= second.endExclusive()) left++;
            else right++;
        }
        return result;
    }

    private record Sink(long entry, Consumer<CoverageComparison.Change> output, BooleanSupplier cancelled) {
        void add(String kind, String detail) { check(cancelled); output.accept(new CoverageComparison.Change(kind, entry, detail)); }
        void different(String kind, String label, Object before, Object after) {
            check(cancelled);
            if (!Objects.equals(before, after)) add(kind, label + "; " + before + " -> " + after);
        }
        void range(String kind, String label, FunctionRange range) {
            add(kind, label + "; [0x" + Long.toHexString(range.address()) + ",0x" + Long.toHexString(range.endExclusive()) + ")");
        }
    }
    private static String quote(String text) { return new JsonPrimitive(text).toString(); }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("variable comparison cancelled");
    }
}
