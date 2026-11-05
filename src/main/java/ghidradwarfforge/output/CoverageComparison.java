package ghidradwarfforge.output;

import ghidradwarfforge.coverage.ExportCoverage.Function;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Read-only comparison of strictly parsed reported evidence, not artifact authentication. */
public final class CoverageComparison {
    private CoverageComparison() { }

    public record Change(String kind, long function, String detail) { }
    public record Result(boolean comparable, long changes, List<String> reasons) {
        public Result { reasons = List.copyOf(reasons); }
    }

    public static Result compare(ExportReportClaims.WithCoverage before, ExportReportClaims.WithCoverage after,
            Consumer<Change> output, BooleanSupplier cancelled) {
        check(cancelled);
        List<String> reasons = new ArrayList<>();
        if (before.coverage() == null || after.coverage() == null) reasons.add("Coverage unavailable in schema one");
        if (!before.claims().artifacts().inputSha256().equalsIgnoreCase(after.claims().artifacts().inputSha256())) {
            reasons.add("Reported original SHA-256 differs");
        }
        if (!before.claims().target().equals(after.claims().target())) reasons.add("Target profile differs");
        if (before.coverage() != null && after.coverage() != null &&
                !before.coverage().profile().equals(after.coverage().profile())) reasons.add("Ghidra language/compiler profile differs");
        // The strict reader admits only metric definition 1 and ELF_LINK_TIME.
        // An unknown definition/address model is rejected before comparison.
        if (!reasons.isEmpty()) return new Result(false, 0, reasons);
        var left = index(before.coverage().coverage().functions(), cancelled);
        var right = index(after.coverage().coverage().functions(), cancelled);
        var addresses = new TreeSet<Long>();
        for (long address : left.keySet()) { check(cancelled); addresses.add(address); }
        for (long address : right.keySet()) { check(cancelled); addresses.add(address); }
        var changes = new Changes(output, cancelled);
        for (long address : addresses) {
            check(cancelled);
            Function old = left.get(address), next = right.get(address);
            if (old == null) changes.add("FUNCTION_ADDED", address, next.function().qualifiedDisplayName());
            else if (next == null) changes.add("FUNCTION_REMOVED", address, old.function().qualifiedDisplayName());
            else compareFunction(old, next, changes, cancelled);
        }
        check(cancelled);
        return new Result(true, changes.count, List.of(
            "Comparison uses reported original SHA-256 and ELF-link-time addresses; no referenced artifact was opened.",
            "Changed function bodies/decoded populations are disclosed. Point losses/gains compare only starts decoded in both reports.",
            "Local identities are export-local: individual local renames and location-range transitions are not established.",
            "Type reports contain counts, not node states: individual resolved-to-opaque transitions may be hidden by other changes.",
            "Variable totals are compared, not individual variable correspondence. This is not an exhaustive semantic equivalence check."));
    }

    private static Map<Long, Function> index(List<Function> functions, BooleanSupplier cancelled) {
        var result = new TreeMap<Long, Function>();
        for (var function : functions) {
            check(cancelled);
            if (result.put(function.function().address(), function) != null) {
                throw new IllegalArgumentException("ambiguous duplicate function entry");
            }
        }
        return result;
    }

    private static void compareFunction(Function before, Function after, Changes changes, BooleanSupplier cancelled) {
        long entry = before.function().address();
        different("FUNCTION_RENAMED", entry, before.function().qualifiedDisplayName(), after.function().qualifiedDisplayName(), changes);
        different("BODY_POPULATION_CHANGED", entry, before.function().ranges(), after.function().ranges(), changes);
        different("SOURCE_DISPOSITION_CHANGED", entry, before.source().disposition(), after.source().disposition(), changes);
        different("SOURCE_DIAGNOSTIC_CHANGED", entry, before.source().diagnostic(), after.source().diagnostic(), changes);
        different("SIGNATURE_EVIDENCE_CHANGED", entry, before.signature(), after.signature(), changes);
        different("TYPE_PROVENANCE_CHANGED", entry, before.typeProvenance(), after.typeProvenance(), changes);
        different("TYPE_COUNTS_CHANGED", entry, before.types(), after.types(), changes);
        different("VARIABLE_COUNTS_CHANGED", entry, before.variables().totals(), after.variables().totals(), changes);
        for (var kind : ghidradwarfforge.coverage.ExportEmission.Kind.values()) {
            different("VARIABLE_COUNTS_" + kind, entry, before.variables().byKind().get(kind), after.variables().byKind().get(kind), changes);
        }
        var old = before.source().observedPoints();
        var next = after.source().observedPoints();
        different("INSTRUCTION_EVIDENCE_CHANGED", entry, before.source().instructionUnavailableReason(),
            after.source().instructionUnavailableReason(), changes);
        different("TOKEN_EVIDENCE_CHANGED", entry, before.source().tokenUnavailableReason(),
            after.source().tokenUnavailableReason(), changes);
        if (old == null || next == null) return; // Unknown is not zero.
        points("DECODED_REMOVED", entry, old.decoded(), next.decoded(), null, changes, cancelled);
        points("DECODED_ADDED", entry, next.decoded(), old.decoded(), null, changes, cancelled);
        if (before.source().anchoredInstructions() != null && after.source().anchoredInstructions() != null) {
            points("ANCHOR_LOST", entry, old.anchored(), next.anchored(), next.decoded(), changes, cancelled);
            points("ANCHOR_GAINED", entry, next.anchored(), old.anchored(), old.decoded(), changes, cancelled);
        }
        points("LINE_VISIBILITY_LOST", entry, old.lineVisible(), next.lineVisible(), next.decoded(), changes, cancelled);
        points("LINE_VISIBILITY_GAINED", entry, next.lineVisible(), old.lineVisible(), old.decoded(), changes, cancelled);
    }

    /** Linear merge over reader-validated sorted unique starts; no per-function address-set copies. */
    private static void points(String kind, long function, List<Long> from, List<Long> other,
            List<Long> eligible, Changes changes, BooleanSupplier cancelled) {
        int otherIndex = 0, eligibleIndex = 0;
        for (long address : from) {
            check(cancelled);
            while (otherIndex < other.size() && other.get(otherIndex) < address) { check(cancelled); otherIndex++; }
            if (otherIndex < other.size() && other.get(otherIndex) == address) continue;
            if (eligible != null) {
                while (eligibleIndex < eligible.size() && eligible.get(eligibleIndex) < address) { check(cancelled); eligibleIndex++; }
                if (eligibleIndex == eligible.size() || eligible.get(eligibleIndex) != address) continue;
            }
            changes.add(kind, function, "0x" + Long.toHexString(address));
        }
    }

    private static void different(String kind, long entry, Object before, Object after, Changes changes) {
        check(changes.cancelled);
        if (!java.util.Objects.equals(before, after)) changes.add(kind, entry, before + " -> " + after);
    }

    private static final class Changes {
        final Consumer<Change> output;
        final BooleanSupplier cancelled;
        long count;
        Changes(Consumer<Change> output, BooleanSupplier cancelled) { this.output = output; this.cancelled = cancelled; }
        void add(String kind, long entry, String detail) {
            check(cancelled);
            output.accept(new Change(kind, entry, detail));
            count++;
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("coverage comparison cancelled");
    }
}
