package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.coverage.ExportEmission.ExpressionLocation;
import ghidradwarfforge.coverage.ExportEmission.ListLocation;
import ghidradwarfforge.coverage.ExportEmission.Location;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Static address-range coverage for one recovered declaration, never execution/time coverage. */
public record LocationCoverage(boolean declarationEmitted, boolean scopeComplete,
        String scopeEvidence, List<FunctionRange> knownScopeRanges,
        List<FunctionRange> locatedRanges, long knownScopeBytes, long coveredScopeBytes,
        long locatedBytes) {
    public LocationCoverage {
        Objects.requireNonNull(scopeEvidence);
        knownScopeRanges = List.copyOf(knownScopeRanges);
        locatedRanges = List.copyOf(locatedRanges);
        if (scopeEvidence.isBlank() || knownScopeBytes < 0 || coveredScopeBytes < 0 ||
                locatedBytes < 0 || coveredScopeBytes > knownScopeBytes ||
                coveredScopeBytes > locatedBytes || (!declarationEmitted && locatedBytes != 0) ||
                (scopeComplete && coveredScopeBytes != locatedBytes)) {
            throw new IllegalArgumentException("inconsistent location coverage");
        }
    }

    /** Unknown visibility may have some known intervals; it never yields a whole-scope percentage. */
    public record Visibility(List<FunctionRange> knownRanges, boolean complete, String evidence) {
        public Visibility {
            knownRanges = List.copyOf(knownRanges);
            if (evidence == null || evidence.isBlank()) {
                throw new IllegalArgumentException("visibility needs evidence or an unknown reason");
            }
        }
    }

    public boolean hasFullValueLocation() {
        return locatedBytes != 0;
    }

    public boolean percentageApplicable() {
        return scopeComplete && knownScopeBytes != 0;
    }

    /**
     * Null location means no declaration was emitted; NoLocation means an emitted
     * declaration without location. ownerRanges are the actual enclosing DIE's
     * ranges, not a variable lifetime. Visibility is separate recovered evidence;
     * it must never be inferred from available location ranges. Complete visibility
     * clips location counts; unknown visibility keeps actual owner-bounded locations
     * descriptive and withholds percentages, including for otherwise stable expressions.
     */
    public static LocationCoverage measure(Location location, List<FunctionRange> ownerRanges,
            Visibility visibility, BooleanSupplier cancelled) {
        Objects.requireNonNull(visibility);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        List<FunctionRange> known = union(visibility.knownRanges(), cancelled);
        List<FunctionRange> owner = union(ownerRanges, cancelled);
        List<FunctionRange> located = List.of();
        if (location instanceof ExpressionLocation) {
            located = owner;
        }
        else if (location instanceof ListLocation list) {
            List<FunctionRange> intervals = new ArrayList<>();
            for (var range : list.ranges()) {
                checkCancelled(cancelled);
                intervals.add(new FunctionRange(range.range().start(),
                    Math.subtractExact(range.range().end(), range.range().start())));
            }
            located = intersect(owner, union(intervals, cancelled), cancelled);
        }
        List<FunctionRange> covered = intersect(located, known, cancelled);
        if (visibility.complete()) located = covered;
        return new LocationCoverage(location != null, visibility.complete(), visibility.evidence(),
            known, located, bytes(known, cancelled), bytes(covered, cancelled), bytes(located, cancelled));
    }

    private static List<FunctionRange> union(List<FunctionRange> ranges, BooleanSupplier cancelled) {
        Objects.requireNonNull(ranges);
        TreeMap<Long, Long> ordered = new TreeMap<>();
        for (FunctionRange range : ranges) {
            checkCancelled(cancelled);
            ordered.merge(range.address(), range.endExclusive(), Math::max);
        }
        List<FunctionRange> result = new ArrayList<>();
        long start = -1;
        long end = -1;
        for (var range : ordered.entrySet()) {
            checkCancelled(cancelled);
            if (start == -1) {
                start = range.getKey();
                end = range.getValue();
            }
            else if (range.getKey() <= end) {
                end = Math.max(end, range.getValue());
            }
            else {
                result.add(new FunctionRange(start, end - start));
                start = range.getKey();
                end = range.getValue();
            }
        }
        if (start != -1) result.add(new FunctionRange(start, end - start));
        return result;
    }

    private static List<FunctionRange> intersect(List<FunctionRange> first,
            List<FunctionRange> second, BooleanSupplier cancelled) {
        List<FunctionRange> result = new ArrayList<>();
        int left = 0;
        int right = 0;
        while (left < first.size() && right < second.size()) {
            checkCancelled(cancelled);
            FunctionRange a = first.get(left);
            FunctionRange b = second.get(right);
            long start = Math.max(a.address(), b.address());
            long end = Math.min(a.endExclusive(), b.endExclusive());
            if (start < end) result.add(new FunctionRange(start, end - start));
            if (a.endExclusive() <= b.endExclusive()) left++;
            else right++;
        }
        return result;
    }

    private static long bytes(List<FunctionRange> ranges, BooleanSupplier cancelled) {
        long total = 0;
        for (FunctionRange range : ranges) {
            checkCancelled(cancelled);
            total = Math.addExact(total, range.size());
        }
        return total;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("location coverage cancelled");
    }
}
