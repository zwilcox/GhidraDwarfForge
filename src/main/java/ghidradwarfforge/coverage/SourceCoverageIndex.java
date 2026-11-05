package ghidradwarfforge.coverage;

import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** One index per emitted line table; reused for all primary function scorecards. */
public final class SourceCoverageIndex {
    private final NavigableMap<Long, Integer> rows;
    private final NavigableMap<Long, Long> visible;

    public SourceCoverageIndex(Dwarf5LineTable.Result emitted, BooleanSupplier cancelled) {
        Objects.requireNonNull(emitted);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        TreeMap<Long, Integer> rowIndex = new TreeMap<>();
        TreeMap<Long, Long> spans = new TreeMap<>();
        for (var sequence : emitted.sequences()) {
            checkCancelled(cancelled);
            if (sequence.rows().isEmpty()) {
                continue;
            }
            spans.merge(sequence.rows().getFirst().address(), sequence.endExclusive(), Math::max);
            for (var row : sequence.rows()) {
                checkCancelled(cancelled);
                Integer previous = rowIndex.putIfAbsent(row.address(), row.line());
                if (previous != null && previous != row.line()) {
                    throw new IllegalArgumentException("conflicting emitted line rows");
                }
            }
        }
        TreeMap<Long, Long> merged = new TreeMap<>();
        for (var span : spans.entrySet()) {
            checkCancelled(cancelled);
            var last = merged.lastEntry();
            if (last != null && span.getKey() <= last.getValue()) {
                merged.put(last.getKey(), Math.max(last.getValue(), span.getValue()));
            }
            else {
                merged.put(span.getKey(), span.getValue());
            }
        }
        rows = Collections.unmodifiableNavigableMap(rowIndex);
        visible = Collections.unmodifiableNavigableMap(merged);
    }

    /** Exact unique starts, retained for union aggregation and comparable-export diagnostics. */
    public record Points(List<Long> decoded, List<Long> anchored, List<Long> lineVisible) {
        public Points {
            decoded = List.copyOf(decoded);
            anchored = List.copyOf(anchored);
            lineVisible = List.copyOf(lineVisible);
        }

        public SourceCoverage counts() {
            return new SourceCoverage(decoded.size(), anchored.size(), lineVisible.size());
        }
    }

    public SourceCoverage measure(FunctionSymbol function, List<Long> decodedStarts,
            List<SourceLine> functionTokens, BooleanSupplier cancelled) {
        return measurePoints(function, decodedStarts, functionTokens, cancelled).counts();
    }

    /**
     * Token mappings belong only to this function and exclude synthetic declaration
     * rows. A token address counts only if its exact line survived emission selection.
     * Listing starts are deduplicated; all must belong to the actual function body.
     */
    public Points measurePoints(FunctionSymbol function, List<Long> decodedStarts,
            List<SourceLine> functionTokens, BooleanSupplier cancelled) {
        Objects.requireNonNull(function);
        Objects.requireNonNull(decodedStarts);
        Objects.requireNonNull(functionTokens);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        TreeSet<Long> instructions = new TreeSet<>();
        for (Long address : decodedStarts) {
            checkCancelled(cancelled);
            if (address == null || !contains(function.ranges(), address)) {
                throw new IllegalArgumentException("decoded instruction outside function body");
            }
            instructions.add(address);
        }
        TreeSet<Long> anchored = new TreeSet<>();
        for (SourceLine token : functionTokens) {
            checkCancelled(cancelled);
            if (token == null || token.line() < 1 || token.addresses() == null) {
                throw new IllegalArgumentException("invalid function token mapping");
            }
            for (Long address : token.addresses()) {
                checkCancelled(cancelled);
                if (address == null || address < 0) {
                    throw new IllegalArgumentException("invalid function token address");
                }
                if (instructions.contains(address) &&
                        Integer.valueOf(token.line()).equals(rows.get(address))) {
                    anchored.add(address);
                }
            }
        }
        List<Long> lineVisible = new ArrayList<>();
        for (long address : instructions) {
            checkCancelled(cancelled);
            var span = visible.floorEntry(address);
            if (span != null && address < span.getValue()) {
                lineVisible.add(address);
            }
        }
        return new Points(new ArrayList<>(instructions), new ArrayList<>(anchored), lineVisible);
    }

    private static boolean contains(List<FunctionRange> ranges, long address) {
        int lower = 0;
        int upper = ranges.size();
        while (lower < upper) {
            int middle = (lower + upper) >>> 1;
            if (ranges.get(middle).address() <= address) {
                lower = middle + 1;
            }
            else {
                upper = middle;
            }
        }
        return lower != 0 && ranges.get(lower - 1).contains(address);
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("source coverage cancelled");
        }
    }
}
