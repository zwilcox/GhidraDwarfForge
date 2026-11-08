package ghidradwarfforge.coverage;

import java.util.List;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** A complete listing-start inventory, or an explicit unavailable denominator. */
public record DecodedInstructions(FunctionSymbol function, List<Long> starts,
        String unavailableReason) {
    public DecodedInstructions {
        if (function == null || starts == null || unavailableReason == null ||
                (!unavailableReason.isEmpty() && unavailableReason.isBlank())) {
            throw new IllegalArgumentException("invalid decoded instruction evidence");
        }
        starts = starts.stream().distinct().sorted().toList();
        if (!unavailableReason.isEmpty() && !starts.isEmpty()) {
            throw new IllegalArgumentException("unavailable inventory cannot retain partial counts");
        }
        int range = 0;
        for (long address : starts) {
            while (range < function.ranges().size() &&
                    function.ranges().get(range).endExclusive() <= address) {
                range++;
            }
            if (range == function.ranges().size() ||
                    !function.ranges().get(range).contains(address)) {
                throw new IllegalArgumentException("instruction start outside selected body");
            }
        }
    }

    public boolean available() {
        return unavailableReason.isEmpty();
    }
}
