package ghidradwarfforge.coverage;

/** Static decoded-instruction counts, never execution coverage or confidence. */
public record SourceCoverage(long decodedInstructions, long anchoredInstructions,
        long lineVisibleInstructions) {
    public SourceCoverage {
        if (anchoredInstructions < 0 || lineVisibleInstructions < anchoredInstructions ||
                decodedInstructions < lineVisibleInstructions) {
            throw new IllegalArgumentException("inconsistent source coverage counts");
        }
    }

    /** An empty instruction inventory has no percentage, rather than full coverage. */
    public boolean applicable() {
        return decodedInstructions != 0;
    }
}
