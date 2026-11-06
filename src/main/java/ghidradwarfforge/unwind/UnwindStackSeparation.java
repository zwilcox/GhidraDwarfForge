package ghidradwarfforge.unwind;

import java.util.List;
import java.util.Objects;

/**
 * Explicit external condition, not an inferred ELF or ABI fact: the listed
 * absolute address ranges never overlap any live stack storage of the closed
 * call group or its callers. Coordinates must match the instruction effects.
 * A result using this condition is valid only when the condition holds.
 */
public record UnwindStackSeparation(int addressBytes, List<Region> regions, String basis) {
    public static final UnwindStackSeparation NONE = new UnwindStackSeparation(0, List.of(), "");

    public record Region(long first, long last) {
        public Region {
            if (Long.compareUnsigned(first, last) > 0) {
                throw new IllegalArgumentException("stack separation region wraps");
            }
        }
    }

    public UnwindStackSeparation {
        Objects.requireNonNull(regions);
        Objects.requireNonNull(basis);
        if (regions.isEmpty()) {
            if (addressBytes != 0 || !basis.isEmpty()) {
                throw new IllegalArgumentException("empty separation condition must be unconditional");
            }
        }
        else if ((addressBytes != 4 && addressBytes != 8) || regions.size() > 128 ||
                basis.isBlank() || basis.length() > 4096) {
            throw new IllegalArgumentException("invalid or unbounded stack separation condition");
        }
        regions = List.copyOf(regions);
        long previous = 0;
        boolean first = true;
        for (Region region : regions) {
            if ((addressBytes == 4 && Long.compareUnsigned(region.last(), 0xffff_ffffL) > 0) ||
                    (!first && Long.compareUnsigned(region.first(), previous) <= 0)) {
                throw new IllegalArgumentException("separation regions overlap, are unordered or exceed address width");
            }
            first = false;
            previous = region.last();
        }
    }

    public boolean conditional() { return !regions.isEmpty(); }

    public boolean permits(UnwindFlow.Value address, int bytes) {
        if (!(address instanceof UnwindFlow.Constant constant) || constant.bytes() != addressBytes ||
                bytes < 1 || bytes > 8) return false;
        long last = constant.value() + bytes - 1;
        if (Long.compareUnsigned(last, constant.value()) < 0) return false;
        for (Region region : regions) {
            if (Long.compareUnsigned(constant.value(), region.first()) >= 0 &&
                    Long.compareUnsigned(last, region.last()) <= 0) return true;
        }
        return false;
    }

    /** Unconditional summaries are usable everywhere; conditional ones require the exact condition. */
    public boolean admits(UnwindStackSeparation required) {
        return !required.conditional() || equals(required);
    }
}
