package ghidradwarfforge.unwind;

import java.util.List;
import java.util.Objects;

/**
 * Explicit external condition, not an inferred ELF or ABI fact: the listed
 * absolute address ranges never overlap any live stack storage of the closed
 * call group or its callers. Coordinates must match the instruction effects.
 * Optional fixed pointers also require invariant full-width values and that all
 * stack-relative accesses remain disjoint from those slots. These stronger
 * conditions are external, not consequences of a symbol or RELRO annotation.
 * A result using this condition is valid only when all attached conditions hold.
 */
public record UnwindStackSeparation(int addressBytes, List<Region> regions, String basis,
        List<Pointer> fixedPointers) {
    /** Optional additional condition: this entire pointer slot retains this value throughout execution. */
    public record Pointer(long address, long value) { }

    public UnwindStackSeparation(int addressBytes, List<Region> regions, String basis) {
        this(addressBytes, regions, basis, List.of());
    }
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
        fixedPointers = List.copyOf(fixedPointers);
        if (regions.isEmpty()) {
            if (addressBytes != 0 || !basis.isEmpty() || !fixedPointers.isEmpty()) {
                throw new IllegalArgumentException("empty separation condition must be unconditional");
            }
        }
        else if ((addressBytes != 4 && addressBytes != 8) || regions.size() > 128 || fixedPointers.size() > 64 ||
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
        long priorEnd = 0;
        first = true;
        for (Pointer pointer : fixedPointers) {
            long end = pointer.address() + addressBytes - 1;
            boolean contained = false;
            for (Region region : regions) {
                if (Long.compareUnsigned(pointer.address(), region.first()) >= 0 &&
                        Long.compareUnsigned(end, region.last()) <= 0) contained = true;
            }
            if (Long.compareUnsigned(end, pointer.address()) < 0 ||
                    (addressBytes == 4 && Long.compareUnsigned(pointer.value(), 0xffff_ffffL) > 0) ||
                    (!first && Long.compareUnsigned(pointer.address(), priorEnd) <= 0) || !contained) {
                throw new IllegalArgumentException("fixed pointer is overlapping, wrapping or outside separated storage");
            }
            first = false;
            priorEnd = end;
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

    /** Exact full-width reads only; no pointer is inferred from arbitrary input memory. */
    public UnwindFlow.Constant readPointer(UnwindFlow.Value address, int bytes) {
        if (!(address instanceof UnwindFlow.Constant constant) || constant.bytes() != addressBytes || bytes != addressBytes) {
            return null;
        }
        for (Pointer pointer : fixedPointers) {
            if (pointer.address() == constant.value()) return new UnwindFlow.Constant(pointer.value(), addressBytes);
        }
        return null;
    }

    /** A conditional immutable read cannot survive a possibly conflicting store. */
    public void requireCompatibleStore(UnwindFlow.Value address, int bytes) {
        if (fixedPointers.isEmpty() || address instanceof UnwindFlow.StackAddress) return;
        if (!(address instanceof UnwindFlow.Constant constant) || constant.bytes() != addressBytes) {
            throw new IllegalArgumentException("unknown write may change a fixed pointer condition");
        }
        long end = constant.value() + bytes - 1;
        if (Long.compareUnsigned(end, constant.value()) < 0) {
            throw new IllegalArgumentException("wrapping write may change a fixed pointer condition");
        }
        for (Pointer pointer : fixedPointers) {
            if (Long.compareUnsigned(constant.value(), pointer.address() + addressBytes - 1) <= 0 &&
                    Long.compareUnsigned(pointer.address(), end) <= 0) {
                throw new IllegalArgumentException("write conflicts with a fixed pointer condition");
            }
        }
    }

    /** Unconditional summaries are usable everywhere; conditional ones require the exact condition. */
    public boolean admits(UnwindStackSeparation required) {
        return !required.conditional() || equals(required);
    }
}
