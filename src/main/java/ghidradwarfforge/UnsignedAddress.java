package ghidradwarfforge;

/** Arithmetic on unsigned target addresses with independently bounded byte counts. */
public final class UnsignedAddress {
    private UnsignedAddress() {
    }

    /** A half-open endpoint must fit the target address field, including the end_sequence row. */
    public static long endExclusive(long address, long size) {
        if (size <= 0) throw new IllegalArgumentException("empty or unbounded target address range");
        long end = address + size;
        if (Long.compareUnsigned(end, address) <= 0) {
            throw new IllegalArgumentException(end == 0
                ? "exclusive range end 2^64 cannot be encoded as an ELF64 address"
                : "target address range wraps through zero");
        }
        return end;
    }

    public static long min(long first, long second) {
        return Long.compareUnsigned(first, second) <= 0 ? first : second;
    }

    public static long max(long first, long second) {
        return Long.compareUnsigned(first, second) >= 0 ? first : second;
    }

    public static long lastByte(long address, long size) {
        if (size <= 0) throw new IllegalArgumentException("empty or unbounded target address range");
        long last = address + (size - 1);
        if (Long.compareUnsigned(last, address) < 0) throw new IllegalArgumentException("target address extent overflows");
        return last;
    }

    public static long distance(long start, long end) {
        long size = end - start;
        if (Long.compareUnsigned(start, end) > 0 || size < 0) {
            throw new IllegalArgumentException("target address distance exceeds the supported byte count");
        }
        return size;
    }
}
