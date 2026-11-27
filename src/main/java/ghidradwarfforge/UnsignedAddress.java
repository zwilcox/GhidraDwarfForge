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

    public static long addOffset(long address, long offset) {
        long result = address + offset;
        if (offset < 0 || Long.compareUnsigned(result, address) < 0) {
            throw new IllegalArgumentException("target address extent overflows");
        }
        return result;
    }

    /** Apply a DW_EH_PE relative pointer's signed or unsigned operand to its target base. */
    public static long addDisplacement(long base, long value, boolean signed) {
        long address = base + value;
        int order = Long.compareUnsigned(address, base);
        if (signed && value < 0 ? order > 0 : order < 0) {
            throw new IllegalArgumentException("relative pointer escapes the target address space");
        }
        return address;
    }

    public static long lastByte(long address, long size) {
        if (size <= 0) throw new IllegalArgumentException("empty or unbounded target address range");
        return addOffset(address, size - 1);
    }

    /** Memory-backed objects must fit the original ELF class, including the last byte. */
    public static boolean fitsObject(long address, long size, int addressBytes) {
        if (size <= 0) return false;
        long last = address + (size - 1);
        return Long.compareUnsigned(last, address) >= 0 &&
            (addressBytes == 8 || addressBytes == 4 && Long.compareUnsigned(last, 0xffff_ffffL) <= 0);
    }

    /** Whether a nonempty inner byte extent is contained in a bounded outer extent. */
    public static boolean contains(long start, long size, long inner, long innerSize) {
        if (size < innerSize || innerSize <= 0) return false;
        return Long.compareUnsigned(inner, start) >= 0 && Long.compareUnsigned(inner - start, size - innerSize) <= 0;
    }

    public static boolean overlaps(long first, long firstSize, long second, long secondSize) {
        if (firstSize <= 0 || secondSize <= 0) return false;
        return Long.compareUnsigned(first, second) <= 0
            ? Long.compareUnsigned(second - first, firstSize) < 0
            : Long.compareUnsigned(first - second, secondSize) < 0;
    }

    public static long distance(long start, long end) {
        long size = end - start;
        if (Long.compareUnsigned(start, end) > 0 || size < 0) {
            throw new IllegalArgumentException("target address distance exceeds the supported byte count");
        }
        return size;
    }
}
