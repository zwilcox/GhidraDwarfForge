package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/**
 * Optional code-address lookup for the exporter's single DWARF32 compilation
 * unit. DWARF 5 sections 6.1.2 and 7.21 retain address-table version 2.
 *
 * Only actual function body intervals belong here. GDB 15.1 uses this table
 * instead of its fallback index of global data addresses, which can disagree
 * with its code-only CU symtab bounds. No data addresses or gaps become code
 * coverage, and this table does not replace the DIEs' authoritative ranges.
 */
public final class DwarfAddressRanges {
    private static final long MAX_UNSIGNED_INT = 0xffff_ffffL;
    private static final int HEADER_BYTES = 12;

    private DwarfAddressRanges() {
    }

    public static byte[] build(List<FunctionSymbol> functions, int addressBytes,
            ByteOrder order) {
        Objects.requireNonNull(functions, "functions");
        Objects.requireNonNull(order, "byte order");
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported address size " + addressBytes);
        }
        if (functions.isEmpty()) {
            return new byte[0];
        }
        List<FunctionRange> tuples = new ArrayList<>();
        for (FunctionRange range : Dwarf5RangeLists.mergedCompilationUnitRanges(functions)) {
            // The model already bounds ELF64 addresses to nonnegative Java longs.
            // ELF32 may end exactly at 2^32, including a full address-space union.
            if (addressBytes == 4 && (range.address() > MAX_UNSIGNED_INT ||
                    range.endExclusive() > MAX_UNSIGNED_INT + 1)) {
                throw new IllegalArgumentException("function range does not fit ELF32 " +
                    "address lookup: " + range);
            }
            if (addressBytes == 4 && range.size() > MAX_UNSIGNED_INT) {
                // A 2^32-byte union needs two width-sized lengths. Adjacent tuples
                // preserve coverage without truncating the length to a terminator.
                tuples.add(new FunctionRange(range.address(), MAX_UNSIGNED_INT));
                tuples.add(new FunctionRange(range.address() + MAX_UNSIGNED_INT,
                    range.size() - MAX_UNSIGNED_INT));
            }
            else {
                tuples.add(range);
            }
        }
        int tupleBytes = 2 * addressBytes;
        int firstTuple = ((HEADER_BYTES + tupleBytes - 1) / tupleBytes) * tupleBytes;
        long totalBytes = firstTuple + ((long) tuples.size() + 1) * tupleBytes;
        if (totalBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("address lookup exceeds Java section size limit");
        }
        ByteBuffer table = ByteBuffer.allocate((int) totalBytes).order(order);
        table.putInt((int) totalBytes - Integer.BYTES); // DWARF32 contribution length
        table.putShort((short) 2);
        table.putInt(0); // Single CU HEADER at .debug_info offset 0, not its first DIE.
        table.put((byte) addressBytes);
        table.put((byte) 0); // Flat address space: no segment selector.
        table.position(firstTuple); // Zero-initialized padding to a tuple boundary.
        for (FunctionRange range : tuples) {
            if (addressBytes == 4) {
                table.putInt((int) range.address()).putInt((int) range.size());
            }
            else {
                table.putLong(range.address()).putLong(range.size());
            }
        }
        // The zero-initialized final address/length tuple terminates this CU.
        return table.array();
    }
}
