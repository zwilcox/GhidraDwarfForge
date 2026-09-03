package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Deterministic DWARF 5 range-list table using absolute start/end entries. */
public final class Dwarf5RangeLists {
    private static final int DW_RLE_END_OF_LIST = 0x00;
    private static final int DW_RLE_START_END = 0x06;

    public record Result(byte[] section, long compilationUnitOffset,
            Map<FunctionSymbol, Long> functionOffsets) {
        public Result {
            section = section.clone();
            functionOffsets = Map.copyOf(functionOffsets);
        }

        @Override
        public byte[] section() {
            return section.clone();
        }

        public boolean empty() {
            return section.length == 0;
        }
    }

    private Dwarf5RangeLists() {
    }

    public static Result build(List<FunctionSymbol> functions, int addressBytes,
            ByteOrder order) {
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported address size " + addressBytes);
        }
        if (functions.stream().allMatch(FunctionSymbol::contiguous)) {
            return new Result(new byte[0], 0, Map.of());
        }

        ByteArrayOutputStream lists = new ByteArrayOutputStream();
        long unitOffset = 12; // DWARF32 length plus the DWARF 5 rnglists header.
        writeList(lists, mergedCompilationUnitRanges(functions), addressBytes, order);

        Map<FunctionSymbol, Long> offsets = new LinkedHashMap<>();
        for (FunctionSymbol function : functions) {
            if (function.contiguous()) {
                continue;
            }
            long offset = Math.addExact(unitOffset, lists.size());
            offsets.put(function, offset);
            writeList(lists, function.ranges(), addressBytes, order);
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeUnsigned(body, 5, 2, order);
        body.write(addressBytes);
        body.write(0); // segment selector size
        writeUnsigned(body, 0, 4, order); // offset entry count
        body.writeBytes(lists.toByteArray());

        ByteArrayOutputStream section = new ByteArrayOutputStream();
        writeUnsigned(section, body.size(), 4, order);
        section.writeBytes(body.toByteArray());
        return new Result(section.toByteArray(), unitOffset, offsets);
    }

    private static List<FunctionRange> mergedCompilationUnitRanges(
            List<FunctionSymbol> functions) {
        List<FunctionRange> ordered = functions.stream()
            .flatMap(function -> function.ranges().stream())
            .sorted(Comparator.comparingLong(FunctionRange::address)
                .thenComparingLong(FunctionRange::size))
            .toList();
        if (ordered.isEmpty()) {
            throw new IllegalArgumentException("at least one function range is required");
        }
        List<FunctionRange> merged = new ArrayList<>();
        long start = ordered.get(0).address();
        long end = ordered.get(0).endExclusive();
        for (int index = 1; index < ordered.size(); index++) {
            FunctionRange range = ordered.get(index);
            if (range.address() <= end) {
                end = Math.max(end, range.endExclusive());
            }
            else {
                merged.add(new FunctionRange(start, Math.subtractExact(end, start)));
                start = range.address();
                end = range.endExclusive();
            }
        }
        merged.add(new FunctionRange(start, Math.subtractExact(end, start)));
        return merged;
    }

    private static void writeList(ByteArrayOutputStream output,
            List<FunctionRange> ranges, int addressBytes, ByteOrder order) {
        for (FunctionRange range : ranges) {
            output.write(DW_RLE_START_END);
            writeUnsigned(output, range.address(), addressBytes, order);
            writeUnsigned(output, range.endExclusive(), addressBytes, order);
        }
        output.write(DW_RLE_END_OF_LIST);
    }

    private static void writeUnsigned(ByteArrayOutputStream output, long value, int width,
            ByteOrder order) {
        for (int index = 0; index < width; index++) {
            int shift = order == ByteOrder.LITTLE_ENDIAN ? index * 8 :
                (width - index - 1) * 8;
            output.write((int) (value >>> shift) & 0xff);
        }
    }
}
