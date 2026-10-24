package ghidradwarfforge.nativeapi;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Native-free model checks, optionally followed by an isolated real producer. */
public final class FunctionEntrySmoke {
    private FunctionEntrySmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        List<FunctionSymbol> functions = functions(0x1000);
        for (int width : new int[] { 4, 8 }) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var ranges = Dwarf5RangeLists.build(functions, width, order);
                if (ranges.empty() || ranges.functionOffsets().size() != 2) {
                    throw new AssertionError("split body lost its ranges");
                }
                checkRanges(ranges, functions.get(0), width, order,
                    new long[][] { { 0x1022, 0x1028 }, { 0x1000, 0x1008 },
                        { 0x1020, 0x1022 } });
                checkRanges(ranges, functions.get(1), width, order,
                    new long[][] { { 0x1044, 0x1050 }, { 0x1040, 0x1044 } });
                byte[] lines = Dwarf5LineTable.build("entry.c", width, order, functions,
                    List.of(new SourceLine(3, List.of(0x1000L, 0x1020L, 0x1040L))));
                if (lines.length == 0 || functions.get(0).contains(0x1010)) {
                    throw new AssertionError("missing lines or false gap coverage");
                }
            }
        }
        reject(0x1010); // A hole between real ranges is not an entry.
        reject(0x1028); // Nor is the exclusive range end.
        reject(0xfff);
        if (arguments.length == 4) {
            Path input = Path.of(arguments[2]);
            Path output = Path.of(arguments[3]);
            Files.createDirectories(output.toAbsolutePath().getParent());
            ElfImage elf = ElfImage.read(input);
            // Synthetic addresses exercise the producer and all relocation
            // widths. Executable code is independently checked by headless/GDB.
            long base = Math.addExact(elf.preferredImageBase(), 0x1000);
            var result = new MinimalDwarfSidecarExporter().export(input, output,
                Path.of(arguments[0]), Path.of(arguments[1]), functions(base));
            System.out.printf("entry-producer=PASS target=%s split-entry=0x%x " +
                "middle-entry=0x%x middle-low=0x%x%n", result.target().name(),
                base + 0x22, base + 0x44, base + 0x40);
        }
        else if (arguments.length != 0) {
            throw new IllegalArgumentException(
                "usage: FunctionEntrySmoke [<libdwarf> <libdwarfp> <input> <output>]");
        }
        System.out.println("function-entry-smoke=PASS");
    }

    private static void checkRanges(Dwarf5RangeLists.Result result, FunctionSymbol function,
            int width, ByteOrder order, long[][] expected) {
        ByteBuffer data = ByteBuffer.wrap(result.section()).order(order);
        data.position(Math.toIntExact(result.functionOffsets().get(function)));
        for (long[] range : expected) {
            if (data.get() != 6) {
                throw new AssertionError("expected DW_RLE_start_end");
            }
            long start = width == 8 ? data.getLong() : Integer.toUnsignedLong(data.getInt());
            long end = width == 8 ? data.getLong() : Integer.toUnsignedLong(data.getInt());
            if (start != range[0] || end != range[1]) {
                throw new AssertionError("wrong entry/order/body interval");
            }
        }
        if (data.get() != 0 || function.ranges().get(0).address() >= function.address()) {
            throw new AssertionError("unterminated list or extraction model was reordered");
        }
    }

    private static List<FunctionSymbol> functions(long base) {
        return List.of(new FunctionSymbol("split_entry", base + 0x22,
                List.of(new FunctionRange(base, 8), new FunctionRange(base + 0x20, 8))),
            new FunctionSymbol("middle_entry", base + 0x44,
                List.of(new FunctionRange(base + 0x40, 16))),
            new FunctionSymbol("ordinary_entry", base + 0x80, 8));
    }

    private static void reject(long entry) {
        try {
            new FunctionSymbol("invalid", entry,
                List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x1020, 8)));
            throw new AssertionError("accepted entry outside body: " + entry);
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("outside its body ranges")) {
                throw expected;
            }
        }
    }
}
