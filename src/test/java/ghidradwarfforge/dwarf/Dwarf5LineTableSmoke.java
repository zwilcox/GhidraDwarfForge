package ghidradwarfforge.dwarf;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.dwarf.Dwarf5LineTable.LineRow;
import ghidradwarfforge.dwarf.Dwarf5LineTable.LineSequence;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Native-free overlap and discontiguous-range checks for line-table planning. */
public final class Dwarf5LineTableSmoke {
    private Dwarf5LineTableSmoke() {
    }

    public static void main(String[] args) {
        FunctionSymbol later = new FunctionSymbol("later", 0x3000, 0x10);
        FunctionSymbol split = new FunctionSymbol("split", 0x1000, List.of(
            new FunctionRange(0x1000, 0x10), new FunctionRange(0x2000, 0x10)));
        List<SourceLine> mappings = List.of(
            new SourceLine(30, List.of(0x1800L)),
            new SourceLine(20, List.of(0x2008L, 0x1004L)),
            new SourceLine(19, List.of(0x1004L)),
            new SourceLine(40, List.of(0x3004L)));

        List<LineSequence> expected = List.of(
            new LineSequence(0x1000, 0x1010, List.of(new LineRow(0x1004, 19))),
            new LineSequence(0x2000, 0x2010, List.of(new LineRow(0x2008, 20))),
            new LineSequence(0x3000, 0x3010, List.of(new LineRow(0x3004, 40))));
        List<LineSequence> planned = Dwarf5LineTable.plan(List.of(later, split), mappings);
        if (!planned.equals(expected)) {
            throw new AssertionError("unexpected line sequences: " + planned);
        }

        byte[] first = Dwarf5LineTable.build("fixture.dbg.c", 8,
            ByteOrder.LITTLE_ENDIAN, List.of(later, split), mappings);
        byte[] reordered = Dwarf5LineTable.build("fixture.dbg.c", 8,
            ByteOrder.LITTLE_ENDIAN, List.of(split, later), mappings.reversed());
        if (!Arrays.equals(first, reordered)) {
            throw new AssertionError("line table depends on function or evidence order");
        }
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : new int[] { 4, 8 }) {
                for (String directory : List.of("/tmp/source directory/é", "C:/source directory")) {
                    byte[] explicit = Dwarf5LineTable.build("fixture.dbg.c", directory,
                        width, order, List.of(later, split), mappings);
                    ByteBuffer header = ByteBuffer.wrap(explicit).order(order);
                    require(header.getInt() == explicit.length - 4, "unit length");
                    require(header.getShort() == 5, "version");
                    require(header.get() == width && header.get() == 0, "address metadata");
                    int headerLength = header.getInt();
                    int headerEnd = header.position() + headerLength;
                    header.position(header.position() + 18); // line-machine and opcode fields
                    require(header.get() == 1 && header.get() == 1 && header.get() == 8 &&
                        header.get() == 1, "directory-table format");
                    require(readString(header).equals(directory), "source directory");
                    require(header.get() == 2 && header.get() == 1 && header.get() == 8 &&
                        header.get() == 2 && header.get() == 15 && header.get() == 1,
                        "file-table format");
                    require(readString(header).equals("fixture.dbg.c") && header.get() == 0,
                        "source filename/directory index");
                    require(header.position() == headerEnd, "header length");
                    require(Arrays.equals(explicit, Dwarf5LineTable.build("fixture.dbg.c",
                        directory, width, order, List.of(split, later), mappings.reversed())),
                        "directory-aware deterministic output");
                }
            }
        }
        for (String invalid : new String[] { null, "", " ", "bad\0directory" }) {
            try {
                Dwarf5LineTable.build("fixture.dbg.c", invalid, 8, ByteOrder.LITTLE_ENDIAN,
                    List.of(later), mappings);
                throw new AssertionError("invalid source directory accepted");
            }
            catch (IllegalArgumentException expectedFailure) {
                // Reject invalid strings before serializing a truncated DWARF string.
            }
        }
        System.out.println("dwarf-line-table-smoke=PASS");
    }

    private static String readString(ByteBuffer buffer) {
        int start = buffer.position();
        while (buffer.get() != 0) {
            // Find the terminating byte in this bounded test header.
        }
        return new String(buffer.array(), start, buffer.position() - start - 1,
            StandardCharsets.UTF_8);
    }

    private static void require(boolean condition, String detail) {
        if (!condition) {
            throw new AssertionError("invalid line table: " + detail);
        }
    }
}
