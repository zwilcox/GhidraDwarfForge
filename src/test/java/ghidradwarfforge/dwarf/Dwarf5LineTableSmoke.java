package ghidradwarfforge.dwarf;

import java.nio.ByteOrder;
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
        System.out.println("dwarf-line-table-smoke=PASS");
    }
}
