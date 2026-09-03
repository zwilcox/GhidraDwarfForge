package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Native-free structural checks for deterministic DWARF 5 range lists. */
public final class Dwarf5RangeListsSmoke {
    private Dwarf5RangeListsSmoke() {
    }

    public static void main(String[] args) {
        FunctionSymbol contiguous = new FunctionSymbol("contiguous", 0x1000, 0x10);
        FunctionSymbol split = new FunctionSymbol("split", 0x2000, List.of(
            new FunctionRange(0x2000, 0x10), new FunctionRange(0x3000, 0x08)));
        if (split.contains(0x2800) || !split.contains(0x200f) || !split.contains(0x3007)) {
            throw new AssertionError("discontiguous containment includes a gap or loses a range");
        }

        Dwarf5RangeLists.Result little = Dwarf5RangeLists.build(
            List.of(contiguous, split), 8, ByteOrder.LITTLE_ENDIAN);
        byte[] section = little.section();
        if (section.length != 99 || little.compilationUnitOffset() != 12 ||
                little.functionOffsets().get(split) != 64L) {
            throw new AssertionError("unexpected ELF64 range-list layout");
        }
        ByteBuffer le = ByteBuffer.wrap(section).order(ByteOrder.LITTLE_ENDIAN);
        if (le.getInt(0) != 95 || Short.toUnsignedInt(le.getShort(4)) != 5 ||
                Byte.toUnsignedInt(section[6]) != 8 || le.getInt(8) != 0 ||
                Byte.toUnsignedInt(section[12]) != 0x06 || le.getLong(13) != 0x1000 ||
                le.getLong(21) != 0x1010 || Byte.toUnsignedInt(section[64]) != 0x06 ||
                le.getLong(65) != 0x2000 || le.getLong(73) != 0x2010 ||
                Byte.toUnsignedInt(section[81]) != 0x06 || le.getLong(82) != 0x3000 ||
                le.getLong(90) != 0x3008 || Byte.toUnsignedInt(section[98]) != 0) {
            throw new AssertionError("range-list bytes do not describe the expected intervals");
        }

        Dwarf5RangeLists.Result big = Dwarf5RangeLists.build(
            List.of(contiguous, split), 4, ByteOrder.BIG_ENDIAN);
        ByteBuffer be = ByteBuffer.wrap(big.section()).order(ByteOrder.BIG_ENDIAN);
        if (be.getInt(0) != big.section().length - 4 || be.getInt(13) != 0x1000 ||
                be.getInt(17) != 0x1010) {
            throw new AssertionError("big-endian ELF32 range-list encoding is incorrect");
        }

        if (!Dwarf5RangeLists.build(List.of(contiguous), 8,
                ByteOrder.LITTLE_ENDIAN).empty()) {
            throw new AssertionError("contiguous-only input should not need .debug_rnglists");
        }
        System.out.println("dwarf5-range-lists-smoke=PASS");
    }
}
