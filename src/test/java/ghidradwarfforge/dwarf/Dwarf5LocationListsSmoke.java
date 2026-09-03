package ghidradwarfforge.dwarf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Piece;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Native-free byte-level checks for DWARF 5 location lists. */
public final class Dwarf5LocationListsSmoke {
    private Dwarf5LocationListsSmoke() {
    }

    public static void main(String[] args) {
        Evidence analysis = new Evidence(Confidence.ANALYSIS, "fixture stack depth");
        TargetRegisterMap registers = TargetRegisterMap.forTarget("x86_64");
        VariableLocation local = new VariableLocation("function", 0x1000, "local",
            VariableKind.LOCAL, 4, List.of(
                new LocationRange(0x1000, 0x1001,
                    new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                        "prologue depth unavailable"), analysis),
                new LocationRange(0x1001, 0x1010,
                    registers.registerRelative("RSP", -4), analysis),
                new LocationRange(0x1010, 0x1011,
                    registers.registerRelative("RSP", -12), analysis)));
        Dwarf5LocationLists.Result result = Dwarf5LocationLists.build(List.of(local),
            8, ByteOrder.LITTLE_ENDIAN);
        byte[] section = result.section();
        if (result.offsets().get(local) != 12L || section.length != 55) {
            throw new AssertionError("unexpected location-list layout");
        }
        ByteBuffer bytes = ByteBuffer.wrap(section).order(ByteOrder.LITTLE_ENDIAN);
        if (bytes.getInt(0) != 51 || Short.toUnsignedInt(bytes.getShort(4)) != 5 ||
                Byte.toUnsignedInt(section[6]) != 8 || bytes.getInt(8) != 0 ||
                Byte.toUnsignedInt(section[12]) != 0x07 || bytes.getLong(13) != 0x1001 ||
                bytes.getLong(21) != 0x1010 || Byte.toUnsignedInt(section[29]) != 3 ||
                Byte.toUnsignedInt(section[30]) != DwarfLocationExpression.DW_OP_BREGX ||
                Byte.toUnsignedInt(section[31]) != 7 || section[32] != 0x7c ||
                Byte.toUnsignedInt(section[54]) != 0) {
            throw new AssertionError("location-list bytes are incorrect");
        }
        Dwarf5LocationLists.Result big = Dwarf5LocationLists.build(List.of(local),
            4, ByteOrder.BIG_ENDIAN);
        if (ByteBuffer.wrap(big.section()).order(ByteOrder.BIG_ENDIAN).getInt(13) !=
                0x1001) {
            throw new AssertionError("big-endian location-list addresses are incorrect");
        }
        VariableLocation unresolved = new VariableLocation("function", 0x1000,
            "raw-stack", VariableKind.LOCAL, 4, List.of(
                new LocationRange(0x1000, 0x1008, new StackStorage(-8), analysis),
                new LocationRange(0x1008, 0x1010, new StackStorage(-16), analysis)));
        if (!Dwarf5LocationLists.build(List.of(unresolved), 8,
                ByteOrder.LITTLE_ENDIAN).empty()) {
            throw new AssertionError("unsupported available storage must fail closed");
        }
        CompositeStorage composite = new CompositeStorage(List.of(
            new Piece(registers.register("RAX", 0, 32), 32),
            new Piece(registers.register("RDX", 0, 32), 32)));
        VariableLocation compositeList = new VariableLocation("function", 0x1000,
            "composite", VariableKind.LOCAL, 8, List.of(
                new LocationRange(0x1000, 0x1001,
                    new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                        "not live yet"), analysis),
                new LocationRange(0x1001, 0x1010, composite, analysis)));
        byte[] compositeSection = Dwarf5LocationLists.build(List.of(compositeList),
            8, ByteOrder.LITTLE_ENDIAN).section();
        if (!contains(compositeSection, new byte[] {
                (byte) DwarfLocationExpression.DW_OP_REGX, 0,
                (byte) DwarfLocationExpression.DW_OP_BIT_PIECE, 32, 0,
                (byte) DwarfLocationExpression.DW_OP_REGX, 1,
                (byte) DwarfLocationExpression.DW_OP_BIT_PIECE, 32, 0 })) {
            throw new AssertionError("composite location-list expression is incorrect");
        }
        System.out.println("dwarf5-location-lists-smoke=PASS");
    }

    private static boolean contains(byte[] data, byte[] expected) {
        outer: for (int start = 0; start <= data.length - expected.length; start++) {
            for (int index = 0; index < expected.length; index++) {
                if (data[start + index] != expected[index]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
