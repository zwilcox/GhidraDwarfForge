package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;

import java.nio.ByteOrder;

/** Checks the isolated, fail-closed ELF-to-libdwarf target description table. */
public final class DwarfTargetSmoke {
    private DwarfTargetSmoke() {
    }

    public static void main(String[] arguments) {
        assertTarget(62, 8, ByteOrder.LITTLE_ENDIAN, "x86_64", "x86_64", true);
        assertTarget(183, 8, ByteOrder.LITTLE_ENDIAN, "aarch64", "arm64", true);
        assertTarget(40, 4, ByteOrder.LITTLE_ENDIAN, "arm", "arm", true);
        assertTarget(8, 4, ByteOrder.LITTLE_ENDIAN, "mipsel", "mips", true);
        assertTarget(8, 4, ByteOrder.BIG_ENDIAN, "mips", "mips", false);

        expectFailure(() -> DwarfTarget.fromMetadata(0xffff, 8,
            ByteOrder.LITTLE_ENDIAN), "unsupported ELF machine");
        expectFailure(() -> DwarfTarget.fromMetadata(62, 4,
            ByteOrder.LITTLE_ENDIAN), "requires ELF64");
        expectFailure(() -> DwarfTarget.fromMetadata(8, 8,
            ByteOrder.BIG_ENDIAN), "requires ELF32");
        expectFailure(() -> DwarfTarget.fromMetadata(62, 8,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        expectFailure(() -> DwarfTarget.fromMetadata(183, 8,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        expectFailure(() -> DwarfTarget.fromMetadata(40, 4,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        expectFailure(() -> DwarfTarget.fromMetadata(8, 4, null),
            "ELF byte order is required");
        System.out.println("dwarf-target-smoke=PASS");
    }

    private static void assertTarget(int machine, int addressBytes, ByteOrder byteOrder,
            String name, String producerIsa, boolean littleEndian) {
        DwarfTarget target = DwarfTarget.fromMetadata(machine, addressBytes, byteOrder);
        if (!target.name().equals(name) || !target.producerIsa().equals(producerIsa) ||
                target.addressBytes() != addressBytes ||
                target.littleEndian() != littleEndian) {
            throw new AssertionError("unexpected target description " + target);
        }
        long expectedPointer = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
        long expectedByteOrder = littleEndian
            ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
        if ((target.producerFlags() & expectedPointer) == 0 ||
                (target.producerFlags() & expectedByteOrder) == 0) {
            throw new AssertionError("target flags do not match " + target);
        }
    }

    private static void expectFailure(Runnable action, String expectedMessage) {
        try {
            action.run();
            throw new AssertionError("invalid target description was accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(expectedMessage)) {
                throw new AssertionError("unexpected failure: " + expected.getMessage());
            }
        }
    }
}
