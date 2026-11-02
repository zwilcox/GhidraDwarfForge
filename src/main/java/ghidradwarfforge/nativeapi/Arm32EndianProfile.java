package ghidradwarfforge.nativeapi;

import java.nio.ByteOrder;
import ghidradwarfforge.elf.ElfImage;

/** ARM ELF data/instruction encoding, separate from a function's call ABI. */
final class Arm32EndianProfile {
    private static final int EM_ARM = 40;
    private static final long EF_ARM_BE8 = 0x00800000L;
    private static final long EF_ARM_LE8 = 0x00400000L;
    private static final long EF_ARM_EABIMASK = 0xff000000L;
    private static final long EF_ARM_EABI5 = 0x05000000L;

    private Arm32EndianProfile() { }

    static boolean isBe8(ElfImage image) {
        return image.machine() == EM_ARM && image.byteOrder() == ByteOrder.BIG_ENDIAN &&
            (image.flags() & EF_ARM_BE8) != 0;
    }

    static void requireSupportedEncoding(ElfImage image) {
        if (image.machine() != EM_ARM) return;
        if (image.byteOrder() == ByteOrder.LITTLE_ENDIAN) {
            if ((image.flags() & EF_ARM_BE8) != 0) {
                throw new IllegalArgumentException("ARM BE8 flag contradicts little-endian ELF data");
            }
            return;
        }
        if (!isBe8(image) || (image.flags() & EF_ARM_LE8) != 0 ||
                (image.flags() & EF_ARM_EABIMASK) != EF_ARM_EABI5) {
            throw new IllegalArgumentException("ARM big-endian encoding requires EABI5 BE8; " +
                "BE32 and contradictory instruction flags have no validated profile");
        }
    }

    static ByteOrder instructionByteOrder(ElfImage image) {
        return isBe8(image) ? ByteOrder.LITTLE_ENDIAN : null;
    }
}
