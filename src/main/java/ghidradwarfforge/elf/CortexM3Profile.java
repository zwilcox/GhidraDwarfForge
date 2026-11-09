package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.function.BooleanSupplier;

/** Explicit ARMv7-M/base-PCS profile, never inferred from the generic ARM target. */
public final class CortexM3Profile {
    private CortexM3Profile() { }

    public static void requireImage(ElfImage image, BooleanSupplier cancelled) throws IOException {
        require(image.machine() == 40 && !image.is64Bit() && image.type() == 2 &&
            image.byteOrder() == ByteOrder.LITTLE_ENDIAN, "requires little-endian ARM ELF32 ET_EXEC");
        byte[] header = image.headerBytes();
        require(header[7] == 0 && header[8] == 0 &&
            (image.flags() & ~0x200L) == 0x05000000L, "requires System V EABI5 base PCS flags");
        final Map<Integer, Long> attributes;
        try {
            attributes = Arm32CallAbi.readFileAttributes(image, cancelled);
        }
        catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Cortex-M3 profile: " + invalid.getMessage(), invalid);
        }
        // Arm addenda32: CPU_arch=10 denotes v7, CPU_arch_profile='M' selects v7-M.
        require(!attributes.containsKey(64), "Tag_nodefaults does not prove this profile");
        require(attributes.getOrDefault(6, 0L) == 10 && attributes.getOrDefault(7, 0L) == 77,
            "requires explicit ARMv7-M build attributes");
        require(attributes.getOrDefault(8, 0L) == 0, "ARM-state instructions are incompatible");
        long thumb = attributes.getOrDefault(9, 0L);
        require(thumb == 2 || thumb == 3, "requires Thumb-2 or architecture-derived Thumb permission");
        // Reject declared extensions outside M3 and non-base procedure-call assumptions.
        // Software floating-point arithmetic/IEEE number-model tags are not FPU use.
        for (int tag : new int[] {10, 11, 12, 27, 28, 29, 36, 42, 46, 48, 50, 52, 66, 68, 70}) {
            require(attributes.getOrDefault(tag, 0L) == 0,
                "unsupported extension or calling convention attribute " + tag);
        }
        require(!attributes.containsKey(65), "alternate architecture compatibility needs separate validation");
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new IllegalArgumentException("Cortex-M3 profile: " + reason);
    }
}
