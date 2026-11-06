package ghidradwarfforge.targets;

import java.nio.ByteOrder;
import java.util.Map;
import java.util.Set;

import ghidradwarfforge.elf.ElfImage;

/** Processor-specific frame section types; not authority to trust frame rules. */
public final class UnwindSectionProfile {
    private record Key(int machine, boolean wide, ByteOrder order) { }

    // AMD64 psABI 1.0, sections 4.2.2 through 4.2.4. Keep recognition limited
    // to the validated ELF64 little-endian layout; this does not qualify x32.
    private static final Map<Key, Set<Long>> TYPES = Map.of(
        new Key(62, true, ByteOrder.LITTLE_ENDIAN), Set.of(0x70000001L));

    private UnwindSectionProfile() { }

    public static boolean isFrameData(ElfImage image, String name, long type) {
        return type == 1 || name.equals(".eh_frame") && isProcessorFrameType(image, type);
    }

    public static boolean isProcessorFrameType(ElfImage image, long type) {
        return TYPES.getOrDefault(
            new Key(image.machine(), image.is64Bit(), image.byteOrder()), Set.of())
            .contains(type);
    }
}
