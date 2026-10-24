package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_OFFSET32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_SYMBOLIC_RELOCATIONS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;

import java.nio.ByteOrder;
import java.util.Map;

import ghidradwarfforge.elf.ElfImage;

/** Table-driven libdwarf target description derived from the original ELF. */
public record DwarfTarget(String name, String producerIsa, int addressBytes,
        boolean littleEndian, String ghidraProcessor) {
    private static final int EM_MIPS = 8;
    private static final int EM_ARM = 40;
    private static final int EM_X86_64 = 62;
    private static final int EM_AARCH64 = 183;
    // Processor identities follow Ghidra 12.0.3's ELF .opinion and .ldefs files.
    // Language variants and compiler-spec IDs are not portable ABI identifiers.
    private static final Map<Integer, TargetDescription> TARGETS = Map.of(
        EM_MIPS, new TargetDescription("MIPS32", 4, "mipsel", "mips", "mips", true, "MIPS"),
        EM_ARM, new TargetDescription("ARM", 4, "arm", null, "arm", false, "ARM"),
        EM_X86_64,
            new TargetDescription("x86-64", 8, "x86_64", null, "x86_64", false, "x86"),
        EM_AARCH64,
            new TargetDescription("AArch64", 8, "aarch64", null, "arm64", false, "AARCH64"));

    private record TargetDescription(String displayName, int addressBytes,
            String littleEndianName, String bigEndianName, String producerIsa,
            boolean bigEndianSupported, String ghidraProcessor) {

        private DwarfTarget create(int actualAddressBytes, ByteOrder byteOrder) {
            if (actualAddressBytes != addressBytes) {
                throw new IllegalArgumentException(displayName + " requires ELF" +
                    (addressBytes * 8) + ", found ELF" + (actualAddressBytes * 8));
            }
            boolean littleEndian = byteOrder == ByteOrder.LITTLE_ENDIAN;
            if (!littleEndian && !bigEndianSupported) {
                throw new IllegalArgumentException(displayName +
                    " big-endian producer mode has not been audited");
            }
            String targetName = littleEndian ? littleEndianName : bigEndianName;
            if (targetName == null) {
                throw new IllegalArgumentException(displayName +
                    " byte order has no audited target description");
            }
            return new DwarfTarget(targetName, producerIsa, addressBytes, littleEndian,
                ghidraProcessor);
        }
    }

    public DwarfTarget {
        if (name == null || name.isBlank() || producerIsa == null ||
                producerIsa.isBlank() || (addressBytes != 4 && addressBytes != 8) ||
                ghidraProcessor == null || ghidraProcessor.isBlank()) {
            throw new IllegalArgumentException("invalid DWARF target description");
        }
    }

    public static DwarfTarget fromElf(ElfImage elf) {
        int addressBytes = elf.is64Bit() ? 8 : 4;
        return fromMetadata(elf.machine(), addressBytes, elf.byteOrder());
    }

    static DwarfTarget fromMetadata(int machine, int addressBytes, ByteOrder byteOrder) {
        if (byteOrder == null) {
            throw new IllegalArgumentException("ELF byte order is required");
        }
        TargetDescription description = TARGETS.get(machine);
        if (description == null) {
            throw new IllegalArgumentException("unsupported ELF machine " + machine +
                "; add an audited libdwarf target description before exporting");
        }
        return description.create(addressBytes, byteOrder);
    }

    public long producerFlags() {
        long pointerFlag = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
        long byteOrderFlag = littleEndian
                ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
        return pointerFlag | DW_DLC_OFFSET32 | DW_DLC_SYMBOLIC_RELOCATIONS |
            byteOrderFlag;
    }

}
