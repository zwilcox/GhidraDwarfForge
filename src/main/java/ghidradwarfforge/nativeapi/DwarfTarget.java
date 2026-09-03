package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_OFFSET32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_SYMBOLIC_RELOCATIONS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;

import java.nio.ByteOrder;

import ghidradwarfforge.elf.ElfImage;

/** Table-driven libdwarf target description derived from the original ELF. */
public record DwarfTarget(String name, String producerIsa, int addressBytes,
        boolean littleEndian) {
    private static final int EM_MIPS = 8;
    private static final int EM_X86_64 = 62;
    private static final int EM_AARCH64 = 183;

    public static DwarfTarget fromElf(ElfImage elf) {
        int addressBytes = elf.is64Bit() ? 8 : 4;
        boolean littleEndian = elf.byteOrder() == ByteOrder.LITTLE_ENDIAN;
        return switch (elf.machine()) {
            case EM_X86_64 -> {
                requireWidth("x86-64", addressBytes, 8);
                requireLittleEndian("x86-64", littleEndian);
                yield new DwarfTarget("x86_64", "x86_64", 8, littleEndian);
            }
            case EM_AARCH64 -> {
                requireWidth("AArch64", addressBytes, 8);
                requireLittleEndian("AArch64", littleEndian);
                yield new DwarfTarget("aarch64", "arm64", 8, littleEndian);
            }
            case EM_MIPS -> new DwarfTarget(
                littleEndian ? "mipsel" : "mips", "mips", addressBytes, littleEndian);
            default -> throw new IllegalArgumentException(
                "unsupported ELF machine " + elf.machine() +
                    "; add an audited libdwarf target description before exporting");
        };
    }

    public long producerFlags() {
        long pointerFlag = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
        long byteOrderFlag = littleEndian
                ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
        return pointerFlag | DW_DLC_OFFSET32 | DW_DLC_SYMBOLIC_RELOCATIONS |
            byteOrderFlag;
    }

    private static void requireWidth(String architecture, int actual, int expected) {
        if (actual != expected) {
            throw new IllegalArgumentException(
                architecture + " requires ELF" + (expected * 8) + ", found ELF" +
                    (actual * 8));
        }
    }

    private static void requireLittleEndian(String architecture, boolean littleEndian) {
        if (!littleEndian) {
            throw new IllegalArgumentException(
                architecture + " big-endian producer mode has not been audited");
        }
    }
}
