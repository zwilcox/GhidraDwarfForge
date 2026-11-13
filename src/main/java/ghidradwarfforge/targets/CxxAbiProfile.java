package ghidradwarfforge.targets;

import java.nio.ByteOrder;

/** Explicit C++ layout profiles; an ELF machine alone does not select a C++ ABI. */
public enum CxxAbiProfile {
    UNSPECIFIED(0, 0),
    ITANIUM_X86_64(62, 8),
    ITANIUM_AARCH64(183, 8);

    private final int machine;
    private final int pointerBytes;

    CxxAbiProfile(int machine, int pointerBytes) {
        this.machine = machine;
        this.pointerBytes = pointerBytes;
    }

    public int pointerBytes() { return pointerBytes; }

    public void requireTarget(int actualMachine, int addressBytes, ByteOrder order) {
        if (this == UNSPECIFIED || actualMachine != machine || addressBytes != pointerBytes ||
                order != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("C++ ABI profile does not match a validated target layout");
        }
    }

    public void requireProgramTarget(String processor, int addressBytes, ByteOrder order) {
        String expected = switch (this) {
            case ITANIUM_X86_64 -> "x86";
            case ITANIUM_AARCH64 -> "AARCH64";
            case UNSPECIFIED -> "";
        };
        if (expected.isEmpty() || !expected.equals(processor)) {
            throw new IllegalArgumentException("C++ ABI profile does not match Ghidra processor");
        }
        requireTarget(machine, addressBytes, order);
    }

    /** Vbase displacements precede the offset-to-top and RTTI entries. */
    public void requireVirtualBase(long vptrOffset, long slotOffset, long objectBytes) {
        if (this == UNSPECIFIED || vptrOffset < 0 || vptrOffset % pointerBytes != 0 ||
                objectBytes < pointerBytes || vptrOffset > objectBytes - pointerBytes ||
                slotOffset > -3L * pointerBytes || slotOffset % pointerBytes != 0) {
            throw new IllegalArgumentException("invalid virtual-base location for C++ ABI profile");
        }
    }
}
