package ghidradwarfforge.elf;

/**
 * Separates ARM EABI5 function entry mode from its allocation byte address.
 * See AAELF32 section 5.5.3 (Symbol Values); the serialized value retains its tag.
 */
final class Arm32SymbolValues {
    private Arm32SymbolValues() {
    }

    static long allocationAddress(ElfImage image, int symbolType, long value) {
        if (!image.is64Bit() && image.machine() == 40 &&
                (image.flags() & 0xff000000L) == 0x05000000L && symbolType == 2) {
            // The tag belongs to the preserved STT_FUNC value, not its extent.
            // This rule is independent of ELF data byte order and BE8 code order.
            return value & ~1L;
        }
        return value;
    }
}
