package ghidradwarfforge.firmware;

import java.nio.ByteOrder;
import java.util.Map;
import java.util.List;
import java.util.Objects;

/** Analyst-selected target identity; never inferred from a raw file's contents. */
public record FirmwareTarget(String profile, String architecture, String abi,
        int machine, int addressBits, int pointerBits, ByteOrder byteOrder,
        String instructionMode, String languageId, String compilerSpecId, long elfFlags) {
    public static final FirmwareTarget CORTEX_M3 = new FirmwareTarget(
        "cortex-m3", "ARMv7-M", "AAPCS32-base", 40, 32, 32, ByteOrder.LITTLE_ENDIAN,
        "Thumb-only", "ARM:LE:32:Cortex", "default", 0x05000000L);

    private static final Map<String, FirmwareTarget> PROFILES = Map.of(
        CORTEX_M3.profile(), CORTEX_M3);

    public FirmwareTarget {
        for (String value : new String[] {profile, architecture, abi, instructionMode,
                languageId, compilerSpecId}) {
            if (value == null || value.isBlank() || value.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("firmware target requires explicit identity fields");
            }
        }
        Objects.requireNonNull(byteOrder, "firmware byte order");
        if (machine <= 0 || machine > 0xffff || (addressBits != 32 && addressBits != 64) ||
                (pointerBits != 32 && pointerBits != 64) || elfFlags < 0 || elfFlags > 0xffff_ffffL) {
            throw new IllegalArgumentException("invalid firmware target widths or ELF metadata");
        }
    }

    /** Registry membership selects an implementation profile, not a validation claim. */
    public static FirmwareTarget select(String profile) {
        FirmwareTarget target = PROFILES.get(Objects.requireNonNull(profile, "firmware profile"));
        if (target == null) {
            throw new IllegalArgumentException("unsupported raw firmware profile: " + profile);
        }
        return target;
    }

    public void requireSupported() {
        if (!equals(PROFILES.get(profile))) {
            throw new IllegalArgumentException("unsupported or contradictory raw firmware target: " + profile);
        }
    }

    public record MetadataSection(String name, long type, byte[] bytes) { }

    /** Profile-declared ABI metadata, not recovered compiler attributes. */
    public List<MetadataSection> metadataSections() {
        requireSupported();
        if (equals(CORTEX_M3)) {
            // AAELF32 vendor subsection: Tag_CPU_arch=v7, profile=M, Thumb-2;
            // omitted extension/VFP tags are zero, the selected base-PCS profile.
            return List.of(new MetadataSection(".ARM.attributes", 0x70000003L,
                new byte[] {0x41, 21, 0, 0, 0, 'a', 'e', 'a', 'b', 'i', 0,
                    1, 11, 0, 0, 0, 6, 10, 7, 77, 9, 2}));
        }
        throw new IllegalArgumentException("firmware target has no audited metadata profile: " + profile);
    }
}
