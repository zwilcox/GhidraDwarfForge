package ghidradwarfforge.targets;

import java.nio.ByteOrder;
import java.util.Map;
import java.util.List;
import java.util.Set;

import ghidradwarfforge.elf.ElfImage;

/** Pinned AMD64/AAELF64 dynamic data-write shapes, not relocation evaluation. */
public record UnwindRelocationProfile(String id, Map<Long, Integer> fixedWidths,
        long copyType, long indirectType, long relativeType, int alignment) {
    public UnwindRelocationProfile { fixedWidths = Map.copyOf(fixedWidths); }

    private static final Map<Integer, UnwindRelocationProfile> PROFILES = Map.of(
        62, new UnwindRelocationProfile("amd64-sysv", Map.ofEntries(
            Map.entry(0L, 0), Map.entry(1L, 8), Map.entry(2L, 4),
            Map.entry(6L, 8), Map.entry(7L, 8), Map.entry(8L, 8),
            Map.entry(10L, 4), Map.entry(11L, 4), Map.entry(16L, 8),
            Map.entry(17L, 8), Map.entry(18L, 8), Map.entry(24L, 8),
            Map.entry(32L, 4), Map.entry(33L, 8), Map.entry(36L, 16)), 5, 37, 8, 1),
        183, new UnwindRelocationProfile("aarch64-sysv", Map.ofEntries(
            Map.entry(0L, 0), Map.entry(257L, 8), Map.entry(1025L, 8),
            Map.entry(1026L, 8), Map.entry(1027L, 8), Map.entry(1028L, 8),
            Map.entry(1029L, 8), Map.entry(1030L, 8), Map.entry(1031L, 16)), 1024, 1032, 1027, 8));

    // These tags describe ordinary gABI/GNU loading. Unknown extensions are
    // not silently treated as metadata-only: the caller must reject them.
    private static final Set<Long> TAGS = Set.of(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L, 11L,
        12L, 13L, 14L, 15L, 16L, 17L, 18L, 19L, 20L, 21L, 22L, 23L, 24L,
        25L, 26L, 27L, 28L, 29L, 30L, 32L, 33L, 34L, 35L, 36L, 37L,
        0x6ffffef5L, 0x6ffffff0L, 0x6ffffff9L, 0x6ffffffaL, 0x6ffffffbL,
        0x6ffffffcL, 0x6ffffffdL, 0x6ffffffeL, 0x6fffffffL);

    public static UnwindRelocationProfile select(ElfImage image) {
        byte[] header = image.headerBytes();
        var profile = PROFILES.get(image.machine());
        if (profile == null || !image.is64Bit() || image.byteOrder() != ByteOrder.LITTLE_ENDIAN ||
                (image.type() != 2 && image.type() != 3) || image.flags() != 0 ||
                (header[7] != 0 && header[7] != 3) || header[8] != 0) {
            throw new IllegalArgumentException("no audited ordinary unwind relocation profile");
        }
        return profile;
    }

    public record PointerWrite(long tag, int offset, int size) { }

    /** Reserved GOT slots, plus the GNU descriptor resolver slot when declared. */
    public List<PointerWrite> loaderPointerWrites() {
        return id.equals("amd64-sysv") ? List.of(new PointerWrite(3, 8, 16), new PointerWrite(0x6ffffef7L, 0, 8)) :
            List.of(new PointerWrite(3, 8, 16));
    }

    public void requireTag(long tag, long value) {
        // GNU descriptor PLT/GOT pointers describe the ordinary descriptor
        // mechanism. The descriptor relocation itself carries the two-word write.
        boolean descriptorMetadata = id.equals("amd64-sysv") && (tag == 0x6ffffef6L || tag == 0x6ffffef7L);
        if (!TAGS.contains(tag) && !descriptorMetadata) {
            throw new IllegalArgumentException("unknown unwind relocation metadata tag: " + Long.toHexString(tag));
        }
        if (tag == 30 && (value & ~0x1fL) != 0) throw new IllegalArgumentException("unknown dynamic flags");
        // NOW, GLOBAL, NODELETE, ORIGIN, NODEFLIB and PIE do not introduce a
        // new relocation encoding. Other loader modes need their own audit.
        if (tag == 0x6ffffffbL && (value & ~0x0800088bL) != 0) {
            throw new IllegalArgumentException("unreviewed dynamic loader mode");
        }
    }
}
