package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Read-only corroboration for the strict checker's inherited frame diagnostic policy. */
public final class InheritedFrameBytes {
    public record Evidence(long address, long bytes, String sha256, long originalOffset, boolean fromProgramHeaders) { }

    private InheritedFrameBytes() { }

    /**
     * No match is inferred from diagnostic text alone. A sectionless original
     * must independently establish the complete frame extent from its program
     * headers/search table. Callers bracket this with full input observations.
     */
    public static Evidence compare(Path original, Path sidecar, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        ElfImage before = ElfImage.read(original);
        ElfImage after = ElfImage.read(sidecar);
        if (!Arrays.equals(Arrays.copyOf(before.headerBytes(), 16), Arrays.copyOf(after.headerBytes(), 16)) ||
                before.type() != after.type() || before.machine() != after.machine() || before.flags() != after.flags()) {
            throw new IOException("inherited frame ELF identities differ");
        }
        boolean sectionless = before.sections().isEmpty();
        var originalFrame = sectionless ? discovered(before, cancelled) : frame(before);
        var sidecarFrame = frame(after);
        if (originalFrame.address != sidecarFrame.address || originalFrame.flags != sidecarFrame.flags ||
                originalFrame.size != sidecarFrame.size) {
            throw new IOException("inherited frame section identities differ");
        }
        check(cancelled);
        byte[] originalBytes = before.sectionData(originalFrame);
        byte[] sidecarBytes = after.sectionData(sidecarFrame);
        check(cancelled);
        if (!Arrays.equals(originalBytes, sidecarBytes)) throw new IOException("inherited frame bytes differ");
        try {
            return new Evidence(originalFrame.address, originalBytes.length,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(originalBytes)),
                originalFrame.offset, sectionless);
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static ElfImage.Section frame(ElfImage image) throws IOException {
        var frames = image.sections().stream().filter(section -> section.name.equals(".eh_frame")).toList();
        if (frames.size() != 1 || frames.getFirst().type != 1 || frames.getFirst().size == 0 ||
                frames.getFirst().size > ElfImage.MAX_TABLE_BYTES) {
            throw new IOException("frame corroboration requires one bounded nonempty PROGBITS .eh_frame");
        }
        return frames.getFirst();
    }

    static ElfImage.Section discovered(ElfImage image, BooleanSupplier cancelled) throws IOException {
        var diagnostics = new java.util.ArrayList<String>();
        var frame = SectionlessUnwind.find(image, cancelled, diagnostics::add);
        if (frame == null || !diagnostics.isEmpty()) {
            throw new IOException("original program headers do not establish frame records: " + diagnostics);
        }
        return frame;
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("frame corroboration cancelled");
    }
}
