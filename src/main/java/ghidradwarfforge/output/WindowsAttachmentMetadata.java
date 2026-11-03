package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Combines complete security, ordinary metadata and backup-stream admission for
 * private attachment stages. This is not a complete filesystem/durability Host.
 * Requires an already authorized token and never adjusts privileges. Unsupported
 * source/stage metadata is rejected before application. No file is published.
 */
public final class WindowsAttachmentMetadata {
    // Presence/defaulted, auto-inherit request/result, and protection, from the
    // pinned SECURITY_DESCRIPTOR_CONTROL header. Empty SACL is not no metadata.
    private static final int SACL_FLAGS = 0x2a30;
    private final WindowsFileMetadata metadata;
    private final WindowsFileSecurity security;
    private final WindowsBackupStreams streams;

    public record Preservation(WindowsFileMetadata.Preservation ordinary, int fullControl) { }
    public record Snapshot(WindowsFileMetadata.Snapshot ordinary,
            WindowsFileSecurity.Descriptor security, WindowsBackupStreams.Inventory streams) {
        public Snapshot {
            Objects.requireNonNull(ordinary);
            Objects.requireNonNull(security);
            Objects.requireNonNull(streams);
        }
        public Preservation preservation() { return new Preservation(ordinary.preservation(), security.control()); }
    }

    public WindowsAttachmentMetadata() throws IOException {
        metadata = new WindowsFileMetadata();
        security = new WindowsFileSecurity();
        streams = new WindowsBackupStreams(metadata);
    }

    public Snapshot inspect(Path path, BooleanSupplier cancelled) throws IOException {
        var ordinary = metadata.inspect(path, cancelled);
        WindowsFileMetadata.supported(ordinary);
        require(ordinary.facts().links() == 1, "Windows attachment metadata rejects hardlinks");
        var complete = security.inspect(path, cancelled);
        require(ordinary.facts().equals(complete.facts()), "Windows attachment security identity changed");
        require(!complete.descriptor().saclPresent() && complete.descriptor().saclHex() == null &&
            (complete.descriptor().control() & 0x30) == 0,
            "Windows attachment metadata does not support populated, null or empty SACLs");
        require((complete.descriptor().control() & 0x40c0) == 0 &&
            HexFormat.of().parseHex(complete.descriptor().rawDescriptor())[1] == 0,
            "Windows attachment metadata rejects resource-manager or unsupported security controls");
        var inventory = streams.inspect(path, cancelled);
        WindowsBackupStreams.requireOrdinaryData(inventory);
        require(ordinary.facts().equals(inventory.facts()), "Windows attachment stream identity changed");
        require(ordinary.equals(metadata.inspect(path, cancelled)), "Windows attachment metadata changed during admission");
        require(complete.equals(security.inspect(path, cancelled)), "Windows attachment security changed during admission");
        return new Snapshot(ordinary, complete.descriptor(), inventory);
    }

    public Snapshot applyToOwnedStage(Path source, Snapshot expected, Path stage, BooleanSupplier cancelled)
            throws IOException {
        Objects.requireNonNull(expected);
        var before = inspect(source, cancelled);
        require(before.equals(expected), "Windows attachment metadata source changed");
        var prior = inspect(stage, cancelled);
        require(!before.ordinary().facts().identity().equals(prior.ordinary().facts().identity()),
            "Windows attachment metadata stage aliases source");
        require((before.security().control() & SACL_FLAGS) == (prior.security().control() & SACL_FLAGS),
            "Windows attachment stage has different SACL control flags");
        metadata.applyToOwnedStage(source, before.ordinary(), stage, cancelled);
        var after = inspect(stage, cancelled);
        require(after.ordinary().facts().identity().equals(prior.ordinary().facts().identity()) &&
            after.ordinary().facts().bytes() == prior.ordinary().facts().bytes(),
            "Windows attachment stage identity or size changed");
        require(after.preservation().equals(before.preservation()),
            "Windows attachment complete metadata readback differs");
        require(inspect(source, cancelled).equals(before), "Windows attachment source metadata changed during application");
        return after;
    }

    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
