package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.function.BooleanSupplier;

/**
 * Read-only cooperative stop channel across an OS authorization boundary.
 * The caller owns a fresh empty file. Any observed change, removal or inspection
 * failure latches cancellation. Its contents are never interpreted or executed.
 * The helper never writes this file and never kills a transaction on cancellation.
 */
final class AttachmentCancellationFile implements BooleanSupplier {
    private final Path path;
    private final WindowsFileMetadata windows;
    private final Observation initial;
    private boolean stopped;
    private record Observation(Object identity, long bytes, Object modified) { }

    AttachmentCancellationFile(Path selected) throws IOException {
        if (!selected.isAbsolute()) throw new IOException("cancellation file must be absolute");
        path = FileSystemPaths.resolveLeaf(selected, "cancellation file");
        // Windows' Java provider can return null fileKey even for local NTFS.
        // Reuse the already audited handle-based volume/file-ID reader; do not
        // substitute a pathname or timestamp for replacement identity.
        windows = com.sun.jna.Platform.isWindows() ? new WindowsFileMetadata() : null;
        initial = observe();
        stopped = initial.bytes() != 0;
    }

    @Override
    public synchronized boolean getAsBoolean() {
        if (!stopped) {
            try {
                stopped = !initial.equals(observe());
            }
            catch (IOException | SecurityException unavailable) { stopped = true; }
        }
        return stopped;
    }

    private Observation observe() throws IOException {
        if (windows != null) {
            var observed = windows.inspectFacts(path, () -> false);
            return new Observation(observed.identity(), observed.bytes(), observed.modified());
        }
        var attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.fileKey() == null) {
            throw new IOException("cancellation file must be a regular non-link file with an observable identity");
        }
        return new Observation(attributes.fileKey(), attributes.size(), attributes.lastModifiedTime());
    }
}
