package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.function.BooleanSupplier;

/**
 * Read-only cooperative stop channel across an OS authorization boundary.
 * The caller owns a fresh empty file. Any observed change, removal or inspection
 * failure latches cancellation. Its contents are never interpreted or executed.
 * The helper never writes this file and never kills a transaction on cancellation.
 */
final class AttachmentCancellationFile implements BooleanSupplier {
    private final Path path;
    private final Object identity;
    private final FileTime modified;
    private boolean stopped;

    AttachmentCancellationFile(Path selected) throws IOException {
        if (!selected.isAbsolute()) throw new IOException("cancellation file must be absolute");
        path = selected;
        var attributes = attributes();
        if (!attributes.isRegularFile() || attributes.fileKey() == null) {
            throw new IOException("cancellation file must be a regular non-link file with an observable identity");
        }
        identity = attributes.fileKey();
        modified = attributes.lastModifiedTime();
        stopped = attributes.size() != 0;
    }

    @Override
    public synchronized boolean getAsBoolean() {
        if (!stopped) {
            try {
                var current = attributes();
                stopped = !current.isRegularFile() || !identity.equals(current.fileKey()) ||
                    current.size() != 0 || !modified.equals(current.lastModifiedTime());
            }
            catch (IOException | SecurityException unavailable) { stopped = true; }
        }
        return stopped;
    }

    private BasicFileAttributes attributes() throws IOException {
        return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }
}
