package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Internal protected-attribute visibility session for an already authorized
 * platform thread. No elevation, target mutation or complete Host admission.
 * Caller must preflight the workspace parent before creating this owned canary.
 * The filesystem magic check admits the ext family, not proof of ext4 itself;
 * full host filesystem admission is separate. Native tests currently use ext4.
 */
final class LinuxMetadataVisibility implements AutoCloseable {
    private final Thread owner = Thread.currentThread();
    private final LinuxFileMetadata metadata;
    private final LinuxDirectorySync directories;
    private final Path workspace;
    private final Path canary;
    private final LinuxDirectorySync.Snapshot directory;
    private final LinuxFileMetadata.Snapshot expected;
    private boolean closed;

    private LinuxMetadataVisibility(LinuxFileMetadata metadata, LinuxDirectorySync directories,
            Path workspace, Path canary, LinuxDirectorySync.Snapshot directory,
            LinuxFileMetadata.Snapshot expected) {
        this.metadata = metadata;
        this.directories = directories;
        this.workspace = workspace;
        this.canary = canary;
        this.directory = directory;
        this.expected = expected;
    }

    static LinuxMetadataVisibility create(Path selectedParent, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        require(!Thread.currentThread().isVirtual(), "visibility session requires a platform thread");
        var metadata = new LinuxFileMetadata();
        var directories = new LinuxDirectorySync();
        Path parent = selectedParent.toRealPath();
        var parentBefore = directories.inspect(parent, cancelled);
        require(parentBefore.fileSystemType() == 0xef53, "visibility session requires an ext-family filesystem");
        Path workspace = Files.createTempDirectory(parent, ".forge-visibility-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path canary = workspace.resolve("canary");
        Object directoryKey = null;
        Object fileKey = null;
        try {
            directoryKey = key(workspace, true);
            checkCancelled(cancelled);
            var directory = directories.inspect(workspace, cancelled);
            require(directory.fileSystemType() == parentBefore.fileSystemType() &&
                directory.fileSystemId().equals(parentBefore.fileSystemId()), "visibility workspace filesystem changed");
            Files.createFile(canary,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            fileKey = key(canary, false);
            var before = metadata.inspect(canary, cancelled);
            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            var expected = metadata.markOwnedCanary(canary, before, nonce, cancelled);
            var session = new LinuxMetadataVisibility(metadata, directories, workspace, canary, directory, expected);
            session.check(cancelled);
            require(parentBefore.equals(directories.inspect(parent, cancelled)), "visibility parent changed");
            return session;
        }
        catch (IOException | RuntimeException failure) {
            // Only an exclusively created, still-empty owned leaf is eligible.
            // Preserve changed/unknown paths and attach a useful cleanup error.
            try {
                require(directoryKey != null && directoryKey.equals(key(workspace, true)),
                    "visibility workspace changed; retained " + workspace);
                if (fileKey != null) {
                    require(fileKey.equals(key(canary, false)) && Files.size(canary) == 0,
                        "visibility canary changed; retained " + canary);
                    Files.delete(canary);
                }
                Files.delete(workspace);
            }
            catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    /** Bracket target metadata operations with this check on the owning thread. */
    void check(BooleanSupplier cancelled) throws IOException {
        requireOwner();
        require(!closed, "visibility session is closed");
        checkCancelled(cancelled);
        require(directory.equals(directories.inspect(workspace, cancelled)), "visibility workspace changed");
        require(expected.equals(metadata.inspect(canary, cancelled)),
            "protected metadata visibility lost or canary changed");
        require(directory.equals(directories.inspect(workspace, cancelled)), "visibility workspace changed");
        checkCancelled(cancelled);
    }

    @Override public void close() throws IOException {
        requireOwner();
        if (closed) return;
        // Cleanup ignores user cancellation but refuses changed identities or
        // metadata. Lost visibility retains the private workspace for diagnosis.
        check(() -> false);
        Files.delete(canary);
        Files.delete(workspace);
        closed = true;
    }

    private void requireOwner() throws IOException {
        require(Thread.currentThread() == owner && !owner.isVirtual(),
            "visibility session belongs to a different platform thread");
    }

    private static Object key(Path path, boolean directory) throws IOException {
        var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        require(directory ? attrs.isDirectory() : attrs.isRegularFile(), "unexpected visibility path kind: " + path);
        require(attrs.fileKey() != null, "visibility path has no file identity");
        return attrs.fileKey();
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("visibility session cancelled");
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
