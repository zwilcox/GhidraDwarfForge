package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Independently copied, verified recovery material. Not an attachment approval:
 * the transaction must preflight all roles and validate its ELF/report evidence.
 * Mandatory host operations define identity, metadata and durability. Ordinary
 * export does not invoke this class. Checks detect ordinary concurrent changes,
 * not an adversary racing between observations and filesystem operations.
 */
public final class AttachmentFileStore {
    public record Snapshot(Path path, FileDigests.Result digest,
            AttachmentReceiptStore.Fingerprint fingerprint) {
        public Snapshot {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(digest, "digest");
            Objects.requireNonNull(fingerprint, "fingerprint");
        }

        public AttachmentReceipt.Artifact artifact() {
            return new AttachmentReceipt.Artifact(path.toString(), digest.sha256(), digest.byteCount(),
                fingerprint.identity(), fingerprint.metadataSha256());
        }
    }

    /** A complete backup may already exist; retain it and reconcile before retrying. */
    public static final class PublicationFailure extends IOException {
        private final Path backupPath;

        private PublicationFailure(Path path, Throwable cause) {
            super("backup publication requires reconciliation at " + path + ": " + cause, cause);
            backupPath = path;
        }

        public Path backupPath() { return backupPath; }
    }

    enum Boundary { CREATED, COPIED, BEFORE_PUBLICATION, AFTER_PUBLICATION }
    @FunctionalInterface interface Hook {
        void at(Boundary boundary, Path stage, Path destination) throws IOException;
    }
    private static final Hook NO_HOOK = (boundary, stage, destination) -> { };
    private static final int BUFFER_BYTES = 64 * 1024;

    private AttachmentFileStore() {
    }

    /** Observes a selected regular non-link file, with host checks around a streamed digest. */
    public static Snapshot observe(Path selected, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(selected, "attachment recovery file");
        var before = singleLink(host.inspect(path));
        var digest = FileDigests.read(path, cancelled,
            file -> Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
        var after = singleLink(host.inspect(path));
        if (!before.equals(after)) {
            throw new IOException("attachment recovery file changed while reading: " + path);
        }
        check(cancelled);
        return new Snapshot(path, digest, after);
    }

    public static void unchanged(Snapshot expected, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        if (!expected.equals(observe(expected.path(), host, cancelled))) {
            throw new IOException("attachment recovery file no longer matches its observation: " + expected.path());
        }
    }

    /**
     * Copies the expected source to a fresh backup. Never overwrites a destination
     * and never uses a hardlink. The published independent backup is always retained,
     * even if a later flush, readback or cleanup fails.
     */
    public static Snapshot backup(Snapshot source, Path destination, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled) throws IOException {
        return backup(source, destination, host, cancelled, NO_HOOK);
    }

    static Snapshot backup(Snapshot source, Path selected, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled, Hook hook) throws IOException {
        return copy(source, source, selected, host, cancelled, hook);
    }

    /** Copy new bytes while preserving a separately verified file's access metadata. */
    public static Snapshot copyWithMetadata(Snapshot source, Snapshot metadata, Path selected,
            AttachmentReceiptStore.Host host, BooleanSupplier cancelled) throws IOException {
        return copy(source, metadata, selected, host, cancelled, NO_HOOK);
    }

    private static Snapshot copy(Snapshot source, Snapshot metadata, Path selected, AttachmentReceiptStore.Host host,
            BooleanSupplier cancelled, Hook hook) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(metadata, "metadata source");
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(hook, "hook");
        check(cancelled);
        Path destination = FileSystemPaths.resolveLeaf(selected, "attachment backup");
        absent(destination);
        unchanged(source, host, cancelled);
        if (!metadata.equals(source)) unchanged(metadata, host, cancelled);
        Path directory = Files.createTempDirectory(destination.getParent(), ".forge-backup-");
        Path stage = directory.resolve("image");
        String directoryIdentity = null;
        String stageIdentity = null;
        boolean attempted = false;
        Throwable failure = null;
        try {
            directoryIdentity = Objects.requireNonNull(host.directoryIdentity(directory), "directory identity");
            try (FileChannel output = FileChannel.open(stage, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                stageIdentity = singleLink(host.inspect(stage)).identity();
                if (stageIdentity.equals(source.fingerprint().identity())) {
                    throw new IOException("backup stage is not independent of its source");
                }
                hook.at(Boundary.CREATED, stage, destination);
                copy(source.path(), output, source.digest().byteCount(), cancelled);
                output.force(true);
            }
            hook.at(Boundary.COPIED, stage, destination);
            unchanged(source, host, cancelled);
            if (!metadata.equals(source)) unchanged(metadata, host, cancelled);
            // Refuse a changed stage before asking the adapter to apply metadata.
            var copied = observe(stage, host, cancelled);
            if (!stageIdentity.equals(copied.fingerprint().identity()) || !source.digest().equals(copied.digest())) {
                throw new IOException("backup copied bytes or identity differ from the expected source");
            }
            try (FileChannel output = FileChannel.open(stage, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                host.preserveMetadata(metadata.path(), metadata.fingerprint(), stage);
                output.force(true);
            }
            var staged = observe(stage, host, cancelled);
            requireCopy(source, metadata, staged);
            if (!stageIdentity.equals(staged.fingerprint().identity())) {
                throw new IOException("backup stage identity changed while preserving metadata");
            }
            host.syncDirectory(directory);
            hook.at(Boundary.BEFORE_PUBLICATION, stage, destination);
            check(cancelled);
            absent(destination);
            unchanged(source, host, cancelled);
            if (!metadata.equals(source)) unchanged(metadata, host, cancelled);
            unchanged(staged, host, cancelled);
            attempted = true;
            host.publishNew(stage, destination);
            hook.at(Boundary.AFTER_PUBLICATION, stage, destination);
            // Finish flush/readback after publication, even if cancellation arrives.
            host.syncDirectory(destination.getParent());
            var installed = observe(destination, host, () -> false);
            requireCopy(source, metadata, installed);
            if (!stageIdentity.equals(installed.fingerprint().identity())) {
                throw new IOException("published backup identity differs from its owned stage");
            }
            return installed;
        }
        catch (IOException | RuntimeException caught) {
            failure = attempted ? new PublicationFailure(destination, caught) : caught;
            if (failure instanceof IOException io) throw io;
            throw (RuntimeException) failure;
        }
        finally {
            try {
                if (directoryIdentity == null || !directoryIdentity.equals(host.directoryIdentity(directory))) {
                    throw new IOException("backup staging directory changed; retained " + directory);
                }
                try {
                    Files.readAttributes(stage, java.nio.file.attribute.BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                    if (stageIdentity == null || !stageIdentity.equals(host.inspect(stage).identity())) {
                        throw new IOException("backup stage identity changed; retained " + stage);
                    }
                    Files.delete(stage);
                }
                catch (NoSuchFileException consumed) {
                    // Successful atomic publication consumed the stage.
                }
                Files.delete(directory);
                host.syncDirectory(destination.getParent());
            }
            catch (IOException cleanup) {
                if (failure != null) failure.addSuppressed(cleanup);
                else throw new PublicationFailure(destination, cleanup);
            }
        }
    }

    private static void copy(Path source, FileChannel output, long expectedBytes,
            BooleanSupplier cancelled) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(BUFFER_BYTES);
        long copied = 0;
        try (FileChannel input = FileChannel.open(source, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            while (true) {
                check(cancelled);
                buffer.clear();
                int count = input.read(buffer);
                if (count == -1) break;
                if (count == 0 || copied > expectedBytes - count) {
                    throw new IOException("backup source exceeds expected size or read made no progress");
                }
                copied += count;
                buffer.flip();
                while (buffer.hasRemaining()) {
                    check(cancelled);
                    if (output.write(buffer) <= 0) throw new IOException("backup write made no progress");
                }
            }
        }
        if (copied != expectedBytes) throw new IOException("backup source shrank while copying");
        check(cancelled);
    }

    private static void requireCopy(Snapshot source, Snapshot metadata, Snapshot copy) throws IOException {
        if (!source.digest().equals(copy.digest()) ||
                !metadata.fingerprint().metadataSha256().equals(copy.fingerprint().metadataSha256()) ||
                source.fingerprint().identity().equals(copy.fingerprint().identity()) ||
                metadata.fingerprint().identity().equals(copy.fingerprint().identity()) ||
                copy.fingerprint().links() != 1) {
            throw new IOException("backup is not an independent byte/metadata copy of the expected source");
        }
    }

    private static AttachmentReceiptStore.Fingerprint singleLink(AttachmentReceiptStore.Fingerprint fingerprint)
            throws IOException {
        if (fingerprint.links() != 1) throw new IOException("attachment recovery file must have exactly one link");
        return fingerprint;
    }

    private static void absent(Path path) throws IOException {
        try {
            Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            throw new IOException("new attachment backup already exists: " + path);
        }
        catch (NoSuchFileException absent) {
            // An inaccessible or dangling-link path is not considered absent.
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment backup cancelled");
    }
}
