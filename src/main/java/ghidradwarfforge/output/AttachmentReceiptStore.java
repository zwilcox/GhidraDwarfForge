package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Complete-record publication and conditional updates of an attachment receipt.
 * Never accesses the executable or any path embedded in an artifact record.
 * The caller must verify backups/artifacts before executing any transaction.
 *
 * The host supplies mandatory identity/metadata and directory-sync operations;
 * there is no no-op production default. Checks detect ordinary concurrent
 * changes, not adversarial races between a check and a filesystem operation.
 */
public final class AttachmentReceiptStore {
    public record Fingerprint(String identity, String metadataSha256, long links) {
        public Fingerprint {
            if (identity == null || identity.isEmpty() || metadataSha256 == null ||
                    !metadataSha256.matches("[0-9a-f]{64}") || links < 1) {
                throw new IllegalArgumentException("invalid receipt host fingerprint");
            }
        }
    }

    public interface Host {
        String contract();
        String durability();
        /** Must inspect a regular, non-reparse leaf using native file identity. */
        Fingerprint inspect(Path path) throws IOException;
        String directoryIdentity(Path directory) throws IOException;
        /** Copy supported preservation attributes, then independently verify them. */
        void preserveMetadata(Path source, Fingerprint expected, Path stage) throws IOException;
        /**
         * Atomically consume the stage at an absent destination. Must refuse an
         * existing name, including a dangling link, without any copy fallback.
         * Must not temporarily hardlink the record: a crash could leave two
         * links and make the prepared recovery record unreadable.
         */
        void publishNew(Path stage, Path destination) throws IOException;
        /** A failure must propagate; implementations must document namespace durability. */
        void syncDirectory(Path directory) throws IOException;
    }

    /** Reading this state is not proof that its referenced transaction succeeded. */
    public record State(Path path, AttachmentReceipt receipt, String sha256, Fingerprint fingerprint) {
        public State {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(receipt, "receipt");
            Objects.requireNonNull(fingerprint, "fingerprint");
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid receipt content digest");
            }
        }
    }

    /** Publication may have happened; the caller must reconcile rather than guess. */
    public static final class PublicationFailure extends IOException {
        private final Path receiptPath;

        private PublicationFailure(Path path, Throwable cause) {
            super("receipt publication requires reconciliation at " + path + ": " + cause, cause);
            receiptPath = path;
        }

        public Path receiptPath() {
            return receiptPath;
        }
    }

    enum Boundary { STAGED, BEFORE_PUBLICATION, AFTER_PUBLICATION }
    @FunctionalInterface interface Hook {
        void at(Boundary boundary, Path stage, Path destination) throws IOException;
    }
    private static final Hook NO_HOOK = (boundary, stage, destination) -> { };
    private static final int MAX_RECEIPT_BYTES = 1024 * 1024;

    private AttachmentReceiptStore() {
    }

    /** Publishes only a new PREPARED receipt, without ever replacing an existing name. */
    public static State prepare(Path path, AttachmentReceipt receipt, Host host,
            BooleanSupplier cancelled) throws IOException {
        return publish(path, null, receipt, host, cancelled, NO_HOOK);
    }

    public static State advance(State previous, AttachmentReceipt.Phase phase, String diagnostic,
            Host host, BooleanSupplier cancelled) throws IOException {
        return publish(previous.path(), previous, previous.receipt().advance(phase, diagnostic),
            host, cancelled, NO_HOOK);
    }

    /** Loads only the selected record, with bounded bytes and before/after host observations. */
    public static State read(Path selected, Host host, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(selected, "attachment receipt");
        Fingerprint before = singleLink(host.inspect(path));
        byte[] bytes;
        try (var channel = Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                var input = java.nio.channels.Channels.newInputStream(channel)) {
            bytes = input.readNBytes(MAX_RECEIPT_BYTES + 1);
        }
        check(cancelled);
        if (bytes.length > MAX_RECEIPT_BYTES) {
            throw new IOException("attachment receipt exceeds 1 MiB");
        }
        AttachmentReceipt receipt = AttachmentReceipt.read(new ByteArrayInputStream(bytes), cancelled);
        requireContract(path, receipt, host);
        Fingerprint after = singleLink(host.inspect(path));
        if (!before.equals(after)) {
            throw new IOException("attachment receipt changed while reading: " + path);
        }
        check(cancelled);
        return new State(path, receipt, sha256(bytes), after);
    }

    static State publish(Path selected, State previous, AttachmentReceipt next, Host host,
            BooleanSupplier cancelled, Hook hook) throws IOException {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(hook, "hook");
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(selected, "attachment receipt");
        requireContract(path, next, host);
        if (previous == null) {
            if (next.phase() != AttachmentReceipt.Phase.PREPARED) {
                throw new IOException("new attachment receipts must be PREPARED");
            }
            absent(path);
        }
        else {
            if (!path.equals(previous.path()) ||
                    !next.equals(previous.receipt().advance(next.phase(), next.diagnostic()))) {
                throw new IOException("receipt update changed immutable transaction claims");
            }
            unchanged(previous, host, cancelled);
        }
        byte[] bytes = next.toJson().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_RECEIPT_BYTES) {
            throw new IOException("encoded attachment receipt exceeds 1 MiB");
        }
        Path directory = Files.createTempDirectory(path.getParent(), ".forge-receipt-");
        Path stage = directory.resolve("record.json");
        String directoryIdentity = null;
        String stageIdentity = null;
        boolean publicationAttempted = false;
        Throwable failure = null;
        try {
            directoryIdentity = Objects.requireNonNull(host.directoryIdentity(directory), "directory identity");
            try (var channel = FileChannel.open(stage, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                stageIdentity = singleLink(host.inspect(stage)).identity();
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    check(cancelled);
                    if (channel.write(buffer) <= 0) {
                        throw new IOException("receipt write made no progress");
                    }
                }
                channel.force(true);
            }
            if (previous != null) {
                host.preserveMetadata(path, previous.fingerprint(), stage);
                try (var channel = FileChannel.open(stage, StandardOpenOption.WRITE)) {
                    channel.force(true);
                }
            }
            Fingerprint stagedFingerprint = singleLink(host.inspect(stage));
            if (!stageIdentity.equals(stagedFingerprint.identity()) ||
                    !sha256(bytes).equals(sha256(bounded(stage)))) {
                throw new IOException("staged receipt identity or bytes changed");
            }
            hook.at(Boundary.STAGED, stage, path);
            host.syncDirectory(directory);
            hook.at(Boundary.BEFORE_PUBLICATION, stage, path);
            check(cancelled);
            if (previous == null) {
                absent(path);
            }
            else {
                unchanged(previous, host, cancelled);
            }
            if (!stagedFingerprint.equals(host.inspect(stage)) ||
                    !sha256(bytes).equals(sha256(bounded(stage)))) {
                throw new IOException("staged receipt changed before publication");
            }
            publicationAttempted = true;
            if (previous == null) {
                host.publishNew(stage, path);
            }
            else {
                Files.move(stage, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            }
            hook.at(Boundary.AFTER_PUBLICATION, stage, path);
            // After namespace mutation, finish reconciliation without allowing a
            // late cancellation to skip the required flush/observation.
            host.syncDirectory(path.getParent());
            State installed = read(path, host, () -> false);
            if (!installed.receipt().equals(next) || !installed.sha256().equals(sha256(bytes)) ||
                    !installed.fingerprint().identity().equals(stagedFingerprint.identity())) {
                throw new IOException("published receipt differs from the owned staged record");
            }
            return installed;
        }
        catch (IOException | RuntimeException caught) {
            failure = publicationAttempted ? new PublicationFailure(path, caught) : caught;
            if (failure instanceof IOException io) {
                throw io;
            }
            throw (RuntimeException) failure;
        }
        finally {
            try {
                if (directoryIdentity == null || !directoryIdentity.equals(host.directoryIdentity(directory))) {
                    throw new IOException("receipt stage directory identity changed; retained " + directory);
                }
                try {
                    Files.readAttributes(stage, java.nio.file.attribute.BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                    if (stageIdentity == null || !stageIdentity.equals(host.inspect(stage).identity())) {
                        throw new IOException("receipt stage identity changed; retained " + stage);
                    }
                    Files.delete(stage);
                }
                catch (java.nio.file.NoSuchFileException absentStage) {
                    // An atomic move or successful initial link publication consumed it.
                }
                Files.delete(directory);
                host.syncDirectory(path.getParent());
            }
            catch (IOException cleanup) {
                if (failure != null) {
                    failure.addSuppressed(cleanup);
                }
                else {
                    throw new PublicationFailure(path, cleanup);
                }
            }
        }
    }

    private static void unchanged(State expected, Host host, BooleanSupplier cancelled) throws IOException {
        if (!expected.equals(read(expected.path(), host, cancelled))) {
            throw new IOException("attachment receipt no longer matches the owned record: " + expected.path());
        }
    }

    private static void requireContract(Path path, AttachmentReceipt receipt, Host host) throws IOException {
        if (!path.toString().equals(receipt.receiptPath()) ||
                !host.contract().equals(receipt.hostContract()) ||
                !host.durability().equals(receipt.durability())) {
            throw new IOException("attachment receipt path or host contract mismatch");
        }
    }

    private static Fingerprint singleLink(Fingerprint fingerprint) throws IOException {
        if (fingerprint.links() != 1) {
            throw new IOException("attachment receipt must have exactly one link");
        }
        return fingerprint;
    }

    private static void absent(Path path) throws IOException {
        try {
            Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            throw new IOException("new attachment receipt already exists: " + path);
        }
        catch (java.nio.file.NoSuchFileException expected) {
            // Includes no other failure: inaccessible paths are not absent.
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static byte[] bounded(Path path) throws IOException {
        try (var input = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = input.readNBytes(MAX_RECEIPT_BYTES + 1);
            if (bytes.length > MAX_RECEIPT_BYTES) {
                throw new IOException("staged attachment receipt exceeds 1 MiB");
            }
            return bytes;
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("attachment receipt publication cancelled");
        }
    }
}
