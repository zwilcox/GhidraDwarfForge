package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;

/** Durable, explicit recovery selections, published before the transaction can replace its target. */
final class AttachmentRecoveryFile {
    private AttachmentRecoveryFile() { }

    static AttachmentRecoveryInvocation selection(AttachmentTransaction.Request request) {
        var selected = new TreeMap<>(request.files());
        selected.put("receipt", request.receipt());
        selected.put("recoveryReceipt", request.recoveryReceipt());
        selected.put("restoreImage", request.restoreImage());
        var prepared = request.prepared();
        return new AttachmentRecoveryInvocation(selected,
            AttachmentHelper.sha256(prepared.toJson().getBytes(StandardCharsets.UTF_8)),
            AttachmentHelper.sha256(prepared.advance(AttachmentReceipt.Phase.COMMITTED, null).toJson()
                .getBytes(StandardCharsets.UTF_8)));
    }

    static AttachmentFileStore.Snapshot publish(Path destination, AttachmentTransaction.Request request,
            AttachmentOperation.Host host, BooleanSupplier cancelled) throws IOException {
        var plan = AttachmentPaths.preflight(java.util.List.of(new AttachmentPaths.Selection("recoveryInvocation",
            destination, AttachmentPaths.Kind.NEW_FILE)));
        Path selected = plan.paths().get("recoveryInvocation");
        byte[] bytes = selection(request).toJson().getBytes(StandardCharsets.UTF_8);
        Path directory = Files.createTempDirectory(selected.getParent(), ".forge-recovery-selection-");
        Path stage = directory.resolve("selection.json");
        String identity = null;
        AttachmentFileStore.Snapshot snapshot = null;
        Throwable failure = null;
        try {
            identity = host.directoryIdentity(directory);
            try (var file = FileChannel.open(stage, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                var buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    if (cancelled.getAsBoolean()) throw new java.util.concurrent.CancellationException("recovery selection cancelled");
                    if (file.write(buffer) <= 0) throw new IOException("recovery selection write made no progress");
                }
                file.force(true);
            }
            snapshot = AttachmentFileStore.observe(stage, host, cancelled);
            if (!snapshot.digest().sha256().equals(AttachmentHelper.sha256(bytes))) {
                throw new IOException("staged recovery selection changed");
            }
            plan.recheck();
            // Reuse the audited independent-copy/exclusive-publication path,
            // including host identity, metadata, namespace flush and readback.
            return AttachmentFileStore.backup(snapshot, selected, host, cancelled);
        }
        catch (IOException | RuntimeException problem) {
            failure = problem;
            throw problem;
        }
        finally {
            try {
                if (identity != null && identity.equals(host.directoryIdentity(directory)) && snapshot != null) {
                    AttachmentFileStore.unchanged(snapshot, host, () -> false);
                    Files.delete(stage);
                    Files.delete(directory);
                    host.syncDirectory(selected.getParent());
                }
                // Incomplete/unverified stages are retained, never guessed away.
                else if (Files.exists(directory)) {
                    throw new IOException("unverified recovery selection stage retained at " + directory);
                }
            }
            catch (IOException | RuntimeException cleanup) {
                if (failure != null) failure.addSuppressed(cleanup);
                else throw cleanup;
            }
        }
    }
}
