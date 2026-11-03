package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Conditional replacement of an observed target, and restoration from independent
 * recovery material. This is an internal transaction primitive, not a public
 * attachment entry point or approval. Its caller must validate the complete ELF,
 * artifact/receipt bindings, all-role preflight and prepared recovery journal.
 * Supplied replacement images must already have been written, flushed and checked
 * under the host contract. No target-specific layout or ABI assumptions occur here.
 */
public final class AttachmentTargetStore {
    public interface Host extends AttachmentReceiptStore.Host {
        /**
         * A single host-supported atomic replacement, without a copy fallback.
         * Failure may have changed the namespace; callers always reconcile it.
         * Implementations must not ignore metadata errors or silently change
         * supported metadata, and must document sharing/locking behavior.
         */
        void replaceAtomic(Path ownedStage, Path target) throws IOException;
    }

    public static final class ReplacementFailure extends IOException {
        private final Path target;
        private final Path stage;

        private ReplacementFailure(Path target, Path stage, Throwable cause) {
            super("target replacement requires reconciliation at " + target +
                "; retained recovery material must be verified: " + cause, cause);
            this.target = target;
            this.stage = stage;
        }

        public Path target() { return target; }
        public Path stage() { return stage; }
    }

    enum Boundary { BEFORE_REPLACEMENT, AFTER_REPLACEMENT }
    @FunctionalInterface interface Hook {
        void at(Boundary boundary, Path stage, Path target) throws IOException;
    }
    private static final Hook NO_HOOK = (boundary, stage, target) -> { };

    private AttachmentTargetStore() {
    }

    public static AttachmentFileStore.Snapshot replace(AttachmentFileStore.Snapshot expectedTarget,
            AttachmentFileStore.Snapshot ownedStage, Host host, BooleanSupplier cancelled) throws IOException {
        return replace(expectedTarget, ownedStage, host, cancelled, NO_HOOK);
    }

    static AttachmentFileStore.Snapshot replace(AttachmentFileStore.Snapshot expectedTarget,
            AttachmentFileStore.Snapshot ownedStage, Host host, BooleanSupplier cancelled, Hook hook)
            throws IOException {
        Objects.requireNonNull(expectedTarget, "expected target");
        Objects.requireNonNull(ownedStage, "owned stage");
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(hook, "hook");
        check(cancelled);
        Path target = expectedTarget.path();
        Path stage = ownedStage.path();
        if (target.equals(stage) || expectedTarget.fingerprint().identity().equals(ownedStage.fingerprint().identity())) {
            throw new IOException("target replacement requires an independent owned stage");
        }
        if (!expectedTarget.fingerprint().metadataSha256().equals(ownedStage.fingerprint().metadataSha256())) {
            throw new IOException("replacement would change supported target metadata");
        }
        AttachmentFileStore.unchanged(expectedTarget, host, cancelled);
        AttachmentFileStore.unchanged(ownedStage, host, cancelled);
        if (!Files.getFileStore(target).equals(Files.getFileStore(stage))) {
            throw new IOException("replacement stage must be on the target filesystem");
        }
        String targetParentIdentity = host.directoryIdentity(target.getParent());
        String stageParentIdentity = host.directoryIdentity(stage.getParent());
        hook.at(Boundary.BEFORE_REPLACEMENT, stage, target);
        check(cancelled);
        if (!targetParentIdentity.equals(host.directoryIdentity(target.getParent())) ||
                !stageParentIdentity.equals(host.directoryIdentity(stage.getParent()))) {
            throw new IOException("replacement parent directory changed");
        }
        AttachmentFileStore.unchanged(expectedTarget, host, cancelled);
        AttachmentFileStore.unchanged(ownedStage, host, cancelled);
        check(cancelled);
        try {
            host.replaceAtomic(stage, target);
            hook.at(Boundary.AFTER_REPLACEMENT, stage, target);
            // Once attempted, finish observations without late cancellation.
            // Both directories changed when the stage was in a private directory.
            host.syncDirectory(stage.getParent());
            if (!target.getParent().equals(stage.getParent())) host.syncDirectory(target.getParent());
            var installed = AttachmentFileStore.observe(target, host, () -> false);
            if (!installed.digest().equals(ownedStage.digest()) ||
                    !installed.fingerprint().equals(ownedStage.fingerprint())) {
                throw new IOException("installed target differs from the verified owned stage");
            }
            return installed;
        }
        catch (IOException | RuntimeException failure) {
            throw new ReplacementFailure(target, stage, failure);
        }
    }

    /**
     * Builds a fresh independent restore image, then conditionally replaces only
     * the expected current target. The retained backup is never renamed, deleted
     * or overwritten. A failed restore retains the new recovery copy if it still
     * exists; the caller must report/reconcile that path and journal the result.
     */
    public static AttachmentFileStore.Snapshot restore(AttachmentFileStore.Snapshot expectedTarget,
            AttachmentFileStore.Snapshot verifiedBackup, Path newRestorePath, Host host,
            BooleanSupplier cancelled) throws IOException {
        AttachmentFileStore.unchanged(expectedTarget, host, cancelled);
        if (expectedTarget.fingerprint().identity().equals(verifiedBackup.fingerprint().identity()) ||
                !expectedTarget.fingerprint().metadataSha256().equals(verifiedBackup.fingerprint().metadataSha256())) {
            throw new IOException("recovery requires an independent metadata-preserving backup");
        }
        var restore = AttachmentFileStore.backup(verifiedBackup, newRestorePath, host, cancelled);
        return replace(expectedTarget, restore, host, cancelled);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment target replacement cancelled");
    }
}
