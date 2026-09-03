package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Publishes an already-staged sidecar/source pair with rollback on failure. */
public final class ArtifactPairPublisher {
    @FunctionalInterface
    public interface StagedWriter {
        void write(Path stagedPath) throws Exception;
    }

    @FunctionalInterface
    public interface PrePublishCheck {
        void check() throws Exception;
    }

    @FunctionalInterface
    interface PublishHook {
        void afterArtifactInstall() throws IOException;
    }

    private ArtifactPairPublisher() {
    }

    /** Produces both staging files, checks cancellation, then publishes the pair. */
    public static void stageAndPublish(Path artifact, Path source,
            StagedWriter artifactWriter, StagedWriter sourceWriter,
            PrePublishCheck prePublishCheck) throws Exception {
        Path artifactTarget = normalize(artifact);
        Path sourceTarget = normalize(source);
        Path artifactParent = artifactTarget.getParent();
        Path sourceParent = sourceTarget.getParent();
        if (artifactParent == null || !Files.isDirectory(artifactParent) ||
                sourceParent == null || !artifactParent.equals(sourceParent)) {
            throw new IOException("artifact pair must share an existing output directory");
        }
        if (artifactWriter == null || sourceWriter == null || prePublishCheck == null) {
            throw new IllegalArgumentException("artifact pair callbacks are required");
        }
        Path stagedArtifact = Files.createTempFile(artifactParent,
            "." + artifactTarget.getFileName() + "-", ".staged");
        Path stagedSource = null;
        try {
            stagedSource = Files.createTempFile(sourceParent,
                "." + sourceTarget.getFileName() + "-", ".staged");
            artifactWriter.write(stagedArtifact);
            sourceWriter.write(stagedSource);
            prePublishCheck.check();
            publish(stagedArtifact, artifactTarget, stagedSource, sourceTarget);
        }
        finally {
            Files.deleteIfExists(stagedArtifact);
            if (stagedSource != null) {
                Files.deleteIfExists(stagedSource);
            }
        }
    }

    public static void publish(Path stagedArtifact, Path artifact,
            Path stagedSource, Path source) throws IOException {
        publish(stagedArtifact, artifact, stagedSource, source, () -> {
            // Production has no injected interruption.
        });
    }

    static void publish(Path stagedArtifact, Path artifact, Path stagedSource,
            Path source, PublishHook hook) throws IOException {
        Path artifactStage = normalize(stagedArtifact);
        Path artifactTarget = normalize(artifact);
        Path sourceStage = normalize(stagedSource);
        Path sourceTarget = normalize(source);
        if (artifactStage.equals(artifactTarget) || sourceStage.equals(sourceTarget) ||
                artifactTarget.equals(sourceTarget)) {
            throw new IllegalArgumentException("artifact pair paths must be distinct");
        }
        requireStagedFile(artifactStage, artifactTarget);
        requireStagedFile(sourceStage, sourceTarget);
        if (hook == null) {
            throw new IllegalArgumentException("publish hook is required");
        }

        Path artifactBackup = null;
        Path sourceBackup = null;
        boolean artifactInstalled = false;
        boolean sourceInstalled = false;
        boolean success = false;
        try {
            if (Files.exists(artifactTarget)) {
                artifactBackup = backupPath(artifactTarget);
                moveAtomically(artifactTarget, artifactBackup);
            }
            moveAtomically(artifactStage, artifactTarget);
            artifactInstalled = true;
            hook.afterArtifactInstall();

            if (Files.exists(sourceTarget)) {
                sourceBackup = backupPath(sourceTarget);
                moveAtomically(sourceTarget, sourceBackup);
            }
            moveAtomically(sourceStage, sourceTarget);
            sourceInstalled = true;
            success = true;
        }
        catch (IOException failure) {
            rollback(sourceTarget, sourceBackup, sourceInstalled, failure);
            rollback(artifactTarget, artifactBackup, artifactInstalled, failure);
            throw failure;
        }
        finally {
            Files.deleteIfExists(artifactStage);
            Files.deleteIfExists(sourceStage);
            if (success) {
                if (artifactBackup != null) {
                    Files.deleteIfExists(artifactBackup);
                }
                if (sourceBackup != null) {
                    Files.deleteIfExists(sourceBackup);
                }
            }
        }
    }

    private static Path normalize(Path path) {
        if (path == null) {
            throw new IllegalArgumentException("artifact path is required");
        }
        return path.toAbsolutePath().normalize();
    }

    private static void requireStagedFile(Path stage, Path target) throws IOException {
        if (!Files.isRegularFile(stage)) {
            throw new IOException("staged artifact is missing: " + stage);
        }
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent) ||
                !parent.equals(stage.getParent())) {
            throw new IOException("staged and final artifacts must share a directory");
        }
    }

    private static Path backupPath(Path target) throws IOException {
        Path backup = Files.createTempFile(target.getParent(),
            "." + target.getFileName() + "-", ".backup");
        Files.delete(backup);
        return backup;
    }

    private static void rollback(Path target, Path backup, boolean installed,
            IOException failure) {
        try {
            if (backup != null && Files.exists(backup)) {
                moveAtomically(backup, target);
            }
            else if (installed) {
                Files.deleteIfExists(target);
            }
        }
        catch (IOException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        }
        catch (AtomicMoveNotSupportedException unsupported) {
            throw new IOException("output filesystem does not support atomic replacement",
                unsupported);
        }
    }
}
