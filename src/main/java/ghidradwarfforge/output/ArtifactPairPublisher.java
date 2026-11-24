package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Optional;

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
        logWarning(stageAndPublish(artifact, source, artifactWriter, sourceWriter, prePublishCheck, false));
    }

    /** Fresh attachment generations must never overwrite an earlier pair. */
    public static void stageAndPublishNew(Path artifact, Path source,
            StagedWriter artifactWriter, StagedWriter sourceWriter,
            PrePublishCheck prePublishCheck) throws Exception {
        logWarning(stageAndPublish(artifact, source, artifactWriter, sourceWriter, prePublishCheck, true));
    }

    /** Preserve a successful attachment preparation when private staging cleanup needs attention. */
    public static Optional<IOException> stageAndPublishNew(Path artifact, Path source,
            StagedWriter artifactWriter, StagedWriter sourceWriter, PrePublishCheck check,
            PrePublishCheck pollCancellation) throws Exception {
        List<Path> targets = validatePair(artifact, source, artifactWriter, sourceWriter, check);
        return CompanionArtifactPublisher.publishResolved(targets, true, stages -> {
            artifactWriter.write(stages.get(0));
            sourceWriter.write(stages.get(1));
        }, check, pollCancellation, index -> { });
    }

    private static Optional<IOException> stageAndPublish(Path artifact, Path source, StagedWriter artifactWriter,
            StagedWriter sourceWriter, PrePublishCheck prePublishCheck, boolean exclusive) throws Exception {
        List<Path> targets = validatePair(artifact, source, artifactWriter, sourceWriter, prePublishCheck);
        return CompanionArtifactPublisher.publishResolved(targets, exclusive, stages -> {
            artifactWriter.write(stages.get(0));
            sourceWriter.write(stages.get(1));
            prePublishCheck.check();
        }, () -> { }, () -> { }, index -> { });
    }

    private static List<Path> validatePair(Path artifact, Path source, StagedWriter artifactWriter,
            StagedWriter sourceWriter, PrePublishCheck check) throws IOException {
        Path artifactTarget = resolve(artifact);
        Path sourceTarget = resolve(source);
        Path parent = artifactTarget.getParent();
        if (parent == null || !Files.isDirectory(parent) || !parent.equals(sourceTarget.getParent())) {
            throw new IOException("artifact pair must share an existing output directory");
        }
        if (artifactWriter == null || sourceWriter == null || check == null) {
            throw new IllegalArgumentException("artifact pair callbacks are required");
        }
        requireDistinct(artifactTarget, sourceTarget);
        requireDestination(artifactTarget);
        requireDestination(sourceTarget);
        return List.of(artifactTarget, sourceTarget);
    }

    static void publishNew(Path stagedArtifact, Path artifact, Path stagedSource, Path source,
            PublishHook hook) throws IOException {
        publish(stagedArtifact, artifact, stagedSource, source, hook, true);
    }

    public static void publish(Path stagedArtifact, Path artifact, Path stagedSource, Path source) throws IOException {
        publish(stagedArtifact, artifact, stagedSource, source, () -> { });
    }

    static void publish(Path stagedArtifact, Path artifact, Path stagedSource, Path source,
            PublishHook hook) throws IOException {
        publish(stagedArtifact, artifact, stagedSource, source, hook, false);
    }

    private static void publish(Path stagedArtifact, Path artifact, Path stagedSource, Path source,
            PublishHook hook, boolean exclusive) throws IOException {
        Path artifactStage = resolve(stagedArtifact);
        Path artifactTarget = resolve(artifact);
        Path sourceStage = resolve(stagedSource);
        Path sourceTarget = resolve(source);
        requireDistinct(artifactStage, artifactTarget, sourceStage, sourceTarget);
        requireStagedFile(artifactStage, artifactTarget);
        requireStagedFile(sourceStage, sourceTarget);
        requireDestination(artifactTarget);
        requireDestination(sourceTarget);
        if (hook == null) throw new IllegalArgumentException("publish hook is required");

        List<Path> supplied = List.of(artifactStage, sourceStage);
        try {
            var warning = CompanionArtifactPublisher.publishResolved(List.of(artifactTarget, sourceTarget), exclusive,
                stages -> {
                    for (int i = 0; i < stages.size(); i++) {
                        if (exclusive) {
                            // Caller owns the supplied staging names throughout fresh publication.
                            Files.delete(stages.get(i));
                            Files.createLink(stages.get(i), supplied.get(i));
                        }
                        else moveAtomically(supplied.get(i), stages.get(i));
                    }
                }, () -> { }, () -> { }, index -> {
                    if (index == 0) hook.afterArtifactInstall();
                });
            logWarning(warning);
        }
        catch (IOException | RuntimeException failure) { throw failure; }
        catch (Exception failure) { throw new IOException("could not publish artifact pair", failure); }
    }

    private static void logWarning(Optional<IOException> warning) {
        warning.ifPresent(problem -> System.getLogger(ArtifactPairPublisher.class.getName())
            .log(System.Logger.Level.WARNING, problem.getMessage(), problem));
    }

    private static Path resolve(Path path) throws IOException {
        return FileSystemPaths.resolveLeaf(path, "artifact path");
    }

    private static void requireDistinct(Path... paths) throws IOException {
        for (int first = 0; first < paths.length; first++) {
            for (int second = first + 1; second < paths.length; second++) {
                if (FileSystemPaths.aliases(paths[first], paths[second])) {
                    throw new IllegalArgumentException("artifact pair paths must be distinct: " +
                        paths[first] + " aliases " + paths[second]);
                }
            }
        }
    }

    private static void requireStagedFile(Path stage, Path target) throws IOException {
        if (!Files.isRegularFile(stage, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("staged artifact is missing: " + stage);
        }
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent) ||
                !parent.equals(stage.getParent())) {
            throw new IOException("staged and final artifacts must share a directory");
        }
    }

    private static void requireDestination(Path target) throws IOException {
        try {
            var attributes = Files.readAttributes(target, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() && !attributes.isSymbolicLink()) {
                throw new IOException("artifact destination must be a regular file or symbolic link: " +
                    target);
            }
        }
        catch (NoSuchFileException missing) {
            // A new output leaf is allowed; its parent was resolved already.
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
