package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;

/** Filesystem regression for staged pair publication and rollback. */
public final class ArtifactPairPublisherSmoke {
    private ArtifactPairPublisherSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 0 && args.length != 2) {
            throw new IllegalArgumentException(
                "usage: ArtifactPairPublisherSmoke [<locked-artifact> <locked-source>]");
        }
        Path directory = Files.createTempDirectory("forge-artifact-pair-");
        try {
            Path artifact = directory.resolve("fixture.dbg");
            Path source = directory.resolve("fixture.dbg.c");
            Path artifactStage = directory.resolve("artifact.staged");
            Path sourceStage = directory.resolve("source.staged");
            write(artifact, "old artifact");
            write(source, "old source");
            write(artifactStage, "new artifact");
            write(sourceStage, "new source");
            try {
                ArtifactPairPublisher.publish(artifactStage, artifact, sourceStage, source,
                    () -> {
                        throw new IOException("controlled publication failure");
                    });
                throw new AssertionError("controlled publication failure was ignored");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("controlled")) {
                    throw expected;
                }
            }
            assertText(artifact, "old artifact");
            assertText(source, "old source");
            if (Files.exists(artifactStage) || Files.exists(sourceStage)) {
                throw new AssertionError("failed publication left staged files");
            }

            write(artifactStage, "new artifact");
            write(sourceStage, "new source");
            ArtifactPairPublisher.publish(artifactStage, artifact, sourceStage, source);
            assertText(artifact, "new artifact");
            assertText(source, "new source");
            try (var files = Files.list(directory)) {
                if (files.anyMatch(path -> path.toString().endsWith(".backup"))) {
                    throw new AssertionError("successful publication left backup files");
                }
            }

            Files.delete(artifact);
            Files.delete(source);
            write(artifactStage, "fresh artifact");
            write(sourceStage, "fresh source");
            try {
                ArtifactPairPublisher.publish(artifactStage, artifact, sourceStage, source,
                    () -> {
                        throw new IOException("controlled fresh failure");
                    });
                throw new AssertionError("fresh publication failure was ignored");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("controlled")) {
                    throw expected;
                }
            }
            if (Files.exists(artifact) || Files.exists(source)) {
                throw new AssertionError("failed fresh publication left a final artifact");
            }

            write(artifact, "preserved artifact");
            write(source, "preserved source");
            try {
                ArtifactPairPublisher.stageAndPublish(artifact, source,
                    stage -> write(stage, "cancelled artifact"),
                    stage -> write(stage, "cancelled source"), () -> {
                        throw new ControlledCancellation();
                    });
                throw new AssertionError("controlled cancellation was ignored");
            }
            catch (ControlledCancellation expected) {
                // Expected after both complete staging files exist and before publication.
            }
            assertText(artifact, "preserved artifact");
            assertText(source, "preserved source");
            try (var files = Files.list(directory)) {
                if (files.anyMatch(path -> path.toString().endsWith(".staged"))) {
                    throw new AssertionError("cancellation left staging files");
                }
            }
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        System.out.println("artifact-pair-publisher-smoke=PASS");
        if (args.length == 2) {
            testExternallyLockedSource(Path.of(args[0]), Path.of(args[1]));
            System.out.println("windows-file-lock-rollback=PASS");
        }
    }

    /**
     * Exercises Windows deny-delete semantics. The caller must hold source open
     * with FileShare.None for the duration of this process.
     */
    private static void testExternallyLockedSource(Path artifact, Path source)
            throws Exception {
        Path artifactTarget = artifact.toAbsolutePath().normalize();
        Path sourceTarget = source.toAbsolutePath().normalize();
        if (!System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT)
                .startsWith("windows")) {
            throw new IllegalStateException(
                "the external file-lock regression must run on Windows");
        }
        if (!Files.isRegularFile(artifactTarget) || !Files.isRegularFile(sourceTarget)) {
            throw new IOException("locked publication targets must already exist");
        }
        byte[] originalArtifact = Files.readAllBytes(artifactTarget);
        Path directory = artifactTarget.getParent();
        if (directory == null || !directory.equals(sourceTarget.getParent())) {
            throw new IOException("locked publication targets must share a directory");
        }
        Path artifactStage = Files.createTempFile(directory,
            ".locked-artifact-", ".staged");
        Path sourceStage = Files.createTempFile(directory,
            ".locked-source-", ".staged");
        write(artifactStage, "replacement artifact");
        write(sourceStage, "replacement source");
        boolean[] artifactInstalled = { false };
        try {
            ArtifactPairPublisher.publish(artifactStage, artifactTarget, sourceStage,
                sourceTarget, () -> artifactInstalled[0] = true);
            throw new AssertionError("publication replaced a FileShare.None source");
        }
        catch (IOException expected) {
            if (!artifactInstalled[0]) {
                throw new AssertionError(
                    "file-lock failure occurred before the artifact install", expected);
            }
        }
        if (!Arrays.equals(originalArtifact, Files.readAllBytes(artifactTarget))) {
            throw new AssertionError("file-lock rollback did not restore the artifact");
        }
        if (Files.exists(artifactStage) || Files.exists(sourceStage)) {
            throw new AssertionError("file-lock rollback left staged files");
        }
        try (var files = Files.list(directory)) {
            if (files.anyMatch(path -> path.toString().endsWith(".backup"))) {
                throw new AssertionError("file-lock rollback left backup files");
            }
        }
    }

    private static final class ControlledCancellation extends Exception {
        private static final long serialVersionUID = 1L;
    }

    private static void write(Path path, String value) throws IOException {
        Files.writeString(path, value, StandardCharsets.UTF_8);
    }

    private static void assertText(Path path, String expected) throws IOException {
        String actual = Files.readString(path, StandardCharsets.UTF_8);
        if (!expected.equals(actual)) {
            throw new AssertionError("unexpected content in " + path + ": " + actual);
        }
    }
}
