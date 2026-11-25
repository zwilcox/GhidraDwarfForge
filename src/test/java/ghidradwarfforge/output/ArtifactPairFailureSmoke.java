package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

/** Real owned-file failures at staging, exclusive rollback and backup restoration. */
public final class ArtifactPairFailureSmoke {
    private static int checks;

    private ArtifactPairFailureSmoke() { }

    static void run(Path root) throws Exception {
        checks = 0;
        callbacks(Files.createDirectory(root.resolve("callbacks")));
        unreadableDestination(Files.createDirectory(root.resolve("unreadable")));
        reusedStageNames(Files.createDirectory(root.resolve("reused")));
        parents(Files.createDirectory(root.resolve("parents")));
        for (boolean missing : List.of(false, true)) {
            changedFreshTarget(Files.createDirectory(root.resolve("fresh-" + missing)), missing);
        }
        failedRestoration(Files.createDirectory(root.resolve("restore")));
        System.out.println("artifact-pair-failure-boundaries=PASS checks=" + checks);
    }

    private static void unreadableDestination(Path root) throws Exception {
        if (!Files.getFileStore(root).supportsFileAttributeView("posix")) return;
        Path artifact = Files.writeString(root.resolve("pair.dbg"), "previous artifact");
        Path source = Files.writeString(root.resolve("pair.dbg.c"), "previous source");
        var permissions = Files.getPosixFilePermissions(source);
        try {
            Files.setPosixFilePermissions(source, java.util.Set.of());
            if (Files.isReadable(source)) return;
            Path artifactStage = Files.writeString(root.resolve("artifact.stage"), "new artifact");
            Path sourceStage = Files.writeString(root.resolve("source.stage"), "new source");
            try {
                ArtifactPairPublisher.publish(artifactStage, artifact, sourceStage, source,
                    () -> { throw new AssertionError("unreadable destination reached installation"); });
                throw new AssertionError("published over an unreadable destination");
            }
            catch (java.nio.file.AccessDeniedException expected) {
                require(source.toString().equals(expected.getFile()), "wrong unreadable destination");
            }
            require(names(root).equals(List.of("pair.dbg", "pair.dbg.c")),
                "unreadable destination left supplied staging files");
        }
        finally { Files.setPosixFilePermissions(source, permissions); }
        text(artifact, "previous artifact");
        text(source, "previous source");
    }

    private static void reusedStageNames(Path root) throws Exception {
        Path artifact = Files.writeString(root.resolve("pair.dbg"), "previous artifact");
        Path source = Files.writeString(root.resolve("pair.dbg.c"), "previous source");
        Path first = Files.writeString(root.resolve("artifact.stage"), "new artifact");
        Path second = Files.writeString(root.resolve("source.stage"), "new source");
        var stop = new IOException("stop after installing the artifact");
        try {
            ArtifactPairPublisher.publish(first, artifact, second, source, () -> {
                Files.writeString(first, "another artifact stage", java.nio.file.StandardOpenOption.CREATE_NEW);
                Files.writeString(second, "another source stage", java.nio.file.StandardOpenOption.CREATE_NEW);
                throw stop;
            });
            throw new AssertionError("controlled interruption was ignored");
        }
        catch (IOException expected) { require(expected == stop, "wrong publication failure"); }
        text(artifact, "previous artifact");
        text(source, "previous source");
        text(first, "another artifact stage");
        text(second, "another source stage");
    }

    private static void callbacks(Path root) throws Exception {
        Path artifact = root.resolve("pair.dbg"), source = root.resolve("pair.dbg.c");
        Files.writeString(artifact, "original artifact");
        Files.writeString(source, "original source");
        var artifactTime = Files.getLastModifiedTime(artifact);
        var sourceTime = Files.getLastModifiedTime(source);
        for (int missing = 0; missing < 3; missing++) {
            int[] calls = {0};
            ArtifactPairPublisher.StagedWriter writer = stage -> calls[0]++;
            ArtifactPairPublisher.PrePublishCheck check = () -> calls[0]++;
            try {
                ArtifactPairPublisher.stageAndPublish(artifact, source,
                    missing == 0 ? null : writer, missing == 1 ? null : writer, missing == 2 ? null : check);
                throw new AssertionError("null callback accepted");
            }
            catch (IllegalArgumentException expected) {
                require(expected.getMessage().equals("artifact pair callbacks are required"), "wrong callback refusal");
            }
            require(calls[0] == 0, "callback ran before argument admission");
        }
        for (int failAt = 0; failAt < 2; failAt++) {
            int stageIndex = failAt;
            var calls = new ArrayList<String>();
            var failure = new IOException("controlled writer failure " + failAt);
            try {
                ArtifactPairPublisher.stageAndPublish(artifact, source, stage -> {
                    calls.add("artifact");
                    Files.writeString(stage, "partial new artifact");
                    if (stageIndex == 0) throw failure;
                }, stage -> {
                    calls.add("source");
                    Files.writeString(stage, "partial new source");
                    throw failure;
                }, () -> calls.add("publication"));
                throw new AssertionError("writer failure ignored");
            }
            catch (IOException observed) { require(observed == failure, "writer failure identity lost"); }
            require(calls.equals(stageIndex == 0 ? List.of("artifact") : List.of("artifact", "source")),
                "failed staging reached a later callback");
            text(artifact, "original artifact");
            text(source, "original source");
            require(Files.getLastModifiedTime(artifact).equals(artifactTime) &&
                Files.getLastModifiedTime(source).equals(sourceTime), "failed staging changed prior timestamps");
            require(names(root).equals(List.of("pair.dbg", "pair.dbg.c")), "failed staging leaked a file");
        }
    }

    private static void parents(Path root) throws Exception {
        Path first = Files.createDirectory(root.resolve("first"));
        Path other = Files.createDirectory(root.resolve("other"));
        Path artifact = first.resolve("pair.dbg"), source = other.resolve("pair.dbg.c");
        try {
            ArtifactPairPublisher.stageAndPublish(artifact, source,
                path -> { throw new AssertionError("cross-directory artifact writer ran"); },
                path -> { throw new AssertionError("cross-directory source writer ran"); },
                () -> { throw new AssertionError("cross-directory publication ran"); });
            throw new AssertionError("cross-directory pair accepted");
        }
        catch (IOException expected) {
            require(expected.getMessage().equals("artifact pair must share an existing output directory"),
                "wrong pair directory refusal");
        }
        require(names(first).isEmpty() && names(other).isEmpty(), "directory admission created files");
        Path artifactStage = first.resolve("artifact.stage"), sourceStage = first.resolve("source.stage");
        Files.writeString(artifactStage, "staged artifact");
        Files.writeString(sourceStage, "staged source");
        for (boolean exclusive : List.of(false, true)) {
            for (boolean artifactElsewhere : List.of(false, true)) {
                Path selectedArtifact = (artifactElsewhere ? other : first).resolve("pair.dbg");
                Path selectedSource = (artifactElsewhere ? first : other).resolve("pair.dbg.c");
                try {
                    publish(exclusive, artifactStage, selectedArtifact, sourceStage, selectedSource,
                        () -> { throw new AssertionError("cross-directory install reached hook"); });
                    throw new AssertionError("cross-directory stage accepted");
                }
                catch (IOException expected) {
                    require(expected.getMessage().equals("staged and final artifacts must share a directory"),
                        "wrong staged directory refusal");
                }
                text(artifactStage, "staged artifact");
                text(sourceStage, "staged source");
                require(!Files.exists(selectedArtifact) && !Files.exists(selectedSource), "refused stage became final");
            }
            try {
                publish(exclusive, artifactStage, artifact, sourceStage, first.resolve("pair.dbg.c"), null);
                throw new AssertionError("null hook accepted");
            }
            catch (IllegalArgumentException expected) {
                require(expected.getMessage().equals("publish hook is required"), "wrong hook refusal");
            }
            require(names(first).equals(List.of("artifact.stage", "source.stage")) && names(other).isEmpty(),
                "hook refusal changed files");
        }
    }

    private static void changedFreshTarget(Path root, boolean missing) throws Exception {
        Path artifact = root.resolve("pair.dbg"), source = root.resolve("pair.dbg.c");
        Path artifactStage = root.resolve("artifact.stage"), sourceStage = root.resolve("source.stage");
        Files.writeString(artifactStage, "owned artifact stage");
        Files.writeString(sourceStage, "owned source stage");
        try {
            ArtifactPairPublisher.publishNew(artifactStage, artifact, sourceStage, source, () -> {
                require(Files.isSameFile(artifactStage, artifact), "exclusive install is not the selected staged inode");
                Files.delete(artifact);
                if (!missing) Files.writeString(artifact, "concurrent artifact");
                Files.writeString(source, "concurrent source");
            });
            throw new AssertionError("late source collision ignored");
        }
        catch (FileAlreadyExistsException expected) {
            require(java.util.Arrays.stream(expected.getSuppressed()).anyMatch(problem ->
                problem.getMessage().contains("recovery files retained")), "unsafe rollback lost recovery location");
            require(java.util.Arrays.stream(expected.getSuppressed()).anyMatch(problem ->
                problem.getMessage().contains("changed concurrently")), "changed fresh output lacked an ownership diagnostic");
        }
        text(source, "concurrent source");
        text(artifactStage, "owned artifact stage");
        text(sourceStage, "owned source stage");
        if (missing) require(!Files.exists(artifact), "rollback recreated an externally removed artifact");
        else text(artifact, "concurrent artifact");
        require(Files.isRegularFile(PublicationJournal.claimPath(artifact).resolve("owner.properties")),
            "exclusive rollback lost the generation recovery claim");
    }

    private static void failedRestoration(Path root) throws Exception {
        Path artifact = root.resolve("pair.dbg"), source = root.resolve("pair.dbg.c");
        Path artifactStage = root.resolve("artifact.stage"), sourceStage = root.resolve("source.stage");
        Files.writeString(artifact, "recoverable original artifact");
        Files.writeString(source, "untouched original source");
        var original = Files.readAttributes(artifact, BasicFileAttributes.class);
        var sourceTime = Files.getLastModifiedTime(source);
        Files.writeString(artifactStage, "new artifact");
        Files.writeString(sourceStage, "new source");
        var failure = new IOException("controlled post-install failure");
        try {
            ArtifactPairPublisher.publish(artifactStage, artifact, sourceStage, source, () -> {
                Files.delete(artifact);
                Files.createDirectory(artifact);
                Files.writeString(artifact.resolve("concurrent"), "must survive rollback");
                throw failure;
            });
            throw new AssertionError("post-install failure ignored");
        }
        catch (IOException observed) {
            require(observed == failure && java.util.Arrays.stream(observed.getSuppressed()).anyMatch(error ->
                error.getMessage().contains("recovery files retained")), "restoration failure hid primary error or recovery location");
        }
        text(artifact.resolve("concurrent"), "must survive rollback");
        text(source, "untouched original source");
        require(Files.getLastModifiedTime(source).equals(sourceTime), "rollback touched unchanged source");
        List<Path> backups;
        try (var paths = Files.walk(root)) {
            backups = paths.filter(path -> path.getFileName().toString().equals("backup-0")).toList();
        }
        require(backups.size() == 1, "failed rollback discarded recovery backup");
        text(backups.getFirst(), "recoverable original artifact");
        var retained = Files.readAttributes(backups.getFirst(), BasicFileAttributes.class);
        require(java.util.Objects.equals(original.fileKey(), retained.fileKey()) &&
            original.lastModifiedTime().equals(retained.lastModifiedTime()), "retained backup lost original identity/time");
        require(!Files.exists(artifactStage) && !Files.exists(sourceStage), "failed rollback leaked disposable stages");
    }

    private static void publish(boolean exclusive, Path stage, Path artifact, Path sourceStage, Path source,
            ArtifactPairPublisher.PublishHook hook) throws IOException {
        if (exclusive) ArtifactPairPublisher.publishNew(stage, artifact, sourceStage, source, hook);
        else ArtifactPairPublisher.publish(stage, artifact, sourceStage, source, hook);
    }

    private static List<String> names(Path root) throws IOException {
        try (var paths = Files.list(root)) { return paths.map(path -> path.getFileName().toString()).sorted().toList(); }
    }

    private static void text(Path path, String expected) throws IOException {
        require(Files.readString(path).equals(expected), "file content changed: " + path.getFileName());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
