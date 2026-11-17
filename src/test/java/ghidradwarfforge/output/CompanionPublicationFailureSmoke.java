package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Real owned-filesystem changes at observation, installation and cleanup boundaries. */
public final class CompanionPublicationFailureSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-companion-failures-");
        try {
            for (String change : List.of("identity", "size", "timestamp")) observationRace(root, change);
            for (boolean directory : List.of(false, true)) changedDestination(root, directory);
            missingStageAfterBackup(root);
            committedCleanupFailure(root);
            System.out.println("companion-publication-failures=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private record Saved(byte[] bytes, Object key, FileTime modified) {
        static Saved read(Path path) throws IOException {
            var attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return new Saved(Files.readAllBytes(path), attributes.fileKey(), attributes.lastModifiedTime());
        }

        void unchanged(Path path) throws IOException {
            check(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
                "publication lost protected file: " + path.getFileName());
            var actual = read(path);
            check(Arrays.equals(bytes, actual.bytes) && Objects.equals(key, actual.key) && modified.equals(actual.modified),
                "publication changed protected bytes, identity or timestamp: " + path.getFileName());
        }
    }

    private record Fixture(Path root, Path original, List<Path> outputs, Saved input, List<Saved> prior) {
        static Fixture create(Path root) throws IOException {
            Files.createDirectory(root);
            Path original = Files.writeString(root.resolve("original"), "original executable sentinel");
            var outputs = new ArrayList<Path>();
            var prior = new ArrayList<Saved>();
            for (String name : List.of("sidecar", "source", "loader")) {
                Path path = Files.writeString(root.resolve(name), "old " + name);
                Files.setLastModifiedTime(path, FileTime.fromMillis(1700000000000L));
                outputs.add(path);
                prior.add(Saved.read(path));
            }
            return new Fixture(root, original, List.copyOf(outputs), Saved.read(original), List.copyOf(prior));
        }

        void unchanged() throws IOException {
            input.unchanged(original);
            for (int i = 0; i < outputs.size(); i++) prior.get(i).unchanged(outputs.get(i));
        }

        void noStages(int expectedEntries) throws IOException {
            try (var paths = Files.list(root)) {
                check(paths.count() == expectedEntries, "disposable generation files leaked");
            }
        }
    }

    private static void write(List<Path> stages) throws IOException {
        for (int i = 0; i < stages.size(); i++) Files.writeString(stages.get(i), "new generation " + i);
    }

    private static void observationRace(Path root, String change) throws Exception {
        var fixture = Fixture.create(root.resolve("observed-" + change));
        Path output = fixture.outputs.getFirst();
        int[] polls = {0};
        boolean[] changed = {false};
        Saved[] concurrent = {null};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs,
                stages -> { throw new AssertionError("writer ran after unstable output observation"); }, () -> {
                    // observe's check precedes its metadata read; FileDigests' first check
                    // follows that read, before it opens the file. No timing/thread race.
                    if (++polls[0] != 2) return;
                    switch (change) {
                        case "identity" -> {
                            Files.move(output, fixture.root.resolve("concurrent-old-inode"));
                            Files.write(output, fixture.prior.getFirst().bytes);
                            Files.setLastModifiedTime(output, fixture.prior.getFirst().modified);
                            check(!Objects.equals(Saved.read(output).key, fixture.prior.getFirst().key),
                                "identity fixture did not replace its inode");
                        }
                        case "size" -> {
                            Files.writeString(output, "a longer concurrent output");
                            Files.setLastModifiedTime(output, fixture.prior.getFirst().modified);
                        }
                        case "timestamp" -> Files.setLastModifiedTime(output, FileTime.fromMillis(1700000002000L));
                        default -> throw new AssertionError(change);
                    }
                    concurrent[0] = Saved.read(output);
                    changed[0] = true;
                });
            throw new AssertionError("unstable output observation was accepted: " + change);
        }
        catch (IOException expected) {
            check(changed[0] && expected.getMessage().contains("changed while observing"), "wrong observation rejection");
            check(expected.getSuppressed().length == 0, "observation rejection attempted publication cleanup");
        }
        concurrent[0].unchanged(output);
        fixture.input.unchanged(fixture.original);
        for (int i = 1; i < fixture.outputs.size(); i++) fixture.prior.get(i).unchanged(fixture.outputs.get(i));
        if (change.equals("identity")) fixture.prior.getFirst().unchanged(fixture.root.resolve("concurrent-old-inode"));
        fixture.noStages(change.equals("identity") ? 5 : 4);
    }

    private static void changedDestination(Path root, boolean directory) throws Exception {
        var fixture = Fixture.create(root.resolve("changed-destination-" + directory));
        Path changed = fixture.outputs.get(1);
        Saved[] concurrent = {null};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs, stages -> {
                write(stages);
                if (directory) {
                    Files.delete(changed);
                    Files.createDirectory(changed);
                    Files.writeString(changed.resolve("user-file"), "concurrent directory contents");
                }
                else {
                    Files.writeString(changed, "new source"); // Same size as the selected old source.
                    Files.setLastModifiedTime(changed, fixture.prior.get(1).modified);
                    concurrent[0] = Saved.read(changed);
                }
            }, () -> { });
            throw new AssertionError("concurrent destination was overwritten");
        }
        catch (IOException expected) {
            check(expected.getMessage().contains(directory ? "not a regular file" : "changed concurrently"),
                "wrong concurrent destination rejection");
            check(expected.getSuppressed().length == 0, "early refusal left incomplete cleanup");
        }
        if (directory) check(Files.readString(changed.resolve("user-file")).equals("concurrent directory contents"),
            "concurrent directory contents were lost");
        else concurrent[0].unchanged(changed);
        fixture.input.unchanged(fixture.original);
        fixture.prior.get(0).unchanged(fixture.outputs.get(0));
        fixture.prior.get(2).unchanged(fixture.outputs.get(2));
        fixture.noStages(4);
    }

    private static void missingStageAfterBackup(Path root) throws Exception {
        var fixture = Fixture.create(root.resolve("missing-stage"));
        var stages = new ArrayList<Path>();
        boolean[] removed = {false};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs, selected -> {
                stages.addAll(selected);
                write(selected);
            }, () -> { }, index -> {
                if (index == 0) {
                    Files.delete(stages.get(1));
                    removed[0] = true;
                }
            });
            throw new AssertionError("missing stage was accepted");
        }
        catch (java.nio.file.NoSuchFileException expected) {
            check(removed[0], "missing stage fixture did not reach partial installation");
            check(expected.getSuppressed().length == 0, "backup restoration failed after missing stage");
        }
        fixture.unchanged();
        fixture.noStages(4);
    }

    private static void committedCleanupFailure(Path root) throws Exception {
        var fixture = Fixture.create(root.resolve("committed-cleanup"));
        Path[] retained = {null};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs, CompanionPublicationFailureSmoke::write,
                () -> { }, index -> {
                    if (index == 2) {
                        try (var paths = Files.list(fixture.root)) {
                            Path recovery = paths.filter(Files::isDirectory).findFirst().orElseThrow();
                            retained[0] = Files.writeString(recovery.resolve("concurrent-user-file"), "preserve this file");
                        }
                    }
                });
            throw new AssertionError("failed generation cleanup was reported as success");
        }
        catch (IOException expected) {
            check(expected.getMessage().contains("generation installed but staging cleanup failed"),
                "cleanup failure lost committed outcome");
            check(expected.getCause() instanceof java.nio.file.DirectoryNotEmptyException,
                "cleanup error cause not retained");
        }
        fixture.input.unchanged(fixture.original);
        for (int i = 0; i < fixture.outputs.size(); i++) {
            check(Files.readString(fixture.outputs.get(i)).equals("new generation " + i),
                "cleanup failure rolled back committed generation");
        }
        check(Files.readString(retained[0]).equals("preserve this file"), "cleanup removed unrelated file");
        fixture.noStages(5);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
