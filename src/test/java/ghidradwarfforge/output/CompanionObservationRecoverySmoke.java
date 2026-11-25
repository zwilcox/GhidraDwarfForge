package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real owned-filesystem changes at observation, installation and cleanup boundaries. */
public final class CompanionObservationRecoverySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-companion-failures-");
        try {
            for (String change : List.of("identity", "size", "timestamp")) observationRace(root, change);
            for (boolean directory : List.of(false, true)) changedDestination(root, directory);
            missingStageAfterBackup(root);
            for (SaveAt point : SaveAt.values()) replacementWhileObserved(root, point);
            readDuringSuccessfulReplacements(root);
            if (System.getProperty("os.name").startsWith("Windows")) lockedExchange(root);
            System.out.println("companion-observation-recovery=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void lockedExchange(Path root) throws Exception {
        Path staged = Files.writeString(root.resolve("exchange-stage"), "staged");
        Path target = Files.writeString(root.resolve("locked-public"), "previous");
        Saved beforeStage = Saved.read(staged);
        Saved beforeTarget = Saved.read(target);
        try (var lock = FileChannel.open(target, StandardOpenOption.READ,
                com.sun.nio.file.ExtendedOpenOption.NOSHARE_DELETE)) {
            var exchange = PublicationExchange.open();
            try {
                exchange.exchange(staged, target);
                throw new AssertionError("transaction exchanged a delete-locked file");
            }
            catch (FileSystemException expected) {
                check(target.toString().equals(expected.getFile()), "exchange error omitted the locked path");
                check(expected.getReason().contains("Win32 error"), "exchange error omitted the native diagnostic");
            }
        }
        beforeStage.unchanged(staged);
        beforeTarget.unchanged(target);
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
        // BasicFileAttributes permits an unavailable file key. OpenJDK 21's
        // Windows provider returns null, so identical replacement bytes/mtime
        // cannot exercise the production key-comparison branch on that host.
        // Keep the other real race/recovery controls and disclose this gap;
        // a null key is not evidence of preserved or changed file identity.
        if (change.equals("identity") && fixture.prior.getFirst().key == null) {
            fixture.unchanged();
            fixture.noStages(4);
            System.out.println("companion-observation-identity=NOT_RUN reason=basic-file-key-unavailable");
            return;
        }
        Path output = fixture.outputs.getFirst();
        int[] polls = {0};
        boolean[] changed = {false};
        Saved[] concurrent = {null};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs,
                stages -> { throw new AssertionError("writer ran after unstable output observation"); }, () -> { }, () -> {
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

    private enum SaveAt { NEVER, BEFORE_EXCHANGE, AFTER_EXCHANGE }

    private static void replacementWhileObserved(Path root, SaveAt save) throws Exception {
        var fixture = Fixture.create(root.resolve("observed-replacement-" + save));
        Path source = fixture.outputs.get(1);
        Path claim = PublicationJournal.claimPath(source);
        Path[] backup = {null};
        boolean[] observed = {false};
        boolean[] edited = {false};
        boolean[] missingName = {false};
        try {
            CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs,
                CompanionObservationRecoverySmoke::write, () -> { }, () -> {
                    if (backup[0] == null && Files.isRegularFile(claim)) {
                        var owner = new java.util.Properties();
                        try (var stream = Files.newInputStream(claim)) { owner.load(stream); }
                        backup[0] = Path.of(owner.getProperty("inventory")).resolveSibling("backup-1");
                    }
                    if (backup[0] == null || !Files.exists(backup[0])) return;
                    try {
                        String bytes = Files.readString(source);
                        check(bytes.equals("old source") || bytes.equals("new generation 1") ||
                            edited[0] && bytes.equals("independent save"), "reader observed partial output bytes");
                        boolean editNow = save == SaveAt.BEFORE_EXCHANGE && bytes.equals("old source") ||
                            save == SaveAt.AFTER_EXCHANGE && bytes.equals("new generation 1");
                        if (editNow && !edited[0]) {
                            Path replacement = Files.writeString(fixture.root.resolve("editor.stage"), "independent save");
                            Files.move(replacement, source, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            edited[0] = true;
                        }
                    }
                    catch (java.nio.file.NoSuchFileException missing) { missingName[0] = true; }
                    observed[0] = true;
                });
            check(save == SaveAt.NEVER, "re-export reported success after overwriting the editor's save");
        }
        catch (IOException conflict) {
            if (!edited[0] || !conflict.getMessage().contains("changed concurrently")) throw conflict;
            if (save == SaveAt.AFTER_EXCHANGE) {
                check(Files.readString(backup[0]).equals("old source"), "conflict lost prior source backup");
                check(Files.exists(claim), "conflict lost recovery claim");
            }
        }
        check(observed[0] && !missingName[0], "public source disappeared while verifying its backup");
        check(Files.readString(source).equals(edited[0] ? "independent save" : "new generation 1"),
            "public source lost the independent save");
        if (edited[0]) {
            fixture.prior.get(0).unchanged(fixture.outputs.get(0));
            fixture.prior.get(2).unchanged(fixture.outputs.get(2));
        }
        fixture.input.unchanged(fixture.original);
    }

    private static void readDuringSuccessfulReplacements(Path root) throws Exception {
        var fixture = Fixture.create(root.resolve("concurrent-reader"));
        var sawOld = new CountDownLatch(1);
        var sawNew = new CountDownLatch(1);
        var finished = new AtomicBoolean();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var reader = executor.submit(() -> {
                try {
                    while (!finished.get()) {
                        for (int i = 0; i < fixture.outputs.size(); i++) {
                            Path output = fixture.outputs.get(i);
                            String bytes = Files.readString(output);
                            if (bytes.equals("new generation " + i)) sawNew.countDown();
                            else if (bytes.equals("old " + output.getFileName())) sawOld.countDown();
                            else throw new AssertionError("reader observed partial bytes in " + output);
                        }
                    }
                }
                finally {
                    // Surface a reader failure immediately if the writer is waiting for it.
                    sawOld.countDown();
                    sawNew.countDown();
                }
                return null;
            });
            try {
                check(sawOld.await(30, TimeUnit.SECONDS), "reader did not see the first generation");
                for (int generation = 0; generation < 4; generation++) {
                    CompanionArtifactPublisher.stageAndPublish(fixture.original, fixture.outputs,
                        CompanionObservationRecoverySmoke::write, () -> { });
                }
                check(sawNew.await(30, TimeUnit.SECONDS), "reader did not see the published generation");
            }
            finally {
                finished.set(true);
                reader.get(30, TimeUnit.SECONDS);
            }
        }
        fixture.input.unchanged(fixture.original);
        fixture.noStages(4);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
