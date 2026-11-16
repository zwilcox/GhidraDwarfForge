package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Actual Linux backup copying/publication, with a test-only metadata contract. */
public final class AttachmentFileStoreSmoke {
    private static int checks;
    private static final AttachmentReceiptStoreSmoke.Host HOST = new AttachmentReceiptStoreSmoke.Host();

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").equals("Linux")) throw new IllegalStateException("requires Linux");
        if (args.length != 0) {
            crashChild(args);
            return;
        }
        Path root = Files.createTempDirectory("forge-backup-smoke-");
        try {
            Path source = Files.write(root.resolve("target"), new byte[256 * 1024 + 7]);
            Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("r-xr-----"));
            Files.setLastModifiedTime(source, FileTime.fromMillis(1234567890000L));
            var expected = AttachmentFileStore.observe(source, HOST, () -> false);
            Path destination = root.resolve("original backup λ.elf");
            var backup = AttachmentFileStore.backup(expected, destination, HOST, () -> false);
            equal(expected.digest(), backup.digest());
            equal(expected.fingerprint().metadataSha256(), backup.fingerprint().metadataSha256());
            equal(false, expected.fingerprint().identity().equals(backup.fingerprint().identity()));
            equal(1L, backup.fingerprint().links());
            equal(backup.artifact().sha256(), expected.digest().sha256());
            equal(expected, AttachmentFileStore.observe(source, HOST, () -> false));
            reject(() -> AttachmentFileStore.backup(expected, destination, HOST, () -> false));
            equal(backup, AttachmentFileStore.observe(destination, HOST, () -> false));
            reject(() -> AttachmentFileStore.backup(expected, source, HOST, () -> false));
            collisions(root, expected);
            failures(root, expected);
            cancellation(root);
            concurrentChanges(root);
            copyExtentChanges(root);
            stagedReadbackChanges(root, expected);
            metadataStageReplacement(root, expected);
            publishedIdentityReplacement(root, expected);
            publishedDirectoryReplacement(root, expected);
            unavailableIdentity(root, expected);
            observationChange(root);
            crashRecovery(root, expected);
            equal(expected, AttachmentFileStore.observe(source, HOST, () -> false));
            equal(backup, AttachmentFileStore.observe(destination, HOST, () -> false));
            System.out.println("attachment-file-store-smoke=PASS checks=" + checks +
                " abrupt-process-exits=4 original-preserved=true");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void collisions(Path root, AttachmentFileStore.Snapshot expected) throws Exception {
        Path dangling = Files.createSymbolicLink(root.resolve("dangling"), root.resolve("absent"));
        reject(() -> AttachmentFileStore.backup(expected, dangling, HOST, () -> false));
        equal(true, Files.isSymbolicLink(dangling));
        Path directory = Files.createDirectory(root.resolve("directory"));
        reject(() -> AttachmentFileStore.backup(expected, directory, HOST, () -> false));
        Path link = Files.createLink(root.resolve("source-hardlink"), expected.path());
        reject(() -> AttachmentFileStore.backup(expected, root.resolve("hardlinked-backup"), HOST, () -> false));
        Files.delete(link);
        Path symlink = Files.createSymbolicLink(root.resolve("source-symlink"), expected.path());
        reject(() -> AttachmentFileStore.observe(symlink, HOST, () -> false));
        Path raced = root.resolve("raced");
        var host = new AttachmentReceiptStoreSmoke.Host() {
            @Override public void publishNew(Path stage, Path destination) throws IOException {
                Files.writeString(destination, "concurrent file", StandardOpenOption.CREATE_NEW);
                super.publishNew(stage, destination);
            }
        };
        var failure = reject(() -> AttachmentFileStore.backup(expected, raced, host, () -> false));
        equal(true, failure instanceof AttachmentFileStore.PublicationFailure);
        equal("concurrent file", Files.readString(raced));
    }

    private static void failures(Path root, AttachmentFileStore.Snapshot expected) throws Exception {
        for (var boundary : AttachmentFileStore.Boundary.values()) {
            Path directory = Files.createDirectory(root.resolve("failure-" + boundary));
            Path backup = directory.resolve("backup");
            var failure = reject(() -> AttachmentFileStore.backup(expected, backup, HOST, () -> false,
                (point, stage, destination) -> {
                    if (point == boundary) throw new IOException("injected " + boundary);
                }));
            boolean published = boundary == AttachmentFileStore.Boundary.AFTER_PUBLICATION;
            equal(published, failure instanceof AttachmentFileStore.PublicationFailure);
            equal(published, Files.exists(backup));
            if (published) equal(expected.digest(), AttachmentFileStore.observe(backup, HOST, () -> false).digest());
            try (var children = Files.list(directory)) {
                equal(false, children.anyMatch(path -> path.getFileName().toString().startsWith(".forge-")));
            }
            equal(expected, AttachmentFileStore.observe(expected.path(), HOST, () -> false));
        }
        Path badMetadata = root.resolve("metadata-failure");
        var ignoringMetadata = new AttachmentReceiptStoreSmoke.Host() {
            @Override public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint fingerprint,
                    Path stage) { }
        };
        reject(() -> AttachmentFileStore.backup(expected, badMetadata, ignoringMetadata, () -> false));
        equal(false, Files.exists(badMetadata));
        for (boolean after : new boolean[] { false, true }) {
            Path destination = root.resolve("flush-failure-" + after);
            var host = new AttachmentReceiptStoreSmoke.Host() {
                @Override public void syncDirectory(Path directory) throws IOException {
                    if (after == directory.equals(root)) throw new IOException("injected flush failure");
                    super.syncDirectory(directory);
                }
            };
            var failure = reject(() -> AttachmentFileStore.backup(expected, destination, host, () -> false));
            equal(after, failure instanceof AttachmentFileStore.PublicationFailure);
            equal(after, Files.exists(destination));
            if (after) equal(expected.digest(), AttachmentFileStore.observe(destination, HOST, () -> false).digest());
        }
    }

    private static void cancellation(Path root) throws Exception {
        Path source = Files.write(root.resolve("large-source"), new byte[16 * 1024 * 1024]);
        var expected = AttachmentFileStore.observe(source, HOST, () -> false);
        AtomicBoolean copying = new AtomicBoolean();
        AtomicInteger calls = new AtomicInteger();
        Path destination = root.resolve("cancelled-backup");
        try {
            AttachmentFileStore.backup(expected, destination, HOST,
                () -> copying.get() && calls.incrementAndGet() >= 20,
                (point, stage, backup) -> {
                    if (point == AttachmentFileStore.Boundary.CREATED) copying.set(true);
                });
            throw new AssertionError("copy cancellation was ignored");
        }
        catch (CancellationException expectedCancellation) { checks++; }
        equal(false, Files.exists(destination));
        equal(expected, AttachmentFileStore.observe(source, HOST, () -> false));
        AtomicBoolean late = new AtomicBoolean();
        var published = AttachmentFileStore.backup(expected, destination, HOST, late::get,
            (point, stage, backup) -> {
                if (point == AttachmentFileStore.Boundary.AFTER_PUBLICATION) late.set(true);
            });
        equal(expected.digest(), published.digest());
    }

    private static void concurrentChanges(Path root) throws Exception {
        Path source = Files.writeString(root.resolve("mutable"), "before");
        var expected = AttachmentFileStore.observe(source, HOST, () -> false);
        Path backup = root.resolve("stale-backup");
        reject(() -> AttachmentFileStore.backup(expected, backup, HOST, () -> false,
            (point, stage, destination) -> {
                if (point == AttachmentFileStore.Boundary.COPIED) Files.writeString(source, "concurrent update");
            }));
        equal("concurrent update", Files.readString(source));
        equal(false, Files.exists(backup));

        var current = AttachmentFileStore.observe(source, HOST, () -> false);
        Path[] conflict = new Path[1];
        reject(() -> AttachmentFileStore.backup(current, backup, HOST, () -> false,
            (point, stage, destination) -> {
                if (point == AttachmentFileStore.Boundary.BEFORE_PUBLICATION) {
                    Files.move(stage, stage.resolveSibling("retained-owned"));
                    Files.writeString(stage, "unrelated replacement");
                    conflict[0] = stage;
                }
            }));
        equal("unrelated replacement", Files.readString(conflict[0]));
        equal(false, Files.exists(backup));
        equal(current, AttachmentFileStore.observe(source, HOST, () -> false));
    }

    private static void noStages(Path directory) throws IOException {
        try (var paths = Files.list(directory)) {
            equal(false, paths.anyMatch(path -> path.getFileName().toString().startsWith(".forge-backup-")));
        }
    }

    private static void message(Throwable failure, String expected) {
        if (!failure.getMessage().contains(expected)) {
            throw new AssertionError("expected " + expected + " but got " + failure, failure);
        }
        checks++;
    }

    /** Actual source extent changes after observation, before the first copied byte. */
    private static void copyExtentChanges(Path root) throws Exception {
        for (boolean grows : new boolean[] { false, true }) {
            Path directory = Files.createDirectory(root.resolve("extent-change-" + grows));
            Path source = Files.write(directory.resolve("source"), new byte[129]);
            var before = AttachmentFileStore.observe(source, HOST, () -> false);
            byte[] concurrent = new byte[grows ? 130 : 128];
            java.util.Arrays.fill(concurrent, (byte) 53);
            Path destination = directory.resolve("backup");
            var failure = reject(() -> AttachmentFileStore.backup(before, destination, HOST, () -> false,
                (point, stage, output) -> {
                    if (point == AttachmentFileStore.Boundary.CREATED) Files.write(source, concurrent);
                }));
            message(failure, grows ? "source exceeds expected size" : "source shrank while copying");
            equal(false, failure instanceof AttachmentFileStore.PublicationFailure);
            equal(false, Files.exists(destination));
            equal(true, java.util.Arrays.equals(concurrent, Files.readAllBytes(source)));
            noStages(directory);
        }
    }

    /** A failed copied-stage observation must not authorize metadata writes. */
    private static void stagedReadbackChanges(Path root, AttachmentFileStore.Snapshot source) throws Exception {
        for (String change : new String[] { "contents", "file", "directory" }) {
            boolean replaces = !change.equals("contents");
            Path directory = Files.createDirectory(root.resolve("copied-stage-change-" + change));
            Path destination = directory.resolve("backup");
            Path[] changedStage = { null };
            Path[] retainedStage = { null };
            AtomicInteger metadataCalls = new AtomicInteger();
            var host = new AttachmentReceiptStoreSmoke.Host() {
                @Override public void preserveMetadata(Path input, AttachmentReceiptStore.Fingerprint expected,
                        Path stage) throws IOException {
                    metadataCalls.incrementAndGet();
                    super.preserveMetadata(input, expected, stage);
                }
            };
            var failure = reject(() -> AttachmentFileStore.backup(source, destination, host, () -> false,
                (point, stage, output) -> {
                    if (point != AttachmentFileStore.Boundary.COPIED) return;
                    changedStage[0] = stage;
                    if (change.equals("directory")) {
                        Path retained = directory.resolve("retained-owned-directory");
                        Files.move(stage.getParent(), retained);
                        Files.createDirectory(stage.getParent());
                        retainedStage[0] = retained.resolve(stage.getFileName());
                    }
                    else if (replaces) {
                        retainedStage[0] = stage.resolveSibling("retained-owned");
                        Files.move(stage, retainedStage[0]);
                    }
                    Files.writeString(stage, "foreign stage contents");
                }));
            equal(0, metadataCalls.get());
            message(failure, "backup copied bytes or identity differ");
            equal(false, failure instanceof AttachmentFileStore.PublicationFailure);
            equal(false, Files.exists(destination));
            if (replaces) {
                equal("foreign stage contents", Files.readString(changedStage[0]));
                equal(source.digest(), FileDigests.read(retainedStage[0], () -> false));
                equal(1, failure.getSuppressed().length);
                message(failure.getSuppressed()[0], change.equals("directory") ?
                    "backup staging directory changed; retained" : "backup stage identity changed; retained");
            }
            else noStages(directory);
            equal(source, AttachmentFileStore.observe(source.path(), HOST, () -> false));
        }
    }

    private static void metadataStageReplacement(Path root, AttachmentFileStore.Snapshot source) throws Exception {
        Path directory = Files.createDirectory(root.resolve("metadata-stage-replacement"));
        Path destination = directory.resolve("backup");
        Path[] replacement = { null };
        var host = new AttachmentReceiptStoreSmoke.Host() {
            @Override public void preserveMetadata(Path input, AttachmentReceiptStore.Fingerprint expected,
                    Path stage) throws IOException {
                super.preserveMetadata(input, expected, stage);
                Path retained = stage.resolveSibling("retained-owned");
                Files.move(stage, retained);
                Files.copy(retained, stage, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
                replacement[0] = stage;
            }
        };
        var failure = reject(() -> AttachmentFileStore.backup(source, destination, host, () -> false));
        equal(false, Files.exists(destination));
        equal(false, failure instanceof AttachmentFileStore.PublicationFailure);
        message(failure, "backup stage identity changed while preserving metadata");
        var foreign = AttachmentFileStore.observe(replacement[0], HOST, () -> false);
        var retained = AttachmentFileStore.observe(replacement[0].resolveSibling("retained-owned"), HOST, () -> false);
        equal(source.digest(), foreign.digest());
        equal(source.fingerprint().metadataSha256(), foreign.fingerprint().metadataSha256());
        equal(false, foreign.fingerprint().identity().equals(retained.fingerprint().identity()));
        equal(1, failure.getSuppressed().length);
        message(failure.getSuppressed()[0], "backup stage identity changed; retained");
        equal(source, AttachmentFileStore.observe(source.path(), HOST, () -> false));
    }

    private static void publishedIdentityReplacement(Path root, AttachmentFileStore.Snapshot source) throws Exception {
        Path directory = Files.createDirectory(root.resolve("published-identity-replacement"));
        Path destination = directory.resolve("backup");
        Path retained = directory.resolve("retained-published");
        var host = new AttachmentReceiptStoreSmoke.Host() {
            @Override public void publishNew(Path stage, Path output) throws IOException {
                super.publishNew(stage, output);
                Files.move(output, retained);
                Files.copy(retained, output, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
            }
        };
        var failure = reject(() -> AttachmentFileStore.backup(source, destination, host, () -> false));
        equal(true, failure instanceof AttachmentFileStore.PublicationFailure);
        equal(destination, ((AttachmentFileStore.PublicationFailure) failure).backupPath());
        message(failure.getCause(), "published backup identity differs from its owned stage");
        var replaced = AttachmentFileStore.observe(destination, HOST, () -> false);
        var owned = AttachmentFileStore.observe(retained, HOST, () -> false);
        equal(source.digest(), replaced.digest());
        equal(source.fingerprint().metadataSha256(), replaced.fingerprint().metadataSha256());
        equal(false, owned.fingerprint().identity().equals(replaced.fingerprint().identity()));
        equal(source, AttachmentFileStore.observe(source.path(), HOST, () -> false));
        noStages(directory);
    }

    /** Successful publication still needs reconciliation if cleanup loses directory ownership. */
    private static void publishedDirectoryReplacement(Path root, AttachmentFileStore.Snapshot source) throws Exception {
        for (boolean occupied : new boolean[] { false, true }) {
            Path directory = Files.createDirectory(root.resolve("published-directory-replacement-" + occupied));
            Path destination = directory.resolve("backup");
            Path[] replaced = { null };
            Path retained = directory.resolve("retained-empty-directory");
            var failure = reject(() -> AttachmentFileStore.backup(source, destination, HOST, () -> false,
                (point, stage, output) -> {
                    if (point != AttachmentFileStore.Boundary.AFTER_PUBLICATION) return;
                    replaced[0] = stage.getParent();
                    Files.move(stage.getParent(), retained);
                    Files.createDirectory(stage.getParent());
                    if (occupied) Files.writeString(stage.getParent().resolve("foreign"), "concurrent directory contents");
                }));
            equal(true, failure instanceof AttachmentFileStore.PublicationFailure);
            equal(destination, ((AttachmentFileStore.PublicationFailure) failure).backupPath());
            message(failure.getCause(), "backup staging directory changed; retained");
            equal(true, Files.isDirectory(replaced[0]));
            if (occupied) equal("concurrent directory contents", Files.readString(replaced[0].resolve("foreign")));
            else {
                try (var files = Files.list(replaced[0])) { equal(0L, files.count()); }
            }
            equal(true, Files.isDirectory(retained));
            equal(source.digest(), AttachmentFileStore.observe(destination, HOST, () -> false).digest());
            equal(source, AttachmentFileStore.observe(source.path(), HOST, () -> false));
        }
    }

    /** An adapter failure before identity capture cannot authorize deleting an unverified path. */
    private static void unavailableIdentity(Path root, AttachmentFileStore.Snapshot source) throws Exception {
        for (boolean directoryFailure : new boolean[] { false, true }) {
            Path directory = Files.createDirectory(root.resolve("unavailable-identity-" + directoryFailure));
            Path destination = directory.resolve("backup");
            Path[] selected = { null };
            var marker = new IOException("owned adapter identity observation unavailable");
            var host = new AttachmentReceiptStoreSmoke.Host() {
                @Override public String directoryIdentity(Path path) throws IOException {
                    if (directoryFailure && path.getFileName().toString().startsWith(".forge-backup-")) {
                        selected[0] = path;
                        throw marker;
                    }
                    return super.directoryIdentity(path);
                }
                @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
                    if (!directoryFailure && path.getFileName().toString().equals("image") &&
                            path.getParent().getFileName().toString().startsWith(".forge-backup-")) {
                        selected[0] = path;
                        throw marker;
                    }
                    return super.inspect(path);
                }
            };
            var failure = reject(() -> AttachmentFileStore.backup(source, destination, host, () -> false));
            equal(true, failure == marker);
            equal(false, Files.exists(destination));
            equal(true, Files.exists(selected[0]));
            if (directoryFailure) {
                try (var files = Files.list(selected[0])) { equal(0L, files.count()); }
            }
            else equal(0L, Files.size(selected[0]));
            equal(1, failure.getSuppressed().length);
            message(failure.getSuppressed()[0], directoryFailure ?
                "backup staging directory changed; retained" : "backup stage identity changed; retained");
            equal(source, AttachmentFileStore.observe(source.path(), HOST, () -> false));
        }
    }

    private static void observationChange(Path root) throws Exception {
        Path source = Files.writeString(root.resolve("observation-change"), "unchanged bytes");
        FileTime concurrent = FileTime.fromMillis(Files.getLastModifiedTime(source).toMillis() + 2000);
        var host = new AttachmentReceiptStoreSmoke.Host() {
            private int observations;
            @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
                if (path.equals(source) && ++observations == 2) Files.setLastModifiedTime(path, concurrent);
                return super.inspect(path);
            }
        };
        var failure = reject(() -> AttachmentFileStore.observe(source, host, () -> false));
        message(failure, "attachment recovery file changed while reading");
        equal("unchanged bytes", Files.readString(source));
        equal(concurrent, Files.getLastModifiedTime(source));
    }

    private static void crashChild(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("--crash")) throw new IllegalArgumentException("bad crash child");
        var source = AttachmentFileStore.observe(Path.of(args[1]), HOST, () -> false);
        var boundary = AttachmentFileStore.Boundary.valueOf(args[3]);
        AttachmentFileStore.backup(source, Path.of(args[2]), HOST, () -> false,
            (point, stage, backup) -> { if (point == boundary) Runtime.getRuntime().halt(87); });
        throw new AssertionError("child did not halt");
    }

    private static void crashRecovery(Path root, AttachmentFileStore.Snapshot expected) throws Exception {
        for (var boundary : AttachmentFileStore.Boundary.values()) {
            Path directory = Files.createDirectory(root.resolve("crash-" + boundary));
            Path backup = directory.resolve("backup");
            var child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                AttachmentFileStoreSmoke.class.getName(), "--crash", expected.path().toString(),
                backup.toString(), boundary.name()).redirectErrorStream(true)
                .redirectOutput(directory.resolve("child.log").toFile()).start();
            try {
                if (!child.waitFor(20, TimeUnit.SECONDS)) throw new AssertionError("owned crash child timed out");
                equal(87, child.exitValue());
                boolean published = boundary == AttachmentFileStore.Boundary.AFTER_PUBLICATION;
                equal(published, Files.exists(backup));
                if (published) {
                    var observed = AttachmentFileStore.observe(backup, HOST, () -> false);
                    equal(expected.digest(), observed.digest());
                    equal(expected.fingerprint().metadataSha256(), observed.fingerprint().metadataSha256());
                    equal(false, expected.fingerprint().identity().equals(observed.fingerprint().identity()));
                }
                equal(expected, AttachmentFileStore.observe(expected.path(), HOST, () -> false));
            }
            finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    if (!child.waitFor(5, TimeUnit.SECONDS)) throw new AssertionError("owned child could not be reaped");
                }
            }
        }
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static IOException reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected rejection"); }
        catch (IOException expected) { checks++; return expected; }
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
