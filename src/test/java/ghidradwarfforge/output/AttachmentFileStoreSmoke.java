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
