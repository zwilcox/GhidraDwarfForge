package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Actual Linux replacement/restore operations on owned files; no production metadata claim. */
public final class AttachmentTargetStoreSmoke {
    private static int checks;
    private static final Host HOST = new Host();

    private record Fixture(Path directory, AttachmentFileStore.Snapshot before,
            AttachmentFileStore.Snapshot after, AttachmentFileStore.Snapshot backup) { }

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").equals("Linux")) throw new IllegalStateException("requires Linux");
        if (args.length != 0) {
            child(args);
            return;
        }
        Path root = Files.createTempDirectory("forge-target-store-");
        try {
            success(root);
            failures(root);
            concurrentChanges(root);
            interruptedRestore(root);
            cancellations(root);
            crashes(root);
            System.out.println("attachment-target-store-smoke=PASS checks=" + checks +
                " abrupt-process-exits=2 backups-retained=true");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void interruptedRestore(Path root) throws Exception {
        var fixture = fixture(root, "restore-conflict");
        var attached = AttachmentTargetStore.replace(fixture.before(), fixture.after(), HOST, () -> false);
        Path restorePath = fixture.directory().resolve("restore-copy");
        var racingHost = new Host() {
            @Override public void publishNew(Path stage, Path destination) throws IOException {
                super.publishNew(stage, destination);
                if (destination.equals(restorePath)) {
                    Files.move(attached.path(), attached.path().resolveSibling("retained-attached"));
                    Files.writeString(attached.path(), "concurrent during recovery");
                }
            }
        };
        reject(() -> AttachmentTargetStore.restore(attached, fixture.backup(), restorePath, racingHost, () -> false));
        equal("concurrent during recovery", Files.readString(attached.path()));
        equal(fixture.backup().digest(), AttachmentFileStore.observe(restorePath, HOST, () -> false).digest());
        equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));

        // A host primitive may report failure after renaming the old target out
        // of the namespace. Exercise that real filesystem state, without claiming
        // this Linux injection proves any native Windows API behavior.
        var missing = fixture(root, "missing-target");
        var partialHost = new Host() {
            @Override public void replaceAtomic(Path stage, Path target) throws IOException {
                Files.move(target, target.resolveSibling("native-retained-original"));
                throw new IOException("injected failure after old-name removal");
            }
        };
        var failure = reject(() -> AttachmentTargetStore.replace(missing.before(), missing.after(), partialHost, () -> false));
        equal(true, failure instanceof AttachmentTargetStore.ReplacementFailure);
        equal(false, Files.exists(missing.before().path()));
        var recovered = AttachmentFileStore.backup(missing.backup(), missing.before().path(), HOST, () -> false);
        equal(missing.before().digest(), recovered.digest());
        equal(missing.before().fingerprint().metadataSha256(), recovered.fingerprint().metadataSha256());
        equal(missing.backup(), AttachmentFileStore.observe(missing.backup().path(), HOST, () -> false));
        equal(missing.after(), AttachmentFileStore.observe(missing.after().path(), HOST, () -> false));
    }

    private static Fixture fixture(Path root, String name) throws Exception {
        Path directory = Files.createDirectory(root.resolve(name));
        Path target = Files.writeString(directory.resolve("target"), "original executable image");
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r-xr-----"));
        Files.setLastModifiedTime(target, FileTime.fromMillis(1234567890000L));
        var before = AttachmentFileStore.observe(target, HOST, () -> false);
        var backup = AttachmentFileStore.backup(before, directory.resolve("backup"), HOST, () -> false);
        Path stageDirectory = Files.createDirectory(directory.resolve("candidate-work"));
        Path stage = stageDirectory.resolve("candidate");
        try (var channel = FileChannel.open(stage, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            channel.write(java.nio.ByteBuffer.wrap("complete attached image with debuglink".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            HOST.preserveMetadata(target, before.fingerprint(), stage);
            channel.force(true);
        }
        return new Fixture(directory, before, AttachmentFileStore.observe(stage, HOST, () -> false), backup);
    }

    private static void success(Path root) throws Exception {
        var fixture = fixture(root, "success");
        var installed = AttachmentTargetStore.replace(fixture.before(), fixture.after(), HOST, () -> false);
        equal(fixture.after().digest(), installed.digest());
        equal(fixture.after().fingerprint(), installed.fingerprint());
        equal(false, Files.exists(fixture.after().path()));
        var restored = AttachmentTargetStore.restore(installed, fixture.backup(),
            fixture.directory().resolve("restore-stage"), HOST, () -> false);
        equal(fixture.before().digest(), restored.digest());
        equal(fixture.before().fingerprint().metadataSha256(), restored.fingerprint().metadataSha256());
        equal(false, fixture.before().fingerprint().identity().equals(restored.fingerprint().identity()));
        equal(false, fixture.backup().fingerprint().identity().equals(restored.fingerprint().identity()));
        equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
    }

    private static void failures(Path root) throws Exception {
        for (var boundary : AttachmentTargetStore.Boundary.values()) {
            var fixture = fixture(root, "failure-" + boundary);
            var failure = reject(() -> AttachmentTargetStore.replace(fixture.before(), fixture.after(), HOST, () -> false,
                (point, stage, target) -> { if (point == boundary) throw new IOException("injected " + boundary); }));
            boolean replaced = boundary == AttachmentTargetStore.Boundary.AFTER_REPLACEMENT;
            equal(replaced, failure instanceof AttachmentTargetStore.ReplacementFailure);
            var current = AttachmentFileStore.observe(fixture.before().path(), HOST, () -> false);
            equal(replaced ? fixture.after().digest() : fixture.before().digest(), current.digest());
            if (replaced) {
                var restored = AttachmentTargetStore.restore(current, fixture.backup(),
                    fixture.directory().resolve("restore"), HOST, () -> false);
                equal(fixture.before().digest(), restored.digest());
            }
            equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
        }
        for (boolean changed : new boolean[] { false, true }) {
            var fixture = fixture(root, "native-failure-" + changed);
            var host = new Host() {
                @Override public void replaceAtomic(Path stage, Path target) throws IOException {
                    if (changed) super.replaceAtomic(stage, target);
                    throw new IOException("injected uncertain native failure");
                }
            };
            var failure = reject(() -> AttachmentTargetStore.replace(fixture.before(), fixture.after(), host, () -> false));
            equal(true, failure instanceof AttachmentTargetStore.ReplacementFailure);
            equal(changed ? fixture.after().digest() : fixture.before().digest(),
                AttachmentFileStore.observe(fixture.before().path(), HOST, () -> false).digest());
            equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
        }
        var fixture = fixture(root, "flush-failure");
        var noSync = new Host() {
            @Override public void syncDirectory(Path directory) throws IOException { throw new IOException("flush failure"); }
        };
        var failure = reject(() -> AttachmentTargetStore.replace(fixture.before(), fixture.after(), noSync, () -> false));
        equal(true, failure instanceof AttachmentTargetStore.ReplacementFailure);
        equal(fixture.after().digest(), AttachmentFileStore.observe(fixture.before().path(), HOST, () -> false).digest());
        equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
    }

    private static void concurrentChanges(Path root) throws Exception {
        var fixture = fixture(root, "concurrent");
        Path[] displaced = new Path[1];
        reject(() -> AttachmentTargetStore.replace(fixture.before(), fixture.after(), HOST, () -> false,
            (point, stage, target) -> {
                if (point == AttachmentTargetStore.Boundary.BEFORE_REPLACEMENT) {
                    displaced[0] = target.resolveSibling("retained-target");
                    Files.move(target, displaced[0]);
                    Files.writeString(target, "unrelated concurrent target");
                }
            }));
        equal("unrelated concurrent target", Files.readString(fixture.before().path()));
        equal(fixture.after(), AttachmentFileStore.observe(fixture.after().path(), HOST, () -> false));
        reject(() -> AttachmentTargetStore.restore(fixture.before(), fixture.backup(),
            fixture.directory().resolve("restore"), HOST, () -> false));
        equal(false, Files.exists(fixture.directory().resolve("restore")));
        equal("unrelated concurrent target", Files.readString(fixture.before().path()));
        equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));

        var metadata = fixture(root, "metadata");
        Files.setPosixFilePermissions(metadata.after().path(), PosixFilePermissions.fromString("rw-------"));
        var changed = AttachmentFileStore.observe(metadata.after().path(), HOST, () -> false);
        reject(() -> AttachmentTargetStore.replace(metadata.before(), changed, HOST, () -> false));
        equal(metadata.before(), AttachmentFileStore.observe(metadata.before().path(), HOST, () -> false));
        reject(() -> AttachmentTargetStore.replace(metadata.before(), metadata.before(), HOST, () -> false));
    }

    private static void cancellations(Path root) throws Exception {
        for (var boundary : AttachmentTargetStore.Boundary.values()) {
            var fixture = fixture(root, "cancel-" + boundary);
            AtomicBoolean cancelled = new AtomicBoolean();
            try {
                var result = AttachmentTargetStore.replace(fixture.before(), fixture.after(), HOST, cancelled::get,
                    (point, stage, target) -> { if (point == boundary) cancelled.set(true); });
                equal(AttachmentTargetStore.Boundary.AFTER_REPLACEMENT, boundary);
                equal(fixture.after().digest(), result.digest());
            }
            catch (CancellationException expected) {
                equal(AttachmentTargetStore.Boundary.BEFORE_REPLACEMENT, boundary);
                equal(fixture.before(), AttachmentFileStore.observe(fixture.before().path(), HOST, () -> false));
            }
            equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
        }
    }

    private static void child(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("--crash")) throw new IllegalArgumentException("bad child");
        var before = AttachmentFileStore.observe(Path.of(args[1]), HOST, () -> false);
        var after = AttachmentFileStore.observe(Path.of(args[2]), HOST, () -> false);
        var boundary = AttachmentTargetStore.Boundary.valueOf(args[3]);
        AttachmentTargetStore.replace(before, after, HOST, () -> false,
            (point, stage, target) -> { if (point == boundary) Runtime.getRuntime().halt(88); });
        throw new AssertionError("child did not halt");
    }

    private static void crashes(Path root) throws Exception {
        for (var boundary : AttachmentTargetStore.Boundary.values()) {
            var fixture = fixture(root, "crash-" + boundary);
            var child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                AttachmentTargetStoreSmoke.class.getName(), "--crash", fixture.before().path().toString(),
                fixture.after().path().toString(), boundary.name()).redirectErrorStream(true)
                .redirectOutput(fixture.directory().resolve("child.log").toFile()).start();
            try {
                if (!child.waitFor(20, TimeUnit.SECONDS)) throw new AssertionError("owned child timed out");
                equal(88, child.exitValue());
                var current = AttachmentFileStore.observe(fixture.before().path(), HOST, () -> false);
                boolean replaced = boundary == AttachmentTargetStore.Boundary.AFTER_REPLACEMENT;
                equal(replaced ? fixture.after().digest() : fixture.before().digest(), current.digest());
                if (replaced) {
                    var recovered = AttachmentTargetStore.restore(current, fixture.backup(),
                        fixture.directory().resolve("recovery"), HOST, () -> false);
                    equal(fixture.before().digest(), recovered.digest());
                }
                equal(fixture.backup(), AttachmentFileStore.observe(fixture.backup().path(), HOST, () -> false));
            }
            finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    if (!child.waitFor(5, TimeUnit.SECONDS)) throw new AssertionError("owned child could not be reaped");
                }
            }
        }
    }

    private static class Host extends AttachmentReceiptStoreSmoke.Host implements AttachmentTargetStore.Host {
        public void replaceAtomic(Path stage, Path target) throws IOException {
            new LinuxAtomicRename().replaceAtomic(stage, target);
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
