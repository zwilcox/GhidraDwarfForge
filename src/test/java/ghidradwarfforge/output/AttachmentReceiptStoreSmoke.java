package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.TimeUnit;

/** Actual Linux filesystem operations; this host is not a production target adapter. */
public final class AttachmentReceiptStoreSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").equals("Linux")) {
            throw new IllegalStateException("receipt store smoke requires Linux; no Windows claim");
        }
        if (args.length != 0) {
            crashChild(args);
            return;
        }
        Path root = Files.createTempDirectory("forge-receipt-store-");
        try {
            Host host = new Host();
            Path target = root.resolve("receipt.json");
            var prepared = prepared(target);
            var state = AttachmentReceiptStore.prepare(target, prepared, host, () -> false);
            equal(prepared, AttachmentReceiptStore.read(target, host, () -> false).receipt());
            equal(1L, Files.getAttribute(target, "unix:nlink") instanceof Number n ? n.longValue() : -1L);
            reject(() -> AttachmentReceiptStore.prepare(target, prepared, host, () -> false));
            state = AttachmentReceiptStore.advance(state, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false);
            equal(AttachmentReceipt.Phase.COMMITTED, state.receipt().phase());
            var immutable = state;
            try {
                AttachmentReceiptStore.advance(immutable, AttachmentReceipt.Phase.ROLLED_BACK, "bad", host, () -> false);
                throw new AssertionError("committed receipt was changed");
            }
            catch (IllegalStateException expected) { checks++; }
            equal(immutable, AttachmentReceiptStore.read(target, host, () -> false));
            var recovery = AttachmentReceiptStore.prepare(root.resolve("recovery.json"),
                prepared(root.resolve("recovery.json")), host, () -> false);
            recovery = AttachmentReceiptStore.advance(recovery, AttachmentReceipt.Phase.RECOVERY_REQUIRED,
                "owned interrupted operation", host, () -> false);
            recovery = AttachmentReceiptStore.advance(recovery, AttachmentReceipt.Phase.ROLLED_BACK,
                "owned backup verified and restored", host, () -> false);
            equal(AttachmentReceipt.Phase.ROLLED_BACK, recovery.receipt().phase());
            concurrentRecords(root, host);
            boundaries(root, host);
            cancellations(root, host);
            flushFailures(root);
            changedStage(root, host);
            atomicRename(root);
            crashRecovery(root, host);
            lastMomentCollision(root);
            metadataAndReadControls(root, host);
            equal(true, host.syncs > 0);
            System.out.println("attachment-receipt-store-smoke=PASS checks=" + checks +
                " real-directory-fsyncs=" + host.syncs);
        }
        finally {
            try (var files = Files.walk(root)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void atomicRename(Path root) throws Exception {
        var rename = new LinuxAtomicRename();
        Path source = Files.writeString(root.resolve("native-source"), "complete bytes");
        Path destination = root.resolve("unicode λ receipt with spaces.json");
        Object identity = Files.getAttribute(source, "unix:ino");
        rename.publishNew(source, destination);
        equal(false, Files.exists(source));
        equal(identity, Files.getAttribute(destination, "unix:ino"));
        equal("complete bytes", Files.readString(destination));
        Files.writeString(source, "next bytes");
        reject(() -> rename.publishNew(source, destination));
        equal("complete bytes", Files.readString(destination));
        equal("next bytes", Files.readString(source));
        Path dangling = Files.createSymbolicLink(root.resolve("native-dangling"), root.resolve("missing-target"));
        reject(() -> rename.publishNew(source, dangling));
        equal(true, Files.isSymbolicLink(dangling));
        Path directory = Files.createDirectory(root.resolve("native-directory"));
        reject(() -> rename.publishNew(source, directory));
        equal(true, Files.isDirectory(directory));
        reject(() -> rename.publishNew(source, root.resolve("missing-parent/new")));
        equal("next bytes", Files.readString(source));
    }

    private static void crashChild(String[] args) throws Exception {
        if (args.length != 4 || !args[0].equals("--crash")) throw new IllegalArgumentException("bad crash child");
        Path path = Path.of(args[1]);
        var boundary = AttachmentReceiptStore.Boundary.valueOf(args[2]);
        boolean update = Boolean.parseBoolean(args[3]);
        Host host = new Host();
        var old = update ? AttachmentReceiptStore.read(path, host, () -> false) : null;
        var next = update ? old.receipt().advance(AttachmentReceipt.Phase.COMMITTED, null) : prepared(path);
        AttachmentReceiptStore.publish(path, old, next, host, () -> false,
            (point, stage, destination) -> {
                if (point == boundary) Runtime.getRuntime().halt(86);
            });
        throw new AssertionError("crash hook did not terminate child");
    }

    private static void crashRecovery(Path root, Host host) throws Exception {
        for (var boundary : AttachmentReceiptStore.Boundary.values()) {
            for (boolean update : List.of(false, true)) {
                Path directory = Files.createDirectory(root.resolve("crash-" + boundary + "-" + update));
                Path path = directory.resolve("receipt.json");
                var before = update ? AttachmentReceiptStore.prepare(path, prepared(path), host, () -> false) : null;
                Path log = directory.resolve("child.log");
                Process process = new ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                    AttachmentReceiptStoreSmoke.class.getName(), "--crash", path.toString(),
                    boundary.name(), Boolean.toString(update)).redirectErrorStream(true).redirectOutput(log.toFile()).start();
                try {
                    if (!process.waitFor(20, TimeUnit.SECONDS)) throw new AssertionError("crash child timed out");
                    equal(86, process.exitValue());
                    boolean published = boundary == AttachmentReceiptStore.Boundary.AFTER_PUBLICATION;
                    if (published || update) {
                        var observed = AttachmentReceiptStore.read(path, host, () -> false);
                        equal(published && update ? AttachmentReceipt.Phase.COMMITTED : AttachmentReceipt.Phase.PREPARED,
                            observed.receipt().phase());
                        equal(1L, observed.fingerprint().links());
                        if (!published) equal(before, observed);
                        if (observed.receipt().phase() == AttachmentReceipt.Phase.PREPARED) {
                            // A fresh process can parse and advance a complete prepared
                            // record; the real transaction must verify/restore its backup first.
                            var recovered = AttachmentReceiptStore.advance(observed, AttachmentReceipt.Phase.ROLLED_BACK,
                                "test-only recovery; no executable was involved", host, () -> false);
                            equal(AttachmentReceipt.Phase.ROLLED_BACK, recovered.receipt().phase());
                        }
                    }
                    else {
                        equal(false, Files.exists(path));
                    }
                    try (var children = Files.list(directory)) {
                        equal(1L, children.filter(p -> p.getFileName().toString().startsWith(".forge-receipt-")).count());
                    }
                }
                finally {
                    if (process.isAlive()) {
                        process.destroyForcibly();
                        if (!process.waitFor(5, TimeUnit.SECONDS)) throw new AssertionError("owned child could not be reaped");
                    }
                }
            }
        }
    }

    private static void lastMomentCollision(Path root) throws Exception {
        Path path = root.resolve("last-moment.json");
        Host host = new Host() {
            @Override public void publishNew(Path stage, Path destination) throws IOException {
                Files.writeString(destination, "concurrent creator", StandardOpenOption.CREATE_NEW);
                super.publishNew(stage, destination);
            }
        };
        var failure = reject(() -> AttachmentReceiptStore.prepare(path, prepared(path), host, () -> false));
        equal(true, failure instanceof AttachmentReceiptStore.PublicationFailure);
        equal("concurrent creator", Files.readString(path));
    }

    private static void metadataAndReadControls(Path root, Host host) throws Exception {
        Path path = root.resolve("metadata.json");
        AttachmentReceiptStore.prepare(path, prepared(path), host, () -> false);
        Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions.fromString("r--r-----"));
        Files.setLastModifiedTime(path, java.nio.file.attribute.FileTime.fromMillis(1234567890000L));
        var before = AttachmentReceiptStore.read(path, host, () -> false);
        var after = AttachmentReceiptStore.advance(before, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false);
        equal(before.fingerprint().metadataSha256(), after.fingerprint().metadataSha256());
        equal(false, before.fingerprint().identity().equals(after.fingerprint().identity()));
        Path alias = Files.createSymbolicLink(root.resolve("read-link"), path);
        reject(() -> AttachmentReceiptStore.read(alias, host, () -> false));
        Path oversized = Files.write(root.resolve("oversized.json"), new byte[1024 * 1024 + 1]);
        reject(() -> AttachmentReceiptStore.read(oversized, host, () -> false));
        Host wrongContract = new Host() {
            @Override public String contract() { return "wrong-host-contract"; }
        };
        reject(() -> AttachmentReceiptStore.read(path, wrongContract, () -> false));
        equal(after, AttachmentReceiptStore.read(path, host, () -> false));

        Path refusedPath = root.resolve("host-replace-refused.json");
        var refused = AttachmentReceiptStore.prepare(refusedPath, prepared(refusedPath), host, () -> false);
        var rejectingHost = new Host() {
            @Override public void replaceAtomic(Path stage, Path destination) throws IOException {
                throw new IOException("host replacement refusal");
            }
        };
        reject(() -> AttachmentReceiptStore.advance(refused, AttachmentReceipt.Phase.COMMITTED, null,
            rejectingHost, () -> false));
        equal(refused, AttachmentReceiptStore.read(refusedPath, host, () -> false));

        Path changedMetadata = root.resolve("host-replace-metadata.json");
        var initial = AttachmentReceiptStore.prepare(changedMetadata, prepared(changedMetadata), host, () -> false);
        var changingHost = new Host() {
            @Override public void replaceAtomic(Path stage, Path destination) throws IOException {
                super.replaceAtomic(stage, destination);
                Files.setLastModifiedTime(destination, java.nio.file.attribute.FileTime.fromMillis(1000));
            }
        };
        var mismatch = reject(() -> AttachmentReceiptStore.advance(initial, AttachmentReceipt.Phase.COMMITTED, null,
            changingHost, () -> false));
        equal(true, mismatch instanceof AttachmentReceiptStore.PublicationFailure);
    }

    private static AttachmentReceipt prepared(Path path) {
        var fixture = AttachmentProtocolSmoke.fixture(AttachmentReceipt.Mode.INITIAL);
        return new AttachmentReceipt(fixture.operationId(), fixture.mode(), fixture.phase(),
            path.toString(), fixture.backend(), "linux-store-test-v1", "linux-test-directory-fsync",
            fixture.debuglinkCrc32(), fixture.files(), null);
    }

    private static void concurrentRecords(Path root, Host host) throws Exception {
        Path changed = root.resolve("changed.json");
        var state = AttachmentReceiptStore.prepare(changed, prepared(changed), host, () -> false);
        Files.writeString(changed, "unrelated concurrent content");
        reject(() -> AttachmentReceiptStore.advance(state, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false));
        equal("unrelated concurrent content", Files.readString(changed));

        Path clone = root.resolve("clone.json");
        var old = AttachmentReceiptStore.prepare(clone, prepared(clone), host, () -> false);
        Path retained = root.resolve("old-inode.json");
        Files.move(clone, retained);
        Files.copy(retained, clone);
        Files.setPosixFilePermissions(clone, Files.getPosixFilePermissions(retained));
        Files.setLastModifiedTime(clone, Files.getLastModifiedTime(retained));
        reject(() -> AttachmentReceiptStore.advance(old, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false));
        equal(Files.readString(retained), Files.readString(clone));

        Path linked = root.resolve("linked.json");
        var linkedState = AttachmentReceiptStore.prepare(linked, prepared(linked), host, () -> false);
        Path alias = Files.createLink(root.resolve("receipt-hardlink"), linked);
        reject(() -> AttachmentReceiptStore.advance(linkedState, AttachmentReceipt.Phase.COMMITTED, null, host, () -> false));
        equal(Files.readString(linked), Files.readString(alias));
        Path dangling = Files.createSymbolicLink(root.resolve("dangling.json"), root.resolve("absent"));
        reject(() -> AttachmentReceiptStore.prepare(dangling, prepared(dangling), host, () -> false));
        equal(true, Files.isSymbolicLink(dangling));
    }

    private static void boundaries(Path root, Host host) throws Exception {
        for (var boundary : AttachmentReceiptStore.Boundary.values()) {
            for (boolean update : List.of(false, true)) {
                Path directory = Files.createDirectory(root.resolve(boundary + "-" + update));
                Path path = directory.resolve("record.json");
                var prepared = prepared(path);
                var old = update ? AttachmentReceiptStore.prepare(path, prepared, host, () -> false) : null;
                var next = update ? prepared.advance(AttachmentReceipt.Phase.COMMITTED, null) : prepared;
                var failure = reject(() -> AttachmentReceiptStore.publish(path, old, next, host, () -> false,
                    (point, stage, destination) -> {
                        if (point == boundary) throw new IOException("injected " + boundary);
                    }));
                equal(boundary == AttachmentReceiptStore.Boundary.AFTER_PUBLICATION,
                    failure instanceof AttachmentReceiptStore.PublicationFailure);
                if (boundary == AttachmentReceiptStore.Boundary.AFTER_PUBLICATION) {
                    equal(next, AttachmentReceiptStore.read(path, host, () -> false).receipt());
                }
                else if (update) {
                    equal(old, AttachmentReceiptStore.read(path, host, () -> false));
                }
                else {
                    equal(false, Files.exists(path));
                }
                try (var children = Files.list(directory)) {
                    equal(false, children.anyMatch(p -> p.getFileName().toString().startsWith(".forge-")));
                }
            }
        }
        Path raced = root.resolve("raced.json");
        reject(() -> AttachmentReceiptStore.publish(raced, null, prepared(raced), host, () -> false,
            (point, stage, destination) -> {
                if (point == AttachmentReceiptStore.Boundary.BEFORE_PUBLICATION) {
                    Files.writeString(destination, "another operation", StandardOpenOption.CREATE_NEW);
                }
            }));
        equal("another operation", Files.readString(raced));
    }

    private static void cancellations(Path root, Host host) throws Exception {
        for (var boundary : AttachmentReceiptStore.Boundary.values()) {
            Path path = root.resolve("cancel-" + boundary + ".json");
            AtomicBoolean cancelled = new AtomicBoolean();
            try {
                var state = AttachmentReceiptStore.publish(path, null, prepared(path), host, cancelled::get,
                    (point, stage, destination) -> { if (point == boundary) cancelled.set(true); });
                if (boundary != AttachmentReceiptStore.Boundary.AFTER_PUBLICATION) {
                    throw new AssertionError("pre-publication cancellation was ignored");
                }
                equal(AttachmentReceipt.Phase.PREPARED, state.receipt().phase());
            }
            catch (CancellationException expected) {
                if (boundary == AttachmentReceiptStore.Boundary.AFTER_PUBLICATION) throw expected;
                equal(false, Files.exists(path));
            }
        }
    }

    private static void flushFailures(Path root) throws Exception {
        for (boolean afterPublish : List.of(false, true)) {
            Path path = root.resolve("flush-" + afterPublish + ".json");
            Host host = new Host() {
                @Override public void syncDirectory(Path directory) throws IOException {
                    if (afterPublish == directory.equals(root)) throw new IOException("injected directory fsync failure");
                    super.syncDirectory(directory);
                }
            };
            reject(() -> AttachmentReceiptStore.prepare(path, prepared(path), host, () -> false));
            equal(afterPublish, Files.exists(path));
            if (afterPublish) {
                equal(prepared(path), AttachmentReceiptStore.read(path, new Host(), () -> false).receipt());
            }
        }
    }

    private static void changedStage(Path root, Host host) throws Exception {
        Path directory = Files.createDirectory(root.resolve("stage-conflict"));
        Path path = directory.resolve("record.json");
        Path[] preserved = new Path[1];
        reject(() -> AttachmentReceiptStore.publish(path, null, prepared(path), host, () -> false,
            (point, stage, destination) -> {
                if (point == AttachmentReceiptStore.Boundary.STAGED) {
                    Files.move(stage, stage.resolveSibling("original-stage.json"));
                    Files.writeString(stage, "unrelated staged replacement");
                    preserved[0] = stage;
                }
            }));
        equal(false, Files.exists(path));
        equal("unrelated staged replacement", Files.readString(preserved[0]));
    }

    static class Host implements AttachmentReceiptStore.Host {
        private int syncs;
        public String contract() { return "linux-store-test-v1"; }
        public String durability() { return "linux-test-directory-fsync"; }
        public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
            var attributes = new TreeMap<>(Files.readAttributes(path,
                "unix:dev,ino,nlink,mode,uid,gid,lastModifiedTime", LinkOption.NOFOLLOW_LINKS));
            int mode = ((Number) attributes.get("mode")).intValue();
            if ((mode & 0170000) != 0100000) throw new IOException("expected regular non-link receipt");
            String identity = attributes.remove("dev") + ":" + attributes.remove("ino");
            long links = ((Number) attributes.remove("nlink")).longValue();
            try {
                String metadata = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    new TreeMap<>(attributes).toString().getBytes(StandardCharsets.UTF_8)));
                return new AttachmentReceiptStore.Fingerprint(identity, metadata, links);
            }
            catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        }
        public String directoryIdentity(Path path) throws IOException {
            return new LinuxDirectorySync().inspect(path, () -> false).identity();
        }
        public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint expected, Path stage)
                throws IOException {
            if (!inspect(source).equals(expected)) throw new IOException("source receipt changed");
            Files.setPosixFilePermissions(stage, Files.getPosixFilePermissions(source));
            Files.setLastModifiedTime(stage, Files.getLastModifiedTime(source));
            if (!inspect(stage).metadataSha256().equals(expected.metadataSha256())) {
                throw new IOException("test metadata preservation failed");
            }
        }
        public void syncDirectory(Path path) throws IOException {
            var directory = new LinuxDirectorySync();
            directory.sync(path, directory.inspect(path, () -> false), () -> false);
            syncs++;
        }
        public void publishNew(Path stage, Path destination) throws IOException {
            new LinuxAtomicRename().publishNew(stage, destination);
        }
        public void replaceAtomic(Path stage, Path destination) throws IOException {
            new LinuxAtomicRename().replaceAtomic(stage, destination);
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
