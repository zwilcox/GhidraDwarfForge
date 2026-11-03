package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.List;

/** Standalone owned-file Host mechanism test, not real ELF/validator acceptance. */
public final class LinuxAttachmentHostSmoke {
    @FunctionalInterface interface Action { void run() throws Exception; }
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !List.of("privileged", "unprivileged").contains(args[0])) {
            throw new IllegalArgumentException("usage: privileged|unprivileged new-results-directory");
        }
        Path root = Files.createDirectory(Path.of(args[1]));
        Path target = Files.writeString(root.resolve("target"), "original fixture bytes");
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rwx--x---"));
        Files.setLastModifiedTime(target, FileTime.fromMillis(1700000000123L));
        Files.getFileAttributeView(target, UserDefinedFileAttributeView.class)
            .write("fixture", ByteBuffer.wrap(new byte[] {0, -1, 10}));
        if (args[0].equals("privileged")) {
            String uid = System.getenv("SUDO_UID");
            String gid = System.getenv("SUDO_GID");
            require(uid != null && gid != null && Integer.parseInt(uid) > 0,
                "privileged fixture requires the explicit sudo harness with a non-root invoking owner");
            // Only this new disposable target changes owner. Backups/stages start
            // as root, so preservation must actually exercise fchown/readback.
            Files.setAttribute(target, "unix:uid", Integer.parseInt(uid));
            Files.setAttribute(target, "unix:gid", Integer.parseInt(gid));
        }
        Path sidecar = Files.writeString(root.resolve("sidecar.dbg"), "sidecar fixture");
        Path source = Files.writeString(root.resolve("sidecar.dbg.c"), "source fixture");
        Path report = Files.writeString(root.resolve("export.json"), "report fixture");
        var request = request(root, target, sidecar, source, report, root.resolve("backup"));
        var bad = request(root, target, sidecar, source, report, target);
        refused(() -> LinuxAttachmentHost.open(bad, () -> false), "already exists");
        noWorkspace(root);
        if (args[0].equals("unprivileged")) {
            refused(() -> LinuxAttachmentHost.open(request, () -> false), "create protected visibility canary failed (errno=1)");
            require(Files.readString(target).equals("original fixture bytes"), "unprivileged attempt changed target");
            noWorkspace(root);
        }
        else {
            try (var host = LinuxAttachmentHost.open(request, () -> false)) {
                var before = AttachmentFileStore.observe(target, host, () -> false);
                var backup = AttachmentFileStore.backup(before, request.originalBackup(), host, () -> false);
                require(before.digest().equals(backup.digest()), "backup bytes differ");
                require(before.fingerprint().metadataSha256().equals(backup.fingerprint().metadataSha256()), "backup metadata differs");
                require(!before.fingerprint().identity().equals(backup.fingerprint().identity()), "backup is not independent");
                Path stage = Files.writeString(root.resolve("stage"), "new fixture bytes");
                refused(() -> host.replaceAtomic(stage, target), "would change metadata");
                AttachmentFileStore.unchanged(before, host, () -> false);
                host.preserveMetadata(target, before.fingerprint(), stage);
                refused(() -> host.publishNew(stage, request.originalBackup()), "no-replace rename failed");
                require(Files.exists(stage), "no-overwrite failure consumed stage");
                AttachmentFileStore.unchanged(backup, host, () -> false);
                host.replaceAtomic(stage, target);
                host.syncDirectory(root);
                require(Files.readString(target).equals("new fixture bytes") && !Files.exists(stage), "replacement failed");
                require(host.inspect(target).metadataSha256().equals(before.fingerprint().metadataSha256()), "replacement metadata differs");
                Path restored = Files.copy(request.originalBackup(), root.resolve("restore-stage"));
                host.preserveMetadata(request.originalBackup(), backup.fingerprint(), restored);
                host.replaceAtomic(restored, target);
                host.syncDirectory(root);
                require(Files.readString(target).equals("original fixture bytes"), "restore bytes differ");
                require(host.inspect(target).metadataSha256().equals(before.fingerprint().metadataSha256()), "restore metadata differs");
                AttachmentFileStore.unchanged(backup, host, () -> false);
                Path link = Files.createLink(root.resolve("hardlink"), target);
                refused(() -> host.inspect(target), "hardlinks");
                Files.delete(link);
                Path symbolic = Files.createSymbolicLink(root.resolve("symlink"), target);
                refused(() -> host.inspect(symbolic), "regular non-link");
                Files.delete(symbolic);
                Files.setAttribute(target, "unix:mode", 04710);
                refused(() -> host.inspect(target), "privileged file mode");
                Files.setAttribute(target, "unix:mode", 0710);
                Path unsupported = Files.createFile(root.resolve("owned-unsupported-canary"),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                var primitive = new LinuxFileMetadata();
                primitive.markOwnedCanary(unsupported, primitive.inspect(unsupported, () -> false), new byte[32], () -> false);
                refused(() -> host.inspect(unsupported), "unsupported visible metadata namespace");
                Files.delete(unsupported);
                require(new String(host.debuglinkBasename(root.resolve("λ.dbg")), java.nio.charset.StandardCharsets.UTF_8)
                    .equals("λ.dbg"), "native UTF-8 basename differs");
            }
            noWorkspace(root);
        }
        System.out.println("linux-attachment-host=" + args[0] + " PASS checks=" + checks);
    }

    private static AttachmentOperation.Request request(Path root, Path target, Path sidecar, Path source,
            Path report, Path backup) {
        return new AttachmentOperation.Request(target, sidecar, source, report, backup,
            root.resolve("validation.json"), root.resolve("receipt.json"), root.resolve("recovery.json"),
            root.resolve("restore-image"), null);
    }
    private static void noWorkspace(Path root) throws IOException {
        try (var files = Files.list(root)) {
            require(files.noneMatch(path -> path.getFileName().toString().startsWith(".forge-visibility-")), "visibility workspace leaked");
        }
    }
    private static void refused(Action action, String message) throws Exception {
        try { action.run(); }
        catch (IOException failure) {
            require(failure.getMessage().contains(message), "wrong refusal: " + failure);
            require(failure.getSuppressed().length == 0, "refusal cleanup failed");
            return;
        }
        throw new AssertionError("unexpected success");
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
