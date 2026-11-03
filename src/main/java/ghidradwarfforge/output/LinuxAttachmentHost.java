package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.function.BooleanSupplier;

/**
 * Internal Linux ext4 host using an already authorized platform thread. Creates
 * only an owned visibility workspace after all-role path preflight; never elevates.
 * Callers must close the session after transaction/recovery and retain receipts.
 * File force plus directory fsync is the durability contract, not proof of power-loss survival.
 */
public final class LinuxAttachmentHost implements AttachmentOperation.Host, AutoCloseable {
    private final LinuxFileMetadata metadata;
    private final LinuxDirectorySync directories;
    private final LinuxAttachmentMount mounts;
    private final LinuxAtomicRename names;
    private final LinuxMetadataVisibility visibility;

    private LinuxAttachmentHost(Path parent, BooleanSupplier cancelled) throws IOException {
        metadata = new LinuxFileMetadata();
        directories = new LinuxDirectorySync();
        mounts = new LinuxAttachmentMount(directories);
        names = new LinuxAtomicRename();
        visibility = LinuxMetadataVisibility.create(parent, cancelled);
    }

    public static LinuxAttachmentHost open(AttachmentOperation.Request request, BooleanSupplier cancelled)
            throws IOException {
        var plan = AttachmentOperation.preflightPaths(request);
        plan.recheck();
        var host = new LinuxAttachmentHost(plan.paths().get("targetBefore").getParent(), cancelled);
        try { plan.recheck(); return host; }
        catch (IOException | RuntimeException failure) {
            try { host.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    @Override public String contract() { return "linux-x64-ext4-protected-metadata-v1"; }
    @Override public String durability() { return "linux-file-force-directory-fsync-v1"; }

    @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
        visibility.check(() -> false);
        Path selected = FileSystemPaths.resolveLeaf(path, "Linux attachment file");
        var parent = mounts.inspect(selected.getParent(), () -> false);
        var snapshot = observe(selected);
        String[] fileDevice = snapshot.facts().identity().split(":", 3);
        String[] parentDevice = parent.directory().identity().split(":", 3);
        require(fileDevice[0].equals(parentDevice[0]) && fileDevice[1].equals(parentDevice[1]),
            "Linux attachment file and directory devices differ");
        require(parent.equals(mounts.inspect(selected.getParent(), () -> false)) &&
            selected.equals(FileSystemPaths.resolveLeaf(path, "Linux attachment file")),
            "Linux attachment directory traversal changed");
        visibility.check(() -> false);
        return fingerprint(snapshot);
    }

    @Override public String directoryIdentity(Path path) throws IOException {
        visibility.check(() -> false);
        var snapshot = mounts.inspect(path, () -> false);
        visibility.check(() -> false);
        var directory = snapshot.directory();
        // Fixed fields are ASCII scalars/hex and cannot contain the separator;
        // the opaque mount record is last. Do not bind receipts to record.toString().
        return directory.identity() + ":" + hash("linux-ext4-directory-v1\n" + directory.identity() + "\n" +
            Long.toUnsignedString(directory.fileSystemType()) + "\n" + directory.fileSystemId() + "\n" +
            Long.toUnsignedString(directory.mountFlags()) + "\n" + directory.maximumNameBytes() + "\n" + snapshot.mountRecord());
    }

    @Override public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint expected, Path stage)
            throws IOException {
        require(inspect(source).equals(expected), "Linux attachment source fingerprint changed");
        inspect(stage);
        var before = observe(source);
        require(fingerprint(before).equals(expected), "Linux attachment source metadata changed");
        metadata.applyToOwnedStage(source, before, stage, () -> false);
        visibility.check(() -> false);
        require(inspect(stage).metadataSha256().equals(expected.metadataSha256()) && inspect(source).equals(expected),
            "Linux attachment metadata preservation differs");
    }

    @Override public void publishNew(Path stage, Path destination) throws IOException { rename(stage, destination, false); }
    @Override public void replaceAtomic(Path stage, Path target) throws IOException { rename(stage, target, true); }

    private void rename(Path stage, Path destination, boolean replace) throws IOException {
        visibility.check(() -> false);
        Path selected = FileSystemPaths.resolveLeaf(stage, "Linux attachment stage");
        Path target = FileSystemPaths.resolveLeaf(destination, "Linux attachment destination");
        var sourceParent = mounts.inspect(selected.getParent(), () -> false);
        var targetParent = mounts.inspect(target.getParent(), () -> false);
        require(sourceParent.mountRecord().equals(targetParent.mountRecord()), "Linux attachment rename crosses mounts");
        var before = observe(selected);
        if (replace) {
            var old = observe(target);
            require(before.preservationSha256().equals(old.preservationSha256()), "Linux replacement would change metadata");
            require(!before.facts().identity().equals(old.facts().identity()), "Linux replacement aliases target");
        }
        visibility.check(() -> false);
        if (replace) names.replaceAtomic(selected, target);
        else names.publishNew(selected, target);
        var installed = observe(target);
        require(fingerprint(before).equals(fingerprint(installed)) && before.facts().bytes() == installed.facts().bytes(),
            "Linux attachment rename changed metadata or identity");
        require(sourceParent.equals(mounts.inspect(selected.getParent(), () -> false)) &&
            targetParent.equals(mounts.inspect(target.getParent(), () -> false)), "Linux attachment rename directory changed");
        visibility.check(() -> false);
    }

    @Override public void syncDirectory(Path path) throws IOException {
        visibility.check(() -> false);
        var before = mounts.inspect(path, () -> false);
        directories.sync(path, before.directory(), () -> false);
        require(before.equals(mounts.inspect(path, () -> false)), "Linux attachment sync mount changed");
        visibility.check(() -> false);
    }

    @Override public byte[] debuglinkBasename(Path sidecar) throws IOException {
        visibility.check(() -> false);
        return DebuglinkBasename.linuxUtf8(sidecar);
    }

    @Override public void close() throws IOException { visibility.close(); }

    private LinuxFileMetadata.Snapshot observe(Path path) throws IOException {
        visibility.check(() -> false);
        var snapshot = metadata.inspect(path, () -> false);
        LinuxFileMetadata.supported(snapshot);
        require(snapshot.facts().links() == 1, "Linux attachment rejects hardlinks");
        visibility.check(() -> false);
        return snapshot;
    }

    private static AttachmentReceiptStore.Fingerprint fingerprint(LinuxFileMetadata.Snapshot snapshot) {
        return new AttachmentReceiptStore.Fingerprint(snapshot.facts().identity(), snapshot.preservationSha256(),
            snapshot.facts().links());
    }

    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
