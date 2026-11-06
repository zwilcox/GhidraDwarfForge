package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Linux Intel LP64/ext4 installation host. Preserves ordinary mode, uid/gid,
 * mtime, visible user xattrs and access ACLs through the audited metadata primitive.
 * Unlike executable attachment, installation only publishes new debug artifacts;
 * it never modifies the selected executable or enables privileges. Hidden metadata,
 * access/change/birth times and power-loss survival are not preservation claims.
 * Unsupported visible namespaces, inode policies, aliases and failed copies refuse.
 */
public final class LinuxBuildIdHost implements AttachmentOperation.Host {
    private final LinuxFileMetadata metadata = new LinuxFileMetadata();
    private final LinuxDirectorySync directories = new LinuxDirectorySync();
    private final LinuxAttachmentMount mounts = new LinuxAttachmentMount(directories);
    private final LinuxAtomicRename names = new LinuxAtomicRename();

    public LinuxBuildIdHost() throws IOException { }

    @Override public String contract() { return "linux-x64-ext4-build-id-visible-metadata-v1"; }
    @Override public String durability() { return "linux-file-force-directory-fsync-v1"; }

    @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
        Path selected = FileSystemPaths.resolveLeaf(path, "build-ID file");
        var parent = mounts.inspect(selected.getParent(), () -> false);
        var observed = observe(selected);
        require(sameDevice(observed.facts().identity(), parent.directory().identity()),
            "build-ID file and parent devices differ");
        require(parent.equals(mounts.inspect(selected.getParent(), () -> false)) &&
            selected.equals(FileSystemPaths.resolveLeaf(path, "build-ID file")), "build-ID file traversal changed");
        return fingerprint(observed);
    }

    @Override public String directoryIdentity(Path path) throws IOException {
        var mount = mounts.inspect(path, () -> false);
        var directory = mount.directory();
        return directory.identity() + ":" + hash("linux-build-id-directory-v1\n" + directory.identity() + "\n" +
            Long.toUnsignedString(directory.fileSystemType()) + "\n" + directory.fileSystemId() + "\n" +
            Long.toUnsignedString(directory.mountFlags()) + "\n" + directory.maximumNameBytes() + "\n" + mount.mountRecord());
    }

    @Override public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint expected, Path stage)
            throws IOException {
        require(inspect(source).equals(expected), "build-ID metadata source changed");
        inspect(stage);
        var before = observe(source);
        require(fingerprint(before).equals(expected), "build-ID source metadata changed");
        metadata.applyToOwnedStage(source, before, stage, () -> false);
        require(inspect(stage).metadataSha256().equals(expected.metadataSha256()) && inspect(source).equals(expected),
            "build-ID metadata preservation differs");
    }

    @Override public void publishNew(Path stage, Path destination) throws IOException { rename(stage, destination, false); }
    @Override public void replaceAtomic(Path stage, Path destination) throws IOException { rename(stage, destination, true); }

    private void rename(Path stage, Path destination, boolean replace) throws IOException {
        Path selected = FileSystemPaths.resolveLeaf(stage, "build-ID stage");
        Path target = FileSystemPaths.resolveLeaf(destination, "build-ID destination");
        var from = mounts.inspect(selected.getParent(), () -> false);
        var to = mounts.inspect(target.getParent(), () -> false);
        require(from.mountRecord().equals(to.mountRecord()), "build-ID rename crosses mounts");
        var before = observe(selected);
        if (replace) {
            var old = observe(target);
            require(before.preservationSha256().equals(old.preservationSha256()), "build-ID replacement would change access metadata");
            require(!before.facts().identity().equals(old.facts().identity()), "build-ID replacement aliases target");
            names.replaceAtomic(selected, target);
        }
        else names.publishNew(selected, target);
        var after = observe(target);
        require(fingerprint(before).equals(fingerprint(after)) && before.facts().bytes() == after.facts().bytes(),
            "build-ID publication changed metadata or identity");
        require(from.equals(mounts.inspect(selected.getParent(), () -> false)) &&
            to.equals(mounts.inspect(target.getParent(), () -> false)), "build-ID publication directory changed");
    }

    @Override public void syncDirectory(Path path) throws IOException {
        var before = mounts.inspect(path, () -> false);
        directories.sync(path, before.directory(), () -> false);
        require(before.equals(mounts.inspect(path, () -> false)), "build-ID sync mount changed");
    }

    @Override public byte[] debuglinkBasename(Path path) throws IOException { return DebuglinkBasename.linuxUtf8(path); }

    private LinuxFileMetadata.Snapshot observe(Path path) throws IOException {
        var observed = metadata.inspect(path, () -> false);
        LinuxFileMetadata.supported(observed);
        require(observed.facts().links() == 1, "build-ID installation rejects hardlinks");
        return observed;
    }

    private static AttachmentReceiptStore.Fingerprint fingerprint(LinuxFileMetadata.Snapshot snapshot) {
        return new AttachmentReceiptStore.Fingerprint(snapshot.facts().identity(), snapshot.preservationSha256(), snapshot.facts().links());
    }

    private static boolean sameDevice(String file, String directory) {
        String[] left = file.split(":", 3), right = directory.split(":", 3);
        return left.length == 3 && right.length == 3 && left[0].equals(right[0]) && left[1].equals(right[1]);
    }

    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
