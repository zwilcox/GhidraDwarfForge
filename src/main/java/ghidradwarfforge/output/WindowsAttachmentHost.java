package ghidradwarfforge.output;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Internal local-NTFS transaction adapter. Requires an already authorized token;
 * never enables privileges. Unsupported or invisible metadata is an error.
 * Caller supplies explicit intent, validation, backups and recovery protocol.
 * File contents are forced by the stores; directory synchronization uses the
 * audited directory FlushFileBuffers primitive. This is not a power-loss claim.
 */
public final class WindowsAttachmentHost implements AttachmentOperation.Host {
    private final WindowsAttachmentMetadata metadata = new WindowsAttachmentMetadata();
    private final WindowsDirectorySync directories = new WindowsDirectorySync();
    private final WindowsFileRename names = new WindowsFileRename();

    public WindowsAttachmentHost() throws IOException { }

    @Override public String contract() { return "windows-x64-local-ntfs-raw-security-v1"; }
    @Override public String durability() { return "windows-file-force-directory-flush-v1"; }

    @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
        Path selected = FileSystemPaths.resolveLeaf(path, "Windows attachment file");
        var parent = directory(selected.getParent());
        var snapshot = metadata.inspect(selected, () -> false);
        require(snapshot.ordinary().facts().identity().split(":", 2)[0].equals(
            parent.identity().split(":", 2)[0]), "Windows attachment file and directory volumes differ");
        require(parent.equals(directory(selected.getParent())) &&
            selected.equals(FileSystemPaths.resolveLeaf(path, "Windows attachment file")),
            "Windows attachment directory traversal changed");
        return fingerprint(snapshot);
    }

    @Override public String directoryIdentity(Path path) throws IOException {
        var snapshot = directory(path);
        return snapshot.identity() + ":" + digest(output -> {
            output.writeLong(snapshot.volumeSerial());
            output.writeLong(snapshot.maximumNameUnits());
            output.writeLong(snapshot.fileSystemFlags());
            text(output, snapshot.fileSystem());
            text(output, snapshot.volume().root());
            output.writeInt(snapshot.volume().driveType());
        });
    }

    @Override public void preserveMetadata(Path source, AttachmentReceiptStore.Fingerprint expected, Path stage)
            throws IOException {
        require(inspect(source).equals(expected), "Windows attachment source fingerprint changed");
        inspect(stage);
        var before = metadata.inspect(source, () -> false);
        require(fingerprint(before).equals(expected), "Windows attachment source metadata changed");
        metadata.applyToOwnedStage(source, before, stage, () -> false);
        require(inspect(stage).metadataSha256().equals(expected.metadataSha256()) && inspect(source).equals(expected),
            "Windows attachment metadata preservation differs");
    }

    @Override public void publishNew(Path stage, Path destination) throws IOException {
        rename(stage, destination, false);
    }

    @Override public void replaceAtomic(Path stage, Path target) throws IOException {
        rename(stage, target, true);
    }

    private void rename(Path stage, Path destination, boolean replace) throws IOException {
        Path selected = FileSystemPaths.resolveLeaf(stage, "Windows attachment stage");
        Path target = FileSystemPaths.resolveLeaf(destination, "Windows attachment destination");
        var sourceParent = directory(selected.getParent());
        var targetParent = directory(target.getParent());
        require(sourceParent.volume().equals(targetParent.volume()), "Windows attachment rename crosses volumes");
        var before = metadata.inspect(selected, () -> false);
        if (replace) {
            var old = metadata.inspect(target, () -> false);
            require(before.preservation().equals(old.preservation()), "Windows replacement would change metadata");
            names.replace(selected, before.ordinary(), target, old.ordinary(), () -> false);
        }
        else {
            names.publishNew(selected, before.ordinary(), target, () -> false);
        }
        var installed = metadata.inspect(target, () -> false);
        require(fingerprint(before).equals(fingerprint(installed)) &&
            before.ordinary().facts().bytes() == installed.ordinary().facts().bytes(),
            "Windows attachment rename changed complete metadata or identity");
        require(sourceParent.equals(directory(selected.getParent())) && targetParent.equals(directory(target.getParent())),
            "Windows attachment rename directory changed");
    }

    @Override public void syncDirectory(Path directory) throws IOException {
        directories.sync(directory, directory(directory), () -> false);
    }

    @Override public byte[] debuglinkBasename(Path sidecar) throws IOException {
        return DebuglinkBasename.portableAscii(sidecar);
    }

    private WindowsDirectorySync.Snapshot directory(Path path) throws IOException {
        var snapshot = directories.inspect(path, () -> false);
        // DRIVE_FIXED and FILE_PERSISTENT_ACLS. Other filesystems require their
        // own preservation/namespace evidence, not an assumed NTFS contract.
        require(snapshot.volume().driveType() == 3 && snapshot.fileSystem().equals("NTFS") &&
            (snapshot.fileSystemFlags() & 8) != 0, "Windows attachment requires a fixed local NTFS volume with ACLs");
        return snapshot;
    }

    private static AttachmentReceiptStore.Fingerprint fingerprint(WindowsAttachmentMetadata.Snapshot snapshot)
            throws IOException {
        var ordinary = snapshot.ordinary();
        String hash = digest(output -> {
            text(output, "windows-attachment-preservation-v1");
            output.writeInt(ordinary.facts().attributes());
            output.writeLong(ordinary.facts().created());
            output.writeLong(ordinary.facts().modified());
            output.writeInt(ordinary.security().control());
            text(output, ordinary.security().owner());
            text(output, ordinary.security().group());
            text(output, ordinary.security().dacl());
            text(output, snapshot.security().rawDescriptor());
        });
        return new AttachmentReceiptStore.Fingerprint(ordinary.facts().identity(), hash, ordinary.facts().links());
    }

    @FunctionalInterface private interface Encoding { void write(DataOutputStream output) throws IOException; }

    private static String digest(Encoding encoding) throws IOException {
        try {
            var hash = MessageDigest.getInstance("SHA-256");
            try (var output = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(), hash))) {
                encoding.write(output);
            }
            return HexFormat.of().formatHex(hash.digest());
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void text(DataOutputStream output, String text) throws IOException {
        if (text == null) { output.writeInt(-1); return; }
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
