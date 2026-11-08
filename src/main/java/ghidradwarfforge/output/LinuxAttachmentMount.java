package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Binds the opened directory's mount ID/device to this thread's ext4 mount record. */
final class LinuxAttachmentMount {
    static final int LIMIT = 2 * 1024 * 1024;
    record Snapshot(LinuxDirectorySync.Snapshot directory, String mountRecord) { }
    private final LinuxDirectorySync directories;

    LinuxAttachmentMount(LinuxDirectorySync directories) { this.directories = directories; }

    Snapshot inspect(Path path, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        require(!Thread.currentThread().isVirtual(), "mount observation requires a platform thread");
        var before = directories.inspect(path, cancelled);
        require(before.fileSystemType() == 0xef53, "attachment requires an ext4 mount");
        String record = select(read(), before.identity());
        check(cancelled);
        require(before.equals(directories.inspect(path, cancelled)), "attachment directory or mount changed");
        require(record.equals(select(read(), before.identity())), "attachment mount record changed");
        check(cancelled);
        return new Snapshot(before, record);
    }

    private static byte[] read() throws IOException {
        try (var stream = Files.newInputStream(Path.of("/proc/thread-self/mountinfo"))) {
            byte[] bytes = stream.readNBytes(LIMIT + 1);
            require(bytes.length <= LIMIT, "mount information exceeds bound");
            return bytes;
        }
    }

    /** Paths remain escaped opaque bytes; selection uses native mount ID, never a path prefix. */
    static String select(byte[] bytes, String identity) throws IOException {
        require(bytes.length > 0 && bytes.length <= LIMIT && bytes[bytes.length - 1] == '\n',
            "incomplete or oversized mount information");
        String[] nativeParts = identity.split(":", -1);
        require(nativeParts.length == 3, "invalid native directory identity");
        String[] inodeMount = nativeParts[2].split("@", -1);
        require(inodeMount.length == 2 && decimal(inodeMount[1]), "missing native mount ID");
        String device = nativeParts[0] + ":" + nativeParts[1];
        String selected = null;
        // Latin-1 retains every byte in mount-source/path fields without lossy
        // Unicode decoding. We do not turn these opaque fields into file paths.
        for (String line : new String(bytes, StandardCharsets.ISO_8859_1).split("\n")) {
            require(line.indexOf('\0') < 0 && line.indexOf('\r') < 0 && line.indexOf('\t') < 0,
                "malformed mount information");
            String[] fields = line.split(" ", -1);
            require(fields.length >= 10 && decimal(fields[0]) && decimal(fields[1]), "malformed mount entry");
            if (!fields[0].equals(inodeMount[1])) continue;
            require(selected == null, "duplicate native mount ID");
            int separator = 6;
            while (separator < fields.length && !fields[separator].equals("-")) separator++;
            require(separator + 4 == fields.length, "malformed selected mount entry");
            for (String field : fields) require(!field.isEmpty(), "empty selected mount field");
            require(fields[2].equals(device), "native mount device differs from mount record");
            require(fields[separator + 1].equals("ext4"), "attachment requires an ext4 mount");
            require(writable(fields[5]) && writable(fields[separator + 3]), "attachment mount is not writable");
            for (int i = 6; i < separator; i++) {
                String field = fields[i];
                require(field.equals("unbindable") ||
                    (field.startsWith("shared:") && decimal(field.substring(7))) ||
                    (field.startsWith("master:") && decimal(field.substring(7))) ||
                    (field.startsWith("propagate_from:") && decimal(field.substring(15))),
                    "unreviewed attachment mount field");
            }
            selected = line;
        }
        require(selected != null, "native mount ID is absent from this thread's mount information");
        return selected;
    }

    private static boolean writable(String options) {
        var values = Arrays.asList(options.split(",", -1));
        return values.contains("rw") && !values.contains("ro") && !values.contains("");
    }

    private static boolean decimal(String value) {
        if (value.isEmpty() || (value.length() > 1 && value.charAt(0) == '0')) return false;
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) < '0' || value.charAt(i) > '9') return false;
        try { Long.parseUnsignedLong(value); return true; }
        catch (NumberFormatException invalid) { return false; }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("mount observation cancelled");
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
}
