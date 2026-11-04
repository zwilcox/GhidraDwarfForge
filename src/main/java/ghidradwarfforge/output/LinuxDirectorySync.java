package ghidradwarfforge.output;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Opened-directory identity and fsync for the audited Linux Intel LP64 host.
 * This is a mechanism, not filesystem admission or a power-loss guarantee.
 * A complete host must select/document its supported filesystem/storage contract.
 * Never follows a directory leaf link, substitutes a global sync, or ignores errors.
 */
public final class LinuxDirectorySync {
    private interface LibC extends Library {
        int open(byte[] path, int flags);
        int close(int fd);
        int statx(int fd, byte[] path, int flags, int mask, Pointer result);
        int fstatfs(int fd, Pointer result);
        int fsync(int fd);
    }

    /** Stable identity/mount facts; excludes changing free space and directory times. */
    public record Snapshot(String identity, long fileSystemType, String fileSystemId,
            long mountFlags, long maximumNameBytes) { }

    @FunctionalInterface interface Hook { void opened() throws IOException; }
    private static final Hook NO_HOOK = () -> { };
    private static final int FIELDS = 0x1101; // TYPE, INO, MNT_ID
    private final LibC libc;

    public LinuxDirectorySync() throws IOException {
        if (!System.getProperty("os.name").equals("Linux") || !Platform.isIntel() ||
                Native.LONG_SIZE != 8 || Native.POINTER_SIZE != 8 ||
                !Charset.forName(System.getProperty("sun.jnu.encoding")).equals(StandardCharsets.UTF_8)) {
            throw new IOException("Linux directory sync requires audited Intel LP64 libc and UTF-8 paths");
        }
        try { libc = Native.load("c", LibC.class); }
        catch (RuntimeException | LinkageError unavailable) {
            throw new IOException("Linux directory calls are unavailable", unavailable);
        }
    }

    public Snapshot inspect(Path directory, BooleanSupplier cancelled) throws IOException {
        return operate(directory, null, cancelled, NO_HOOK);
    }

    /** Caller supplies the observed directory/mount; a changed selection is refused. */
    public void sync(Path directory, Snapshot expected, BooleanSupplier cancelled) throws IOException {
        sync(directory, expected, cancelled, NO_HOOK);
    }

    void sync(Path directory, Snapshot expected, BooleanSupplier cancelled, Hook hook) throws IOException {
        operate(directory, Objects.requireNonNull(expected, "expected directory"), cancelled, hook);
    }

    private Snapshot operate(Path directory, Snapshot expected, BooleanSupplier cancelled, Hook hook)
            throws IOException {
        check(cancelled);
        byte[] path = pathBytes(directory);
        // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK; no creation/write flags.
        int fd = libc.open(path, 0x10000 | 0x20000 | 0x80000 | 0x800);
        if (fd < 0) throw error("open directory");
        try (var opened = new Descriptor(fd)) {
            check(cancelled);
            Snapshot before = observe(fd);
            require(expected == null || before.equals(expected), "directory identity or mount changed");
            require(before.identity().equals(identity(-100, path, 0x100)), "directory path changed after open");
            hook.opened();
            check(cancelled);
            require(before.identity().equals(identity(-100, path, 0x100)), "directory path changed before sync");
            if (expected != null) checked(libc.fsync(fd), "fsync directory");
            require(before.equals(observe(fd)), "directory identity or mount changed during sync");
            require(before.identity().equals(identity(-100, path, 0x100)), "directory path changed during sync");
            check(cancelled);
            return before;
        }
    }

    private Snapshot observe(int fd) throws IOException {
        String identity = identity(fd, new byte[] {0}, 0x1000);
        try (var buffer = new Memory(120)) {
            buffer.clear();
            checked(libc.fstatfs(fd, buffer), "fstatfs directory");
            long maximum = buffer.getLong(64);
            require(maximum > 0, "filesystem has no usable basename bound");
            return new Snapshot(identity, buffer.getLong(0),
                HexFormat.of().formatHex(buffer.getByteArray(56, 8)), buffer.getLong(80), maximum);
        }
    }

    private String identity(int fd, byte[] path, int flags) throws IOException {
        try (var buffer = new Memory(256)) {
            buffer.clear();
            checked(libc.statx(fd, path, flags, FIELDS, buffer), "statx directory");
            require((buffer.getInt(0) & FIELDS) == FIELDS, "directory identity/mount fields are unavailable");
            require((Short.toUnsignedInt(buffer.getShort(28)) & 0170000) == 0040000,
                "expected a non-link directory");
            return Integer.toUnsignedString(buffer.getInt(136)) + ":" +
                Integer.toUnsignedString(buffer.getInt(140)) + ":" +
                Long.toUnsignedString(buffer.getLong(32)) + "@" + Long.toUnsignedString(buffer.getLong(144));
        }
    }

    private final class Descriptor implements AutoCloseable {
        private final int fd;
        Descriptor(int fd) { this.fd = fd; }
        @Override public void close() throws IOException {
            // Do not retry close after EINTR: Linux has already released the descriptor.
            checked(libc.close(fd), "close directory");
        }
    }

    private static byte[] pathBytes(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        String text = absolute.toString();
        require(Path.of(text).equals(absolute), "directory path cannot be represented losslessly");
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, bytes.length + 1);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("directory operation cancelled");
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
    private static IOException error(String operation) {
        return new IOException("Linux " + operation + " failed (errno=" + Native.getLastError() + ")");
    }
    private static void checked(int result, String operation) throws IOException {
        if (result != 0) throw error(operation);
    }
}
