package ghidradwarfforge.output;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Whole-file lease whose verification cannot release or conflict with its own lock. */
final class BuildIdFileLock implements AutoCloseable {
    private interface LibC extends Library {
        int open(byte[] path, int flags, Object... mode);
        int fcntl(int fd, int command, Object... argument);
        int close(int fd);
    }

    private final Path path;
    private final byte[] magic;
    private final AttachmentOperation.Host host;
    private final AttachmentReceiptStore.Fingerprint fingerprint;
    private FileChannel channel;
    private FileLock windowsLock;
    private LibC libc;
    private int linuxDescriptor = -1;

    private BuildIdFileLock(Path path, byte[] magic, AttachmentOperation.Host host) throws IOException {
        this.path = path;
        this.magic = magic.clone();
        this.host = host;
        fingerprint = host.inspect(path);
        require(fingerprint.links() == 1, "build-ID lock must have one link");
    }

    static BuildIdFileLock acquire(Path path, byte[] magic, AttachmentOperation.Host host,
            BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var result = new BuildIdFileLock(path, magic, host);
        try {
            result.channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS);
            if (System.getProperty("os.name").equals("Linux")) result.acquireLinux();
            else if (Platform.isWindows()) {
                try { result.windowsLock = result.channel.tryLock(); }
                catch (OverlappingFileLockException busy) { throw new IOException("build-ID installation is busy", busy); }
                require(result.windowsLock != null, "build-ID installation is busy");
            }
            else throw new IOException("unsupported build-ID lock host");
            result.verify(cancelled);
            return result;
        }
        catch (IOException | RuntimeException | LinkageError failure) {
            try { result.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private void acquireLinux() throws IOException {
        // Audited by linux-build-id-lock-contract.c. Traditional POSIX process
        // locks are released by closing ANY descriptor for this inode, including
        // the metadata host's independent inspection handles. OFD locks retain
        // exclusion until this specific descriptor is closed and also conflict
        // with traditional POSIX locks held by older cooperating processes.
        require(Platform.isIntel() && Native.LONG_SIZE == 8 && Native.POINTER_SIZE == 8 &&
            Charset.forName(System.getProperty("sun.jnu.encoding")).equals(StandardCharsets.UTF_8),
            "Linux build-ID locking requires audited Intel LP64 and UTF-8 paths");
        try { libc = Native.load("c", LibC.class); }
        catch (RuntimeException | LinkageError unavailable) {
            throw new IOException("Linux build-ID locking libc is unavailable", unavailable);
        }
        byte[] encoded = path.toString().getBytes(StandardCharsets.UTF_8);
        byte[] terminated = Arrays.copyOf(encoded, encoded.length + 1);
        linuxDescriptor = libc.open(terminated, 2 | 0x20000 | 0x80000);
        if (linuxDescriptor < 0) throw new IOException("open build-ID lock failed errno=" + Native.getLastError());
        try (var record = new Memory(32)) {
            record.clear();
            record.setShort(0, (short) 1); // F_WRLCK; SEEK_SET/start/length/pid are zero.
            if (libc.fcntl(linuxDescriptor, 37, record) != 0) {
                int error = Native.getLastError();
                if (error == 11 || error == 13) throw new IOException("build-ID installation is busy");
                throw new IOException("F_OFD_SETLK build-ID lock failed errno=" + error);
            }
        }
    }

    void verify(BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        require(fingerprint.equals(host.inspect(path)), "build-ID lock identity or metadata changed");
        require(channel.size() == magic.length, "foreign or incomplete build-ID lock");
        // Windows exclusive byte locks reject a read through a second handle,
        // even in this process. Read only through the actual locking channel.
        ByteBuffer bytes = ByteBuffer.allocate(magic.length);
        while (bytes.hasRemaining()) {
            check(cancelled);
            int count = channel.read(bytes, bytes.position());
            require(count > 0, "build-ID lock read made no progress");
        }
        require(Arrays.equals(bytes.array(), magic) && channel.size() == magic.length,
            "foreign or incomplete build-ID lock");
        require(fingerprint.equals(host.inspect(path)), "build-ID lock identity or metadata changed");
        check(cancelled);
    }

    @Override public void close() throws IOException {
        try {
            try { if (windowsLock != null) windowsLock.release(); }
            finally { if (channel != null) channel.close(); }
        }
        finally {
            if (linuxDescriptor >= 0) {
                int descriptor = linuxDescriptor;
                linuxDescriptor = -1;
                if (libc.close(descriptor) != 0) {
                    throw new IOException("close build-ID lock failed errno=" + Native.getLastError());
                }
            }
        }
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("build-ID lock cancelled");
    }
}
