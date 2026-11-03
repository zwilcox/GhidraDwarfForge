package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Bounded, read-only backup-stream inventory for ordinary Windows files.
 * Security processing is disabled: this does NOT establish SACL absence or
 * replace privileged metadata admission. Payloads are skipped, never copied.
 * No privileges are enabled. Cancellation is checked between native calls.
 */
public final class WindowsBackupStreams {
    private interface Kernel extends StdCallLibrary {
        Pointer CreateFileW(WString path, int access, int sharing, Pointer security, int disposition, int flags, Pointer template);
        int CloseHandle(Pointer handle);
        int BackupRead(Pointer handle, Pointer buffer, int bytes, IntByReference read,
            int abort, int security, PointerByReference context);
        int BackupSeek(Pointer handle, int low, int high, IntByReference lowSkipped,
            IntByReference highSkipped, PointerByReference context);
    }

    public record Stream(int kind, int attributes, long bytes, String name) { }
    public record Inventory(WindowsFileMetadata.Facts facts, List<Stream> streams) {
        public Inventory { streams = List.copyOf(streams); }
    }

    private final WindowsFileMetadata metadata;
    private final Kernel kernel;

    public WindowsBackupStreams() throws IOException { this(new WindowsFileMetadata()); }

    WindowsBackupStreams(WindowsFileMetadata metadata) throws IOException {
        this.metadata = metadata; // Constructor of metadata checks the audited Windows64 ABI.
        try { kernel = Native.load("kernel32", Kernel.class); }
        catch (LinkageError | RuntimeException failure) {
            throw new IOException("Windows backup APIs are unavailable", failure);
        }
    }

    public Inventory inspect(Path path, BooleanSupplier cancelled) throws IOException {
        return inspect(path, cancelled, stream -> { });
    }

    Inventory inspect(Path path, BooleanSupplier cancelled, Consumer<Stream> observed) throws IOException {
        // This also enforces resolved local drive spelling and rejects reparse leaves.
        var expected = metadata.inspect(path, cancelled);
        check(cancelled);
        Pointer handle = kernel.CreateFileW(new WString("\\\\?\\" + path.toAbsolutePath()),
            0x80020000, 7, null, 3, 0x00200000, null);
        if (handle == null || Pointer.nativeValue(handle) == -1L) {
            throw new IOException("Windows backup CreateFileW failed (error=" + Native.getLastError() + ")");
        }
        try (var file = new Opened(handle)) {
            var result = inspectOpened(handle, expected.facts(), cancelled, observed);
            require(metadata.inspect(path, cancelled).equals(expected), "Windows backup selected path changed");
            return result;
        }
    }

    Inventory inspectOpened(Pointer handle, WindowsFileMetadata.Facts expected,
            BooleanSupplier cancelled) throws IOException {
        return inspectOpened(handle, expected, cancelled, stream -> { });
    }

    private Inventory inspectOpened(Pointer handle, WindowsFileMetadata.Facts expected,
            BooleanSupplier cancelled, Consumer<Stream> observed) throws IOException {
        require(metadata.facts(handle).equals(expected), "Windows backup opened identity changed");
        var streams = new ArrayList<Stream>();
        int nameBytes = 0;
        // Allocate more than sizeof(WIN32_STREAM_ID), but consume the on-wire
        // 20-byte prefix. sizeof includes padding and one placeholder WCHAR.
        try (var context = new Context(handle); var buffer = new Memory(65536)) {
            while (context.read(buffer, 20, true, cancelled)) {
                require(streams.size() < 4096, "Windows backup stream count exceeds bound");
                int kind = buffer.getInt(0);
                int attributes = buffer.getInt(4);
                long bytes = buffer.getLong(8);
                long length = Integer.toUnsignedLong(buffer.getInt(16));
                require(kind != 0 && bytes >= 0 && length <= 65534 && (length & 1) == 0,
                    "Windows backup stream header is invalid or exceeds bound");
                nameBytes += (int) length;
                require(nameBytes <= 1024 * 1024, "Windows backup stream names exceed bound");
                String name = "";
                if (length != 0) {
                    context.read(buffer, (int) length, false, cancelled);
                    name = StandardCharsets.UTF_16LE.newDecoder()
                        .decode(ByteBuffer.wrap(buffer.getByteArray(0, (int) length))).toString();
                    require(name.indexOf('\0') < 0, "Windows backup stream name contains NUL");
                }
                streams.add(new Stream(kind, attributes, bytes, name));
                observed.accept(streams.get(streams.size() - 1));
                context.skip(bytes, cancelled);
            }
        }
        check(cancelled);
        require(metadata.facts(handle).equals(expected), "Windows backup metadata changed during inventory");
        return new Inventory(expected, streams);
    }

    /** Initial attachment rejects EAs, object IDs and all other unhandled streams. */
    public static void requireOrdinaryData(Inventory inventory) throws IOException {
        var streams = inventory.streams();
        if (streams.isEmpty() && inventory.facts().bytes() == 0) return;
        require(streams.size() == 1, "Windows backup inventory contains unsupported metadata streams");
        var data = streams.get(0);
        require(data.kind() == 1 && data.attributes() == 0 && data.name().isEmpty() &&
            data.bytes() == inventory.facts().bytes(), "Windows backup inventory is not ordinary unnamed data");
    }

    private final class Context implements AutoCloseable {
        private final Pointer handle;
        private final PointerByReference context = new PointerByReference();
        private Context(Pointer handle) { this.handle = handle; }

        private boolean read(Memory buffer, int bytes, boolean eof, BooleanSupplier cancelled) throws IOException {
            int offset = 0;
            while (offset < bytes) {
                check(cancelled);
                var count = new IntByReference();
                success(kernel.BackupRead(handle, buffer.share(offset), bytes - offset, count, 0, 0, context), "BackupRead");
                int actual = count.getValue();
                if (actual == 0 && offset == 0 && eof) return false;
                require(actual > 0 && actual <= bytes - offset, "Windows backup stream is truncated");
                offset += actual;
            }
            return true;
        }

        private void skip(long bytes, BooleanSupplier cancelled) throws IOException {
            check(cancelled);
            if (bytes == 0) return;
            var low = new IntByReference();
            var high = new IntByReference();
            success(kernel.BackupSeek(handle, (int) bytes, (int) (bytes >>> 32), low, high, context), "BackupSeek");
            long skipped = Integer.toUnsignedLong(low.getValue()) | (Integer.toUnsignedLong(high.getValue()) << 32);
            require(skipped == bytes, "Windows backup seek was incomplete");
        }

        public void close() throws IOException {
            // Mandatory even after a failed read or cancellation. Never cancel cleanup.
            success(kernel.BackupRead(handle, null, 0, new IntByReference(), 1, 0, context), "BackupRead abort");
        }
    }

    private final class Opened implements AutoCloseable {
        private final Pointer handle;
        private Opened(Pointer handle) { this.handle = handle; }
        public void close() throws IOException { success(kernel.CloseHandle(handle), "CloseHandle"); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Windows backup inventory cancelled");
    }
    private static void success(int result, String operation) throws IOException {
        if (result == 0) throw new IOException("Windows " + operation + " failed (error=" + Native.getLastError() + ")");
    }
    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
