package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Opened-directory identity and FlushFileBuffers for Windows Intel 64-bit.
 * Not a complete filesystem admission or power-loss recovery contract. No volume
 * flush, privilege adjustment or fallback. Blocking filesystem calls cannot be
 * interrupted; cancellation is checked around calls. Rejects leaf reparse points;
 * the caller remains responsible for full traversal and transaction admission.
 */
public final class WindowsDirectorySync {
    private interface Kernel extends StdCallLibrary {
        Pointer CreateFileW(WString path, int access, int share, Pointer security,
            int disposition, int flags, Pointer template);
        int CloseHandle(Pointer handle);
        int GetFileType(Pointer handle);
        int GetFileInformationByHandleEx(Pointer handle, int kind, Pointer info, int bytes);
        int GetVolumeInformationByHandleW(Pointer handle, Pointer label, int labelUnits,
            Pointer serial, Pointer maximumNameUnits, Pointer flags, Pointer fileSystem, int fileSystemUnits);
        int FlushFileBuffers(Pointer handle);
    }

    public record Snapshot(String identity, long volumeSerial, long maximumNameUnits,
            long fileSystemFlags, String fileSystem) { }

    @FunctionalInterface interface Hook { void opened() throws IOException; }
    private static final Hook NO_HOOK = () -> { };
    private final Kernel kernel;

    public WindowsDirectorySync() throws IOException {
        require(Platform.isWindows() && Platform.isIntel() && Native.POINTER_SIZE == 8,
            "Windows directory sync requires the audited Intel 64-bit ABI");
        try { kernel = Native.load("kernel32", Kernel.class); }
        catch (RuntimeException | LinkageError unavailable) {
            throw new IOException("Windows directory APIs are unavailable", unavailable);
        }
    }

    public Snapshot inspect(Path directory, BooleanSupplier cancelled) throws IOException {
        return operate(directory, null, cancelled, NO_HOOK);
    }

    public void sync(Path directory, Snapshot expected, BooleanSupplier cancelled) throws IOException {
        sync(directory, expected, cancelled, NO_HOOK);
    }

    void sync(Path directory, Snapshot expected, BooleanSupplier cancelled, Hook hook) throws IOException {
        operate(directory, Objects.requireNonNull(expected, "expected directory"), cancelled, hook);
    }

    private Snapshot operate(Path directory, Snapshot expected, BooleanSupplier cancelled, Hook hook)
            throws IOException {
        check(cancelled);
        String path = selectedPath(directory);
        try (var opened = open(path, expected != null)) {
            check(cancelled);
            Snapshot before = observe(opened.handle);
            require(expected == null || before.equals(expected), "Windows directory identity or filesystem changed");
            require(before.equals(observePath(path)), "Windows directory path changed after open");
            hook.opened();
            check(cancelled);
            require(before.equals(observePath(path)), "Windows directory path changed before flush");
            if (expected != null) success(kernel.FlushFileBuffers(opened.handle), "FlushFileBuffers directory");
            require(before.equals(observe(opened.handle)), "Windows directory changed during flush");
            require(before.equals(observePath(path)), "Windows directory path changed during flush");
            check(cancelled);
            return before;
        }
    }

    private Snapshot observePath(String path) throws IOException {
        try (var opened = open(path, false)) { return observe(opened.handle); }
    }

    private Snapshot observe(Pointer handle) throws IOException {
        require(kernel.GetFileType(handle) == 1, "Windows directory requires a disk handle");
        try (var tag = new Memory(8); var id = new Memory(24); var serial = new Memory(4);
                var maximum = new Memory(4); var flags = new Memory(4); var name = new Memory(256)) {
            tag.clear(); id.clear(); serial.clear(); maximum.clear(); flags.clear(); name.clear();
            success(kernel.GetFileInformationByHandleEx(handle, 9, tag, 8), "FileAttributeTagInfo");
            require((tag.getInt(0) & 0x410) == 0x10 && tag.getInt(4) == 0,
                "Windows directory rejects non-directory and reparse handles");
            success(kernel.GetFileInformationByHandleEx(handle, 18, id, 24), "FileIdInfo directory");
            success(kernel.GetVolumeInformationByHandleW(handle, null, 0, serial, maximum, flags, name, 128),
                "GetVolumeInformationByHandleW");
            int end = 0;
            while (end < 256 && name.getShort(end) != 0) end += 2;
            require(end > 0 && end < 256, "Windows filesystem name exceeds bound");
            String fileSystem = StandardCharsets.UTF_16LE.newDecoder().decode(
                ByteBuffer.wrap(name.getByteArray(0, end))).toString();
            long maximumUnits = Integer.toUnsignedLong(maximum.getInt(0));
            require(maximumUnits > 0 && maximumUnits <= 32767, "Windows filename bound is unavailable");
            return new Snapshot(Long.toUnsignedString(id.getLong(0), 16) + ":" +
                HexFormat.of().formatHex(id.getByteArray(8, 16)), Integer.toUnsignedLong(serial.getInt(0)),
                maximumUnits, Integer.toUnsignedLong(flags.getInt(0)), fileSystem);
        }
    }

    private Opened open(String path, boolean write) throws IOException {
        // FILE_READ_ATTRIBUTES, optionally GENERIC_WRITE; shared read/write/delete;
        // OPEN_EXISTING and OPEN_REPARSE_POINT | BACKUP_SEMANTICS. No privilege enabling.
        Pointer handle = kernel.CreateFileW(new WString("\\\\?\\" + path), write ? 0x40000080 : 0x80,
            7, null, 3, 0x02200000, null);
        if (handle == null || Pointer.nativeValue(handle) == -1L) throw error("CreateFileW directory");
        return new Opened(handle);
    }

    private static String selectedPath(Path directory) throws IOException {
        Path absolute = directory.toAbsolutePath();
        String text = absolute.toString();
        require(text.matches("[A-Za-z]:\\\\.*") && text.indexOf(':', 2) < 0 && text.length() <= 32760 &&
            StandardCharsets.UTF_16LE.newEncoder().canEncode(text),
            "Windows directory requires a bounded drive path without alternate streams");
        for (Path component : absolute) {
            String name = component.toString();
            require(!name.equals(".") && !name.equals("..") && !name.endsWith(".") && !name.endsWith(" "),
                "Windows directory requires resolved traversal without ambiguous suffixes");
        }
        var attributes = Files.readAttributes(absolute, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        require(attributes.isDirectory() && !attributes.isSymbolicLink(), "Windows directory requires a non-link directory");
        return text;
    }

    private final class Opened implements AutoCloseable {
        private final Pointer handle;
        Opened(Pointer handle) { this.handle = handle; }
        @Override public void close() throws IOException { success(kernel.CloseHandle(handle), "CloseHandle directory"); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Windows directory operation cancelled");
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
    private static IOException error(String operation) {
        return new IOException("Windows " + operation + " failed (error=" + Native.getLastError() + ")");
    }
    private static void success(int result, String operation) throws IOException {
        if (result == 0) throw error(operation);
    }
}
