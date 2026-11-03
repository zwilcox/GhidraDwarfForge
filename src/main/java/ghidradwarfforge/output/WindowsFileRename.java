package ghidradwarfforge.output;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Windows opened-stage namespace primitive. Not a host admission/durability policy.
 * Uses one FileRenameInfo request: no copy/delete, delayed reboot, metadata merge,
 * readonly override or POSIX sharing bypass. The transaction owns all prior backup,
 * validation, metadata and durability obligations. Failure after the native call
 * may require reconciliation; do not infer an unchanged namespace from an error.
 */
public final class WindowsFileRename {
    private interface Kernel extends StdCallLibrary {
        Pointer CreateFileW(WString path, int access, int share, Pointer security,
            int disposition, int flags, Pointer template);
        int SetFileInformationByHandle(Pointer handle, int kind, Pointer data, int bytes);
        int CloseHandle(Pointer handle);
    }

    enum Boundary { OPENED, BEFORE_RENAME }
    @FunctionalInterface interface Hook { void at(Boundary point) throws IOException; }
    private static final Hook NO_HOOK = point -> { };
    private final WindowsFileMetadata metadata;
    private final Kernel kernel;

    public WindowsFileRename() throws IOException {
        metadata = new WindowsFileMetadata(); // Applies the audited Windows Intel 64-bit ABI guard.
        try { kernel = Native.load("kernel32", Kernel.class); }
        catch (RuntimeException | LinkageError unavailable) {
            throw new IOException("Windows rename APIs are unavailable", unavailable);
        }
    }

    public WindowsFileMetadata.Snapshot publishNew(Path stage, WindowsFileMetadata.Snapshot expectedStage,
            Path destination, BooleanSupplier cancelled) throws IOException {
        return rename(stage, expectedStage, destination, null, cancelled, NO_HOOK);
    }

    public WindowsFileMetadata.Snapshot replace(Path stage, WindowsFileMetadata.Snapshot expectedStage,
            Path destination, WindowsFileMetadata.Snapshot expectedDestination, BooleanSupplier cancelled)
            throws IOException {
        return rename(stage, expectedStage, destination, Objects.requireNonNull(expectedDestination),
            cancelled, NO_HOOK);
    }

    WindowsFileMetadata.Snapshot rename(Path stage, WindowsFileMetadata.Snapshot expectedStage,
            Path destination, WindowsFileMetadata.Snapshot expectedDestination, BooleanSupplier cancelled,
            Hook hook) throws IOException {
        Objects.requireNonNull(expectedStage, "expected stage");
        check(cancelled);
        String source = selectedPath(stage);
        String target = selectedPath(destination);
        require(expectedStage.facts().links() == 1, "Windows rename rejects multiply linked stages");
        require(metadata.inspect(stage, cancelled).equals(expectedStage), "Windows rename stage changed");
        checkDestination(stage, expectedStage, destination, expectedDestination, cancelled);
        Pointer handle = kernel.CreateFileW(new WString("\\\\?\\" + source), 0x10080, 7, null, 3, 0x02200000, null);
        // DELETE | FILE_READ_ATTRIBUTES, all sharing, OPEN_EXISTING, OPEN_REPARSE_POINT/BACKUP_SEMANTICS.
        if (handle == null || Pointer.nativeValue(handle) == -1L) throw error("CreateFileW stage");
        try (var opened = new Opened(handle)) {
            require(metadata.facts(handle).equals(expectedStage.facts()), "Windows opened rename stage changed");
            hook.at(Boundary.OPENED);
            check(cancelled);
            require(metadata.inspect(stage, cancelled).equals(expectedStage), "Windows rename stage path changed");
            checkDestination(stage, expectedStage, destination, expectedDestination, cancelled);
            byte[] name = ("\\\\?\\" + target).getBytes(StandardCharsets.UTF_16LE);
            require(name.length <= 65532, "Windows rename destination exceeds bound");
            try (var data = new Memory(Math.max(32, 20 + name.length + 2))) {
                data.clear();
                data.setByte(0, (byte) (expectedDestination == null ? 0 : 1));
                // RootDirectory remains NULL. FileNameLength is bytes, not WCHAR count.
                data.setInt(16, name.length);
                data.write(20, name, 0, name.length);
                check(cancelled);
                hook.at(Boundary.BEFORE_RENAME);
                success(kernel.SetFileInformationByHandle(handle, 3, data, (int) data.size()), "FileRenameInfo");
            }
            // Finish identity/readback even if cancellation arrives after publication.
            var installed = metadata.inspect(destination, () -> false);
            require(installed.facts().identity().equals(expectedStage.facts().identity()) &&
                installed.facts().links() == 1 && installed.facts().bytes() == expectedStage.facts().bytes(),
                "Windows renamed file differs from its owned stage");
            require(installed.preservation().equals(expectedStage.preservation()) &&
                installed.dataStreams().equals(expectedStage.dataStreams()),
                "Windows rename changed supported preservation metadata");
            require(metadata.facts(handle).equals(installed.facts()), "Windows renamed handle/path differs");
            absent(stage);
            return installed;
        }
    }

    private void checkDestination(Path stage, WindowsFileMetadata.Snapshot expectedStage,
            Path destination, WindowsFileMetadata.Snapshot expected, BooleanSupplier cancelled) throws IOException {
        if (expected == null) { absent(destination); return; }
        require(expected.facts().links() == 1, "Windows rename rejects multiply linked targets");
        require(!expected.facts().identity().equals(expectedStage.facts().identity()) &&
            !Files.isSameFile(stage, destination), "Windows rename target aliases stage");
        require(metadata.inspect(destination, cancelled).equals(expected), "Windows rename target changed");
    }

    private static String selectedPath(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        String text = absolute.toString();
        require(text.matches("[A-Za-z]:\\\\.*") && text.indexOf(':', 2) < 0,
            "Windows rename requires a drive path without alternate streams");
        for (Path component : absolute) {
            String name = component.toString();
            require(!name.endsWith(".") && !name.endsWith(" ") && !name.equals(".."),
                "Windows rename requires resolved traversal without ambiguous suffixes");
        }
        return text;
    }

    private static void absent(Path path) throws IOException {
        try { Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); }
        catch (NoSuchFileException missing) { return; }
        throw new IOException("Windows rename requires an absent path: " + path);
    }

    private final class Opened implements AutoCloseable {
        private final Pointer handle;
        Opened(Pointer handle) { this.handle = handle; }
        @Override public void close() throws IOException { success(kernel.CloseHandle(handle), "CloseHandle stage"); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("Windows rename cancelled");
    }
    private static void require(boolean value, String message) throws IOException {
        if (!value) throw new IOException(message);
    }
    private static IOException error(String operation) {
        return new IOException("Windows rename " + operation + " failed (error=" + Native.getLastError() + ")");
    }
    private static void success(int result, String operation) throws IOException {
        if (result == 0) throw error(operation);
    }
}
