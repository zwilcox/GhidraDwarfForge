package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Actual Windows handles with single controlled replies; malformed buffers are not kernel observations. */
public final class WindowsDirectoryFailureControls {
    private record Case(String name, String diagnostic, int opens) { }
    private static final List<Case> CASES = List.of(
        new Case("open-error", "CreateFileW directory failed (error=5)", 0),
        new Case("open-null", "CreateFileW directory failed (error=5)", 0),
        new Case("disk-type", "requires a disk handle", 1),
        new Case("tag-error", "FileAttributeTagInfo failed (error=5)", 1),
        new Case("id-error", "FileIdInfo directory failed (error=5)", 1),
        new Case("non-directory", "rejects non-directory and reparse handles", 1),
        new Case("reparse-attribute", "rejects non-directory and reparse handles", 1),
        new Case("reparse-tag", "rejects non-directory and reparse handles", 1),
        new Case("volume-error", "GetVolumeInformationByHandleW failed (error=5)", 1),
        new Case("filesystem-empty", "filesystem name exceeds bound", 1),
        new Case("filesystem-unterminated", "filesystem name exceeds bound", 1),
        new Case("filesystem-invalid-utf16", "Input length", 1),
        new Case("maximum-zero", "filename bound is unavailable", 1),
        new Case("maximum-large", "filename bound is unavailable", 1),
        new Case("maximum-unsigned", "filename bound is unavailable", 1),
        new Case("path-query-error", "GetFinalPathNameByHandleW size failed (error=5)", 1),
        new Case("path-capacity-small", "final volume path exceeds bound", 1),
        new Case("path-capacity-large", "final volume path exceeds bound", 1),
        new Case("path-capacity-unsigned", "final volume path exceeds bound", 1),
        new Case("path-read-error", "GetFinalPathNameByHandleW failed (error=5)", 1),
        new Case("path-length-short", "final volume path changed or exceeds bound", 1),
        new Case("path-length-capacity", "final volume path changed or exceeds bound", 1),
        new Case("path-length-unsigned", "final volume path changed or exceeds bound", 1),
        new Case("path-terminator", "final volume path changed or exceeds bound", 1),
        new Case("path-embedded-null", "final path requires a volume GUID root", 1),
        new Case("path-prefix", "final path requires a volume GUID root", 1),
        new Case("path-brace", "final path requires a volume GUID root", 1),
        new Case("path-slash", "final path requires a volume GUID root", 1),
        new Case("path-guid", "final path requires a volume GUID root", 1),
        new Case("path-invalid-utf16", "Input length", 1),
        new Case("drive-low", "volume drive type is unavailable", 1),
        new Case("drive-high", "volume drive type is unavailable", 1),
        new Case("root-open-error", "CreateFileW directory failed (error=5)", 1),
        new Case("root-disk-type", "volume root requires a disk directory", 2),
        new Case("root-tag-error", "FileAttributeTagInfo volume root failed (error=5)", 2),
        new Case("root-id-error", "FileIdInfo volume root failed (error=5)", 2),
        new Case("root-non-directory", "volume root rejects reparse and non-directory handles", 2),
        new Case("root-reparse-attribute", "volume root rejects reparse and non-directory handles", 2),
        new Case("root-reparse-tag", "volume root rejects reparse and non-directory handles", 2),
        new Case("root-identity", "resolved volume root identity differs", 2),
        new Case("identity-1", "directory identity or filesystem changed", 2),
        new Case("identity-2", "directory path changed after open", 4),
        new Case("identity-3", "directory path changed before flush", 6),
        new Case("identity-4", "directory changed during flush", 7),
        new Case("identity-5", "directory path changed during flush", 9),
        new Case("flush-error", "FlushFileBuffers directory failed (error=5)", 6),
        new Case("close-error-after-release", "CloseHandle directory failed (error=5)", 2));

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("owned results directory required");
        var sync = new WindowsDirectorySync(); // Reject non-Windows before creating any fixture.
        var metadata = new WindowsFileMetadata();
        Path root = Path.of(args[0]);
        Files.createDirectory(root);
        Path directory = Files.createDirectory(root.resolve("owned"));
        Path sentinel = directory.resolve("sentinel");
        Files.writeString(sentinel, "owned directory failure fixture");
        check(sync, directory, sentinel);
        long before = metadata.processHandleCount();
        var rows = check(sync, directory, sentinel);
        long after = metadata.processHandleCount();
        require(before == after, "Windows process handles leaked");
        Files.writeString(root.resolve("result.json"), new Gson().toJson(Map.of(
            "status", "PASS_CONTROLLED_WINDOWS_DIRECTORY_FAILURES", "cases", rows,
            "handlesBefore", before, "handlesAfter", after,
            "scope", "actual Windows x64 handles with controlled replies; owned directory only, no volume flush")));
        System.out.println("windows-directory-failures=PASS cases=" + CASES.size());
    }

    private static List<Map<String, Object>> check(WindowsDirectorySync sync, Path directory, Path sentinel)
            throws Exception {
        var baseline = sync.inspect(directory, () -> false);
        byte[] bytes = Files.readAllBytes(sentinel);
        Field kernel = WindowsDirectorySync.class.getDeclaredField("kernel");
        kernel.setAccessible(true);
        Object real = kernel.get(sync);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            var fault = new Fault(selected.name(), real);
            Object wrapper = Proxy.newProxyInstance(kernel.getType().getClassLoader(),
                new Class<?>[] {kernel.getType()}, (proxy, method, args) -> fault.invoke(method, args));
            kernel.set(sync, wrapper);
            try {
                require(sync.inspect(directory, () -> false).equals(baseline), "forwarding baseline differs");
                fault.arm();
                IOException rejected;
                try {
                    // Only the expected-identity and flush-error controls need a writable owned handle.
                    if (selected.name().equals("identity-1") || selected.name().equals("flush-error")) {
                        sync.sync(directory, baseline, () -> false);
                    }
                    else sync.inspect(directory, () -> false);
                    throw new AssertionError("controlled reply accepted: " + selected.name());
                }
                catch (IOException expected) { rejected = expected; }
                require(rejected.getMessage() != null && rejected.getMessage().contains(selected.diagnostic()),
                    "wrong rejection for " + selected.name() + ": " + rejected);
                require(fault.hits == 1 && fault.opened == selected.opens(),
                    "unexpected fault or open count: " + selected.name() + " " + fault.hits + "/" + fault.opened);
                fault.balanced();
                kernel.set(sync, real);
                require(sync.inspect(directory, () -> false).equals(baseline), "directory identity changed");
                sync.sync(directory, baseline, () -> false); // Real, uninjected retry on the owned directory.
                require(sync.inspect(directory, () -> false).equals(baseline), "retry changed directory identity");
                require(Arrays.equals(bytes, Files.readAllBytes(sentinel)), "sentinel contents changed");
                rows.add(Map.of("name", selected.name(), "faultHits", fault.hits,
                    "opened", fault.opened, "closed", fault.closed, "directoryUnchanged", true,
                    "sentinelUnchanged", true, "retryPassed", true, "diagnostic", rejected.getMessage()));
            }
            finally {
                kernel.set(sync, real);
                fault.releaseLeftovers(); // Cleanup cannot turn a failed resource assertion into a pass.
            }
        }
        return rows;
    }

    private static final class Fault {
        final String name;
        final Object real;
        final HashMap<Pointer, Boolean> handles = new HashMap<>();
        boolean armed;
        int hits, opened, closed, observations;

        Fault(String name, Object real) { this.name = name; this.real = real; }

        void balanced() { require(handles.isEmpty() && opened == closed, "native directory handle leaked: " + name); }

        void arm() { balanced(); hits = opened = closed = observations = 0; armed = true; }

        Object invoke(Method method, Object[] args) throws Throwable {
            String operation = method.getName();
            boolean injecting = armed && hits == 0;
            boolean root = operation.equals("CreateFileW")
                ? args[0].toString().startsWith("\\\\?\\Volume{")
                : args[0] instanceof Pointer && Boolean.TRUE.equals(handles.get((Pointer) args[0]));
            String prefix = root ? "root-" : "";
            if (operation.equals("CreateFileW") && root) {
                require((int) args[1] == 0x80 && args[0].toString().endsWith("\\"),
                    "volume root must be a read-only directory handle");
            }
            if (operation.equals("FlushFileBuffers")) require(!root, "must never flush the volume root");
            if (injecting && operation.equals("CreateFileW") &&
                    (name.equals(prefix + "open-error") || name.equals("open-null") && !root)) {
                hits++; Native.setLastError(5);
                return name.equals("open-null") ? null : Pointer.createConstant(-1L);
            }
            if (injecting && operation.equals("GetFileInformationByHandleEx") &&
                    ((int) args[1] == 9 && name.equals(prefix + "tag-error") ||
                     (int) args[1] == 18 && name.equals(prefix + "id-error"))) return failure();
            if (injecting && operation.equals("GetVolumeInformationByHandleW") && name.equals("volume-error")) {
                return failure();
            }
            if (injecting && operation.equals("FlushFileBuffers") && name.equals("flush-error")) return failure();
            if (injecting && operation.equals("GetFinalPathNameByHandleW") &&
                    name.equals(args[1] == null ? "path-query-error" : "path-read-error")) return failure();
            Object result = call(real, method, args);
            if (operation.equals("CreateFileW") && result != null && Pointer.nativeValue((Pointer) result) != -1L) {
                require(handles.putIfAbsent((Pointer) result, root) == null, "duplicate live handle");
                opened++;
            }
            if (operation.equals("CloseHandle") && (int) result != 0) {
                require(handles.remove((Pointer) args[0]) != null, "untracked close"); closed++;
            }
            if (!injecting) return result;
            if (operation.equals("CloseHandle") && name.equals("close-error-after-release")) {
                require((int) result != 0, "real close failed"); return failure();
            }
            if (operation.equals("GetFileType") && name.equals(prefix + "disk-type")) { hits++; return 2; }
            if (operation.equals("GetFileInformationByHandleEx") && (int) result != 0) {
                Pointer data = (Pointer) args[2];
                int kind = (int) args[1];
                boolean changed = true;
                if (kind == 9 && name.equals(prefix + "non-directory")) data.setInt(0, data.getInt(0) & ~0x10);
                else if (kind == 9 && name.equals(prefix + "reparse-attribute")) data.setInt(0, data.getInt(0) | 0x400);
                else if (kind == 9 && name.equals(prefix + "reparse-tag")) data.setInt(4, 1);
                else if (kind == 18 && root && name.equals("root-identity")) data.setLong(0, data.getLong(0) ^ 1);
                else if (kind == 18 && !root && name.equals("identity-" + (++observations))) {
                    data.setByte(8, (byte) (data.getByte(8) ^ 1)); // File ID only; retain real volume identity.
                }
                else changed = false;
                if (changed) hits++;
            }
            if (operation.equals("GetVolumeInformationByHandleW") && (int) result != 0 &&
                    (name.startsWith("filesystem-") || name.startsWith("maximum-"))) {
                Pointer data = (Pointer) args[6];
                require((int) args[7] == 128, "unexpected filesystem buffer size");
                switch (name) {
                    case "filesystem-empty" -> data.setShort(0, (short) 0);
                    case "filesystem-unterminated" -> { for (int i = 0; i < 128; i++) data.setShort(i * 2, (short) 'x'); }
                    case "filesystem-invalid-utf16" -> { data.setShort(0, (short) 0xd800); data.setShort(2, (short) 0); }
                    case "maximum-zero" -> ((Pointer) args[4]).setInt(0, 0);
                    case "maximum-large" -> ((Pointer) args[4]).setInt(0, 32768);
                    case "maximum-unsigned" -> ((Pointer) args[4]).setInt(0, -1);
                    default -> throw new AssertionError(name);
                }
                hits++;
            }
            if (operation.equals("GetFinalPathNameByHandleW") && name.startsWith("path-")) {
                require((int) result > 0, "real final path query failed");
                if (args[1] == null && name.startsWith("path-capacity-")) {
                    hits++;
                    return switch (name) {
                        case "path-capacity-small" -> 49;
                        case "path-capacity-large" -> 32769;
                        case "path-capacity-unsigned" -> -1;
                        default -> throw new AssertionError(name);
                    };
                }
                if (args[1] != null) {
                    int length = (int) result, capacity = (int) args[2];
                    require(length >= 49 && length < capacity, "unexpected real final path length");
                    Pointer data = (Pointer) args[1];
                    hits++;
                    switch (name) {
                        case "path-length-short" -> { return 48; }
                        case "path-length-capacity" -> { return capacity; }
                        case "path-length-unsigned" -> { return -1; }
                        case "path-terminator" -> data.setShort(length * 2L, (short) 'x');
                        case "path-embedded-null" -> data.setShort(22, (short) 0);
                        case "path-prefix" -> data.setShort(0, (short) 'x');
                        case "path-brace" -> data.setShort(94, (short) 'x');
                        case "path-slash" -> data.setShort(96, (short) 'x');
                        case "path-guid" -> data.setShort(22, (short) 'z');
                        case "path-invalid-utf16" -> data.setShort(22, (short) 0xd800);
                        default -> throw new AssertionError(name);
                    }
                }
            }
            if (operation.equals("GetDriveTypeW") && (name.equals("drive-low") || name.equals("drive-high"))) {
                hits++; return name.equals("drive-low") ? 1 : 7;
            }
            return result;
        }

        private int failure() { hits++; Native.setLastError(5); return 0; }

        void releaseLeftovers() throws Exception {
            Method close = real.getClass().getInterfaces()[0].getDeclaredMethod("CloseHandle", Pointer.class);
            close.setAccessible(true);
            for (Pointer handle : List.copyOf(handles.keySet())) close.invoke(real, handle);
        }
    }

    private static Object call(Object real, Method method, Object[] args) throws Throwable {
        method.setAccessible(true);
        try { return method.invoke(real, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
