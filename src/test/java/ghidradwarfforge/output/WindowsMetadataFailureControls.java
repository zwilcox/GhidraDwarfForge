package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Isolated real-Windows forwarding controls. Malformed replies are injected, not kernel observations. */
public final class WindowsMetadataFailureControls {
    private record Case(String name, String diagnostic) { }
    private static final int LIMIT = 1024 * 1024;
    private static final List<Case> CASES = List.of(
        new Case("open-error", "CreateFileW failed (error=5)"),
        new Case("open-null", "CreateFileW failed (error=5)"),
        new Case("disk-type", "requires a disk file"),
        new Case("info-0-error", "GetFileInformationByHandleEx(0) failed (error=5)"),
        new Case("info-1-error", "GetFileInformationByHandleEx(1) failed (error=5)"),
        new Case("info-18-error", "GetFileInformationByHandleEx(18) failed (error=5)"),
        new Case("info-9-error", "GetFileInformationByHandleEx(9) failed (error=5)"),
        new Case("info-7-error", "GetFileInformationByHandleEx(7) failed (error=5)"),
        new Case("delete-pending", "rejects deleted, directory or reparse files"),
        new Case("directory", "rejects deleted, directory or reparse files"),
        new Case("reparse-attribute", "rejects deleted, directory or reparse files"),
        new Case("reparse-tag", "rejects deleted, directory or reparse files"),
        new Case("attribute-change", "Windows file attributes changed"),
        new Case("negative-size", "Windows file size exceeds bound"),
        new Case("security-error", "GetSecurityInfo failed (error=5)"),
        new Case("descriptor-missing", "Windows security descriptor is missing"),
        new Case("descriptor-invalid", "IsValidSecurityDescriptor failed (error=5)"),
        new Case("descriptor-short", "Windows security descriptor exceeds bound"),
        new Case("descriptor-long", "Windows security descriptor exceeds bound"),
        new Case("control-error", "GetSecurityDescriptorControl failed (error=5)"),
        new Case("descriptor-revision", "unsupported Windows descriptor format"),
        new Case("descriptor-absolute", "unsupported Windows descriptor format"),
        new Case("owner-missing", "missing Windows descriptor field"),
        new Case("owner-before", "Windows descriptor field exceeds allocation"),
        new Case("owner-after", "Windows descriptor field exceeds allocation"),
        new Case("sid-invalid", "IsValidSid failed (error=5)"),
        new Case("sid-short", "Windows SID exceeds bound"),
        new Case("sid-long", "Windows SID exceeds bound"),
        new Case("stream-empty-name", "invalid Windows stream name"),
        new Case("stream-odd-name", "invalid Windows stream name"),
        new Case("stream-long-name", "invalid Windows stream name"),
        new Case("stream-negative-size", "invalid or duplicate Windows stream"),
        new Case("stream-duplicate", "invalid or duplicate Windows stream"),
        new Case("stream-unaligned", "invalid Windows stream chain"),
        new Case("stream-short-next", "invalid Windows stream chain"),
        new Case("stream-long-next", "invalid Windows stream chain"),
        new Case("stream-excess-count", "Windows stream list exceeds bound"),
        new Case("stream-invalid-utf16", "Input length"),
        new Case("free-error-after-release", "Windows LocalFree failed"),
        new Case("close-error-after-release", "CloseHandle failed (error=5)"));

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("owned results directory required");
        // Construct the production adapter first: its actual Windows/x64 admission must pass.
        var metadata = new WindowsFileMetadata();
        Path root = Path.of(args[0]);
        Files.createDirectory(root);
        Path source = root.resolve("source");
        Files.writeString(source, "owned Windows metadata failure fixture");
        check(metadata, source); // Warm reflection, error classes and native bindings before handle accounting.
        long before = metadata.processHandleCount();
        var rows = check(metadata, source);
        long after = metadata.processHandleCount();
        require(before == after, "Windows process handles leaked");
        Files.writeString(root.resolve("result.json"), new Gson().toJson(Map.of(
            "status", "PASS_CONTROLLED_WINDOWS_FAILURES", "cases", rows,
            "handlesBefore", before, "handlesAfter", after,
            "scope", "real Windows x64 APIs with controlled replies; read-only inspection, no full host admission")));
        System.out.println("windows-metadata-failures=PASS cases=" + CASES.size());
    }

    private static List<Map<String, Object>> check(WindowsFileMetadata metadata, Path source) throws Exception {
        var baseline = metadata.inspect(source, () -> false);
        byte[] bytes = Files.readAllBytes(source);
        Field kernel = WindowsFileMetadata.class.getDeclaredField("kernel");
        Field security = WindowsFileMetadata.class.getDeclaredField("security");
        kernel.setAccessible(true);
        security.setAccessible(true);
        Object realKernel = kernel.get(metadata), realSecurity = security.get(metadata);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            var fault = new Fault(selected.name(), realKernel);
            kernel.set(metadata, wrapper(kernel, fault, realKernel));
            security.set(metadata, wrapper(security, fault, realSecurity));
            try {
                require(metadata.inspect(source, () -> false).equals(baseline), "forwarding baseline differs");
                fault.arm();
                IOException rejected;
                try {
                    metadata.inspect(source, () -> false);
                    throw new AssertionError("controlled reply accepted: " + selected.name());
                }
                catch (IOException expected) { rejected = expected; }
                require(rejected.getMessage() != null && rejected.getMessage().contains(selected.diagnostic()),
                    "wrong rejection for " + selected.name() + ": " + rejected);
                require(fault.hits == 1, "fault not reached exactly once: " + selected.name());
                fault.balanced();
                kernel.set(metadata, realKernel);
                security.set(metadata, realSecurity);
                require(metadata.inspect(source, () -> false).equals(baseline), "source metadata changed");
                require(Arrays.equals(bytes, Files.readAllBytes(source)), "source bytes changed");
                rows.add(Map.of("name", selected.name(), "faultHits", fault.hits,
                    "opened", fault.opened, "closed", fault.closed,
                    "allocated", fault.allocated, "freed", fault.freed,
                    "sourceUnchanged", true, "diagnostic", rejected.getMessage()));
            }
            finally {
                kernel.set(metadata, realKernel);
                security.set(metadata, realSecurity);
                fault.releaseLeftovers(); // A failed ledger assertion above remains a failure.
            }
        }
        return rows;
    }

    private static Object wrapper(Field field, Fault fault, Object real) {
        return Proxy.newProxyInstance(field.getType().getClassLoader(), new Class<?>[] {field.getType()},
            (proxy, method, args) -> fault.invoke(real, method, args));
    }

    private static final class Fault {
        final String name;
        final Object kernel;
        final HashSet<Pointer> handles = new HashSet<>(), allocations = new HashSet<>();
        boolean armed;
        int hits, opened, closed, allocated, freed;

        Fault(String name, Object kernel) {
            this.name = name;
            this.kernel = kernel;
        }

        void balanced() {
            require(handles.isEmpty() && opened == closed, "native file handle leaked: " + name);
            require(allocations.isEmpty() && allocated == freed, "native descriptor allocation leaked: " + name);
        }

        void arm() {
            balanced();
            hits = opened = closed = allocated = freed = 0;
            armed = true;
        }

        Object invoke(Object real, Method method, Object[] args) throws Throwable {
            String operation = method.getName();
            boolean injecting = armed && hits == 0;
            if (injecting && operation.equals("CreateFileW") && name.startsWith("open-")) {
                hits++;
                Native.setLastError(5);
                return name.equals("open-null") ? null : Pointer.createConstant(-1L);
            }
            if (injecting && operation.equals("GetSecurityInfo") &&
                    (name.equals("security-error") || name.equals("descriptor-missing"))) {
                // Do not call an allocating API then discard its owned output.
                hits++;
                return name.equals("security-error") ? 5 : 0;
            }
            if (injecting && operation.equals("GetFileInformationByHandleEx") &&
                    name.equals("info-" + args[1] + "-error")) return failure();
            Object result = call(real, method, args);
            track(operation, args, result);
            if (!injecting) return result;
            if (operation.equals("CloseHandle") && name.equals("close-error-after-release")) {
                require((int) result != 0, "real CloseHandle failed");
                return failure();
            }
            if (operation.equals("LocalFree") && name.equals("free-error-after-release")) {
                require(result == null, "real LocalFree failed");
                hits++;
                return args[0]; // Already released; the production owner must still report failure.
            }
            if (operation.equals("GetFileType") && name.equals("disk-type")) { hits++; return 2; }
            if (operation.equals("GetFileInformationByHandleEx") && (int) result != 0) {
                Pointer data = (Pointer) args[2];
                int kind = (int) args[1];
                boolean changed = true;
                if (kind == 1 && name.equals("delete-pending")) data.setByte(20, (byte) 1);
                else if (kind == 1 && name.equals("directory")) data.setByte(21, (byte) 1);
                else if (kind == 1 && name.equals("negative-size")) data.setLong(8, -1);
                else if (kind == 9 && name.equals("reparse-attribute")) data.setInt(0, data.getInt(0) | 0x400);
                else if (kind == 9 && name.equals("reparse-tag")) data.setInt(4, 1);
                else if (kind == 9 && name.equals("attribute-change")) data.setInt(0, data.getInt(0) ^ 0x20);
                else if (kind == 7 && name.startsWith("stream-")) stream(data, (int) args[3]);
                else changed = false;
                if (changed) hits++;
            }
            if (operation.equals("GetSecurityInfo") && (int) result == 0 && name.startsWith("owner-")) {
                Pointer base = ((PointerByReference) args[7]).getValue();
                ((PointerByReference) args[3]).setValue(switch (name) {
                    case "owner-missing" -> null;
                    case "owner-before" -> new Pointer(Pointer.nativeValue(base) - 1);
                    case "owner-after" -> new Pointer(Pointer.nativeValue(base) + LIMIT);
                    default -> throw new AssertionError(name);
                }); // Production bounds checks run before these values could be dereferenced.
                hits++;
            }
            if ((operation.equals("IsValidSecurityDescriptor") && name.equals("descriptor-invalid")) ||
                    (operation.equals("GetSecurityDescriptorControl") && name.equals("control-error")) ||
                    (operation.equals("IsValidSid") && name.equals("sid-invalid"))) {
                require((int) result != 0, "real security validation failed");
                return failure();
            }
            if (operation.equals("GetSecurityDescriptorLength") &&
                    (name.equals("descriptor-short") || name.equals("descriptor-long"))) {
                hits++;
                return name.equals("descriptor-short") ? 19 : LIMIT + 1;
            }
            if (operation.equals("GetLengthSid") && (name.equals("sid-short") || name.equals("sid-long"))) {
                hits++;
                return name.equals("sid-short") ? 7 : 69;
            }
            if (operation.equals("GetSecurityDescriptorControl") && (int) result != 0) {
                if (name.equals("descriptor-revision")) { ((Pointer) args[2]).setInt(0, 2); hits++; }
                if (name.equals("descriptor-absolute")) {
                    Pointer flags = (Pointer) args[1];
                    flags.setShort(0, (short) (flags.getShort(0) & ~0x8000));
                    hits++;
                }
            }
            return result;
        }

        private int failure() { hits++; Native.setLastError(5); return 0; }

        private void stream(Pointer data, int size) {
            require(size == LIMIT, "unexpected stream buffer size");
            data.clear(size);
            int count = name.equals("stream-excess-count") ? 1025 : name.equals("stream-duplicate") ? 2 : 1;
            for (int index = 0; index < count; index++) {
                int offset = index * 48;
                byte[] label = (name.equals("stream-duplicate") ? "::$DATA" : ":s" + index + ":$DATA")
                    .getBytes(StandardCharsets.UTF_16LE);
                require(label.length <= 24, "test stream record overflow");
                data.setInt(offset, index + 1 == count ? 0 : 48);
                data.setInt(offset + 4, label.length);
                data.setLong(offset + 8, 1);
                data.write(offset + 24, label, 0, label.length);
            }
            switch (name) {
                case "stream-empty-name" -> data.setInt(4, 0);
                case "stream-odd-name" -> data.setInt(4, 1);
                case "stream-long-name" -> data.setInt(4, LIMIT);
                case "stream-negative-size" -> data.setLong(8, -1);
                case "stream-unaligned" -> data.setInt(0, 49);
                case "stream-short-next" -> data.setInt(0, 8);
                case "stream-long-next" -> data.setInt(0, LIMIT);
                case "stream-invalid-utf16" -> { data.setInt(4, 2); data.setShort(24, (short) 0xd800); }
                case "stream-duplicate", "stream-excess-count" -> { }
                default -> throw new AssertionError(name);
            }
        }

        private void track(String operation, Object[] args, Object result) {
            if (operation.equals("CreateFileW") && result != null && Pointer.nativeValue((Pointer) result) != -1L) {
                require(handles.add((Pointer) result), "duplicate live native handle");
                opened++;
            }
            if (operation.equals("CloseHandle") && (int) result != 0) {
                require(handles.remove((Pointer) args[0]), "untracked native handle close");
                closed++;
            }
            if (operation.equals("GetSecurityInfo") && (int) result == 0) {
                Pointer allocation = ((PointerByReference) args[7]).getValue();
                require(allocation != null && allocations.add(allocation), "missing/duplicate native allocation");
                allocated++;
            }
            if (operation.equals("LocalFree") && result == null) {
                require(allocations.remove((Pointer) args[0]), "untracked native allocation release");
                freed++;
            }
        }

        void releaseLeftovers() throws Exception {
            for (Pointer handle : List.copyOf(handles)) release("CloseHandle", handle);
            for (Pointer allocation : List.copyOf(allocations)) release("LocalFree", allocation);
        }

        private void release(String operation, Pointer value) throws Exception {
            Method method = kernel.getClass().getInterfaces()[0].getDeclaredMethod(operation, Pointer.class);
            method.setAccessible(true);
            method.invoke(kernel, value);
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
