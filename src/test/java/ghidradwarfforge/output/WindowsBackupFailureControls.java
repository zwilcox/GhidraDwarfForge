package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

/** Real Windows backup contexts with controlled replies; no backup payload or security writes. */
public final class WindowsBackupFailureControls {
    private record Case(String name, String diagnostic) { }
    private static final List<Case> CASES = List.of(
        new Case("open-error", "CreateFileW failed (error=5)"),
        new Case("open-null", "CreateFileW failed (error=5)"),
        new Case("read-error", "BackupRead failed (error=5)"),
        new Case("read-negative", "stream is truncated"),
        new Case("read-excess", "stream is truncated"),
        new Case("header-zero-kind", "header is invalid or exceeds bound"),
        new Case("header-negative-size", "header is invalid or exceeds bound"),
        new Case("header-name-large", "header is invalid or exceeds bound"),
        new Case("header-name-odd", "header is invalid or exceeds bound"),
        new Case("header-name-unsigned", "header is invalid or exceeds bound"),
        new Case("name-zero-count", "stream is truncated"),
        new Case("name-nul", "stream name contains NUL"),
        new Case("name-invalid-utf16", "Input length"),
        new Case("partial-header-eof", "stream is truncated"),
        new Case("seek-error", "BackupSeek failed (error=5)"),
        new Case("seek-low-mismatch", "seek was incomplete"),
        new Case("seek-high-mismatch", "seek was incomplete"),
        new Case("abort-error-after-release", "BackupRead abort failed (error=5)"),
        new Case("close-error-after-release", "CloseHandle failed (error=5)"),
        new Case("cancel-after-header", "backup inventory cancelled"));

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("owned results and input directories required");
        var metadata = new WindowsFileMetadata(); // Actual host/ABI admission before any injected replies.
        var backup = new WindowsBackupStreams(metadata);
        Path root = Path.of(args[0]);
        Files.createDirectory(root);
        // Python creates and hashes the alternate stream: Windows NIO rejects colon paths.
        Path inputs = Path.of(args[1]);
        Path source = inputs.resolve("source"), named = inputs.resolve("named-source"), empty = inputs.resolve("empty");
        WindowsBackupStreams.requireOrdinaryData(backup.inspect(source, () -> false));
        WindowsBackupStreams.requireOrdinaryData(backup.inspect(empty, () -> false));
        require(backup.inspect(named, () -> false).streams().stream().anyMatch(s -> !s.name().isEmpty()),
            "named-stream fixture was not observed by native backup APIs");
        check(backup, metadata, source, named);
        long before = metadata.processHandleCount();
        var rows = check(backup, metadata, source, named);
        long after = metadata.processHandleCount();
        require(before == after, "Windows backup process handles leaked");
        Files.writeString(root.resolve("result.json"), new Gson().toJson(Map.of(
            "status", "PASS_CONTROLLED_WINDOWS_BACKUP_FAILURES", "cases", rows,
            "handlesBefore", before, "handlesAfter", after, "fragmentedReadPassed", true,
            "emptyDataPassed", true, "namedStreamObserved", true,
            "scope", "Real Windows handles and backup contexts; controlled malformed replies and buffered short reads; read-only fixtures")));
        System.out.println("windows-backup-failures=PASS cases=" + CASES.size());
    }

    private static List<Map<String, Object>> check(WindowsBackupStreams backup, WindowsFileMetadata metadata,
            Path source, Path named) throws Exception {
        Field field = WindowsBackupStreams.class.getDeclaredField("kernel");
        field.setAccessible(true);
        Object real = field.get(backup);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            Path path = selected.name().startsWith("name-") ? named : source;
            var baseline = backup.inspect(path, () -> false);
            var facts = metadata.inspect(path, () -> false);
            byte[] bytes = Files.readAllBytes(path);
            var fault = new Fault(selected.name(), real);
            field.set(backup, wrapper(field, fault));
            try {
                require(backup.inspect(path, () -> false).equals(baseline), "forwarding backup inventory differs");
                fault.arm();
                RuntimeException cancelled = null;
                IOException failure = null;
                try {
                    backup.inspect(path, () -> fault.cancelled, stream -> {
                        if (selected.name().equals("cancel-after-header")) {
                            fault.hits++;
                            fault.cancelled = true;
                        }
                    });
                    throw new AssertionError("controlled backup reply accepted: " + selected.name());
                }
                catch (CancellationException expected) { cancelled = expected; }
                catch (IOException expected) { failure = expected; }
                require((cancelled != null) == selected.name().equals("cancel-after-header"), "wrong failure type");
                String diagnostic = (cancelled != null ? cancelled : failure).getMessage();
                require(diagnostic != null && diagnostic.contains(selected.diagnostic()),
                    "wrong backup rejection for " + selected.name() + ": " + diagnostic);
                require(fault.hits == 1, "backup fault not reached exactly once: " + selected.name());
                fault.balanced();
                require(fault.aborts == (selected.name().startsWith("open-") ? 0 : 1), "backup abort was not mandatory");
                field.set(backup, real);
                require(backup.inspect(path, () -> false).equals(baseline), "backup retry differs");
                require(metadata.inspect(path, () -> false).equals(facts), "backup source metadata changed");
                require(Arrays.equals(bytes, Files.readAllBytes(path)), "backup source payload changed");
                rows.add(Map.of("name", selected.name(), "faultHits", fault.hits,
                    "opened", fault.opened, "closed", fault.closed, "aborts", fault.aborts,
                    "contextReleased", true, "sourceUnchanged", true, "retryPassed", true,
                    "diagnostic", diagnostic));
            }
            finally {
                field.set(backup, real);
                fault.releaseLeftovers();
            }
        }
        // Split bytes actually read from Windows into bounded replies without changing their order.
        var baseline = backup.inspect(named, () -> false);
        var fragmented = new Fault("fragmented", real);
        fragmented.arm();
        field.set(backup, wrapper(field, fragmented));
        try {
            require(backup.inspect(named, () -> false).equals(baseline), "short replies changed the native inventory");
            require(fragmented.fragments > 1 && fragmented.aborts == 1, "fragmented native read not exercised");
            fragmented.balanced();
        }
        finally { field.set(backup, real); fragmented.releaseLeftovers(); }
        return rows;
    }

    private static Object wrapper(Field field, Fault fault) {
        return Proxy.newProxyInstance(field.getType().getClassLoader(), new Class<?>[] {field.getType()},
            (proxy, method, args) -> fault.invoke(method, args));
    }

    private static final class Fault {
        final String name;
        final Object real;
        final HashSet<Pointer> handles = new HashSet<>();
        boolean armed, cancelled, contextLive;
        int hits, opened, closed, aborts, nameBytes, fragments;
        Pointer contextHandle;
        PointerByReference context;
        byte[] pending;
        int pendingOffset;

        Fault(String name, Object real) { this.name = name; this.real = real; }
        void arm() {
            balanced();
            armed = true;
            hits = opened = closed = aborts = nameBytes = 0;
            context = null;
            contextHandle = null;
            pending = null;
        }
        void balanced() {
            require(handles.isEmpty() && opened == closed && !contextLive,
                "backup native lifetime was not balanced: " + name);
        }

        Object invoke(Method method, Object[] args) throws Throwable {
            String operation = method.getName();
            boolean injecting = armed && hits == 0;
            if (injecting && operation.equals("CreateFileW") && name.startsWith("open-")) {
                hits++;
                Native.setLastError(5);
                return name.equals("open-null") ? null : Pointer.createConstant(-1L);
            }
            boolean reading = operation.equals("BackupRead") && (int) args[4] == 0;
            if (reading && pending != null) {
                if (name.equals("partial-header-eof")) {
                    ((IntByReference) args[3]).setValue(0);
                    pending = null;
                    hits++;
                    return 1;
                }
                return fragment(args);
            }
            Object result = call(method, args);
            if (operation.equals("CreateFileW") && result != null && Pointer.nativeValue((Pointer) result) != -1L) {
                require(handles.add((Pointer) result), "duplicate backup handle");
                opened++;
            }
            if (operation.equals("CloseHandle") && (int) result != 0) {
                require(handles.remove((Pointer) args[0]), "untracked backup close");
                closed++;
                if (injecting && name.equals("close-error-after-release")) return failure();
            }
            if (operation.equals("BackupRead")) {
                var reference = (PointerByReference) args[6];
                if ((int) args[4] != 0) {
                    require(context == reference && (int) result != 0, "real backup abort failed or changed context");
                    contextLive = false;
                    aborts++;
                    if (injecting && name.equals("abort-error-after-release")) return failure();
                }
                else {
                    require(context == null || context == reference, "backup context reference changed");
                    context = reference;
                    contextHandle = (Pointer) args[0];
                    contextLive |= reference.getValue() != null;
                    if (injecting) return read(args, result);
                }
            }
            if (injecting && operation.equals("BackupSeek")) {
                require((int) result != 0, "real backup seek failed");
                if (name.equals("seek-error")) return failure();
                if (name.equals("seek-low-mismatch") || name.equals("seek-high-mismatch")) {
                    var skipped = (IntByReference) args[name.equals("seek-low-mismatch") ? 3 : 4];
                    skipped.setValue(skipped.getValue() ^ 1);
                    hits++;
                }
            }
            return result;
        }

        private Object read(Object[] args, Object result) {
            require((int) result != 0, "real backup read failed");
            var count = (IntByReference) args[3];
            int actual = count.getValue();
            if (actual == 0) return result;
            Pointer buffer = (Pointer) args[1];
            if (name.equals("fragmented") || name.equals("partial-header-eof")) {
                pending = buffer.getByteArray(0, actual);
                pendingOffset = 0;
                return fragment(args);
            }
            boolean isName = nameBytes != 0;
            if (!isName) {
                require(actual == 20, "fault fixture requires a complete native header");
                nameBytes = buffer.getInt(16);
            }
            else {
                require(actual == nameBytes, "fault fixture requires a complete native stream name");
                nameBytes = 0;
            }
            if (name.equals("read-error")) return failure();
            boolean changed = true;
            switch (name) {
                case "read-negative" -> count.setValue(-1);
                case "read-excess" -> count.setValue((int) args[2] + 1);
                case "header-zero-kind" -> buffer.setInt(0, 0);
                case "header-negative-size" -> buffer.setLong(8, -1);
                case "header-name-large" -> buffer.setInt(16, 65536);
                case "header-name-odd" -> buffer.setInt(16, 1);
                case "header-name-unsigned" -> buffer.setInt(16, -1);
                case "name-zero-count" -> { if (isName) count.setValue(0); else changed = false; }
                case "name-nul" -> { if (isName) buffer.setShort(0, (short) 0); else changed = false; }
                case "name-invalid-utf16" -> { if (isName) buffer.setShort(actual - 2, (short) 0xd800); else changed = false; }
                default -> changed = false;
            }
            if (changed) hits++;
            return result;
        }

        private int fragment(Object[] args) {
            int length = Math.min(7, Math.min((int) args[2], pending.length - pendingOffset));
            ((Pointer) args[1]).write(0, pending, pendingOffset, length);
            ((IntByReference) args[3]).setValue(length);
            pendingOffset += length;
            fragments++;
            if (pendingOffset == pending.length) pending = null;
            return 1;
        }

        private int failure() { hits++; Native.setLastError(5); return 0; }

        private Object call(Method method, Object[] args) throws Throwable {
            method.setAccessible(true);
            try { return method.invoke(real, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }

        void releaseLeftovers() throws Exception {
            if (contextLive) {
                Method abort = real.getClass().getInterfaces()[0].getDeclaredMethod("BackupRead", Pointer.class,
                    Pointer.class, int.class, IntByReference.class, int.class, int.class, PointerByReference.class);
                abort.setAccessible(true);
                abort.invoke(real, contextHandle, null, 0, new IntByReference(), 1, 0, context);
            }
            for (Pointer handle : List.copyOf(handles)) {
                Method close = real.getClass().getInterfaces()[0].getDeclaredMethod("CloseHandle", Pointer.class);
                close.setAccessible(true);
                close.invoke(real, handle);
            }
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
