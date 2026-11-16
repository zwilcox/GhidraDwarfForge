package ghidradwarfforge.output;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Controlled replies around real LP64 libc calls; not evidence of kernel defects or full host admission. */
final class LinuxMetadataFailureControls {
    /** Self-contained mutation oracle; the integration harness supplies its own independently observed file. */
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-metadata-fault-");
        Path source = root.resolve("source");
        try {
            Files.writeString(source, "owned native metadata failure fixture");
            var attributes = Files.getFileAttributeView(source, java.nio.file.attribute.UserDefinedFileAttributeView.class);
            require(attributes != null, "fixture filesystem lacks user attributes");
            attributes.write("forge.failure", java.nio.ByteBuffer.wrap(new byte[] {0, 1, (byte) 255}));
            var result = check(source);
            System.out.println("linux-metadata-failures=PASS cases=" + ((List<?>) result.get("cases")).size());
        }
        finally { Files.deleteIfExists(source); Files.delete(root); }
    }

    private record Case(String name, String diagnostic) { }
    private static final List<Case> CASES = List.of(
        new Case("open-error", "open failed (errno=5)"),
        new Case("stat-error", "statx failed (errno=5)"),
        new Case("opened-stat-error", "statx failed (errno=5)"),
        new Case("list-error", "flistxattr failed (errno=5)"),
        new Case("get-error", "fgetxattr failed (errno=5)"),
        new Case("flags-error", "FS_IOC_GETFLAGS failed (errno=5)"),
        new Case("extended-error", "FS_IOC_FSGETXATTR failed (errno=5)"),
        new Case("close-error-after-release", "close failed (errno=5)"),
        new Case("missing-stat-fields", "statx omitted required metadata"),
        new Case("nonregular-stat", "regular non-link file"),
        new Case("negative-size", "invalid statx size/time"),
        new Case("negative-mtime-nanos", "invalid statx size/time"),
        new Case("excess-mtime-nanos", "invalid statx size/time"),
        new Case("negative-ctime-nanos", "invalid statx size/time"),
        new Case("excess-ctime-nanos", "invalid statx size/time"),
        new Case("opened-identity-change", "opened file differs from path observation"),
        new Case("observed-identity-change", "opened metadata changed while reading attributes"),
        new Case("path-identity-change", "metadata path changed during inspection"),
        new Case("inode-policy-change", "opened inode policy changed while reading metadata"),
        new Case("reserved-inode-field", "unrecognized inode allocation policy fields"),
        new Case("excess-list-size", "attribute list exceeds bound"),
        new Case("empty-attribute-name", "malformed attribute name list"),
        new Case("unterminated-attribute-name", "malformed attribute name list"),
        new Case("long-attribute-name", "malformed attribute name list"),
        new Case("duplicate-attribute-name", "duplicate attribute name"),
        new Case("excess-value-size", "attribute value exceeds bound"),
        new Case("excess-attribute-count", "visible metadata exceeds bound"),
        new Case("excess-attribute-bytes", "visible metadata exceeds bound"));

    static Map<String, Object> check(Path source) throws Exception {
        var metadata = new LinuxFileMetadata();
        var baseline = metadata.inspect(source, () -> false);
        require(!baseline.visibleAttributes().isEmpty(), "fault fixture must have a real visible attribute");
        byte[] bytes = Files.readAllBytes(source);
        Field field = LinuxFileMetadata.class.getDeclaredField("libc");
        field.setAccessible(true);
        Object real = field.get(metadata);
        var results = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            var fault = new Fault(selected.name(), real);
            Object wrapper = Proxy.newProxyInstance(field.getType().getClassLoader(), new Class<?>[] {field.getType()}, fault::invoke);
            field.set(metadata, wrapper);
            try {
                // Exercise the same forwarding path with no fault before arming it.
                require(metadata.inspect(source, () -> false).equals(baseline), "forwarding baseline differs");
                fault.arm();
                IOException rejected;
                try {
                    metadata.inspect(source, () -> false);
                    throw new AssertionError("native reply accepted: " + selected.name());
                }
                catch (IOException expected) { rejected = expected; }
                catch (RuntimeException unexpected) {
                    throw new AssertionError("unbounded native reply escaped as a runtime error: " + selected.name(), unexpected);
                }
                require(rejected.getMessage().contains(selected.diagnostic()), "wrong rejection " + selected.name() + ": " + rejected);
                require(fault.hits == 1, "fault not reached exactly once: " + selected.name());
                require(fault.active.isEmpty() && fault.opens == fault.closes,
                    "native descriptor leaked: " + selected.name());
                int opens = fault.opens, closes = fault.closes;
                field.set(metadata, real);
                require(metadata.inspect(source, () -> false).equals(baseline), "source metadata changed: " + selected.name());
                require(Arrays.equals(bytes, Files.readAllBytes(source)), "source bytes changed: " + selected.name());
                results.add(Map.of("name", selected.name(), "faultHits", fault.hits, "opened", opens, "closed", closes,
                    "diagnostic", rejected.getMessage(), "sourceUnchanged", true));
            }
            finally {
                field.set(metadata, real);
                // Failed assertions must not leave descriptors in the test process.
                // A cleanup here cannot turn a leak into a passing assertion above.
                fault.releaseLeftovers();
            }
        }
        return Map.of("status", "PASS_CONTROLLED_LIBC_FAILURES", "cases", results,
            "scope", "real Linux LP64 descriptor operations with explicitly injected API replies; no full host admission");
    }

    private static final class Fault {
        final String name;
        final Object real;
        final Map<String, Integer> calls = new HashMap<>();
        final HashSet<Integer> active = new HashSet<>();
        boolean armed;
        int hits, opens, closes;

        Fault(String name, Object real) { this.name = name; this.real = real; }

        void arm() {
            require(active.isEmpty() && opens == closes, "forwarding baseline leaked a descriptor");
            calls.clear();
            hits = opens = closes = 0;
            armed = true;
        }

        Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            method.setAccessible(true);
            String operation = method.getName();
            int count = calls.merge(operation, 1, Integer::sum);
            boolean before = armed && hits == 0 && switch (name) {
                case "open-error" -> operation.equals("open");
                case "stat-error" -> operation.equals("statx");
                case "opened-stat-error" -> operation.equals("statx") && count == 2;
                case "list-error" -> operation.equals("flistxattr");
                case "get-error" -> operation.equals("fgetxattr");
                case "flags-error" -> operation.equals("ioctl") && count == 1;
                case "extended-error" -> operation.equals("ioctl") && count == 2;
                default -> false;
            };
            if (before) { hits++; return error(method); }
            if (armed && operation.equals("fgetxattr") && name.startsWith("excess-attribute-")) {
                // Bounded synthetic values accompany the synthetic list below.
                if (name.equals("excess-attribute-bytes")) { ((Pointer) args[2]).clear(65536); return 65536L; }
                return 0L;
            }
            Object result;
            try { result = method.invoke(real, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
            if (operation.equals("open") && (int) result >= 0) { active.add((int) result); opens++; }
            if (operation.equals("close")) {
                require(active.remove((int) args[0]), "closing an untracked native descriptor");
                // Never retry an actual Linux close error: the descriptor may already be released.
                if ((int) result == 0) closes++;
            }
            if (!armed || hits != 0) return result;
            if (name.equals("close-error-after-release") && operation.equals("close")) {
                require((int) result == 0, "real close failed before injected close reply");
                hits++;
                return error(method);
            }
            if (operation.equals("statx") && (int) result == 0) {
                Pointer data = (Pointer) args[4];
                if (count == 2) {
                    boolean changed = true;
                    switch (name) {
                        case "missing-stat-fields" -> data.setInt(0, 0);
                        case "nonregular-stat" -> data.setShort(28, (short) 0040600);
                        case "negative-size" -> data.setLong(40, -1);
                        case "negative-mtime-nanos" -> data.setInt(120, -1);
                        case "excess-mtime-nanos" -> data.setInt(120, 1000000000);
                        case "negative-ctime-nanos" -> data.setInt(104, -1);
                        case "excess-ctime-nanos" -> data.setInt(104, 1000000000);
                        case "opened-identity-change" -> data.setLong(32, data.getLong(32) ^ 1);
                        default -> changed = false;
                    }
                    if (changed) hits++;
                }
                if ((name.equals("observed-identity-change") && count == 4) ||
                        (name.equals("path-identity-change") && count == 5)) {
                    data.setLong(32, data.getLong(32) ^ 1);
                    hits++;
                }
            }
            if (operation.equals("ioctl") && (int) result == 0) {
                if (name.equals("reserved-inode-field") && count == 2) {
                    ((Pointer) args[2]).setByte(20, (byte) 1); hits++;
                }
                if (name.equals("inode-policy-change") && count == 3) {
                    Pointer data = (Pointer) args[2]; data.setInt(0, data.getInt(0) ^ 0x80); hits++;
                }
            }
            if (operation.equals("flistxattr") && (long) result >= 0) {
                Pointer data = (Pointer) args[1];
                byte[] replacement = null;
                switch (name) {
                    case "excess-list-size" -> { hits++; return 65537L; }
                    case "empty-attribute-name" -> replacement = new byte[] {0};
                    case "unterminated-attribute-name" -> replacement = "user.x".getBytes(StandardCharsets.US_ASCII);
                    case "long-attribute-name" -> replacement = ("x".repeat(256) + "\0").getBytes(StandardCharsets.US_ASCII);
                    case "duplicate-attribute-name" -> {
                        byte[] names = data.getByteArray(0, Math.toIntExact((long) result));
                        int length = 0;
                        while (length < names.length && names[length] != 0) length++;
                        require(length > 0 && length < names.length, "real attribute list lacks a complete name");
                        length++;
                        replacement = new byte[length * 2];
                        System.arraycopy(names, 0, replacement, 0, length);
                        System.arraycopy(names, 0, replacement, length, length);
                    }
                    case "excess-attribute-count", "excess-attribute-bytes" -> {
                        var names = new StringBuilder();
                        int entries = name.equals("excess-attribute-count") ? 1025 : 129;
                        for (int index = 0; index < entries; index++) names.append("user.control").append(index).append('\0');
                        replacement = names.toString().getBytes(StandardCharsets.US_ASCII);
                    }
                    default -> { }
                }
                if (replacement != null) {
                    require(replacement.length <= 65536, "fault fixture exceeds native buffer");
                    data.write(0, replacement, 0, replacement.length); hits++;
                    return (long) replacement.length;
                }
            }
            if (name.equals("excess-value-size") && operation.equals("fgetxattr") && (long) result >= 0) {
                hits++; return 65537L;
            }
            return result;
        }

        private Object error(Method method) {
            Native.setLastError(5); // Explicit EIO reply, not an observed filesystem failure.
            if (method.getReturnType() == long.class) return Long.valueOf(-1);
            return Integer.valueOf(-1);
        }

        void releaseLeftovers() throws Exception {
            Method close = real.getClass().getMethod("close", int.class);
            close.setAccessible(true);
            for (int fd : active) require((int) close.invoke(real, fd) == 0, "test cleanup could not release descriptor");
            active.clear();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
