package ghidradwarfforge.output;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Actual owned-stage operations, controlled libc errors and explicit stage tampering. */
final class LinuxMetadataApplicationFailureControls {
    /** Standalone mutation oracle; the full integration harness supplies independently observed inputs. */
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-metadata-application-");
        Path source = root.resolve("source");
        try {
            prepare(source, "owned source".getBytes(StandardCharsets.US_ASCII), "source_value");
            var result = check(source, root.resolve("stages"));
            System.out.println("linux-metadata-application-failures=PASS cases=" + ((List<?>) result.get("cases")).size());
        }
        finally {
            Files.deleteIfExists(source);
            Files.deleteIfExists(root.resolve("stages"));
            Files.delete(root);
        }
    }

    private record Case(String name, String diagnostic, int opens) { }
    private static final List<Case> CASES = List.of(
        new Case("stage-open-error", "open failed (errno=5)", 1),
        new Case("temporary-mode-error", "fchmod temporary stage mode failed (errno=5)", 2),
        new Case("remove-attribute-error", "fremovexattr failed (errno=5)", 2),
        new Case("set-attribute-error", "fsetxattr failed (errno=5)", 2),
        new Case("final-mode-error", "fchmod final stage mode failed (errno=5)", 2),
        new Case("timestamp-error", "futimens failed (errno=5)", 2),
        new Case("stage-size-change", "metadata stage identity or size changed", 2),
        new Case("stage-link-change", "metadata stage identity or size changed", 2),
        new Case("stage-mode-change", "metadata application readback differs", 2),
        new Case("source-path-reply", "metadata source changed during application", 2),
        new Case("stage-path-reply", "metadata stage path changed", 2),
        new Case("close-error-after-release", "close failed (errno=5)", 2));

    static Map<String, Object> check(Path source, Path root) throws Exception {
        var metadata = new LinuxFileMetadata();
        var baseline = metadata.inspect(source, () -> false);
        require(!baseline.visibleAttributes().isEmpty(), "source needs real attributes");
        String extra = "forge_application_extra";
        require(!baseline.visibleAttributes().containsKey(HexFormat.of().formatHex(
            ("user." + extra).getBytes(StandardCharsets.US_ASCII))), "stage attribute collides with source");
        byte[] sourceBytes = Files.readAllBytes(source);
        byte[] stageBytes = "owned application failure stage".getBytes(StandardCharsets.US_ASCII);
        Files.createDirectory(root);
        Field field = LinuxFileMetadata.class.getDeclaredField("libc");
        field.setAccessible(true);
        Object real = field.get(metadata);
        var rows = new ArrayList<Map<String, Object>>();
        for (Case selected : CASES) {
            Path stage = root.resolve(selected.name()), link = root.resolve(selected.name() + ".link");
            prepare(stage, stageBytes, extra);
            var fault = new Fault(selected.name(), real, source, stage, link, baseline.facts().mode());
            Object wrapper = Proxy.newProxyInstance(field.getType().getClassLoader(),
                new Class<?>[] {field.getType()}, (proxy, method, args) -> fault.invoke(method, args));
            field.set(metadata, wrapper);
            try {
                var forwarded = metadata.applyToOwnedStage(source, baseline, stage, () -> false);
                require(forwarded.preservationSha256().equals(baseline.preservationSha256()), "forwarding differs");
                require(Arrays.equals(stageBytes, Files.readAllBytes(stage)), "forwarding changed bytes");
                Files.delete(stage);
                prepare(stage, stageBytes, extra);
                fault.arm();
                IOException rejected;
                try {
                    metadata.applyToOwnedStage(source, baseline, stage, () -> false);
                    throw new AssertionError("application fault accepted: " + selected.name());
                }
                catch (IOException expected) { rejected = expected; }
                require(rejected.getMessage().contains(selected.diagnostic()), "wrong rejection: " + rejected);
                require(fault.hits == 1 && fault.opened == selected.opens(), "unexpected injection or open count");
                fault.balanced();
                field.set(metadata, real);
                require(metadata.inspect(source, () -> false).equals(baseline), "source metadata changed");
                require(Arrays.equals(sourceBytes, Files.readAllBytes(source)), "source bytes changed");
                if (selected.name().equals("stage-size-change")) {
                    byte[] expected = Arrays.copyOf(stageBytes, stageBytes.length + 1);
                    expected[stageBytes.length] = 42;
                    require(Arrays.equals(expected, Files.readAllBytes(stage)), "size tampering not observed");
                }
                else require(Arrays.equals(stageBytes, Files.readAllBytes(stage)), "unexpected stage bytes changed");
                if (selected.name().equals("stage-link-change")) {
                    require(Files.isSameFile(stage, link) && (int) Files.getAttribute(stage, "unix:nlink") == 2,
                        "link tampering not observed");
                }
                if (selected.name().equals("stage-mode-change")) {
                    require(((int) Files.getAttribute(stage, "unix:mode") & 0777) == ((baseline.facts().mode() & 0777) ^ 0100),
                        "mode tampering not observed");
                }
                Files.deleteIfExists(link);
                Files.delete(stage);
                prepare(stage, stageBytes, extra);
                var retried = metadata.applyToOwnedStage(source, baseline, stage, () -> false);
                require(retried.preservationSha256().equals(baseline.preservationSha256()), "retry metadata differs");
                require(Arrays.equals(stageBytes, Files.readAllBytes(stage)), "retry changed stage bytes");
                require(metadata.inspect(source, () -> false).equals(baseline) &&
                    Arrays.equals(sourceBytes, Files.readAllBytes(source)), "retry changed source");
                rows.add(Map.of("name", selected.name(), "faultHits", fault.hits, "opened", fault.opened,
                    "closed", fault.closed, "sourceUnchanged", true, "stageEffectChecked", true,
                    "retryPassed", true, "diagnostic", rejected.getMessage()));
            }
            finally {
                field.set(metadata, real);
                fault.releaseLeftovers();
                Files.deleteIfExists(link);
                Files.deleteIfExists(stage);
            }
        }
        Files.delete(root);
        return Map.of("status", "PASS_CONTROLLED_LIBC_APPLICATION_FAILURES", "cases", rows,
            "scope", "owned-stage tampering and controlled libc replies; source unchanged, no complete host admission");
    }

    private static void prepare(Path stage, byte[] bytes, String extra) throws IOException {
        Files.write(stage, bytes, StandardOpenOption.CREATE_NEW);
        var attributes = Files.getFileAttributeView(stage, UserDefinedFileAttributeView.class);
        require(attributes != null, "stage requires user attributes");
        attributes.write(extra, ByteBuffer.wrap(new byte[] {1, 2, 3}));
    }

    private static final class Fault {
        final String name;
        final Object real;
        final Path source, stage, link;
        final int sourceMode;
        final HashMap<Integer, Boolean> active = new HashMap<>();
        boolean armed, applied;
        int hits, opened, closed, modeCalls;

        Fault(String name, Object real, Path source, Path stage, Path link, int sourceMode) {
            this.name = name; this.real = real; this.source = source; this.stage = stage;
            this.link = link; this.sourceMode = sourceMode;
        }

        void balanced() { require(active.isEmpty() && opened == closed, "application leaked native descriptor"); }
        void arm() { balanced(); hits = opened = closed = modeCalls = 0; applied = false; armed = true; }

        Object invoke(Method method, Object[] args) throws Throwable {
            String operation = method.getName();
            boolean output = operation.equals("open") ? path((byte[]) args[0]).equals(stage.toAbsolutePath())
                : args[0] instanceof Integer && Boolean.TRUE.equals(active.get((int) args[0]));
            if (operation.equals("fchmod") && output) modeCalls++;
            boolean inject = armed && hits == 0;
            if (inject && output && switch (name) {
                case "stage-open-error" -> operation.equals("open");
                case "temporary-mode-error" -> operation.equals("fchmod") && modeCalls == 1;
                case "remove-attribute-error" -> operation.equals("fremovexattr");
                case "set-attribute-error" -> operation.equals("fsetxattr");
                case "final-mode-error" -> operation.equals("fchmod") && modeCalls == 2;
                case "timestamp-error" -> operation.equals("futimens");
                default -> false;
            }) { hits++; Native.setLastError(5); return -1; }
            // Any real mutation must target this test's independently owned stage.
            if (List.of("fchown", "fchmod", "fremovexattr", "fsetxattr", "futimens").contains(operation)) {
                require(output, "attempted mutation outside the owned stage");
            }
            Object result = call(real, method, args);
            if (operation.equals("open") && (int) result >= 0) {
                require(active.putIfAbsent((int) result, output) == null, "duplicate descriptor"); opened++;
            }
            if (operation.equals("close")) {
                require(active.remove((int) args[0]) != null, "untracked descriptor close");
                // Do not retry a real Linux close failure: the descriptor may already be released.
                if ((int) result == 0) closed++;
            }
            if (!inject) return result;
            if (operation.equals("close") && name.equals("close-error-after-release")) {
                require((int) result == 0, "real close failed"); hits++; Native.setLastError(5); return -1;
            }
            if (operation.equals("futimens") && (int) result == 0) {
                applied = true;
                switch (name) {
                    case "stage-size-change" -> Files.write(stage, new byte[] {42}, StandardOpenOption.APPEND);
                    case "stage-link-change" -> Files.createLink(link, stage);
                    case "stage-mode-change" -> Files.setAttribute(stage, "unix:mode", (sourceMode & 0777) ^ 0100);
                    default -> { return result; }
                }
                hits++;
            }
            if (operation.equals("statx") && (int) result == 0 && applied && (int) args[0] == -100 &&
                    ((name.equals("source-path-reply") && path((byte[]) args[1]).equals(source.toAbsolutePath())) ||
                     (name.equals("stage-path-reply") && path((byte[]) args[1]).equals(stage.toAbsolutePath())))) {
                Pointer info = (Pointer) args[4]; info.setLong(32, info.getLong(32) ^ 1); hits++;
            }
            return result;
        }

        void releaseLeftovers() throws Exception {
            Method close = real.getClass().getMethod("close", int.class); close.setAccessible(true);
            for (int fd : List.copyOf(active.keySet())) require((int) close.invoke(real, fd) == 0, "cleanup failed");
            active.clear();
        }
    }

    private static Path path(byte[] bytes) {
        require(bytes.length > 1 && bytes[bytes.length - 1] == 0, "expected a terminated filesystem path");
        return Path.of(new String(bytes, 0, bytes.length - 1, StandardCharsets.UTF_8));
    }

    private static Object call(Object real, Method method, Object[] args) throws Throwable {
        method.setAccessible(true);
        try { return method.invoke(real, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
