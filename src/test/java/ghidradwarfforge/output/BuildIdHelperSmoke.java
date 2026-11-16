package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.Platform;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

/** Real request files, no native installation: preview is never installation approval. */
public final class BuildIdHelperSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-build-id-helper-").toRealPath();
        try {
            options(root);
            requests(root);
            System.out.println("build-id-helper-smoke=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void options(Path root) throws Exception {
        Path request = root.resolve("request λ 'literal'.json");
        String[] valid = {"--request", request.toString(), "--request-sha256", "a".repeat(64)};
        var command = BuildIdHelper.command(valid);
        equal(request, command.request());
        equal(false, command.preview());
        equal(false, command.securityPrivilege());
        equal(null, command.cancelFile());
        // A pending cancellation must win before opening even a missing request.
        failure(valid, () -> true, 130, "CANCELLED", "build-ID command cancelled");
        Path cancel = root.resolve("cancel λ");
        var encoded = BuildIdHelper.command(new String[] {"--request-utf8-base64",
            AttachmentPathArgument.encode(request.toString()), "--request-sha256", "a".repeat(64),
            "--cancel-file-utf8-base64", AttachmentPathArgument.encode(cancel.toString()),
            "--preview", "--cancel-on-stdin"});
        equal(request, encoded.request());
        equal(cancel, encoded.cancelFile());
        equal(true, encoded.preview());
        for (String[] bad : new String[][] {
                {}, {"--request", request.toString()}, {"--request-sha256", "a".repeat(64)},
                {"--request"}, {"--request-sha256"}, {"--cancel-file"},
                {"--request", request.toString(), "--request-sha256", "A".repeat(64)},
                {"--request", request.toString(), "--request-sha256", "a".repeat(63)},
                {"--request", request.toString(), "--request-sha256", "g".repeat(64)},
                {"--request", "relative", "--request-sha256", "a".repeat(64)}}) {
            failure(bad, () -> false, 1, "FAILED", null);
        }
        for (String flag : new String[] {"--preview", "--cancel-on-stdin", "--enable-security-privilege"}) {
            failure(append(valid, flag + "-utf8-base64"), () -> false, 1, "FAILED", "only pathname options");
            failure(append(valid, flag, flag), () -> false, 1, "FAILED", "duplicate");
        }
        failure(append(valid, "--unknown"), () -> false, 1, "FAILED", "unknown build-ID helper option");
        failure(new String[] {"--request", request.toString(), "--request-sha256-utf8-base64",
            AttachmentPathArgument.encode("a".repeat(64))}, () -> false, 1, "FAILED", "SHA-256 must be literal");
        failure(append(valid, "--request-utf8-base64", AttachmentPathArgument.encode(request.toString())),
            () -> false, 1, "FAILED", "duplicate");
        for (String bad : new String[] {"", "a".repeat(16385), "invalid\0path"}) {
            failure(new String[] {"--request", bad, "--request-sha256", "a".repeat(64)},
                () -> false, 1, "FAILED", "invalid build-ID pathname");
            failure(append(valid, "--cancel-file", bad), () -> false, 1, "FAILED", "invalid build-ID pathname");
        }
        var privileged = append(valid, "--enable-security-privilege");
        if (Platform.isWindows()) equal(true, BuildIdHelper.command(privileged).securityPrivilege());
        else failure(privileged, () -> false, 1, "FAILED", "Windows-only");
        var help = new ByteArrayOutputStream();
        equal(0, BuildIdHelper.run(new String[] {"--help"}, () -> false, new PrintStream(help, true, StandardCharsets.UTF_8)));
        contains(help.toString(StandardCharsets.UTF_8), "Preview checks selections only");
        equal(1, BuildIdHelper.run(new String[] {"--help"}, () -> false, brokenOutput()));
        failure(new String[] {"--unknown"}, () -> false, 1, "FAILED", "unknown");
    }

    private static void requests(Path root) throws Exception {
        Path debug = Files.createDirectory(root.resolve("debug λ space"));
        Path request = root.resolve("selected.json");
        JsonObject value = selection(debug, "remove");
        write(request, value);
        String[] selected = arguments(request);
        for (String action : new String[] {"remove", "recover"}) {
            write(request, selection(debug, action));
            var result = failure(append(arguments(request), "--preview"), () -> false, 0,
                "PREVIEW_NOT_VALIDATED", null);
            equal(action, result.get("action").getAsString());
            equal("11223344", result.get("buildId").getAsString());
            equal(debug.toString(), result.get("root").getAsString());
            equal(0, result.getAsJsonObject("files").size());
            equal(0, result.getAsJsonObject("tools").size());
        }
        write(request, value);
        // Same pin, changed content: reject before preview can claim even selection success.
        Files.writeString(request, " ", java.nio.file.StandardOpenOption.APPEND);
        failure(append(selected, "--preview"), () -> false, 1, "FAILED", "selected SHA-256");
        write(request, value);
        var calls = new AtomicInteger();
        failure(append(arguments(request), "--preview"), () -> { calls.incrementAndGet(); return false; },
            0, "PREVIEW_NOT_VALIDATED", null);
        int boundaries = calls.get();
        if (boundaries < 4) throw new AssertionError("request validation did not inspect cancellation");
        byte[] before = Files.readAllBytes(request);
        for (int stop = 1; stop <= boundaries; stop++) {
            int selectedStop = stop;
            calls.set(0);
            failure(append(arguments(request), "--preview"), () -> calls.incrementAndGet() == selectedStop,
                130, "CANCELLED", "cancelled");
            equal(true, Arrays.equals(before, Files.readAllBytes(request)));
        }
        // A caller changing the request while it is being parsed must fail the final pin check.
        calls.set(0);
        failure(append(arguments(request), "--preview"), () -> {
            if (calls.incrementAndGet() == 4) {
                try { Files.writeString(request, " ", java.nio.file.StandardOpenOption.APPEND); }
                catch (IOException failure) { throw new AssertionError(failure); }
            }
            return false;
        }, 1, "FAILED", "selected SHA-256");
        write(request, value);
        Path cancel = Files.createFile(root.resolve("cancel"));
        String[] withCancel = append(arguments(request), "--preview", "--cancel-file", cancel.toString());
        failure(withCancel, () -> false, 0, "PREVIEW_NOT_VALIDATED", null);
        failure(withCancel, () -> true, 130, "CANCELLED", "cancelled");
        calls.set(0);
        failure(withCancel, () -> {
            if (calls.incrementAndGet() == 2) {
                try { Files.writeString(cancel, "stop"); }
                catch (IOException failure) { throw new AssertionError(failure); }
            }
            return false;
        }, 130, "CANCELLED", "cancelled");
        Files.delete(cancel);

        for (String text : new String[] {"{", "[]", "null", value + " {}",
                value.toString().replace("\"action\":\"remove\"", "\"action\":\"remove\",\"action\":\"recover\"")}) {
            Files.writeString(request, text);
            failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", null);
        }
        for (String field : new String[] {"schema", "action", "root", "buildId"}) {
            var invalid = value.deepCopy();
            invalid.remove(field);
            write(request, invalid);
            failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", null);
        }
        for (String[] change : new String[][] {{"schema", "unknown"}, {"action", "erase"},
                {"root", "relative"}, {"buildId", "xyz"}, {"buildId", "112"}}) {
            var invalid = value.deepCopy();
            invalid.addProperty(change[0], change[1]);
            write(request, invalid);
            failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", null);
        }
        // Windows forbids control characters in filenames. Exercise these actual paths on POSIX only.
        if (!Platform.isWindows()) {
            for (String name : new String[] {"debug:separator", "debug\nnewline", "debug\rcarriage", "debug "}) {
                Path invalid = Files.createDirectory(root.resolve(name));
                write(request, selection(invalid, "remove"));
                failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", "search-path separator");
                empty(invalid);
            }
        }
        write(request, selection(request, "remove"));
        failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", "debug root must exist");
        write(request, value);
        String json = Files.readString(request);
        Files.writeString(request, json + " ".repeat(1024 * 1024 - json.getBytes(StandardCharsets.UTF_8).length));
        failure(append(arguments(request), "--preview"), () -> false, 0, "PREVIEW_NOT_VALIDATED", null);
        Files.writeString(request, " ", java.nio.file.StandardOpenOption.APPEND);
        failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", "exceeds 1 MiB");
        write(request, value);
        equal(1, BuildIdHelper.run(append(arguments(request), "--preview"), () -> false, brokenOutput()));
        equal(value.toString(), Files.readString(request));
        empty(debug);
        installPreview(root, debug, request);
    }

    private static void installPreview(Path root, Path debug, Path request) throws Exception {
        var value = selection(debug, "install");
        value.remove("buildId");
        var files = new JsonObject();
        var tools = new JsonObject();
        for (String key : new String[] {"original", "sidecar", "source", "report", "helper", "readelf", "llvm", "strict", "configuration"}) {
            Path path = root.resolve("literal " + key);
            Files.writeString(path, "preview does not validate " + key);
            (files.size() < 4 ? files : tools).addProperty(key, path.toString());
        }
        value.add("files", files);
        value.add("tools", tools);
        for (String action : new String[] {"install", "update"}) {
            value.addProperty("action", action);
            write(request, value);
            var result = failure(append(arguments(request), "--preview"), () -> false, 0, "PREVIEW_NOT_VALIDATED", null);
            equal(files, result.get("files"));
            equal(tools, result.get("tools"));
            equal(true, result.get("buildId").isJsonNull());
            empty(debug);
        }
        tools.addProperty("helper", request.toString());
        write(request, value);
        failure(append(arguments(request), "--preview"), () -> false, 1, "FAILED", "alias");
        for (String key : new String[] {"original", "sidecar", "source", "report", "helper", "readelf", "llvm", "strict", "configuration"}) {
            equal("preview does not validate " + key, Files.readString(root.resolve("literal " + key)));
        }
        empty(debug);
    }

    private static JsonObject selection(Path root, String action) {
        var value = new JsonObject();
        value.addProperty("schema", "forge-build-id-request-v1");
        value.addProperty("action", action);
        value.addProperty("root", root.toString());
        value.addProperty("buildId", "11223344");
        return value;
    }

    private static void empty(Path root) throws IOException {
        try (var paths = Files.list(root)) { equal(0L, paths.count()); }
    }

    private static void write(Path path, JsonObject value) throws IOException { Files.writeString(path, value.toString()); }

    private static String[] arguments(Path request) throws Exception {
        return new String[] {"--request", request.toString(), "--request-sha256",
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(request)))};
    }

    private static String[] append(String[] original, String... tail) {
        String[] result = Arrays.copyOf(original, original.length + tail.length);
        System.arraycopy(tail, 0, result, original.length, tail.length);
        return result;
    }

    private static PrintStream brokenOutput() {
        return new PrintStream(new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("closed response pipe"); }
        });
    }

    private static JsonObject failure(String[] args, BooleanSupplier cancel, int status, String outcome, String error) {
        var bytes = new ByteArrayOutputStream();
        int actual = BuildIdHelper.run(args, cancel, new PrintStream(bytes, true, StandardCharsets.UTF_8));
        String text = bytes.toString(StandardCharsets.UTF_8);
        if (actual != status) throw new AssertionError("expected exit " + status + ", got " + actual + ": " + text);
        var result = JsonParser.parseString(text).getAsJsonObject();
        equal(1, result.get("schemaVersion").getAsInt());
        equal(status, result.get("exitCode").getAsInt());
        equal(outcome, result.get("outcome").getAsString());
        equal(false, result.get("modifiesOriginal").getAsBoolean());
        if (error != null) contains(result.get("error").getAsString(), error);
        if (status != 0) equal(false, result.has("registration"));
        return result;
    }

    private static void contains(String actual, String expected) {
        if (!actual.contains(expected)) throw new AssertionError("missing " + expected + " in " + actual);
        checks++;
    }

    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError("expected " + expected + ", got " + actual);
        checks++;
    }
}
