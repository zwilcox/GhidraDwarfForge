package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;

/** Transport/path admission only; no host privileges, validators or target mutation. */
public final class AttachmentInvocationSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-invocation-λ ");
        try {
            for (String name : new String[] { "target", "sidecar", "source", "exportReport", "previousReceipt",
                    "previousSidecar", "previousSource", "retainedBackup", "helper", "readelf", "llvm", "strict", "configuration" }) {
                Files.writeString(root.resolve(name), "owned sentinel " + name);
            }
            var tools = new HashMap<String, Path>();
            for (String name : new String[] { "helper", "readelf", "llvm", "strict", "configuration" }) tools.put(name, root.resolve(name));
            for (boolean refresh : new boolean[] { false, true }) {
                var prior = refresh ? new AttachmentOperation.Refresh(root.resolve("previousReceipt"),
                    root.resolve("previousSidecar"), root.resolve("previousSource"), root.resolve("prior.backup")) : null;
                var request = new AttachmentOperation.Request(root.resolve("target"), root.resolve("sidecar"), root.resolve("source"),
                    root.resolve("exportReport"), root.resolve(refresh ? "retainedBackup" : "original.backup"),
                    root.resolve("validation.json"), root.resolve("receipt.json"), root.resolve("recovery.json"), root.resolve("restore"), prior);
                var invocation = new AttachmentInvocation(request, tools, root.resolve("saved-recovery.json"));
                String json = invocation.toJson();
                equal(invocation, read(json));
                equal(json, read(json).toJson());
                Path transport = root.resolve(refresh ? "refresh.json" : "initial.json");
                Files.writeString(transport, json);
                equal(invocation, AttachmentInvocation.read(transport, () -> false));
                var before = snapshot(root);
                invocation.preflight(transport).recheck();
                rejects(() -> new AttachmentInvocation(request, tools, transport).preflight(transport));
                rejects(() -> new AttachmentInvocation(request, tools, request.source()).preflight(transport));
                equal(before, snapshot(root));
                rejects(() -> invocation.preflight(root.resolve("source")));
                equal(before, snapshot(root));
                var aliases = new HashMap<>(tools);
                aliases.put("helper", root.resolve("target"));
                rejects(() -> new AttachmentInvocation(request, aliases, root.resolve("saved-recovery.json")).preflight(transport));
                Path link = root.resolve("tool-link-" + refresh);
                Files.createLink(link, root.resolve("target"));
                aliases.put("helper", link);
                rejects(() -> new AttachmentInvocation(request, aliases, root.resolve("saved-recovery.json")).preflight(transport));
                Files.delete(link);
                equal(before, snapshot(root));
                aliases.put("helper", Path.of("relative-tool"));
                rejects(() -> new AttachmentInvocation(request, aliases, root.resolve("saved-recovery.json")));
                aliases.put("helper", root.resolve("x".repeat(16384)));
                rejects(() -> new AttachmentInvocation(request, aliases, root.resolve("saved-recovery.json")));
                rejects(() -> AttachmentInvocation.read(root, () -> false));
                malformed(json);
            }
            System.out.println("attachment-invocation-smoke=PASS checks=" + checks + " targets-unmodified=true helper-execution=false");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void malformed(String valid) throws Exception {
        for (String invalid : new String[] {
                valid.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
                valid.replace("\"schemaVersion\":1", "\"schemaVersion\":1.0"),
                valid.replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
                valid.replaceFirst("\\{", "{\"schemaVersion\":1,"),
                valid.replaceFirst("\\{", "{\"unknown\":null,"),
                valid.replaceFirst("\\{", "{\"elevate\":1,"),
                valid.contains("\"operation\":\"ATTACH\"") ?
                    valid.replace("\"operation\":\"ATTACH\"", "\"operation\":\"REFRESH\"") :
                    valid.replace("\"operation\":\"REFRESH\"", "\"operation\":\"ATTACH\""),
                valid.replace("\"operation\":\"ATTACH\"", "\"operation\":\"RECOVER\"")
                    .replace("\"operation\":\"REFRESH\"", "\"operation\":\"RECOVER\""),
                valid.replace("\"paths\":{", "\"paths\":{\"target\":\"/ignored\","),
                valid.replace("\"helper\":", "\"unknownTool\":"),
                valid.replace("\"helper\":\"", "\"helper\":\"relative"),
                valid.replace("\"paths\":{", "\"paths\":{\"extra\":\"/ignored\","),
                valid.replace("\"validatorTools\":{", "\"validatorTools\":{\"helper\":0,"),
                valid.replace("\"target\":\"", "\"target\":\"\\ud800"),
                valid.replace("\"target\":\"", "\"target\":\"\\u0000"),
                "\ufeff" + valid, valid + "{}", valid.substring(0, valid.length() - 2),
                valid + " ".repeat(256 * 1024) }) {
            rejects(() -> read(invalid));
        }
        byte[] malformedUtf8 = valid.getBytes(StandardCharsets.UTF_8);
        malformedUtf8[3] = (byte) 0xff;
        var invalid = new ClosingInput(malformedUtf8);
        rejects(() -> AttachmentInvocation.read(invalid, () -> false));
        equal(true, invalid.closed);
        var cancelled = new ClosingInput(valid.getBytes(StandardCharsets.UTF_8));
        try {
            AttachmentInvocation.read(cancelled, () -> true);
            throw new AssertionError("cancellation ignored");
        }
        catch (CancellationException expected) { checks++; }
        equal(true, cancelled.closed);
        var successful = new ClosingInput(valid.getBytes(StandardCharsets.UTF_8));
        AttachmentInvocation.read(successful, () -> false);
        equal(true, successful.closed);
    }

    private static AttachmentInvocation read(String json) throws IOException {
        return AttachmentInvocation.read(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)), () -> false);
    }

    private static Map<Path, String> snapshot(Path root) throws IOException {
        var result = new HashMap<Path, String>();
        try (var paths = Files.list(root)) {
            for (Path path : paths.toList()) result.put(path, Files.readString(path));
        }
        return result;
    }

    private static final class ClosingInput extends ByteArrayInputStream {
        boolean closed;
        ClosingInput(byte[] bytes) { super(bytes); }
        @Override public void close() throws IOException { closed = true; super.close(); }
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void rejects(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid invocation accepted"); }
        catch (IOException | IllegalArgumentException expected) { checks++; }
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected " + expected + " but got " + actual);
        checks++;
    }
}
