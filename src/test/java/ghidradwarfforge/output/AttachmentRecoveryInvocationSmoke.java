package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.concurrent.CancellationException;

/** Recovery selection/claims admission only, with no native authority or mutation. */
public final class AttachmentRecoveryInvocationSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-recovery-invocation-λ ");
        try {
            for (var mode : AttachmentReceipt.Mode.values()) {
                Path directory = Files.createDirectory(root.resolve(mode.name()));
                var template = AttachmentProtocolSmoke.fixture(mode);
                var artifacts = new HashMap<String, AttachmentReceipt.Artifact>();
                var paths = new HashMap<String, Path>();
                for (var entry : template.files().entrySet()) {
                    Path selected = directory.resolve(entry.getKey());
                    paths.put(entry.getKey(), selected);
                    if (!entry.getKey().equals("targetAfter")) Files.writeString(selected, entry.getKey());
                    var old = entry.getValue();
                    artifacts.put(entry.getKey(), new AttachmentReceipt.Artifact(directory.resolve(
                        entry.getKey().equals("targetAfter") ? "targetBefore" : entry.getKey()).toString(),
                        old.sha256(), old.bytes(), old.identity(), old.metadataSha256()));
                }
                for (String role : new String[] {"receipt", "recoveryReceipt", "restoreImage"}) paths.put(role, directory.resolve(role));
                var prepared = new AttachmentReceipt(template.operationId(), mode, AttachmentReceipt.Phase.PREPARED,
                    paths.get("receipt").toString(), template.backend(), template.hostContract(), template.durability(),
                    template.debuglinkCrc32(), artifacts, null);
                for (var phase : new AttachmentReceipt.Phase[] {AttachmentReceipt.Phase.PREPARED, AttachmentReceipt.Phase.COMMITTED}) {
                    var record = phase == AttachmentReceipt.Phase.PREPARED ? prepared : prepared.advance(phase, null);
                    Files.writeString(paths.get("receipt"), record.toJson());
                    var invocation = new AttachmentRecoveryInvocation(paths, FileDigests.read(paths.get("receipt"), () -> false).sha256());
                    String json = invocation.toJson();
                    equal(invocation, read(json));
                    var transaction = invocation.transaction(() -> false);
                    equal(prepared, transaction.prepared());
                    Path requestFile = directory.resolve("request.json");
                    Files.writeString(requestFile, json);
                    invocation.preflight(transaction, requestFile).recheck();
                    checks++;
                    rejects(() -> invocation.preflight(transaction, paths.get("targetBefore")));
                    var aliases = new HashMap<>(paths);
                    aliases.put("targetAfter", paths.get("targetBefore"));
                    var aliased = new AttachmentRecoveryInvocation(aliases, invocation.receiptSha256());
                    rejects(() -> aliased.preflight(aliased.transaction(() -> false), requestFile));
                    aliases.put("source", directory.resolve("wrong-source"));
                    rejects(() -> new AttachmentRecoveryInvocation(aliases, invocation.receiptSha256()).transaction(() -> false));
                    rejects(() -> new AttachmentRecoveryInvocation(paths, "0".repeat(64)).transaction(() -> false));
                    for (String invalid : new String[] {
                            json.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
                            json.replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
                            json.replace("\"RECOVER\"", "\"ATTACH\""),
                            json.replaceFirst("\\{", "{\"operation\":\"RECOVER\","),
                            json.replaceFirst("\\{", "{\"elevate\":1,"),
                            json.replace("\"receiptSha256\":", "\"unknown\":"),
                            json.replace("\"paths\":{", "\"paths\":{\"extra\":\"/unused\","),
                            json.replace("\"paths\":{", "\"paths\":{\"targetBefore\":0,"),
                            json.replace("\"targetBefore\":\"", "\"targetBefore\":\"relative"),
                            json + "{}", "\ufeff" + json, json + " ".repeat(256 * 1024)}) rejects(() -> read(invalid));
                    var cancelled = new ClosingInput(json);
                    try { AttachmentRecoveryInvocation.read(cancelled, () -> true); throw new AssertionError("ignored cancellation"); }
                    catch (CancellationException expected) { checks++; }
                    equal(true, cancelled.closed);
                    var malformed = new ClosingInput("{}");
                    rejects(() -> AttachmentRecoveryInvocation.read(malformed, () -> false));
                    equal(true, malformed.closed);
                    equal(record.toJson(), Files.readString(paths.get("receipt")));
                    equal(false, Files.exists(paths.get("recoveryReceipt")));
                    equal(false, Files.exists(paths.get("restoreImage")));
                    Files.writeString(paths.get("receipt"), prepared.advance(AttachmentReceipt.Phase.ROLLED_BACK, "test-only").toJson());
                    var terminal = new AttachmentRecoveryInvocation(paths, FileDigests.read(paths.get("receipt"), () -> false).sha256());
                    rejects(() -> terminal.transaction(() -> false));
                }
            }
            System.out.println("attachment-recovery-invocation-smoke=PASS checks=" + checks + " admission-only=true");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static AttachmentRecoveryInvocation read(String value) throws IOException {
        return AttachmentRecoveryInvocation.read(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)), () -> false);
    }
    private static final class ClosingInput extends ByteArrayInputStream {
        boolean closed;
        ClosingInput(String text) { super(text.getBytes(StandardCharsets.UTF_8)); }
        @Override public void close() throws IOException { closed = true; super.close(); }
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void rejects(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid recovery accepted"); }
        catch (IOException | IllegalArgumentException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected " + expected + " but got " + actual);
        checks++;
    }
}
