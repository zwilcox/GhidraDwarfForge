package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Explicit recovery selections; recorded artifact paths are compared, never followed. */
public record AttachmentRecoveryInvocation(Map<String, Path> paths, String receiptSha256, String committedReceiptSha256) {
    private static final Set<String> COMMON = Set.of("targetBefore", "targetAfter", "originalBackup", "sidecar",
        "source", "exportReport", "validationEvidence", "receipt", "recoveryReceipt", "restoreImage");
    private static final Set<String> REFRESH = Set.of("previousReceipt", "previousSidecar", "previousSource", "priorTargetBackup");
    private static final ReportJsonReader.Limits LIMITS = new ReportJsonReader.Limits(256 * 1024, 16384, 2, 128, 1);

    public AttachmentRecoveryInvocation(Map<String, Path> paths, String receiptSha256) {
        this(paths, receiptSha256, receiptSha256);
    }

    public boolean acceptsReceiptSha256(String actual) {
        return receiptSha256.equals(actual) || committedReceiptSha256.equals(actual);
    }

    public AttachmentRecoveryInvocation {
        paths = Map.copyOf(paths);
        var expected = new HashSet<>(COMMON);
        if (paths.containsKey("priorTargetBackup")) expected.addAll(REFRESH);
        if (!paths.keySet().equals(expected) || receiptSha256 == null || !receiptSha256.matches("[0-9a-f]{64}") ||
                committedReceiptSha256 == null || !committedReceiptSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("recovery requires every explicit role and the selected receipt SHA-256");
        }
        for (var path : paths.values()) {
            if (!path.isAbsolute() || path.toString().length() > 16384) {
                throw new IllegalArgumentException("recovery selections require bounded absolute paths");
            }
        }
    }

    public String toJson() {
        var result = new JsonObject();
        result.addProperty("schemaVersion", 1);
        result.addProperty("operation", "RECOVER");
        result.addProperty("receiptSha256", receiptSha256);
        result.addProperty("committedReceiptSha256", committedReceiptSha256);
        var selected = new JsonObject();
        for (var entry : new TreeMap<>(paths).entrySet()) selected.addProperty(entry.getKey(), entry.getValue().toString());
        result.add("paths", selected);
        String text = result + "\n";
        if (text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > LIMITS.bytes()) {
            throw new IllegalArgumentException("recovery request exceeds transport limit");
        }
        return text;
    }

    static AttachmentRecoveryInvocation read(InputStream input, BooleanSupplier cancelled) throws IOException {
        try (var json = new JsonReader(new ReportJsonReader(input, cancelled, LIMITS))) {
            json.setLenient(false);
            var names = new HashSet<String>();
            String version = null;
            String action = null;
            String sha = null;
            String committedSha = null;
            Map<String, Path> paths = null;
            json.beginObject();
            while (json.hasNext()) {
                switch (AttachmentInvocation.unique(json, names)) {
                    case "schemaVersion" -> {
                        if (json.peek() != JsonToken.NUMBER) throw new IOException("recovery version must be an integer");
                        version = json.nextString();
                    }
                    case "operation" -> action = AttachmentInvocation.string(json);
                    case "receiptSha256" -> sha = AttachmentInvocation.string(json);
                    case "committedReceiptSha256" -> committedSha = AttachmentInvocation.string(json);
                    case "paths" -> paths = AttachmentInvocation.readPaths(json);
                    default -> throw new IOException("unknown recovery request field");
                }
            }
            json.endObject();
            if (json.peek() != JsonToken.END_DOCUMENT || names.size() != 5 || !"1".equals(version) ||
                    !"RECOVER".equals(action) || paths == null) throw new IOException("invalid recovery request");
            return new AttachmentRecoveryInvocation(paths, sha, committedSha);
        }
        catch (CancellationException cancellation) { throw cancellation; }
        catch (IllegalArgumentException | IllegalStateException invalid) { throw new IOException("invalid recovery selection", invalid); }
    }

    /** Decode only the explicitly selected, pinned receipt; no artifact is opened here. */
    public AttachmentTransaction.Request transaction(BooleanSupplier cancelled) throws IOException {
        byte[] bytes = AttachmentHelper.readPinned(paths.get("receipt"), this::acceptsReceiptSha256, 1024 * 1024, cancelled);
        var record = AttachmentReceipt.read(new ByteArrayInputStream(bytes), cancelled);
        if (record.recovery() != null || (record.phase() != AttachmentReceipt.Phase.PREPARED &&
                record.phase() != AttachmentReceipt.Phase.COMMITTED)) {
            throw new IOException("select a normal interrupted PREPARED or COMMITTED receipt");
        }
        var files = new TreeMap<>(paths);
        files.remove("receipt"); files.remove("recoveryReceipt"); files.remove("restoreImage");
        if (!files.keySet().equals(record.files().keySet()) ||
                !FileSystemPaths.resolveLeaf(paths.get("receipt"), "selected interrupted receipt").toString().equals(record.receiptPath())) {
            throw new IOException("selected recovery roles or receipt path differ from the recorded operation");
        }
        for (var entry : files.entrySet()) {
            if (!entry.getKey().equals("targetAfter") && !FileSystemPaths.resolveLeaf(entry.getValue(), entry.getKey())
                    .toString().equals(record.files().get(entry.getKey()).path())) {
                throw new IOException("explicit recovery path differs from recorded role: " + entry.getKey());
            }
        }
        // Reconstruct the normal prepared claims, preserving every image/metadata
        // claim. Native recovery will require the actual durable record to agree.
        var prepared = new AttachmentReceipt(record.operationId(), record.mode(), AttachmentReceipt.Phase.PREPARED,
            record.receiptPath(), record.backend(), record.hostContract(), record.durability(), record.debuglinkCrc32(),
            record.files(), null);
        return new AttachmentTransaction.Request(prepared, files, paths.get("receipt"), paths.get("recoveryReceipt"),
            paths.get("restoreImage"));
    }

    public AttachmentPaths.Plan preflight(AttachmentTransaction.Request transaction, Path requestFile) throws IOException {
        var selections = new ArrayList<>(AttachmentTransaction.preflightRecoveryPaths(transaction).selections());
        selections.add(new AttachmentPaths.Selection("invocation", requestFile, AttachmentPaths.Kind.INPUT));
        return AttachmentPaths.preflight(selections);
    }
}
