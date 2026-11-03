package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.BooleanSupplier;

/**
 * Versioned transaction/recovery claims, not authorization or proof of current
 * files. Reading never follows a recorded path. The transaction must compare
 * every selected file and host metadata observation with these claims before
 * attaching, refreshing or recovering. Committed receipts are immutable.
 */
public record AttachmentReceipt(String operationId, Mode mode, Phase phase,
        String receiptPath, String backend, String hostContract, String durability,
        long debuglinkCrc32, Map<String, Artifact> files, String diagnostic) {
    public enum Mode { INITIAL, REFRESH }
    public enum Phase { PREPARED, COMMITTED, ROLLED_BACK, RECOVERY_REQUIRED }

    private static final Set<String> COMMON = Set.of("targetBefore", "targetAfter",
        "originalBackup", "sidecar", "source", "exportReport", "validationEvidence");
    private static final Set<String> REFRESH = Set.of("previousReceipt", "previousSidecar",
        "previousSource", "priorTargetBackup");
    private static final ReportJsonReader.Limits LIMITS =
        new ReportJsonReader.Limits(1024 * 1024, 16384, 4, 512, 32);

    /** Identity/metadata formats are defined by hostContract, never inferred here. */
    public record Artifact(String path, String sha256, long bytes, String identity,
            String metadataSha256) {
        public Artifact {
            path = text(path, "artifact path", 16384);
            hash(sha256);
            hash(metadataSha256);
            identity = text(identity, "artifact identity", 4096);
            if (bytes < 0) {
                throw new IllegalArgumentException("negative attachment artifact size");
            }
        }
    }

    public AttachmentReceipt {
        if (operationId == null || !UUID.fromString(operationId).toString().equals(operationId)) {
            throw new IllegalArgumentException("attachment operation ID must be a canonical UUID");
        }
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(phase, "phase");
        receiptPath = text(receiptPath, "receipt path", 16384);
        backend = identifier(backend);
        hostContract = identifier(hostContract);
        durability = identifier(durability);
        if (debuglinkCrc32 < 0 || debuglinkCrc32 > 0xffff_ffffL) {
            throw new IllegalArgumentException("invalid GNU debuglink CRC");
        }
        files = Map.copyOf(files);
        Set<String> expected = new HashSet<>(COMMON);
        if (mode == Mode.REFRESH) {
            expected.addAll(REFRESH);
        }
        if (!files.keySet().equals(expected)) {
            throw new IllegalArgumentException("incomplete or unknown attachment artifact roles");
        }
        Artifact before = files.get("targetBefore");
        Artifact after = files.get("targetAfter");
        if (!before.path().equals(after.path()) || before.sha256().equals(after.sha256()) ||
                before.identity().equals(after.identity()) ||
                !before.metadataSha256().equals(after.metadataSha256())) {
            throw new IllegalArgumentException("attachment must bind distinct images at one target path");
        }
        Artifact backup = files.get(mode == Mode.INITIAL ? "originalBackup" : "priorTargetBackup");
        if (!before.sha256().equals(backup.sha256()) || before.bytes() != backup.bytes() ||
                !before.metadataSha256().equals(backup.metadataSha256()) ||
                before.identity().equals(backup.identity())) {
            throw new IllegalArgumentException("backup must independently preserve the prior image and metadata");
        }
        Set<String> paths = new HashSet<>();
        paths.add(receiptPath);
        for (var entry : files.entrySet()) {
            if (!entry.getKey().equals("targetAfter") && !paths.add(entry.getValue().path())) {
                throw new IllegalArgumentException("attachment receipt contains repeated artifact paths");
            }
        }
        if ((phase == Phase.PREPARED || phase == Phase.COMMITTED) != (diagnostic == null)) {
            throw new IllegalArgumentException("receipt outcome and diagnostic disagree");
        }
        if (diagnostic != null) {
            diagnostic = text(diagnostic, "diagnostic", 8192);
        }
    }

    /** Does not write a receipt. Publication must verify ownership of its previous bytes. */
    public AttachmentReceipt advance(Phase next, String reason) {
        boolean permitted = phase == Phase.PREPARED && next != Phase.PREPARED ||
            phase == Phase.RECOVERY_REQUIRED && next == Phase.ROLLED_BACK;
        if (!permitted) {
            throw new IllegalStateException("invalid attachment receipt transition: " + phase + " -> " + next);
        }
        return new AttachmentReceipt(operationId, mode, next, receiptPath, backend, hostContract,
            durability, debuglinkCrc32, files, reason);
    }

    public String toJson() {
        StringWriter result = new StringWriter();
        try (JsonWriter json = new JsonWriter(result)) {
            json.setSerializeNulls(true);
            json.beginObject();
            json.name("schemaVersion").value(1);
            json.name("operationId").value(operationId);
            json.name("mode").value(mode.name());
            json.name("phase").value(phase.name());
            json.name("receiptPath").value(receiptPath);
            json.name("backend").value(backend);
            json.name("hostContract").value(hostContract);
            json.name("durability").value(durability);
            json.name("debuglinkCrc32").value(debuglinkCrc32);
            json.name("files").beginObject();
            for (var entry : new TreeMap<>(files).entrySet()) {
                Artifact artifact = entry.getValue();
                json.name(entry.getKey()).beginObject();
                json.name("path").value(artifact.path());
                json.name("sha256").value(artifact.sha256());
                // Decimal string retains signed-long file lengths without
                // floating-point JSON conversion or the report count limit.
                json.name("bytes").value(Long.toString(artifact.bytes()));
                json.name("identity").value(artifact.identity());
                json.name("metadataSha256").value(artifact.metadataSha256());
                json.endObject();
            }
            json.endObject();
            json.name("diagnostic").value(diagnostic);
            json.endObject();
        }
        catch (IOException impossible) {
            throw new IllegalStateException("in-memory receipt encoding failed", impossible);
        }
        return result + "\n";
    }

    public static AttachmentReceipt read(Path path, BooleanSupplier cancelled) throws IOException {
        if (cancelled.getAsBoolean()) {
            throw new java.util.concurrent.CancellationException("attachment receipt read cancelled");
        }
        if (!Files.isRegularFile(path)) {
            throw new IOException("attachment receipt must be a regular file");
        }
        return read(Files.newInputStream(path), cancelled);
    }

    /** Owns and closes the supplied stream, including malformed/cancelled reads. */
    static AttachmentReceipt read(InputStream input, BooleanSupplier cancelled) throws IOException {
        try (JsonReader json = new JsonReader(new ReportJsonReader(input, cancelled, LIMITS))) {
            json.setLenient(false);
            Map<String, String> values = new TreeMap<>();
            Map<String, Artifact> artifacts = new TreeMap<>();
            Set<String> names = new HashSet<>();
            json.beginObject();
            while (json.hasNext()) {
                String name = uniqueName(json, names);
                switch (name) {
                    case "schemaVersion", "debuglinkCrc32" -> {
                        require(json, JsonToken.NUMBER);
                        values.put(name, json.nextString());
                    }
                    case "operationId", "mode", "phase", "receiptPath", "backend",
                            "hostContract", "durability" -> values.put(name, string(json));
                    case "diagnostic" -> {
                        if (json.peek() == JsonToken.NULL) {
                            json.nextNull();
                            values.put(name, null);
                        }
                        else {
                            values.put(name, string(json));
                        }
                    }
                    case "files" -> {
                        Set<String> roles = new HashSet<>();
                        json.beginObject();
                        while (json.hasNext()) {
                            String role = uniqueName(json, roles);
                            if (!COMMON.contains(role) && !REFRESH.contains(role)) {
                                throw new IOException("unknown attachment artifact role: " + role);
                            }
                            artifacts.put(role, artifact(json));
                        }
                        json.endObject();
                    }
                    default -> throw new IOException("unknown attachment receipt field: " + name);
                }
            }
            json.endObject();
            require(json, JsonToken.END_DOCUMENT);
            if (!names.equals(Set.of("schemaVersion", "operationId", "mode", "phase",
                    "receiptPath", "backend", "hostContract", "durability", "debuglinkCrc32",
                    "files", "diagnostic")) || !"1".equals(values.get("schemaVersion"))) {
                throw new IOException("incomplete or unsupported attachment receipt schema");
            }
            if (cancelled.getAsBoolean()) {
                throw new java.util.concurrent.CancellationException("attachment receipt read cancelled");
            }
            return new AttachmentReceipt(values.get("operationId"), Mode.valueOf(values.get("mode")),
                Phase.valueOf(values.get("phase")), values.get("receiptPath"), values.get("backend"),
                values.get("hostContract"), values.get("durability"),
                Long.parseLong(values.get("debuglinkCrc32")), artifacts, values.get("diagnostic"));
        }
        catch (java.util.concurrent.CancellationException cancelledRead) {
            throw cancelledRead;
        }
        catch (IllegalArgumentException | IllegalStateException invalid) {
            throw new IOException("invalid attachment receipt", invalid);
        }
    }

    private static Artifact artifact(JsonReader json) throws IOException {
        Map<String, String> fields = new TreeMap<>();
        Set<String> names = new HashSet<>();
        json.beginObject();
        while (json.hasNext()) {
            String name = uniqueName(json, names);
            if (!Set.of("path", "sha256", "bytes", "identity", "metadataSha256").contains(name)) {
                throw new IOException("unknown attachment artifact field: " + name);
            }
            fields.put(name, string(json));
        }
        json.endObject();
        if (fields.size() != 5 || !fields.get("bytes").matches("0|[1-9][0-9]{0,18}")) {
            throw new IOException("invalid attachment artifact shape or byte count");
        }
        return new Artifact(fields.get("path"), fields.get("sha256"), Long.parseLong(fields.get("bytes")),
            fields.get("identity"), fields.get("metadataSha256"));
    }

    private static String uniqueName(JsonReader json, Set<String> seen) throws IOException {
        String name = json.nextName();
        if (!seen.add(name)) {
            throw new IOException("duplicate attachment receipt field: " + name);
        }
        return name;
    }

    private static String string(JsonReader json) throws IOException {
        require(json, JsonToken.STRING);
        return json.nextString();
    }

    private static void require(JsonReader json, JsonToken expected) throws IOException {
        if (json.peek() != expected) {
            throw new IOException("attachment receipt expected " + expected);
        }
    }

    private static String identifier(String value) {
        if (value == null || !value.matches("[a-z][a-z0-9-]{0,63}")) {
            throw new IllegalArgumentException("invalid attachment contract identifier");
        }
        return value;
    }

    private static void hash(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid attachment SHA-256");
        }
    }

    private static String text(String value, String field, int limit) {
        if (value == null || value.isEmpty() || value.length() > limit) {
            throw new IllegalArgumentException("invalid attachment " + field);
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 32 || character == 127 || Character.isLowSurrogate(character) ||
                    (Character.isHighSurrogate(character) &&
                        (++index == value.length() || !Character.isLowSurrogate(value.charAt(index))))) {
                throw new IllegalArgumentException("unsupported character in attachment " + field);
            }
        }
        return value;
    }
}
