package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Explicit selections transported from a CLI or GUI to the isolated helper.
 * Parsing never executes tools, follows receipt fields, creates files or grants
 * authority. The entry point must separately obtain explicit target-change and
 * privilege consent, then perform live validation and the full host transaction.
 * Absolute paths preserve selections across an authorization-driven cwd change;
 * traversal is resolved by AttachmentPaths, never by lexical normalization here.
 */
public record AttachmentInvocation(AttachmentOperation.Request operation, Map<String, Path> validatorTools) {
    private static final Set<String> COMMON = Set.of("target", "sidecar", "source", "exportReport",
        "originalBackup", "validationEvidence", "receipt", "recoveryReceipt", "restoreImage");
    private static final Set<String> REFRESH = Set.of("previousReceipt", "previousSidecar", "previousSource", "priorTargetBackup");
    private static final Set<String> TOOLS = Set.of("helper", "readelf", "llvm", "strict", "configuration");
    private static final ReportJsonReader.Limits LIMITS = new ReportJsonReader.Limits(256 * 1024, 16384, 3, 128, 1);

    public AttachmentInvocation {
        Objects.requireNonNull(operation, "operation");
        validatorTools = Map.copyOf(validatorTools);
        if (!validatorTools.keySet().equals(TOOLS)) throw new IllegalArgumentException("select every validator tool explicitly");
        for (var path : paths(operation).values()) absolute(path);
        for (var path : validatorTools.values()) absolute(path);
    }

    /** Include the transport and tools in preflight before any helper workspace. */
    public AttachmentPaths.Plan preflight(Path selectedInvocationFile) throws IOException {
        var selections = new ArrayList<>(AttachmentOperation.preflightPaths(operation).selections());
        selections.add(new AttachmentPaths.Selection("invocation", selectedInvocationFile, AttachmentPaths.Kind.INPUT));
        for (var entry : validatorTools.entrySet()) {
            selections.add(new AttachmentPaths.Selection("tool" + entry.getKey(), entry.getValue(), AttachmentPaths.Kind.INPUT));
        }
        return AttachmentPaths.preflight(selections);
    }

    public AttachmentValidator validator() throws IOException {
        return new AttachmentValidator(validatorTools.get("helper"), validatorTools.get("readelf"),
            validatorTools.get("llvm"), validatorTools.get("strict"), validatorTools.get("configuration"));
    }

    public String toJson() {
        var text = new StringWriter();
        try (var json = new JsonWriter(text)) {
            json.beginObject();
            json.name("schemaVersion").value(1);
            json.name("operation").value(operation.refresh() == null ? "ATTACH" : "REFRESH");
            writePaths(json.name("paths"), paths(operation));
            writePaths(json.name("validatorTools"), validatorTools);
            json.endObject();
        }
        catch (IOException impossible) { throw new IllegalStateException("in-memory invocation encoding failed", impossible); }
        String result = text + "\n";
        if (result.getBytes(StandardCharsets.UTF_8).length > LIMITS.bytes()) {
            throw new IllegalArgumentException("attachment invocation exceeds transport byte limit");
        }
        return result;
    }

    public static AttachmentInvocation read(Path file, BooleanSupplier cancelled) throws IOException {
        if (cancelled.getAsBoolean()) throw new CancellationException("attachment invocation read cancelled");
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("attachment invocation must be a regular non-link file");
        }
        return read(Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS), cancelled);
    }

    /** Owns and closes its bounded, strictly decoded stream, including rejection/cancellation. */
    static AttachmentInvocation read(InputStream input, BooleanSupplier cancelled) throws IOException {
        try (var json = new JsonReader(new ReportJsonReader(input, cancelled, LIMITS))) {
            json.setLenient(false);
            var names = new HashSet<String>();
            String version = null;
            String action = null;
            Map<String, Path> paths = null;
            Map<String, Path> tools = null;
            json.beginObject();
            while (json.hasNext()) {
                String name = unique(json, names);
                switch (name) {
                    case "schemaVersion" -> {
                        require(json.peek() == JsonToken.NUMBER, "invocation version must be an integer");
                        version = json.nextString();
                    }
                    case "operation" -> action = string(json);
                    case "paths" -> paths = readPaths(json);
                    case "validatorTools" -> tools = readPaths(json);
                    default -> throw new IOException("unknown attachment invocation field: " + name);
                }
            }
            json.endObject();
            require(json.peek() == JsonToken.END_DOCUMENT && names.size() == 4 && "1".equals(version),
                "incomplete or unsupported attachment invocation");
            require("ATTACH".equals(action) || "REFRESH".equals(action), "unsupported attachment operation");
            var expected = new HashSet<>(COMMON);
            if ("REFRESH".equals(action)) expected.addAll(REFRESH);
            require(paths != null && paths.keySet().equals(expected) && tools != null && tools.keySet().equals(TOOLS),
                "attachment invocation requires the exact selected path/tool roles");
            var refresh = "REFRESH".equals(action) ? new AttachmentOperation.Refresh(paths.get("previousReceipt"),
                paths.get("previousSidecar"), paths.get("previousSource"), paths.get("priorTargetBackup")) : null;
            return new AttachmentInvocation(new AttachmentOperation.Request(paths.get("target"), paths.get("sidecar"),
                paths.get("source"), paths.get("exportReport"), paths.get("originalBackup"), paths.get("validationEvidence"),
                paths.get("receipt"), paths.get("recoveryReceipt"), paths.get("restoreImage"), refresh), tools);
        }
        catch (CancellationException cancelledRead) { throw cancelledRead; }
        catch (IllegalArgumentException | IllegalStateException invalid) {
            throw new IOException("invalid attachment invocation", invalid);
        }
    }

    private static Map<String, Path> paths(AttachmentOperation.Request request) {
        var paths = new TreeMap<String, Path>();
        paths.put("target", request.target());
        paths.put("sidecar", request.sidecar());
        paths.put("source", request.source());
        paths.put("exportReport", request.exportReport());
        paths.put("originalBackup", request.originalBackup());
        paths.put("validationEvidence", request.validationEvidence());
        paths.put("receipt", request.receipt());
        paths.put("recoveryReceipt", request.recoveryReceipt());
        paths.put("restoreImage", request.restoreImage());
        if (request.refresh() != null) {
            paths.put("previousReceipt", request.refresh().previousReceipt());
            paths.put("previousSidecar", request.refresh().previousSidecar());
            paths.put("previousSource", request.refresh().previousSource());
            paths.put("priorTargetBackup", request.refresh().priorTargetBackup());
        }
        return paths;
    }

    private static void writePaths(JsonWriter json, Map<String, Path> paths) throws IOException {
        json.beginObject();
        for (var entry : new TreeMap<>(paths).entrySet()) json.name(entry.getKey()).value(entry.getValue().toString());
        json.endObject();
    }

    private static Map<String, Path> readPaths(JsonReader json) throws IOException {
        var paths = new TreeMap<String, Path>();
        var names = new HashSet<String>();
        json.beginObject();
        while (json.hasNext()) paths.put(unique(json, names), Path.of(string(json)));
        json.endObject();
        return paths;
    }

    private static String unique(JsonReader json, Set<String> names) throws IOException {
        String name = json.nextName();
        require(names.add(name), "duplicate attachment invocation field: " + name);
        return name;
    }

    private static String string(JsonReader json) throws IOException {
        require(json.peek() == JsonToken.STRING, "invocation field must be a string");
        return json.nextString();
    }

    private static void absolute(Path path) {
        if (path == null || !path.isAbsolute() || path.toString().length() > 16384) {
            throw new IllegalArgumentException("attachment selections require bounded absolute paths");
        }
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
