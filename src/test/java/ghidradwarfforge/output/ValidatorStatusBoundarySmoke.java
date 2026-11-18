package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Untrusted process-owner records must not turn incomplete evidence into success. */
public final class ValidatorStatusBoundarySmoke {
    private static int checks;

    private ValidatorStatusBoundarySmoke() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-validator-status-");
        try { run(root); }
        finally {
            try (var files = Files.walk(root)) {
                for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(file);
            }
        }
    }

    static void run(Path root) throws Exception {
        checks = 0;
        Path file = root.resolve("status-boundaries.json");
        var normal = fields();
        String valid = json(normal);
        var status = read(file, valid);
        require(status.equals(new ValidatorSupervisor.Status("completed", 0, 0, true, 0, 0, 0, 0)),
            "empty successful process retains all fields");
        for (String reason : List.of("completed", "tool_error", "cancelled", "timeout", "output_limit", "descendants", "internal_error")) {
            var values = fields();
            values.put("reason", "\"" + reason + "\"");
            values.put("cleanupComplete", "false");
            values.put("exitCode", "-1");
            status = read(file, json(values));
            require(status.reason().equals(reason) && !status.cleanupComplete() && status.exitCode() == -1,
                "parsing retains failure reason and incomplete cleanup without promoting success");
        }
        var wide = fields();
        wide.put("exitCode", "4294967295");
        wide.put("exitSignal", "64");
        wide.put("stdoutObserved", Long.toString(Long.MAX_VALUE));
        wide.put("stdoutRetained", "4294967296");
        wide.put("stderrObserved", "4294967297");
        wide.put("stderrRetained", "4294967297");
        status = read(file, json(wide));
        require(status.exitCode() == 0xffff_ffffL && status.exitSignal() == 64 &&
            status.stdoutObserved() == Long.MAX_VALUE && status.stdoutRetained() == 0x1_0000_0000L &&
            status.stderrObserved() == 0x1_0000_0001L && status.stderrRetained() == 0x1_0000_0001L,
            "full-width observations and Windows exit status are not narrowed");
        var reversed = new LinkedHashMap<String, String>();
        var keys = new ArrayList<>(wide.keySet());
        Collections.reverse(keys);
        for (String key : keys) reversed.put(key, wide.get(key));
        require(read(file, json(reversed)).equals(status), "field order does not change status");
        require(read(file, valid + " ".repeat(4096 - valid.length())).cleanupComplete(),
            "exact status byte limit is admitted");
        reject(file, valid + " ".repeat(4097 - valid.length()));

        for (String key : normal.keySet()) {
            var missing = fields();
            missing.remove(key);
            reject(file, json(missing));
            reject(file, valid.substring(0, valid.length() - 1) + ",\"" + key + "\":" + normal.get(key) + "}");
            for (String wrongType : List.of("null", "[]", "{}")) reject(file, changed(key, wrongType));
        }
        for (String key : List.of("schemaVersion", "exitCode", "exitSignal", "stdoutObserved", "stdoutRetained", "stderrObserved", "stderrRetained")) {
            for (String invalid : List.of("\"0\"", "true", "-2", "0.0", "1e0", "-0", "9223372036854775808", "12345678901234567890")) {
                reject(file, changed(key, invalid));
            }
        }
        for (String key : List.of("schemaVersion", "exitSignal", "stdoutObserved", "stdoutRetained", "stderrObserved", "stderrRetained")) {
            reject(file, changed(key, "-1"));
        }
        for (String invalid : List.of("0", "2")) reject(file, changed("schemaVersion", invalid));
        for (String invalid : List.of("false", "0", "\"unknown\"", "\"\"", "\"complété\"")) reject(file, changed("reason", invalid));
        for (String invalid : List.of("\"true\"", "1")) reject(file, changed("cleanupComplete", invalid));
        reject(file, changed("stdoutRetained", "1"));
        reject(file, changed("stderrRetained", "1"));
        reject(file, changed("exitCode", "4294967296"));
        reject(file, changed("exitSignal", "65"));
        var unknown = fields();
        unknown.put("unexpected", "0");
        reject(file, json(unknown));
        for (String malformed : List.of("", "[]", "null", "{", valid.substring(0, valid.length() - 1), valid + "{}", valid + " trailing")) {
            reject(file, malformed);
        }
        Files.delete(file);
        try { ValidatorSupervisor.readStatus(file); throw new AssertionError("missing process status admitted"); }
        catch (IOException expected) { checks++; }
        System.out.println("validator-status-boundaries=PASS checks=" + checks);
    }

    private static Map<String, String> fields() {
        var fields = new LinkedHashMap<String, String>();
        fields.put("schemaVersion", "1");
        fields.put("reason", "\"completed\"");
        fields.put("exitCode", "0");
        fields.put("exitSignal", "0");
        fields.put("cleanupComplete", "true");
        fields.put("stdoutObserved", "0");
        fields.put("stdoutRetained", "0");
        fields.put("stderrObserved", "0");
        fields.put("stderrRetained", "0");
        return fields;
    }

    private static String changed(String key, String value) {
        var fields = fields();
        fields.put(key, value);
        return json(fields);
    }

    private static String json(Map<String, String> fields) {
        return "{" + String.join(",", fields.entrySet().stream().map(e -> "\"" + e.getKey() + "\":" + e.getValue()).toList()) + "}";
    }

    private static ValidatorSupervisor.Status read(Path path, String text) throws IOException {
        Files.writeString(path, text, StandardCharsets.UTF_8);
        return ValidatorSupervisor.readStatus(path);
    }

    private static void reject(Path path, String text) throws IOException {
        Files.writeString(path, text, StandardCharsets.UTF_8);
        try { ValidatorSupervisor.readStatus(path); throw new AssertionError("invalid process status admitted: " + text); }
        catch (IOException expected) { checks++; }
        require(Files.readString(path, StandardCharsets.UTF_8).equals(text), "rejection preserves diagnostic evidence");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
