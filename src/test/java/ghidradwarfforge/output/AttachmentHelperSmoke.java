package ghidradwarfforge.output;

import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

/** Admission is read-only. Native helper/validator/GDB acceptance runs in CI. */
public final class AttachmentHelperSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-helper-λ ");
        try {
            for (String role : new String[] {"target", "sidecar", "source", "report", "helper", "readelf", "llvm", "strict", "configuration"}) {
                Files.writeString(root.resolve(role), "owned input " + role);
            }
            var request = new AttachmentOperation.Request(root.resolve("target"), root.resolve("sidecar"), root.resolve("source"),
                root.resolve("report"), root.resolve("original.backup"), root.resolve("validation.json"),
                root.resolve("receipt.json"), root.resolve("recovery.json"), root.resolve("restore"), null);
            var tools = new HashMap<String, Path>();
            for (String role : new String[] {"helper", "readelf", "llvm", "strict", "configuration"}) tools.put(role, root.resolve(role));
            var invocation = new AttachmentInvocation(request, tools);
            Path selection = root.resolve("request.json");
            Files.writeString(selection, invocation.toJson());
            String[] command = {"--request", selection.toString(), "--request-sha256", digest(selection), "--confirm-target-change"};
            var before = snapshot(root);
            var admitted = AttachmentHelper.admit(command, () -> false);
            equal(invocation, admitted.invocation());
            admitted.plan().recheck();
            equal(before, snapshot(root));
            for (String[] rejected : new String[][] {
                    {}, {"--confirm-target-change"}, Arrays.copyOf(command, 4),
                    {"--request", selection.toString(), "--confirm-target-change"},
                    {"--request", "relative", "--request-sha256", digest(selection), "--confirm-target-change"},
                    {"--request", selection.toString(), "--request-sha256", "0".repeat(64), "--confirm-target-change"},
                    {"--request", selection.toString(), "--request-sha256", "invalid", "--confirm-target-change"},
                    append(command, "--confirm-target-change"), append(command, "--elevate"),
                    append(command, "--request", selection.toString()), append(command, "--request"),
                    append(command, "--request-sha256", digest(selection)),
                    append(command, "--recover"), append(command, "--recover", "--recover"),
                    append(command, "--cancel-on-stdin", "--cancel-on-stdin") }) {
                failure(rejected, false, "FAILED", 1);
                equal(before, snapshot(root));
            }
            failure(command, true, "CANCELLED", 130);
            equal(before, snapshot(root));
            equal(true, AttachmentHelper.command(append(command, "--cancel-on-stdin")).cancelOnStdin());

            // A changed request of the same size and mtime must fail its content pin.
            var mtime = Files.getLastModifiedTime(selection);
            String initial = Files.readString(selection);
            Files.writeString(selection, initial.replace("restore", "changed"));
            Files.setLastModifiedTime(selection, mtime);
            failure(command, false, "FAILED", 1);
            Files.writeString(selection, initial);
            Files.setLastModifiedTime(selection, mtime);
            admitted.plan().recheck();
            // Changing only a selected tool is detected by the retained path plan.
            Files.writeString(root.resolve("helper"), "different validator helper contents");
            try { admitted.plan().recheck(); throw new AssertionError("changed helper admitted"); }
            catch (IOException expected) { checks++; }

            // A transport that aliases a target cannot be used even with a fresh digest.
            Files.writeString(root.resolve("target"), initial);
            String[] alias = {"--request", root.resolve("target").toString(), "--request-sha256",
                digest(root.resolve("target")), "--confirm-target-change"};
            failure(alias, false, "FAILED", 1);
            // A large request is bounded before JSON parsing and before native work.
            Files.writeString(selection, " ".repeat(256 * 1024 + 1));
            command[3] = digest(selection);
            failure(command, false, "FAILED", 1);
            var help = new ByteArrayOutputStream();
            equal(0, AttachmentHelper.run(new String[] {"--help"}, () -> false, new PrintStream(help)));
            equal(true, help.toString(StandardCharsets.UTF_8).contains("changes the selected executable"));
            System.out.println("attachment-helper-smoke=PASS checks=" + checks + " admission-only=true native-execution=false");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void failure(String[] args, boolean cancelled, String outcome, int status) {
        var output = new ByteArrayOutputStream();
        equal(status, AttachmentHelper.run(args, () -> cancelled, new PrintStream(output)));
        var result = JsonParser.parseString(output.toString(StandardCharsets.UTF_8)).getAsJsonObject();
        equal(outcome, result.get("outcome").getAsString());
        equal(status, result.get("exitCode").getAsInt());
        equal(false, result.has("recoverySelection"));
    }

    private static String[] append(String[] args, String... additional) {
        var result = new ArrayList<>(Arrays.asList(args));
        result.addAll(Arrays.asList(additional));
        return result.toArray(String[]::new);
    }

    private static String digest(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static Map<String, String> snapshot(Path root) throws Exception {
        var result = new HashMap<String, String>();
        try (var paths = Files.list(root)) {
            for (var path : paths.toList()) result.put(path.toString(), digest(path));
        }
        return result;
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected " + expected + " but got " + actual);
        checks++;
    }
}
