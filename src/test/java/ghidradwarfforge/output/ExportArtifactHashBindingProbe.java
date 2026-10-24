package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

/** Installed-JAR adapter for explicitly selected report and artifact files. */
public final class ExportArtifactHashBindingProbe {
    private ExportArtifactHashBindingProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean rejected = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = rejected ? 1 : 0;
        if (arguments.length == start || (arguments.length - start) % 4 != 0) {
            throw new IllegalArgumentException("supply groups of report, original, sidecar and source");
        }
        origin("binding", ExportArtifactHashBinding.class);
        origin("digests", FileDigests.class);
        origin("claims", ExportReportClaims.class);
        origin("gson", JsonReader.class);
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        Gson gson = new Gson();
        for (int index = start; index < arguments.length; index += 4) {
            try {
                ExportArtifactHashBinding.Result result = ExportArtifactHashBinding.observe(
                    Path.of(arguments[index]), Path.of(arguments[index + 1]),
                    Path.of(arguments[index + 2]), Path.of(arguments[index + 3]));
                if (rejected) {
                    throw new AssertionError("expected rejection returned complete observations");
                }
                Map<String, Object> encoded = new LinkedHashMap<>();
                encoded.put("claims", result.claims());
                encoded.put("original", artifact(result.original()));
                encoded.put("sidecar", artifact(result.sidecar()));
                encoded.put("source", artifact(result.source()));
                System.out.println("binding-base64=" + base64(gson.toJson(encoded)));
            }
            catch (IOException failure) {
                if (!rejected) {
                    throw failure;
                }
                String message = failure.getMessage();
                if (message == null || message.isBlank()) {
                    throw new AssertionError("rejection has no diagnostic", failure);
                }
                System.out.println("rejected=" + failure.getClass().getName() +
                    " diagnostic=" + base64(message) + " terminal=" +
                    (failure instanceof ExportReportClaims.TerminalReportException terminal
                        ? terminal.status().name() : "-"));
            }
        }
    }

    private static Map<String, Object> artifact(ExportArtifactHashBinding.Artifact artifact) {
        Map<String, Object> encoded = new LinkedHashMap<>();
        encoded.put("selectedPath", artifact.selectedPath().toString());
        encoded.put("observed", artifact.observed());
        encoded.put("agreement", artifact.agreement().name());
        return encoded;
    }

    private static void origin(String name, Class<?> type) throws Exception {
        System.out.println(name + "-class-source=" + type.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
