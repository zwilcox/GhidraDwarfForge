package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

/** Installed-JAR adapter; does not resolve or open artifact paths in a report. */
public final class ExportReportClaimsProbe {
    private ExportReportClaimsProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean rejected = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = rejected ? 1 : 0;
        if (arguments.length == start) {
            throw new IllegalArgumentException("supply report files");
        }
        System.out.println("claims-class-source=" + ExportReportClaims.class
            .getProtectionDomain().getCodeSource().getLocation().toURI());
        System.out.println("gson-class-source=" + JsonReader.class
            .getProtectionDomain().getCodeSource().getLocation().toURI());
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        Gson gson = new Gson();
        for (int index = start; index < arguments.length; index++) {
            try {
                ExportReportClaims claims = ExportReportClaims.read(Path.of(arguments[index]));
                if (rejected) {
                    throw new AssertionError("malformed or terminal report returned completed claims");
                }
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("schemaVersion", claims.schemaVersion());
                result.put("status", claims.status().name());
                result.put("target", claims.target());
                result.put("artifacts", claims.artifacts());
                result.put("counts", claims.counts());
                result.put("validationStatus", claims.validationStatus().name());
                result.put("libdwarfVersion", claims.libdwarfVersion());
                // Keep the test protocol independent of stdout's host charset.
                System.out.println("claims-base64=" + Base64.getEncoder().encodeToString(
                    gson.toJson(result).getBytes(StandardCharsets.UTF_8)));
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
                    " diagnostic=" + Base64.getEncoder().encodeToString(
                        message.getBytes(StandardCharsets.UTF_8)) + " terminal=" +
                    (failure instanceof ExportReportClaims.TerminalReportException terminal
                        ? terminal.status().name() : "-"));
            }
        }
    }
}
