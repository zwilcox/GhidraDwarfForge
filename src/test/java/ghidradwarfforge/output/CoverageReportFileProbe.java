package ghidradwarfforge.output;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import com.google.gson.JsonObject;

/** Standalone retained-file decoder/roundtrip measurement; no referenced artifact is opened. */
public final class CoverageReportFileProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("supply one schema-two report");
        var report = Path.of(args[0]);
        var before = FileDigests.read(report);
        long start = System.nanoTime();
        var claims = ExportReportClaims.readWithCoverage(report, () -> false);
        long readNanos = System.nanoTime() - start;
        if (claims.coverage() == null) throw new IllegalArgumentException("coverage is unavailable");
        start = System.nanoTime();
        String roundtrip = CoverageReportJson.write(claims.coverage().coverage(), claims.coverage().profile(), () -> false);
        byte[] bytes = roundtrip.getBytes(StandardCharsets.UTF_8);
        long writeNanos = System.nanoTime() - start;
        if (!FileDigests.read(report).equals(before)) throw new AssertionError("report changed");
        var result = new JsonObject();
        result.addProperty("status", "PARSED");
        result.addProperty("scope", "reported internal consistency and payload roundtrip, not artifact verification");
        result.addProperty("reportSha256", before.sha256());
        result.addProperty("functions", claims.coverage().coverage().functions().size());
        result.addProperty("recoveredVariables", claims.coverage().coverage().variables().recoveredVariables());
        result.addProperty("readNanos", readNanos);
        result.addProperty("payloadWriteNanos", writeNanos);
        result.addProperty("payloadUtf8Bytes", bytes.length);
        result.addProperty("payloadRoundtripSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        System.out.println(result);
    }
}
