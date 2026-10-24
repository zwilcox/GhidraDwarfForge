package ghidradwarfforge.output;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.CRC32;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Current writer reports with independently calculated selected-byte claims. */
final class ExportArtifactHashBindingFixtures {
    record Pair(Path root, Path report, Path original, Path sidecar, Path source) {
        List<Path> artifacts() {
            return List.of(original, sidecar, source);
        }

        List<Path> all() {
            return List.of(report, original, sidecar, source);
        }
    }

    private ExportArtifactHashBindingFixtures() {
    }

    static Pair create(Path root, boolean partial) throws Exception {
        Files.createDirectories(root);
        Pair pair = new Pair(root, root.resolve("report.json"), root.resolve("input"),
            root.resolve("sidecar"), root.resolve("source"));
        byte[] original = new byte[65537];
        for (int index = 0; index < original.length; index++) {
            original[index] = (byte) (index * 17 + 3);
        }
        // Plain data is intentional: this helper must not infer valid ELF or C.
        Files.write(pair.original(), original);
        Files.writeString(pair.sidecar(), "not an ELF sidecar\n", StandardCharsets.UTF_8);
        Files.writeString(pair.source(), "claimed source 😀\n", StandardCharsets.UTF_8);
        write(pair, partial);
        return pair;
    }

    static void write(Pair pair, boolean partial) throws Exception {
        JsonObject json = JsonParser.parseString(ExportReportClaimsFixtures.completed(partial)
            .toJson()).getAsJsonObject();
        JsonObject artifacts = json.getAsJsonObject("artifacts");
        List<Path> paths = pair.artifacts();
        String[] roles = { "input", "output", "source" };
        for (int index = 0; index < roles.length; index++) {
            artifacts.addProperty(roles[index] + "Path", paths.get(index).toString());
            artifacts.addProperty(roles[index] + "Sha256", hash(paths.get(index)));
        }
        Files.writeString(pair.report(), json.toString(), StandardCharsets.UTF_8);
    }

    static JsonObject report(Pair pair) throws Exception {
        return JsonParser.parseString(Files.readString(pair.report(), StandardCharsets.UTF_8))
            .getAsJsonObject();
    }

    static String hash(Path file) throws Exception {
        return expected(Files.readAllBytes(file)).sha256();
    }

    static FileDigests.Result expected(byte[] bytes) throws Exception {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return new FileDigests.Result(HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(bytes)), crc.getValue(), bytes.length);
    }
}
