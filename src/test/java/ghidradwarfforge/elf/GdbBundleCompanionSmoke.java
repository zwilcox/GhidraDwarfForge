package ghidradwarfforge.elf;

import com.google.gson.JsonParser;
import ghidradwarfforge.output.SourceBundleFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/** Bind an actual exported bundle, including the private staged index used during publication. */
public final class GdbBundleCompanionSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("original sidecar index");
        Path original = Path.of(args[0]), sidecar = Path.of(args[1]), source = Path.of(args[2]);
        var bundle = SourceBundleFiles.open(source, () -> false).orElseThrow();
        Path stage = Files.createTempFile(source.getParent(), ".forge-companion-index-", ".staged");
        Path elsewhere = Files.createTempDirectory(source.getParent(), ".forge-companion-other-");
        try {
            Files.write(stage, Files.readAllBytes(source));
            AtomicInteger visits = new AtomicInteger();
            String generated = GdbCompanion.render(original, sidecar, stage, sidecar, source,
                () -> { visits.incrementAndGet(); return false; });
            String repeated = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false);
            if (!generated.equals(repeated)) throw new AssertionError("staging path leaked into companion identity");
            Path published = Path.of(sidecar + ".gdb.py");
            if (!generated.equals(Files.readString(published))) {
                throw new AssertionError("published companion differs from current production generator/runtime");
            }
            var encoded = Pattern.compile("manifest = json.loads\\(base64.b64decode\\('([^']+)'\\)\\)").matcher(generated);
            if (!encoded.find()) throw new AssertionError("missing manifest payload");
            var manifest = JsonParser.parseString(new String(Base64.getDecoder().decode(encoded.group(1)),
                StandardCharsets.UTF_8)).getAsJsonObject();
            if (manifest.get("schema").getAsInt() != 2) throw new AssertionError("missing bundle manifest schema");
            var files = manifest.getAsJsonArray("source_files");
            if (files.size() != bundle.dependencies().size()) throw new AssertionError("omitted source dependencies");
            for (int index = 0; index < files.size(); index++) {
                var expected = bundle.dependencies().get(index);
                var actual = files.get(index).getAsJsonObject();
                if (!actual.get("name").getAsString().equals(expected.name()) ||
                        !actual.get("sha256").getAsString().equals(expected.sha256()) ||
                        actual.get("bytes").getAsLong() != expected.bytes()) {
                    throw new AssertionError("dependency inventory differs");
                }
            }
            try {
                GdbCompanion.render(original, sidecar, stage, sidecar, elsewhere.resolve(source.getFileName()), () -> false);
                throw new AssertionError("non-colocated final bundle accepted");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("co-located")) throw expected;
            }
            for (int stop : new int[] {1, visits.get() / 2, visits.get()}) {
                AtomicInteger reached = new AtomicInteger();
                try {
                    GdbCompanion.render(original, sidecar, stage, sidecar, source,
                        () -> reached.incrementAndGet() == stop);
                    throw new AssertionError("missed companion cancellation at " + stop);
                }
                catch (CancellationException expected) { }
            }
            bundle.verify(() -> false);
            System.out.println("gdb-bundle-companion-smoke=PASS dependencies=" + files.size() +
                " sampledCancellation=3 observedBoundaries=" + visits.get());
        }
        finally {
            Files.deleteIfExists(stage);
            Files.delete(elsewhere);
        }
    }
}
