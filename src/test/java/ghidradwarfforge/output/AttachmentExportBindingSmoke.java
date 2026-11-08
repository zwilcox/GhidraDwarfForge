package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** ELF/report agreement controls. Deliberately malformed DWARF is not validation. */
public final class AttachmentExportBindingSmoke {
    private static final AttachmentReceiptStore.Host HOST = new AttachmentReceiptStoreSmoke.Host();
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-export-binding-");
        try {
            Path c = root.resolve("fixture.c");
            Files.writeString(c, "int main(void) { return 0; }\n");
            Path original = root.resolve("input.elf");
            var process = new ProcessBuilder("cc", "-g0", "-fno-pie", "-no-pie", "-Wl,--build-id=sha1",
                "-o", original.toString(), c.toString()).inheritIO().start();
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor();
                throw new AssertionError("fixture compiler timed out");
            }
            equal(0, process.exitValue());
            Path sidecar = root.resolve("input.elf.dbg");
            // Invalid on purpose: successful identity binding MUST NOT imply a
            // successful structural validator or set report validation to PASS.
            new MatchedElfSidecarWriter().write(original, sidecar, Map.of(".debug_info", new byte[] {1, 2, 3}));
            Path source = root.resolve("input.elf.dbg.c");
            Files.writeString(source, "/* synthetic binding fixture */\n");
            Path report = root.resolve("report.json");
            var pair = new ExportArtifactHashBindingFixtures.Pair(root, report, original, sidecar, source);
            for (boolean partial : new boolean[] {false, true}) {
                ExportArtifactHashBindingFixtures.write(pair, partial);
                var binding = observe(pair);
                equal(partial ? ExportReport.Status.PARTIAL : ExportReport.Status.SUCCESS, binding.claims().status());
                equal(ExportReport.ValidationStatus.NOT_RUN, binding.claims().validationStatus());
                equal(4, binding.files().size());
                binding.recheck(HOST, () -> false);
                checks++;
            }
            // Full file bytes and host observations must still agree, including
            // a same-length edit whose mtime is restored.
            for (Path file : pair.all()) {
                var binding = observe(pair);
                byte[] before = Files.readAllBytes(file);
                FileTime modified = Files.getLastModifiedTime(file);
                byte[] changed = before.clone();
                changed[changed.length - 1] ^= 1;
                Files.write(file, changed);
                Files.setLastModifiedTime(file, modified);
                reject(() -> binding.recheck(HOST, () -> false));
                Files.write(file, before);
                Files.setLastModifiedTime(file, modified);
            }
            var binding = observe(pair);
            byte[] originalBytes = Files.readAllBytes(original);
            Path replacement = root.resolve("replacement");
            Files.copy(original, replacement, StandardCopyOption.COPY_ATTRIBUTES);
            Files.move(replacement, original, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            reject(() -> binding.recheck(HOST, () -> false));
            equal(java.util.Arrays.toString(originalBytes), java.util.Arrays.toString(Files.readAllBytes(original)));

            for (Path file : pair.artifacts()) {
                byte[] before = Files.readAllBytes(file);
                Files.writeString(file, "unrelated bytes");
                reject(() -> observe(pair));
                Files.write(file, before);
            }
            byte[] reportBytes = Files.readAllBytes(report);
            JsonObject json = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
            json.getAsJsonObject("target").addProperty("architecture", "wrong-target");
            Files.writeString(report, json.toString());
            reject(() -> observe(pair));
            Files.write(report, reportBytes);

            byte[] sidecarBytes = Files.readAllBytes(sidecar);
            // Rehashing the report does not excuse changes to retained ELF bytes.
            byte[] damaged = sidecarBytes.clone();
            damaged[64] ^= 1;
            Files.write(sidecar, damaged);
            ExportArtifactHashBindingFixtures.write(pair, true);
            reject(() -> observe(pair));
            Files.write(sidecar, sidecarBytes);
            ExportArtifactHashBindingFixtures.write(pair, true);

            Path hardlink = root.resolve("hardlink");
            Files.createLink(hardlink, original);
            reject(() -> observe(pair));
            Files.delete(hardlink);
            Path link = root.resolve("symlink");
            Files.createSymbolicLink(link, original);
            reject(() -> AttachmentExportBinding.observe(report, link, sidecar, source, HOST, () -> false));
            reject(() -> AttachmentExportBinding.observe(report, original, original, source, HOST, () -> false));
            Files.delete(link);
            var otherHost = new AttachmentReceiptStoreSmoke.Host() {
                @Override public String contract() { return "different-contract"; }
            };
            var observed = observe(pair);
            reject(() -> observed.recheck(otherHost, () -> false));

            for (int limit : new int[] {1, 10, 100, 1000}) {
                AtomicInteger calls = new AtomicInteger();
                try {
                    AttachmentExportBinding.observe(report, original, sidecar, source, HOST,
                        () -> calls.incrementAndGet() >= limit);
                    throw new AssertionError("expected cancellation at " + limit);
                }
                catch (CancellationException expected) { checks++; }
            }
            // A change between initial observation and final checks must not
            // produce a successful binding, even with unchanged report claims.
            AtomicInteger inspections = new AtomicInteger();
            var changingHost = new AttachmentReceiptStoreSmoke.Host() {
                @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
                    if (path.equals(source) && inspections.incrementAndGet() == 3) {
                        Files.writeString(source, "changed during observation");
                    }
                    return super.inspect(path);
                }
            };
            reject(() -> AttachmentExportBinding.observe(report, original, sidecar, source, changingHost, () -> false));
            equal(originalBytes.length, Files.readAllBytes(original).length);
            System.out.println("attachment-export-binding-smoke=PASS checks=" + checks +
                " writes-to-selected-inputs=false-by-production dwarf-validation=false");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static AttachmentExportBinding observe(ExportArtifactHashBindingFixtures.Pair pair) throws IOException {
        return AttachmentExportBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source(), HOST, () -> false);
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected rejection"); }
        catch (IOException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
