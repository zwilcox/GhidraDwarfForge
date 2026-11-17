package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonParser;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Read-only binding of real exporter artifacts; mutations affect owned copies only. */
public final class AttachmentBundleBindingProbe {
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("report original sidecar index fresh-work-directory");
        Path work = Files.createDirectory(Path.of(args[4])).toRealPath();
        var selected = SourceBundleFiles.open(Path.of(args[3]), () -> false).orElseThrow();
        if (selected.manifest().parts().size() < 2) throw new AssertionError("need multiple source parts");
        Path report = Files.copy(Path.of(args[0]), work.resolve("report.json"));
        Path original = Files.copy(Path.of(args[1]), work.resolve("original"));
        Path sidecar = Files.copy(Path.of(args[2]), work.resolve("sidecar.dbg"));
        for (Path file : selected.files()) Files.copy(file, work.resolve(file.getFileName()));
        Path index = work.resolve(Path.of(args[3]).getFileName());
        var host = new AttachmentReceiptStoreSmoke.Host();
        var bundle = SourceBundleFiles.open(index, () -> false).orElseThrow();
        var dependencies = bundle.files().subList(1, bundle.files().size());
        var protectedPaths = new ArrayList<>(List.of(report, original, sidecar));
        protectedPaths.addAll(bundle.files());
        var before = hashes(protectedPaths);
        var binding = AttachmentExportBinding.observe(report, original, sidecar, index, host, () -> false);
        equal(dependencies, binding.sourceDependencies().stream().map(AttachmentFileStore.Snapshot::path).toList());
        binding.recheck(host, () -> false);
        checks++;
        // A retained private index keeps its original DWARF basename explicit.
        Path retained = Files.copy(index, work.resolve("private-source-backup"));
        var backup = AttachmentExportBinding.observe(report, original, sidecar, retained,
            index.getFileName().toString(), host, () -> false);
        equal(dependencies, backup.sourceDependencies().stream().map(AttachmentFileStore.Snapshot::path).toList());
        Files.delete(retained);

        for (Path dependency : dependencies) {
            var observed = binding;
            byte[] bytes = Files.readAllBytes(dependency);
            var modified = Files.getLastModifiedTime(dependency);
            byte[] changed = bytes.clone();
            changed[changed.length - 1] ^= 1;
            Files.write(dependency, changed);
            Files.setLastModifiedTime(dependency, modified);
            rejects(() -> observed.recheck(host, () -> false), "changed bundle dependency accepted");
            Files.write(dependency, bytes);
            Files.setLastModifiedTime(dependency, modified);
            binding.recheck(host, () -> false);
            checks++;

            Path moved = work.resolve("missing-dependency");
            Files.move(dependency, moved);
            rejects(() -> observed.recheck(host, () -> false), "missing bundle dependency accepted");
            Files.move(moved, dependency);
            binding.recheck(host, () -> false);
            checks++;

            // Identical bytes with a different inode must still invalidate the binding.
            Path replacement = work.resolve("replacement-dependency");
            Files.copy(dependency, replacement, StandardCopyOption.COPY_ATTRIBUTES);
            Files.move(replacement, dependency, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            rejects(() -> observed.recheck(host, () -> false), "replaced bundle dependency accepted");
            equal(AttachmentHelper.sha256(bytes), FileDigests.read(dependency, () -> false).sha256());
            binding = AttachmentExportBinding.observe(report, original, sidecar, index, host, () -> false);
        }

        byte[] indexBytes = Files.readAllBytes(index);
        byte[] reportBytes = Files.readAllBytes(report);
        var manifest = bundle.manifest();
        String otherInput = manifest.inputSha256().equals("0".repeat(64)) ? "1".repeat(64) : "0".repeat(64);
        var wrongInput = new SourceBundle.Manifest(manifest.indexName(), otherInput,
            manifest.logicalSourceSha256(), manifest.targetLines(), manifest.parts(), manifest.functions());
        byte[] wrongBytes = SourceBundle.render(wrongInput, () -> false);
        String wrongHash = SourceBundle.sha256(wrongBytes);
        Files.write(work.resolve(SourceBundle.manifestNameFor(wrongHash)), wrongBytes);
        Files.write(index, SourceBundle.renderIndex(wrongInput, wrongHash, () -> false));
        rehashSource(report, index);
        rejectsMessage(() -> AttachmentExportBinding.observe(report, original, sidecar, index, host, () -> false),
            "source bundle input differs from the selected original ELF");
        Files.write(index, indexBytes);
        Files.write(report, reportBytes);

        // A valid inventory for different synthetic text must not excuse a mismatched DWARF file table.
        var unrelated = SourceBundle.prepare(manifest.inputSha256(), manifest.indexName(),
            SyntheticSourceFile.build("binding-control", "test", List.of(
                new SyntheticSourceFile.FunctionText("unrelated", 0x1000, "int unrelated(void) { return 7; }\n", null))),
            3, () -> false);
        SourceBundleStore.install(index, unrelated, List.of(), () -> false);
        Files.write(index, unrelated.indexBytes(() -> false));
        rehashSource(report, index);
        rejectsMessage(() -> AttachmentExportBinding.observe(report, original, sidecar, index, host, () -> false),
            "DWARF source files differ from the selected source bundle");
        Files.write(index, indexBytes);
        Files.write(report, reportBytes);

        Path part = dependencies.get(1);
        byte[] partBytes = Files.readAllBytes(part);
        AtomicInteger changes = new AtomicInteger();
        var changingHost = new AttachmentReceiptStoreSmoke.Host() {
            @Override public AttachmentReceiptStore.Fingerprint inspect(Path path) throws IOException {
                if (path.equals(part) && changes.getAndIncrement() == 0) {
                    byte[] changed = partBytes.clone();
                    changed[changed.length - 1] ^= 1;
                    Files.write(path, changed);
                }
                return super.inspect(path);
            }
        };
        rejects(() -> AttachmentExportBinding.observe(report, original, sidecar, index, changingHost, () -> false),
            "bundle change between inventory and host observation accepted");
        if (changes.get() == 0) throw new AssertionError("race injection was not reached");
        Files.write(part, partBytes);
        var restored = AttachmentExportBinding.observe(report, original, sidecar, index, host, () -> false);
        restored.recheck(host, () -> false);
        equal(before, hashes(protectedPaths));
        var result = new com.google.gson.JsonObject();
        result.addProperty("status", "PASS_SOURCE_BUNDLE_BINDING");
        result.addProperty("checks", checks);
        result.addProperty("dependencies", dependencies.size());
        result.addProperty("inputSha256", manifest.inputSha256());
        result.addProperty("productionHost", false);
        result.addProperty("scope", "Read-only export binding with actual Linux identities; controlled test metadata host; not attachment approval");
        Files.writeString(work.resolve("result.json"), result + "\n");
        System.out.println(result);
    }

    private static void rehashSource(Path report, Path index) throws IOException {
        var json = JsonParser.parseString(Files.readString(report)).getAsJsonObject();
        json.getAsJsonObject("artifacts").addProperty("sourceSha256", FileDigests.read(index, () -> false).sha256());
        Files.writeString(report, json + "\n");
    }

    private static List<String> hashes(List<Path> paths) throws IOException {
        var hashes = new ArrayList<String>();
        for (Path path : paths) hashes.add(FileDigests.read(path, () -> false).sha256());
        return hashes;
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }

    private static void rejects(Action action, String message) throws Exception {
        try { action.run(); throw new AssertionError(message); }
        catch (IOException expected) { checks++; }
    }

    private static void rejectsMessage(Action action, String message) throws Exception {
        try { action.run(); throw new AssertionError("accepted " + message); }
        catch (IOException expected) { equal(message, expected.getMessage()); }
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
