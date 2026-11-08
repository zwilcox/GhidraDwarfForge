package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Tests complete-bundle consumption and transport, independent of the in-memory producer plan. */
public final class SourceBundleFilesSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-source-files-");
        try {
            var plan = SourceBundle.prepare("a".repeat(64), "sample.dbg.c", SourceBundleSmoke.fixture(), 3, () -> false);
            Path original = Files.createDirectory(root.resolve("original"));
            Path index = publish(original, plan);
            var bundle = SourceBundleFiles.open(index, () -> false).orElseThrow();
            require(bundle.manifest().equals(plan.manifest()), "reader sees the recorded inventory");
            require(bundle.files().size() == plan.fileNames().size() + 1, "index and all dependencies retained");
            Path moved = Files.createDirectory(root.resolve("moved"));
            for (Path file : bundle.files()) Files.copy(file, moved.resolve(file.getFileName()));
            Files.move(original, root.resolve("original-unavailable"));
            var portable = SourceBundleFiles.open(moved.resolve("sample.dbg.c"), () -> false).orElseThrow();
            require(portable.manifest().equals(plan.manifest()), "moved output works without old directory");
            Path ordinary = Files.writeString(root.resolve("ordinary.c"), "/* synthetic single file */\n");
            require(SourceBundleFiles.open(ordinary, () -> false).isEmpty(), "single-file default detection");
            reject(() -> bundle.verify(() -> false));
            Path part = moved.resolve(plan.fileNames().getFirst());
            byte[] saved = Files.readAllBytes(part);
            Files.writeString(part, "changed");
            reject(() -> portable.verify(() -> false));
            reject(() -> SourceBundleFiles.open(moved.resolve("sample.dbg.c"), () -> false));
            Files.write(part, saved);
            SourceBundleFiles.open(moved.resolve("sample.dbg.c"), () -> false).orElseThrow().verify(() -> false);

            for (String failure : List.of("missing-part", "missing-manifest", "bad-manifest-hash", "bad-index",
                    "wrong-index-name", "part-symlink", "manifest-symlink", "wrong-logical-sha", "wrong-lines", "bad-header")) {
                if (failure.endsWith("symlink") && !System.getProperty("os.name").equals("Linux")) continue;
                Path directory = Files.createDirectory(root.resolve(failure));
                Path candidate = publish(directory, plan);
                switch (failure) {
                    case "missing-part" -> Files.delete(directory.resolve(plan.fileNames().getFirst()));
                    case "missing-manifest" -> Files.delete(directory.resolve(plan.manifestName()));
                    case "bad-manifest-hash" -> Files.writeString(directory.resolve(plan.manifestName()), "{}\n");
                    case "bad-index" -> Files.writeString(candidate, new String(plan.indexBytes(() -> false), java.nio.charset.StandardCharsets.UTF_8) + "extra\n");
                    case "wrong-index-name" -> {
                        Path renamed = directory.resolve("another.dbg.c");
                        Files.move(candidate, renamed);
                        candidate = renamed;
                    }
                    case "part-symlink", "manifest-symlink" -> {
                        String name = failure.startsWith("part") ? plan.fileNames().getFirst() : plan.manifestName();
                        Path selected = directory.resolve(name);
                        Path target = directory.resolve("target");
                        Files.move(selected, target);
                        Files.createSymbolicLink(selected, target);
                    }
                    case "wrong-logical-sha" -> {
                        var old = plan.manifest();
                        replaceManifest(candidate, new SourceBundle.Manifest(old.indexName(), old.inputSha256(), "b".repeat(64),
                            old.targetLines(), old.parts(), old.functions()));
                    }
                    case "wrong-lines" -> {
                        var old = plan.manifest();
                        var parts = new ArrayList<>(old.parts());
                        var last = parts.getLast();
                        parts.set(parts.size() - 1, new SourceBundle.Part(last.file(), last.sha256(), last.bytes(), last.first(), last.last() + 1));
                        replaceManifest(candidate, new SourceBundle.Manifest(old.indexName(), old.inputSha256(), old.logicalSourceSha256(),
                            old.targetLines(), parts, old.functions()));
                    }
                    case "bad-header" -> {
                        var old = plan.manifest();
                        var parts = new ArrayList<>(old.parts());
                        var first = parts.getFirst();
                        byte[] bytes = plan.bytes(first.fileName()); bytes[0] = '#';
                        var changed = new SourceBundle.Part(first.file(), SourceBundle.sha256(bytes), bytes.length, first.first(), first.last());
                        Files.write(directory.resolve(changed.fileName()), bytes);
                        parts.set(0, changed);
                        replaceManifest(candidate, new SourceBundle.Manifest(old.indexName(), old.inputSha256(), old.logicalSourceSha256(),
                            old.targetLines(), parts, old.functions()));
                    }
                    default -> throw new AssertionError(failure);
                }
                Path selected = candidate;
                reject(() -> SourceBundleFiles.open(selected, () -> false));
            }

            Path largeDirectory = Files.createDirectory(root.resolve("oversized"));
            var largeSource = SyntheticSourceFile.build("large", "test", List.of(new SyntheticSourceFile.FunctionText(
                "large", 0x1000, "void large(void) {\n" + "    /* long source line */\n".repeat(10000) + "}\n", null)));
            var largePlan = SourceBundle.prepare("a".repeat(64), "large.dbg.c", largeSource, 20, () -> false);
            require(largePlan.manifest().parts().stream().anyMatch(p -> p.bytes() > 65536), "stream boundary fixture");
            var large = SourceBundleFiles.open(publish(largeDirectory, largePlan), () -> false).orElseThrow();
            require(large.manifest().logicalSourceSha256().equals(SourceBundle.sha256(largeSource.utf8())), "oversized reconstruction");

            AtomicInteger count = new AtomicInteger();
            Path cancelIndex = moved.resolve("sample.dbg.c");
            SourceBundleFiles.open(cancelIndex, () -> { count.incrementAndGet(); return false; });
            for (int stop = 1; stop <= count.get(); stop++) {
                AtomicInteger reached = new AtomicInteger();
                int limit = stop;
                try {
                    SourceBundleFiles.open(cancelIndex, () -> reached.incrementAndGet() >= limit);
                    throw new AssertionError("ignored read cancellation at " + stop);
                }
                catch (CancellationException expected) { checks++; }
            }
            System.out.println("source-bundle-files-smoke: PASS checks=" + checks + " readCancellationPoints=" + count.get());
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static Path publish(Path directory, SourceBundle.Plan plan) throws Exception {
        Path index = directory.resolve(plan.manifest().indexName());
        SourceBundleStore.install(index, plan, List.of(), () -> false).verify(() -> false);
        Files.write(index, plan.indexBytes(() -> false));
        return index;
    }

    private static void replaceManifest(Path index, SourceBundle.Manifest manifest) throws Exception {
        byte[] bytes = SourceBundle.render(manifest, () -> false);
        String sha = SourceBundle.sha256(bytes);
        Files.write(index.getParent().resolve(SourceBundle.manifestNameFor(sha)), bytes);
        Files.write(index, SourceBundle.renderIndex(manifest, sha, () -> false));
    }

    @FunctionalInterface private interface Operation { void run() throws Exception; }

    private static void reject(Operation operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("accepted incomplete or conflicting source bundle");
        }
        catch (IOException expected) { checks++; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
