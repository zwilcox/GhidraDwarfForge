package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SourcePartitionPlan;

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
            sourceTableAndDependencies(bundle, plan);
            malformedInventory(root, plan);
            partContents(root);
            observationChanges(root, plan);
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
            System.out.println("source-bundle-files-smoke=PASS checks=" + checks + " readCancellationPoints=" + count.get());
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void sourceTableAndDependencies(SourceBundleFiles bundle, SourceBundle.Plan plan) throws Exception {
        var names = new ArrayList<String>();
        names.add("sample.dbg.c");
        for (var part : plan.manifest().parts()) names.add(part.fileName());
        bundle.requireSourceNames(names);
        require(bundle.sourceNames().equals(names), "DWARF file order begins with index and follows logical parts");
        var reversed = new ArrayList<>(names);
        java.util.Collections.reverse(reversed);
        for (var invalid : List.of(List.<String>of(), names.subList(1, names.size()), reversed,
                List.of("sample.dbg.c", plan.manifestName()))) {
            reject("DWARF source files differ", () -> bundle.requireSourceNames(invalid));
        }
        var dependencies = bundle.dependencies();
        require(dependencies.size() == plan.fileNames().size(), "dependencies exclude only mutable index");
        require(dependencies.getFirst().name().equals(plan.manifestName()), "manifest dependency comes first");
        for (var dependency : dependencies) {
            byte[] bytes = plan.bytes(dependency.name());
            require(dependency.bytes() == bytes.length && dependency.sha256().equals(SourceBundle.sha256(bytes)),
                "dependency has independent byte length and hash");
        }
    }

    private static void malformedInventory(Path root, SourceBundle.Plan plan) throws Exception {
        for (String failure : List.of("index-directory", "index-too-large", "manifest-directory",
                "manifest-too-large", "incomplete-reference", "traversal-reference", "uppercase-reference")) {
            Path directory = Files.createDirectory(root.resolve("inventory-" + failure));
            Path index = publish(directory, plan);
            Path manifest = directory.resolve(plan.manifestName());
            String expected;
            switch (failure) {
                case "index-directory", "manifest-directory" -> {
                    Path selected = failure.startsWith("index") ? index : manifest;
                    Files.delete(selected);
                    Files.createDirectory(selected);
                    expected = failure.startsWith("index") ? "synthetic source must be a regular file" : "invalid or oversized source inventory";
                }
                case "index-too-large", "manifest-too-large" -> {
                    Path selected = failure.startsWith("index") ? index : manifest;
                    long maximum = (failure.startsWith("index") ? 16L : 64L) * 1024 * 1024;
                    // Sparse extension proves admission bounds without allocating a large fixture in memory.
                    try (var channel = FileChannel.open(selected, StandardOpenOption.WRITE)) {
                        channel.position(maximum);
                        channel.write(ByteBuffer.wrap(new byte[] { 0 }));
                    }
                    expected = "invalid or oversized source inventory";
                }
                case "incomplete-reference" -> {
                    Files.writeString(index, SourceBundle.INDEX_PREFIX);
                    expected = "invalid synthetic source index manifest reference";
                }
                case "traversal-reference", "uppercase-reference" -> {
                    String name = failure.equals("traversal-reference") ? "../" + plan.manifestName() :
                        "forge-src-" + "A".repeat(64) + ".json";
                    Files.writeString(index, SourceBundle.INDEX_PREFIX + " * synthetic\n * Manifest: " + name + "\nend\n");
                    expected = "invalid synthetic source index manifest reference";
                }
                default -> throw new AssertionError(failure);
            }
            var before = inventory(directory);
            reject(expected, () -> SourceBundleFiles.open(index, () -> false));
            require(inventory(directory).equals(before), "rejected inventory preserved: " + failure);
        }
        Path staged = publish(Files.createDirectory(root.resolve("private-index")), plan);
        Path renamed = staged.resolveSibling(".private-index.staged");
        Files.move(staged, renamed);
        var selected = SourceBundleFiles.open(renamed, "sample.dbg.c", () -> false).orElseThrow();
        require(selected.manifest().equals(plan.manifest()), "private index binds its final basename explicitly");
        reject("synthetic source index differs from its manifest",
            () -> SourceBundleFiles.open(renamed, "other.dbg.c", () -> false));
    }

    private static void partContents(Path root) throws Exception {
        byte[] header = SourcePartitionPlan.syntheticHeader();
        byte[] valid = (new String(header, StandardCharsets.UTF_8) + "int value;\n").getBytes(StandardCharsets.UTF_8);
        for (String failure : List.of("valid", "header-only", "short-header", "missing-newline", "wrong-hash", "part-directory")) {
            Path directory = Files.createDirectory(root.resolve("part-" + failure));
            byte[] bytes = switch (failure) {
                case "header-only" -> header;
                case "short-header" -> Arrays.copyOf(header, header.length - 1);
                case "missing-newline" -> Arrays.copyOf(valid, valid.length - 1);
                default -> valid;
            };
            String hash = failure.equals("wrong-hash") ? "0".repeat(64) : SourceBundle.sha256(bytes);
            var part = new SourceBundle.Part(1, hash, bytes.length, 1, 1);
            var manifest = new SourceBundle.Manifest("part.dbg.c", "a".repeat(64),
                SourceBundle.sha256("int value;\n".getBytes(StandardCharsets.UTF_8)), 10, List.of(part), List.of());
            Path index = directory.resolve("part.dbg.c");
            replaceManifest(index, manifest);
            Path partPath = directory.resolve(part.fileName());
            if (failure.equals("part-directory")) Files.createDirectory(partPath);
            else Files.write(partPath, bytes);
            var before = inventory(directory);
            if (failure.equals("valid")) {
                require(SourceBundleFiles.open(index, () -> false).orElseThrow().manifest().equals(manifest),
                    "one-line source without function records is valid");
            }
            else {
                reject(failure.equals("part-directory") ? "missing a complete regular part" :
                    "source part contents or line bounds disagree", () -> SourceBundleFiles.open(index, () -> false));
            }
            require(inventory(directory).equals(before), "part reader preserves selected bytes and metadata: " + failure);
        }
    }

    /** Sweep public cancellation checkpoints; do not bake internal callback counts into the fixtures. */
    private static void observationChanges(Path root, SourceBundle.Plan plan) throws Exception {
        Path base = Files.createDirectory(root.resolve("observation-changes"));
        Path index = publish(base, plan);
        AtomicInteger callbacks = new AtomicInteger();
        SourceBundleFiles.open(index, () -> { callbacks.incrementAndGet(); return false; }).orElseThrow();
        for (String role : List.of("index", "manifest", "part")) {
            String name = role.equals("index") ? index.getFileName().toString() :
                role.equals("manifest") ? plan.manifestName() : plan.manifest().parts().getFirst().fileName();
            Path selected = base.resolve(name);
            byte[] original = Files.readAllBytes(selected);
            boolean hasFileKeys = Files.readAttributes(selected, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).fileKey() != null;
            for (String change : List.of("grow", "truncate", "mtime", "replace", "replace-content")) {
                var diagnostics = new java.util.HashSet<String>();
                for (int point = 1; point <= callbacks.get(); point++) {
                    Files.write(selected, original);
                    Path retained = base.resolve("retained-original");
                    AtomicInteger reached = new AtomicInteger();
                    int trigger = point;
                    try {
                        var opened = SourceBundleFiles.open(index, () -> {
                            if (reached.incrementAndGet() == trigger) {
                                try {
                                    switch (change) {
                                        case "grow" -> Files.write(selected, new byte[] { 'x' }, StandardOpenOption.APPEND);
                                        case "truncate" -> {
                                            try (var channel = FileChannel.open(selected, StandardOpenOption.WRITE)) {
                                                channel.truncate(original.length - 1);
                                            }
                                        }
                                        case "mtime" -> Files.setLastModifiedTime(selected,
                                            FileTime.fromMillis(Files.getLastModifiedTime(selected).toMillis() + 60000));
                                        case "replace", "replace-content" -> {
                                            FileTime time = Files.getLastModifiedTime(selected);
                                            Files.move(selected, retained);
                                            byte[] replacement = original.clone();
                                            if (change.equals("replace-content")) {
                                                // Preserve length, timestamp and the index's detection prefix.
                                                // Hash/content checks must catch this even without file keys.
                                                replacement[replacement.length - 1] ^= 1;
                                            }
                                            Files.write(selected, replacement);
                                            Files.setLastModifiedTime(selected, time);
                                            require(!Files.isSameFile(selected, retained), "replacement is a distinct file");
                                            var beforeKey = Files.readAttributes(retained, BasicFileAttributes.class).fileKey();
                                            var afterKey = Files.readAttributes(selected, BasicFileAttributes.class).fileKey();
                                            require(hasFileKeys ? beforeKey != null && afterKey != null && !beforeKey.equals(afterKey) :
                                                beforeKey == null && afterKey == null, "provider file-key capability is stable");
                                        }
                                        default -> throw new AssertionError(change);
                                    }
                                }
                                catch (IOException failedFixture) { throw new java.io.UncheckedIOException(failedFixture); }
                            }
                            return false;
                        }).orElseThrow();
                        // A change before acquisition or after an earlier file's final observation can
                        // legitimately finish open(). Publication must recheck the retained binding.
                        if (change.equals("grow") || change.equals("truncate") || change.equals("replace-content")) {
                            reject(() -> opened.verify(() -> false));
                        }
                    }
                    catch (IOException rejected) { diagnostics.add(rejected.getMessage().split(":", 2)[0]); }
                    require(reached.get() >= trigger, "scheduled filesystem change actually ran");
                    if (change.startsWith("replace")) {
                        require(Arrays.equals(Files.readAllBytes(retained), original), "reader preserves replaced original inode");
                        Files.delete(retained);
                    }
                }
                String diagnostic = role.equals("part") ?
                    (change.equals("grow") ? "source part size changed" : "source part contents or line bounds disagree with manifest") :
                    (change.equals("grow") ? "source inventory size changed" : "source inventory changed during observation");
                // Truncation of an inventory can instead fail its exact-size digest observation.
                if (change.equals("replace") && !hasFileKeys) {
                    // BasicFileAttributes.fileKey is null on the supported Windows JDK.
                    // Identical content/size/mtime cannot establish replacement there.
                    // Keep this exercised and reported; do not claim inode protection.
                    require(diagnostics.isEmpty(), "identical replacement without file keys retains content binding");
                }
                else if ((!change.equals("truncate") || role.equals("part")) && !change.equals("replace-content")) {
                    require(diagnostics.contains(diagnostic), role + " " + change + " observed unstable read: " + diagnostics);
                }
                if (!change.equals("replace") || hasFileKeys) {
                    require(!diagnostics.isEmpty(), "changing " + role + " was rejected: " + change);
                }
                System.out.println("source-observation role=" + role + " change=" + change +
                    " fileKeys=" + hasFileKeys + " diagnostics=" + new java.util.TreeSet<>(diagnostics));
                Files.write(selected, original);
            }
        }
        SourceBundleFiles.open(index, () -> false).orElseThrow().verify(() -> false);
    }

    private static Map<String, String> inventory(Path directory) throws Exception {
        var result = new TreeMap<String, String>();
        try (var files = Files.list(directory)) {
            for (Path path : files.toList()) {
                var attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                String hash = attributes.isRegularFile() ? FileDigests.read(path).sha256() : "directory";
                result.put(path.getFileName().toString(), attributes.fileKey() + ":" + attributes.size() + ":" +
                    attributes.lastModifiedTime() + ":" + hash);
            }
        }
        return result;
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

    private static void reject(String diagnostic, Operation operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("accepted invalid source bundle: " + diagnostic);
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(diagnostic), "expected " + diagnostic + ", got " + expected);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
