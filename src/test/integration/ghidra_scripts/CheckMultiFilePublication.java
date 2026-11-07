// Interrupt the actual exporter before and during complete source publication.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.SourceBundleFiles;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class CheckMultiFilePublication extends GhidraScript {
    private record Stop(String name, String owner, String method, int polls, int published) { }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("input new-directory compression");
        Path input = Path.of(args[0]), root = Path.of(args[1]);
        Files.createDirectory(root);
        String originalHash = hash(input);
        Path reference = Files.createDirectory(root.resolve("reference")).resolve("target.dbg");
        export(input, reference, 8, args[2]);
        var expected = immutable(reference.getParent());
        if (expected.size() < 3) throw new AssertionError("fixture needs several source parts");
        List<Stop> stops = List.of(
            new Stop("preparation", "ghidradwarfforge.output.SourceBundle", "prepare", 5, -1),
            new Stop("stage-write", "ghidradwarfforge.output.SourceBundleStore", "write", 2, -1),
            new Stop("first-part", "ghidradwarfforge.output.SourceBundleStore", "install", 0, -1),
            new Stop("manifest-installed", "ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter", "export", 1, -1),
            new Stop("sidecar-published", "", "", 0, 1),
            new Stop("index-published", "", "", 0, 2),
            new Stop("loader-published", "", "", 0, 3));
        var records = new ArrayList<Map<String, Object>>();
        TaskMonitor original = monitor;
        for (boolean replacement : List.of(false, true)) {
            for (boolean ioFailure : List.of(false, true)) {
                for (Stop stop : stops) {
                    String name = (replacement ? "replace-" : "fresh-") + (ioFailure ? "failure-" : "cancel-") + stop.name();
                    Path directory = Files.createDirectory(root.resolve(name));
                    Path output = directory.resolve("target.dbg");
                    Files.writeString(directory.resolve("forge-src-analyst.c"), "analyst-owned source\n");
                    if (replacement) export(input, output, 200, args[2]);
                    Map<String, String> before = snapshot(directory);
                    var probe = new Probe(original, stop, ioFailure, output, before);
                    Exception failure = null;
                    try {
                        monitor = probe;
                        export(input, output, 8, args[2]);
                    }
                    catch (Exception error) { failure = error; }
                    finally { monitor = original; }
                    if (!probe.triggered || failure == null) throw new AssertionError("injection missed " + name);
                    Map<String, String> after = snapshot(directory);
                    for (var entry : before.entrySet()) {
                        if (!entry.getValue().equals(after.get(entry.getKey()))) {
                            throw new AssertionError("interrupted export changed retained file " + name + ":" + entry.getKey());
                        }
                    }
                    var retained = new TreeMap<String, String>();
                    for (var entry : after.entrySet()) {
                        if (before.containsKey(entry.getKey())) continue;
                        if (!entry.getValue().equals(expected.get(entry.getKey()))) {
                            throw new AssertionError("partial/foreign final file or leaked stage " + name + ":" + entry.getKey());
                        }
                        retained.put(entry.getKey(), entry.getValue());
                    }
                    if (stop.name().equals("first-part") && retained.isEmpty()) throw new AssertionError("no partial installation was exercised");
                    if (stop.name().equals("manifest-installed") || stop.published() > 0) {
                        if (!after.entrySet().containsAll(expected.entrySet())) throw new AssertionError("manifest checkpoint lacks complete dependencies");
                    }
                    if (replacement) SourceBundleFiles.open(Path.of(output + ".c"), () -> false).orElseThrow().verify(() -> false);
                    else for (Path mutable : mutable(output)) {
                        if (Files.exists(mutable)) throw new AssertionError("fresh failure left final output " + mutable);
                    }
                    export(input, output, 8, args[2]);
                    var bundle = SourceBundleFiles.open(Path.of(output + ".c"), () -> false).orElseThrow();
                    bundle.verify(() -> false);
                    if (!immutable(directory).entrySet().containsAll(expected.entrySet())) throw new AssertionError("retry lacks complete source");
                    var successful = snapshot(directory);
                    export(input, output, 8, args[2]);
                    if (!snapshot(directory).equals(successful)) throw new AssertionError("retry is not deterministic");
                    if (!hash(input).equals(originalHash)) throw new AssertionError("original changed");
                    records.add(Map.of("case", name, "failureType", failure.getClass().getName(),
                        "retainedAfterFailure", retained, "publishedBeforeFailure", probe.published,
                        "successfulInventory", successful));
                    println("multifile-publication-case=PASS " + name);
                }
            }
        }
        Files.writeString(root.resolve("result.json"), new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("status", "PASS_MULTIFILE_PUBLICATION", "cases", records, "inputSha256", originalHash,
                "referenceInventory", snapshot(reference.getParent()))) + "\n");
        println("multifile-publication=PASS cases=" + records.size());
    }

    private void export(Path input, Path output, int target, String compression) throws Exception {
        runScript("GhidraDwarfForge.java", new String[] { "--packaged-natives", "--input=" + input,
            "--output=" + output, "--source-lines=" + target, "--compress-debug-sections=" + compression, "--gdb-loader" });
    }

    private static List<Path> mutable(Path output) {
        return List.of(output, Path.of(output + ".c"), Path.of(output + ".gdb.py"));
    }

    private static String hash(Path path) throws IOException {
        return FileDigests.read(path, () -> false).sha256();
    }

    private static Map<String, String> snapshot(Path directory) throws IOException {
        var result = new TreeMap<String, String>();
        try (var paths = Files.list(directory)) {
            for (Path path : paths.toList()) {
                if (!Files.isRegularFile(path)) throw new AssertionError("unexpected directory/stage " + path);
                result.put(path.getFileName().toString(), hash(path));
            }
        }
        return result;
    }

    private static Map<String, String> immutable(Path directory) throws IOException {
        var result = new TreeMap<>(snapshot(directory));
        result.keySet().removeIf(name -> !name.startsWith("forge-src-") || name.equals("forge-src-analyst.c"));
        return result;
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Stop stop;
        private final boolean ioFailure;
        private final Path output;
        private final Map<String, String> before;
        private int polls, published;
        private boolean triggered;

        Probe(TaskMonitor delegate, Stop stop, boolean ioFailure, Path output, Map<String, String> before) {
            super(delegate); this.stop = stop; this.ioFailure = ioFailure; this.output = output; this.before = before;
        }

        @Override public synchronized boolean isCancelled() {
            if (triggered) return true;
            if (super.isCancelled()) return true;
            try {
                if (stop.published() > 0) {
                    published = 0;
                    for (Path path : mutable(output)) {
                        if (Files.isRegularFile(path) && !hash(path).equals(before.get(path.getFileName().toString()))) published++;
                    }
                    triggered = published == stop.published();
                }
                else {
                    boolean inside = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                        frame.getClassName().equals(stop.owner()) && frame.getMethodName().equals(stop.method())));
                    if (inside && stop.name().equals("first-part")) {
                        try (var paths = Files.list(output.getParent())) {
                            triggered = paths.anyMatch(path -> path.getFileName().toString().startsWith("forge-src-") &&
                                !before.containsKey(path.getFileName().toString()));
                        }
                    }
                    else if (inside) triggered = ++polls == stop.polls();
                }
                if (triggered && ioFailure) throw new UncheckedIOException(new IOException("injected source publication failure " + stop.name()));
                return triggered;
            }
            catch (IOException failure) { throw new UncheckedIOException(failure); }
        }

        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
