// Cancel inside the production formatter path and retain the entire old generation.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CancellationException;

public class CancelDuringFormatters extends GhidraScript {
    private record Stage(String method, int stop) { }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("input sidecar selection compression companions required");
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        Path selection = Path.of(args[2]);
        var files = new java.util.ArrayList<>(List.of(input, output, Path.of(args[1] + ".c"),
            ghidradwarfforge.formatters.FormatterPlan.outputPath(output), selection));
        if (args[4].equals("all")) {
            files.add(Path.of(args[1] + ".gdb.py"));
            files.add(Path.of(args[1] + ".unwind.json"));
        }
        var hashes = new java.util.ArrayList<String>();
        for (Path path : files) hashes.add(ghidradwarfforge.output.FileDigests.read(path, () -> false).sha256());
        var beforeNames = names(output.getParent());
        var choices = new java.util.ArrayList<>(List.of("--packaged-natives", "--input", args[0], "--output", args[1], "--formatters", args[2],
            "--compress-debug-sections=" + args[3]));
        if (args[4].equals("all")) {
            choices.add("--gdb-loader");
            choices.add("--synthesize-unwind=strict");
        }
        String[] options = choices.toArray(String[]::new);
        TaskMonitor original = monitor;
        for (var stage : List.of(new Stage("prepare", 5), new Stage("render", 2))) {
            Probe probe = new Probe(original, stage);
            boolean cancelled = false;
            try {
                monitor = probe;
                runScript("GhidraDwarfForge.java", options);
            }
            catch (CancelledException | CancellationException expected) { cancelled = true; }
            finally { monitor = original; }
            if (!cancelled || probe.polls != stage.stop()) throw new AssertionError("formatter stage did not cancel: " + stage);
            for (int index = 0; index < files.size(); index++) {
                if (!hashes.get(index).equals(ghidradwarfforge.output.FileDigests.read(files.get(index), () -> false).sha256())) {
                    throw new AssertionError("formatter cancellation changed " + files.get(index));
                }
            }
            if (!beforeNames.equals(names(output.getParent()))) throw new AssertionError("formatter cancellation leaked staging files");
            println("formatter-cancellation=PASS " + stage.method());
        }
        runScript("GhidraDwarfForge.java", options);
        for (int index = 0; index < files.size(); index++) {
            if (!hashes.get(index).equals(ghidradwarfforge.output.FileDigests.read(files.get(index), () -> false).sha256())) {
                throw new AssertionError("formatter retry changed deterministic generation");
            }
        }
        if (!beforeNames.equals(names(output.getParent()))) throw new AssertionError("formatter retry leaked staging files");
        println("formatter-cancellation-recovery=PASS");
    }

    private static java.util.Set<String> names(Path directory) throws Exception {
        try (var paths = Files.list(directory)) {
            return paths.map(path -> path.getFileName().toString()).collect(java.util.stream.Collectors.toSet());
        }
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Stage stage;
        private int polls;
        Probe(TaskMonitor delegate, Stage stage) { super(delegate); this.stage = stage; }
        @Override public synchronized boolean isCancelled() {
            if (polls >= stage.stop() || super.isCancelled()) return true;
            boolean inside = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                frame.getClassName().equals("ghidradwarfforge.formatters.FormatterPlan") &&
                frame.getMethodName().equals(stage.method())));
            return inside && ++polls == stage.stop();
        }
        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
