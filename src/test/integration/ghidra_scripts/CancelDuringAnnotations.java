// Cancel inside each annotation stage of the installed exporter and prove recovery.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.stream.Collectors;

public class CancelDuringAnnotations extends GhidraScript {
    private record Stage(String owner, String method, int stop, String enclosingOwner) {
        Stage(String owner, String method, int stop) { this(owner, method, stop, null); }
    }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("usage: input output consumer producer");
        Path output = Path.of(args[1]);
        Path source = Path.of(args[1] + ".c");
        byte[] beforeOutput = Files.readAllBytes(output);
        byte[] beforeSource = Files.readAllBytes(source);
        Set<String> beforeFiles = files(output.getParent());
        String[] options = {"--input", args[0], "--output", args[1], "--libdwarf", args[2], "--libdwarfp", args[3]};
        var stages = List.of(
            new Stage("ghidradwarfforge.GhidraAnnotationInventory", "read", 5),
            new Stage("ghidradwarfforge.GhidraEquateEvidence$DynamicCollector", "accept", 2),
            new Stage("ghidradwarfforge.GhidraEquateEvidence", "interpret", 5),
            new Stage("ghidradwarfforge.GhidraEquateNames", "extend", 5),
            new Stage("ghidradwarfforge.GhidraEquateSource", "append", 5),
            new Stage("ghidradwarfforge.source.AnnotatedSourceFile", "compose", 5,
                "ghidradwarfforge.GhidraEquateSource"),
            new Stage("ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter", "emitSyntheticConstants", 5));
        TaskMonitor original = monitor;
        for (Stage stage : stages) {
            var probe = new Probe(original, stage);
            boolean cancelled = false;
            try {
                monitor = probe;
                runScript("GhidraDwarfForge.java", options);
            }
            catch (CancelledException | CancellationException expected) { cancelled = true; }
            finally { monitor = original; }
            if (!cancelled || probe.polls != stage.stop()) {
                throw new AssertionError("annotation cancellation did not reach " + stage + ": " + probe.polls);
            }
            if (!Arrays.equals(beforeOutput, Files.readAllBytes(output)) ||
                    !Arrays.equals(beforeSource, Files.readAllBytes(source)) ||
                    !beforeFiles.equals(files(output.getParent()))) {
                throw new AssertionError("cancelled annotation export changed outputs or left temporary files: " + stage);
            }
            println("annotation-cancellation-stage=PASS " + stage.owner() + "#" + stage.method());
        }
        runScript("GhidraDwarfForge.java", options);
        if (!Arrays.equals(beforeOutput, Files.readAllBytes(output)) ||
                !Arrays.equals(beforeSource, Files.readAllBytes(source)) ||
                !beforeFiles.equals(files(output.getParent()))) {
            throw new AssertionError("retry changed deterministic outputs or left temporary files");
        }
        println("annotation-cancellation-recovery=PASS stages=" + stages.size());
    }

    private static Set<String> files(Path directory) throws Exception {
        try (var paths = Files.list(directory)) {
            return paths.map(path -> path.getFileName().toString()).collect(Collectors.toSet());
        }
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Stage stage;
        private int polls;
        Probe(TaskMonitor original, Stage stage) { super(original); this.stage = stage; }
        @Override public synchronized boolean isCancelled() {
            if (polls >= stage.stop() || super.isCancelled()) return true;
            var frames = StackWalker.getInstance().walk(stream -> stream.toList());
            boolean inside = frames.stream().anyMatch(frame -> frame.getClassName().equals(stage.owner()) &&
                frame.getMethodName().equals(stage.method()));
            if (stage.enclosingOwner() != null) {
                inside &= frames.stream().anyMatch(frame -> frame.getClassName().equals(stage.enclosingOwner()));
            }
            return inside && ++polls == stage.stop();
        }
        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
