// Test profile rejection, cancellation, output preservation and recovery in the real exporter.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;

public class CheckCortexMFailures extends GhidraScript {
    private record Stage(String owner, String method, int stop) { }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("original output");
        Path original = Path.of(args[0]);
        Path artifact = Path.of(args[1]);
        byte[] inputBefore = Files.readAllBytes(original);
        byte[] artifactBefore = Files.readAllBytes(artifact);
        byte[] sourceBefore = Files.readAllBytes(Path.of(args[1] + ".c"));
        Path controls = artifact.getParent().resolve("failure-controls");
        Files.createDirectory(controls);
        for (boolean existing : new boolean[] {false, true}) {
            Path output = controls.resolve(existing ? "existing.dbg" : "absent.dbg");
            if (existing) {
                Files.write(output, artifactBefore);
                Files.write(Path.of(output + ".c"), sourceBefore);
            }
            Map<String, String> before = inventory(controls);
            String[] options = {"--packaged-natives", "--target-profile=cortex-m3",
                "--input=" + original, "--output=" + output};
            for (Stage stage : List.of(
                    new Stage("ghidradwarfforge.GhidraCortexM3Profile", "requireAgreement", 3),
                    new Stage("ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter", "produce", 3),
                    new Stage("ghidradwarfforge.elf.MatchedElfSidecarWriter", "write", 5))) {
                TaskMonitor previous = monitor;
                var probe = new Probe(previous, stage);
                boolean cancelled = false;
                try {
                    monitor = probe;
                    runScript("GhidraDwarfForge.java", options);
                }
                catch (CancelledException | CancellationException expected) { cancelled = true; }
                finally { monitor = previous; }
                if (!cancelled || probe.polls != stage.stop()) throw new AssertionError("stage not cancelled: " + stage);
                if (!before.equals(inventory(controls))) throw new AssertionError("cancellation changed outputs: " + stage);
                if (!Arrays.equals(inputBefore, Files.readAllBytes(original))) throw new AssertionError("input changed");
                println("cortex-m-failure=PASS " + stage.owner() + " existing=" + existing);
            }
        }
        runScript("GhidraDwarfForge.java", new String[] {"--packaged-natives", "--target-profile=cortex-m3",
            "--input=" + original, "--output=" + artifact});
        if (!Arrays.equals(artifactBefore, Files.readAllBytes(artifact)) ||
                !Arrays.equals(sourceBefore, Files.readAllBytes(Path.of(artifact + ".c"))) ||
                !Arrays.equals(inputBefore, Files.readAllBytes(original))) {
            throw new AssertionError("post-cancellation recovery was not deterministic/preserving");
        }
        // Run destructive analysis controls last in this disposable read-only
        // domain object. GhidraScript owns an outer transaction, so a nested
        // endTransaction(false) does not immediately restore context. Nothing is saved.
        int tx = currentProgram.startTransaction("test ARM-state rejection");
        try {
            var address = currentProgram.getFunctionManager().getFunctions(true).next().getEntryPoint();
            currentProgram.getListing().clearCodeUnits(address, address.add(3), false);
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
                address, address.add(3), BigInteger.ZERO);
            for (boolean existing : new boolean[] {false, true}) {
                Path output = controls.resolve(existing ? "existing.dbg" : "absent.dbg");
                var before = inventory(controls);
                boolean rejected = false;
                try {
                    runScript("GhidraDwarfForge.java", new String[] {"--packaged-natives", "--target-profile=cortex-m3",
                        "--input=" + original, "--output=" + output});
                }
                catch (IllegalArgumentException expected) {
                    rejected = expected.getMessage().contains("Cortex-M3 profile requires even code addresses");
                }
                if (!rejected) throw new AssertionError("production accepted contradictory ARM-state context");
                if (!before.equals(inventory(controls))) throw new AssertionError("profile rejection changed outputs");
                println("cortex-m-failure=PASS context existing=" + existing);
            }
        }
        finally { currentProgram.endTransaction(tx, false); }
        println("cortex-m-failure-controls=PASS cases=8 recovery=1");
    }

    private static Map<String, String> inventory(Path directory) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.skip(1).toList()) {
                if (!Files.isRegularFile(path)) {
                    result.put(directory.relativize(path).toString(), "non-file");
                    continue;
                }
                result.put(directory.relativize(path).toString(), java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))));
            }
        }
        return result;
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Stage stage;
        private int polls;
        Probe(TaskMonitor delegate, Stage stage) { super(delegate); this.stage = stage; }
        @Override public synchronized boolean isCancelled() {
            if (polls >= stage.stop() || super.isCancelled()) return true;
            boolean inside = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                frame.getClassName().equals(stage.owner()) && frame.getMethodName().equals(stage.method())));
            return inside && ++polls == stage.stop();
        }
        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
