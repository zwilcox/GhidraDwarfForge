// Exercise cancellation and injected failures in the real exporter before publication.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import ghidradwarfforge.output.FileDigests;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

public class CoverageStagingControls extends GhidraScript {
    private record Phase(String name, String owner) { }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("usage: <input> <new controls directory>");
        Path input = Path.of(args[0]);
        Path root = Path.of(args[1]);
        Files.createDirectory(root);
        String inputHash = FileDigests.read(input).sha256();
        List<Phase> phases = List.of(
            new Phase("capture", "ghidradwarfforge.GhidraInstructionEvidence"),
            new Phase("assembly", "ghidradwarfforge.coverage.ExportCoverage"),
            new Phase("type-evidence", "ghidradwarfforge.output.CoverageTypeEvidence"),
            new Phase("writer", "ghidradwarfforge.output.CoverageReportJson"),
            new Phase("reader", "ghidradwarfforge.output.CoverageReportClaims"));
        int controls = 0;
        for (boolean companion : List.of(false, true)) {
            Path directory = Files.createDirectory(root.resolve(companion ? "companion" : "pair"));
            Path output = directory.resolve("forge.dbg");
            List<String> options = new ArrayList<>(List.of("--packaged-natives",
                "--input=" + input, "--output=" + output));
            if (companion) options.add("--gdb-loader");
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            var previous = snapshot(directory);
            if (previous.size() != (companion ? 3 : 2)) throw new AssertionError("initial generation incomplete");
            for (Phase phase : phases) {
                for (boolean failure : List.of(false, true)) {
                    TaskMonitor original = monitor;
                    var probe = new Probe(original, phase, failure, directory);
                    boolean caught = false;
                    try {
                        monitor = probe;
                        runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
                    }
                    catch (CancellationException | CancelledException expected) {
                        if (failure) throw expected;
                        caught = true;
                    }
                    catch (InjectedFailure expected) {
                        if (!failure) throw expected;
                        caught = true;
                    }
                    finally {
                        monitor = original;
                    }
                    if (!caught || probe.polls != 5 || !previous.equals(snapshot(directory))) {
                        throw new AssertionError("report failure/cancellation changed the previous generation: " + phase.name());
                    }
                    if (!phase.name().equals("capture") && probe.stagedFiles < 2) {
                        throw new AssertionError("report was not prepared while both artifacts were staged");
                    }
                    if (phase.name().equals("capture") && probe.stagedFiles != 0) {
                        throw new AssertionError("instruction capture unexpectedly occurs after staging");
                    }
                    controls++;
                    println("coverage-staging-control=PASS mode=" + (companion ? "companion" : "pair") +
                        " phase=" + phase.name() + " outcome=" + (failure ? "FATAL" : "CANCELLED") +
                        " polls=" + probe.polls + " staged=" + probe.stagedFiles);
                }
            }
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            if (!previous.equals(snapshot(directory))) throw new AssertionError("retry is not byte deterministic");
        }
        if (!inputHash.equals(FileDigests.read(input).sha256())) throw new AssertionError("original changed");
        println("coverage-staging-controls=PASS controls=" + controls);
    }

    private static Map<String, String> snapshot(Path directory) throws Exception {
        Map<String, String> result = new LinkedHashMap<>();
        try (var files = Files.list(directory)) {
            for (Path file : files.sorted().toList()) {
                result.put(file.getFileName().toString(), FileDigests.read(file).sha256());
            }
        }
        return result;
    }

    private static final class InjectedFailure extends IllegalStateException {
        private InjectedFailure(String phase) { super("injected coverage staging failure: " + phase); }
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Phase phase;
        private final boolean failure;
        private final Path directory;
        private int polls;
        private long stagedFiles;

        private Probe(TaskMonitor delegate, Phase phase, boolean failure, Path directory) {
            super(delegate);
            this.phase = phase;
            this.failure = failure;
            this.directory = directory;
        }

        @Override
        public synchronized boolean isCancelled() {
            // Do not inject a second exception into the terminal report writer.
            if (polls == 5) return !failure;
            if (super.isCancelled()) return true;
            boolean inside = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                frame.getClassName().equals(phase.owner())));
            if (!inside || ++polls != 5) return false;
            try (var files = Files.list(directory)) {
                stagedFiles = files.filter(path -> path.getFileName().toString().endsWith(".staged")).count();
            }
            catch (java.io.IOException error) { throw new AssertionError(error); }
            if (failure) throw new InjectedFailure(phase.name());
            return true;
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
