// Mutates only owned fixture inputs/programs while the real export is staged.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import ghidradwarfforge.output.FileDigests;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportConsistencyControls extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("input new-output-directory libdwarf libdwarfp");
        Path input = Path.of(args[0]), root = Path.of(args[1]);
        Files.createDirectory(root);
        byte[] originalBytes = Files.readAllBytes(input);
        Path other = Files.createDirectory(root.resolve("other-parent"));
        Files.copy(input, other.resolve(input.getFileName()));
        Path selectedParent = Files.createSymbolicLink(root.resolve("selected-parent"), input.getParent());
        var function = currentProgram.getFunctionManager().getFunctions(true).next();
        String originalComment = function.getComment();
        int controls = 0;
        for (boolean companion : List.of(false, true)) {
            Path directory = Files.createDirectory(root.resolve(companion ? "companion" : "pair"));
            Path output = directory.resolve("forge.dbg");
            var options = new ArrayList<>(List.of("--input=" + input, "--output=" + output,
                "--libdwarf=" + args[2], "--libdwarfp=" + args[3]));
            if (companion) options.add("--gdb-loader");
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            var baseline = snapshot(directory);
            for (String change : List.of("input", "program", "selected-parent")) {
                var selected = new ArrayList<>(options);
                if (change.equals("selected-parent")) selected.set(0, "--input=" + selectedParent.resolve(input.getFileName()));
                TaskMonitor saved = monitor;
                boolean[] injected = {false};
                boolean caught = false;
                monitor = new WrappingTaskMonitor(saved) {
                    @Override public synchronized boolean isCancelled() {
                        if (super.isCancelled()) return true;
                        if (!injected[0] && StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                                frame.getClassName().equals("ghidradwarfforge.output.CoverageReportJson")))) {
                            injected[0] = true;
                            try {
                                switch (change) {
                                    case "program" -> function.setComment("injected export consistency change");
                                    case "input" -> Files.write(input, Arrays.copyOf(originalBytes, originalBytes.length + 1));
                                    default -> {
                                        Files.delete(selectedParent);
                                        Files.createSymbolicLink(selectedParent, other);
                                    }
                                }
                                try (var files = Files.list(directory)) {
                                    if (files.filter(path -> path.toString().endsWith(".staged")).count() < 2) {
                                        throw new AssertionError("consistency control did not reach staged report generation");
                                    }
                                }
                            }
                            catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                        }
                        return false;
                    }
                };
                try { runScript("GhidraDwarfForge.java", selected.toArray(String[]::new)); }
                catch (IOException expected) {
                    String reason = switch (change) {
                        case "program" -> "Ghidra program changed during export";
                        case "input" -> "Original ELF changed during export";
                        default -> "Original ELF selection changed during export";
                    };
                    boolean earlierCompanionCheck = companion && change.equals("input") && expected.getMessage().equals(
                        "GDB companion requires a matched Forge sidecar for the selected input");
                    if (!expected.getMessage().contains(reason) && !earlierCompanionCheck) throw expected;
                    caught = true;
                }
                finally {
                    monitor = saved;
                    switch (change) {
                        case "program" -> function.setComment(originalComment);
                        case "input" -> Files.write(input, originalBytes);
                        default -> {
                            Files.delete(selectedParent);
                            Files.createSymbolicLink(selectedParent, input.getParent());
                        }
                    }
                }
                if (!injected[0] || !caught || !baseline.equals(snapshot(directory))) {
                    throw new AssertionError("changed evidence was published: companion=" + companion + " change=" + change);
                }
                controls++;
                println("export-consistency-control=PASS companion=" + companion + " change=" + change);
                runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
                if (!baseline.equals(snapshot(directory))) throw new AssertionError("restored input/program retry changed artifacts");
            }
            cleanupWarning(directory, options, baseline, companion);
        }
        if (!Arrays.equals(originalBytes, Files.readAllBytes(input))) throw new AssertionError("fixture input was not restored");
        println("export-consistency-controls=PASS controls=" + controls);
    }

    private void cleanupWarning(Path directory, List<String> options, Map<String, String> expected,
            boolean companion) throws Exception {
        for (String name : expected.keySet()) Files.writeString(directory.resolve(name), "previous generation");
        TaskMonitor saved = monitor;
        Path[] witness = {null};
        monitor = new WrappingTaskMonitor(saved) {
            @Override public synchronized boolean isCancelled() {
                if (super.isCancelled()) return true;
                if (witness[0] == null && StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                        frame.getClassName().equals("ghidradwarfforge.output.CoverageReportJson")))) {
                    try (var entries = Files.list(directory)) {
                        Path staging = entries.filter(Files::isDirectory).filter(path ->
                            path.getFileName().toString().startsWith(".forge-generation-")).findFirst().orElseThrow();
                        witness[0] = Files.writeString(staging.resolve("keep"), "cleanup witness");
                    }
                    catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                }
                return false;
            }
        };
        println("cleanup-warning-start companion=" + companion);
        try { runScript("GhidraDwarfForge.java", options.toArray(String[]::new)); }
        finally { monitor = saved; }
        if (witness[0] == null || !Files.readString(witness[0]).equals("cleanup witness")) {
            throw new AssertionError("cleanup removed an unrelated file or the fault was not injected");
        }
        Files.delete(witness[0]);
        Files.delete(witness[0].getParent());
        if (!expected.equals(snapshot(directory))) throw new AssertionError("warning reported an incomplete commit");
        println("cleanup-warning-end companion=" + companion);
    }

    private static Map<String, String> snapshot(Path directory) throws Exception {
        var result = new LinkedHashMap<String, String>();
        try (var files = Files.list(directory)) {
            for (Path file : files.sorted().toList()) result.put(file.getFileName().toString(), FileDigests.read(file).sha256());
        }
        return result;
    }
}
