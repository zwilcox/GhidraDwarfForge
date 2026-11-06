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
            for (boolean programChange : List.of(false, true)) {
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
                                if (programChange) function.setComment("injected export consistency change");
                                else Files.write(input, Arrays.copyOf(originalBytes, originalBytes.length + 1));
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
                try { runScript("GhidraDwarfForge.java", options.toArray(String[]::new)); }
                catch (IOException expected) {
                    String reason = programChange ? "Ghidra program changed during export" : "Original ELF changed during export";
                    boolean earlierCompanionCheck = companion && !programChange && expected.getMessage().equals(
                        "GDB companion requires a matched Forge sidecar for the selected input");
                    if (!expected.getMessage().contains(reason) && !earlierCompanionCheck) throw expected;
                    caught = true;
                }
                finally {
                    monitor = saved;
                    if (programChange) function.setComment(originalComment);
                    else Files.write(input, originalBytes);
                }
                if (!injected[0] || !caught || !baseline.equals(snapshot(directory))) {
                    throw new AssertionError("changed evidence was published: companion=" + companion + " program=" + programChange);
                }
                controls++;
                println("export-consistency-control=PASS companion=" + companion + " program=" + programChange);
                runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
                if (!baseline.equals(snapshot(directory))) throw new AssertionError("restored input/program retry changed artifacts");
            }
        }
        if (!Arrays.equals(originalBytes, Files.readAllBytes(input))) throw new AssertionError("fixture input was not restored");
        println("export-consistency-controls=PASS controls=" + controls);
    }

    private static Map<String, String> snapshot(Path directory) throws Exception {
        var result = new LinkedHashMap<String, String>();
        try (var files = Files.list(directory)) {
            for (Path file : files.sorted().toList()) result.put(file.getFileName().toString(), FileDigests.read(file).sha256());
        }
        return result;
    }
}
