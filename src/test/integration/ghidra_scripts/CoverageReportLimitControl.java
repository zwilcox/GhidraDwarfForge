// Reject an actual oversized captured type identifier before publishing artifacts.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CoverageReportLimitControl extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("usage: <input> <new controls directory>");
        Path input = Path.of(args[0]);
        Path root = Files.createDirectory(Path.of(args[1]));
        String inputHash = FileDigests.read(input).sha256();
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        ghidra.program.model.listing.Function selected = null;
        while (functions.hasNext()) {
            var function = functions.next();
            if (function.getName().equals("scoped")) selected = function;
        }
        if (selected == null) throw new AssertionError("missing lexical fixture function");
        var local = java.util.Arrays.stream(selected.getLocalVariables())
            .filter(variable -> variable.getName().equals("shadow")).findFirst().orElseThrow();
        var originalType = local.getDataType();
        CategoryPath category = CategoryPath.ROOT;
        for (int index = 0; index < 34; index++) {
            category = new CategoryPath(category, "coverage_" + index + "_" + "x".repeat(1990));
        }
        var manager = currentProgram.getDataTypeManager();
        var named = manager.addDataType(new TypedefDataType(category, "EvidenceLimitType",
            originalType, manager), DataTypeConflictHandler.DEFAULT_HANDLER);
        // Named database types use compact universal IDs. Derived pointer types
        // have no universal ID and retain their full category path in coverage.
        var oversized = manager.addDataType(new PointerDataType(named, originalType.getLength(), manager),
            DataTypeConflictHandler.DEFAULT_HANDLER);
        if (oversized.getPathName().length() <= 65536) throw new AssertionError("type does not exceed report string limit");
        if (oversized.getUniversalID() != null) throw new AssertionError("derived type unexpectedly has a compact universal ID");
        println("coverage-limit-type-units=" + oversized.getPathName().length());
        for (boolean companion : List.of(false, true)) {
            Path directory = Files.createDirectory(root.resolve(companion ? "companion" : "pair"));
            Path output = directory.resolve("forge.dbg");
            List<String> options = new ArrayList<>(List.of("--packaged-natives",
                "--input=" + input, "--output=" + output));
            if (companion) options.add("--gdb-loader");
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            var previous = snapshot(directory);
            TaskMonitor originalMonitor = monitor;
            var probe = new ObserveReport(originalMonitor, directory);
            boolean rejected = false;
            try {
                local.setDataType(oversized, SourceType.USER_DEFINED);
                monitor = probe;
                runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            }
            catch (IOException expected) {
                if (!expected.getMessage().equals("coverage string exceeds UTF-16 unit budget")) throw expected;
                rejected = true;
            }
            finally {
                monitor = originalMonitor;
                local.setDataType(originalType, SourceType.USER_DEFINED);
            }
            if (!rejected || probe.stagedFiles < 2 || !previous.equals(snapshot(directory))) {
                throw new AssertionError("real report limit did not preserve the existing generation");
            }
            println("coverage-real-limit=PASS mode=" + (companion ? "companion" : "pair") +
                " staged=" + probe.stagedFiles);
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
            if (!previous.equals(snapshot(directory))) throw new AssertionError("report-limit retry is not deterministic");
        }
        if (!inputHash.equals(FileDigests.read(input).sha256())) throw new AssertionError("original changed");
        println("coverage-real-limit-controls=PASS controls=2");
    }

    private static Map<String, String> snapshot(Path directory) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        try (var files = Files.list(directory)) {
            for (Path file : files.sorted().toList()) {
                result.put(file.getFileName().toString(), FileDigests.read(file).sha256());
            }
        }
        return result;
    }

    private static final class ObserveReport extends WrappingTaskMonitor {
        private final Path directory;
        private long stagedFiles;

        private ObserveReport(TaskMonitor delegate, Path directory) {
            super(delegate);
            this.directory = directory;
        }

        @Override
        public boolean isCancelled() {
            if (stagedFiles == 0 && StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                    frame.getClassName().equals("ghidradwarfforge.output.CoverageReportJson")))) {
                try (var files = Files.list(directory)) {
                    stagedFiles = files.filter(path -> path.getFileName().toString().endsWith(".staged")).count();
                }
                catch (IOException failure) { throw new AssertionError(failure); }
            }
            return super.isCancelled();
        }
    }
}
