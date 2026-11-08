// Genuine native failure/warning context and bounded source composition.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.GhidraSourceContext;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.source.SourceContextMode;
import ghidradwarfforge.source.SyntheticSourceFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;

public class VerifySourceContext extends GhidraScript {
    private void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static class Probe extends TaskMonitorAdapter {
        int checks;
        int stop;
        Probe(int stop) { this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++checks == stop) throw new CancelledException();
        }
    }
    @Override protected void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        Files.createDirectories(output);
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> {}, 0);
        var collectors = new LinkedHashMap<String, GhidraSourceContext>();
        for (var mode : SourceContextMode.values()) collectors.put(mode.name(),
            new GhidraSourceContext(currentProgram, mode, GhidraSourceContext.Limits.DEFAULT));
        collectors.put("TRIGGERS", new GhidraSourceContext(currentProgram, SourceContextMode.BOTH,
            new GhidraSourceContext.Limits(1, 65536, 4194304)));
        collectors.put("FUNCTION", new GhidraSourceContext(currentProgram, SourceContextMode.BOTH,
            new GhidraSourceContext.Limits(8, 1024, 4194304)));
        collectors.put("EXPORT", new GhidraSourceContext(currentProgram, SourceContextMode.BOTH,
            new GhidraSourceContext.Limits(8, 65536, 2048)));
        var limited = new DecompInterface();
        boolean[] failed = {false};
        var observations = new ArrayList<Object>();
        try {
            var options = new DecompileOptions();
            options.setMaxInstructions(1);
            require(limited.setOptions(options) && limited.openProgram(currentProgram), "native limit setup failed");
            var decompilation = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, 0, monitor,
                (normal, function, timeout, taskMonitor) -> {
                    var firstInstruction = currentProgram.getListing().getInstructionAt(function.getEntryPoint());
                    boolean usableSample = firstInstruction != null &&
                        firstInstruction.getLength() == firstInstruction.getParsedLength() &&
                        function.getBody().contains(firstInstruction.getMinAddress(), firstInstruction.getMaxAddress()) &&
                        firstInstruction.getPcode(false).length > 0;
                    var result = !failed[0] && usableSample && function.getBody().getNumAddresses() > 16
                        ? limited.decompileFunction(function, timeout, taskMonitor)
                        : normal.decompileFunction(function, timeout, taskMonitor);
                    if (!failed[0] && !result.decompileCompleted()) failed[0] = true;
                    taskMonitor.checkCancelled();
                    if (result.getCCodeMarkup() != null) for (var line : ghidra.app.decompiler.component.DecompilerUtils.toLines(result.getCCodeMarkup())) {
                        for (var token : line.getAllTokens()) if (token.getSyntaxType() == ghidra.app.decompiler.ClangToken.COMMENT_COLOR)
                            println("native-comment-token=" + token.getClass().getSimpleName() + ":" + token.getText());
                    }
                    for (var collector : collectors.values()) collector.accept(function, result, taskMonitor);
                    var probe = new Probe(-1);
                    new GhidraSourceContext(currentProgram, SourceContextMode.BOTH, GhidraSourceContext.Limits.DEFAULT)
                        .accept(function, result, probe);
                    // Every checked extraction/formatting checkpoint interrupts the same native observation.
                    for (int stop = 1; stop <= probe.checks; stop++) {
                        try {
                            new GhidraSourceContext(currentProgram, SourceContextMode.BOTH, GhidraSourceContext.Limits.DEFAULT)
                                .accept(function, result, new Probe(stop));
                            throw new AssertionError("context cancellation ignored: " + function.getName() + ":" + stop);
                        }
                        catch (CancelledException expected) { }
                    }
                    observations.add(new java.util.TreeMap<>(Map.of("function", function.getName(), "completed", result.decompileCompleted(),
                        "cancellationPoints", probe.checks)));
                    return result;
                });
            require(failed[0], "fixture did not cause a real native instruction-limit failure");
            var original = decompilation.source();
            Files.write(output.resolve("baseline.c"), original.utf8());
            var sizes = new LinkedHashMap<String, Integer>();
            for (var entry : collectors.entrySet()) {
                var composed = entry.getValue().compose(original, 0, 16 * 1024 * 1024, monitor);
                Files.write(output.resolve(entry.getKey() + ".c"), composed.utf8());
                int added = composed.utf8().length - original.utf8().length;
                sizes.put(entry.getKey(), added);
                require(added <= (entry.getKey().equals("EXPORT") ? 2048 : 4194304), "export text budget exceeded");
                String text = new String(composed.utf8(), StandardCharsets.UTF_8);
                if (entry.getKey().equals("OFF")) require(Arrays.equals(original.utf8(), composed.utf8()), "off changed source");
                else {
                    require(added > 0, "no context emitted");
                    if (entry.getKey().equals("TRIGGERS")) require(text.contains("FUNCTION_TRIGGER_LIMIT"), "trigger cap untested");
                    if (entry.getKey().equals("FUNCTION")) require(text.contains("FUNCTION_TEXT_LIMIT"), "function cap untested");
                    if (entry.getKey().equals("EXPORT")) require(text.contains("EXPORT_TEXT_LIMIT"), "export cap untested");
                    if (entry.getKey().equals("BOTH")) {
                        require(text.contains("DECOMPILATION_FAILURE_ENTRY_SAMPLE"), "native failure sample missing");
                        require(text.contains("NATIVE_WARNING_UNMAPPED"), "warning evidence missing");
                        require(text.contains("BAD_INSTRUCTION_RETURN"), "bad-data RETURN evidence missing");
                        require(text.contains("No causal instruction address supplied"), "warning address fabricated");
                        require(text.contains("raw instruction p-code") && text.contains("effective flow-override p-code"), "pcode provenance missing");
                        require(text.contains("assembly:"), "assembly context missing");
                    }
                    if (entry.getKey().equals("ASSEMBLY")) require(!text.contains("raw instruction p-code"), "assembly requested pcode");
                    if (entry.getKey().equals("PCODE")) require(!text.contains("assembly:"), "pcode requested assembly");
                }
                String[] before = new String(original.utf8(), StandardCharsets.UTF_8).split("\n", -1);
                String[] after = text.split("\n", -1);
                require(original.mappedLines().size() == composed.mappedLines().size(), "executable rows added");
                for (int index = 0; index < original.mappedLines().size(); index++) {
                    var oldLine = original.mappedLines().get(index);
                    var newLine = composed.mappedLines().get(index);
                    require(oldLine.addresses().equals(newLine.addresses()) &&
                        before[oldLine.line() - 1].equals(after[newLine.line() - 1]), "executable line changed");
                }
                require(original.functions().size() == composed.functions().size(), "function inventory changed");
                for (int index = 0; index < original.functions().size(); index++) {
                    var oldFunction = original.functions().get(index);
                    var newFunction = composed.functions().get(index);
                    require(oldFunction.decompiled() == newFunction.decompiled() &&
                        java.util.Objects.equals(oldFunction.failureDiagnostic(), newFunction.failureDiagnostic()) &&
                        before[oldFunction.startLine() - 1].equals(after[newFunction.startLine() - 1]) &&
                        before[oldFunction.endLine() - 1].equals(after[newFunction.endLine() - 1]), "function source changed");
                }
            }
            var receipt = new LinkedHashMap<String, Object>();
            receipt.put("status", "PASS_NATIVE_SOURCE_CONTEXT_COMPONENT");
            receipt.put("origin", GhidraSourceContext.class.getProtectionDomain().getCodeSource().getLocation().toString());
            receipt.put("observations", observations);
            receipt.put("addedBytes", sizes);
            receipt.put("scope", "Actual native diagnostics and source remapping; production exporter/DWARF wiring still required.");
            Files.writeString(output.resolve("result.json"), new GsonBuilder().setPrettyPrinting().create().toJson(receipt) + "\n");
        }
        finally { limited.dispose(); }
        println("source-context=PASS");
    }
}
