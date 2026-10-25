// Read-only decompiler parameter evidence and analyst-precedence control.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;

public class ObserveRecoveredParameters extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("curate|observe output required");
        }
        var names = List.of("inferred_scalar", "inferred_pointer", "inferred_floating",
            "unresolved_pair", "curated_scalar");
        var selected = new LinkedHashMap<String, Function>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (names.contains(function.getName()) && selected.put(function.getName(), function) != null) {
                throw new IllegalStateException("duplicate named fixture");
            }
        }
        if (selected.size() != names.size()) { throw new IllegalStateException("missing fixture functions"); }
        if (args[0].equals("curate")) {
            Function function = selected.get("curated_scalar");
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                new ParameterImpl("analyst_seed", IntegerDataType.dataType, currentProgram));
        }
        var decompiler = new DecompInterface();
        var rows = new ArrayList<Object>();
        try {
            if (!decompiler.openProgram(currentProgram)) { throw new IllegalStateException("decompiler open failed"); }
            for (String name : names) {
                monitor.checkCancelled();
                Function function = selected.get(name);
                var row = new LinkedHashMap<String, Object>();
                row.put("name", name);
                row.put("address", function.getEntryPoint().getOffset());
                row.put("signatureSource", function.getSignatureSource().name());
                row.put("listingParameterCount", function.getParameterCount());
                row.put("customStorage", function.hasCustomVariableStorage());
                var result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    throw new IllegalStateException("decompilation failed: " + name);
                }
                var prototype = result.getHighFunction().getFunctionPrototype();
                row.put("varargs", prototype.isVarArg());
                var parameters = new ArrayList<Object>();
                for (int index = 0; index < prototype.getNumParams(); index++) {
                    var parameter = prototype.getParam(index);
                    var observation = new LinkedHashMap<String, Object>();
                    observation.put("name", parameter.getName());
                    observation.put("type", parameter.getDataType().getName());
                    observation.put("bytes", parameter.getDataType().getLength());
                    observation.put("typeClass", parameter.getDataType().getClass().getName());
                    observation.put("hidden", parameter.isHiddenReturn());
                    observation.put("thisPointer", parameter.isThisPointer());
                    parameters.add(observation);
                }
                row.put("parameters", parameters);
                row.put("source", result.getDecompiledFunction().getC());
                rows.add(row);
            }
        }
        finally { decompiler.dispose(); }
        var report = new LinkedHashMap<String, Object>();
        report.put("javaVersion", System.getProperty("java.version"));
        report.put("exporterOrigin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        report.put("functions", rows);
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
    }
}
