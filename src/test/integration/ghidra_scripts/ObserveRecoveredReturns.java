// Read-only return evidence and precedence controls for default signatures.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;

public class ObserveRecoveredReturns extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("curate|observe output required");
        }
        var names = List.of("recovered_signed", "recovered_unsigned", "recovered_double", "curated_pointer", "curated_void");
        var selected = new LinkedHashMap<String, Function>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (names.contains(function.getName()) && selected.put(function.getName(), function) != null) {
                throw new IllegalStateException("duplicate named fixture");
            }
        }
        if (selected.size() != names.size()) { throw new IllegalStateException("missing fixture functions"); }
        if (args[0].equals("curate")) {
            selected.get("curated_pointer").setReturnType(new PointerDataType(IntegerDataType.dataType,
                currentProgram.getDataTypeManager()), SourceType.USER_DEFINED);
            selected.get("curated_void").setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
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
                row.put("returnSource", function.getReturn().getSource().name());
                row.put("formalName", function.getReturn().getFormalDataType().getName());
                row.put("formalClass", function.getReturn().getFormalDataType().getClass().getName());
                row.put("customStorage", function.hasCustomVariableStorage());
                var result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    throw new IllegalStateException("decompilation failed: " + name);
                }
                var returned = result.getHighFunction().getFunctionPrototype().getReturnType();
                row.put("recoveredName", returned.getName());
                row.put("recoveredClass", returned.getClass().getName());
                row.put("recoveredBytes", returned.getLength());
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
