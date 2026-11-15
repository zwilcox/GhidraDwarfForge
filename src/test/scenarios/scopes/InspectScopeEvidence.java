// Read-only research probe; never treats decompiler first-use as lexical scope.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Namespace;

public class InspectScopeEvidence extends GhidraScript {
    private Object owners(Namespace namespace) {
        var rows = new ArrayList<Object>();
        for (var current = namespace; current != null && !current.isGlobal(); current = current.getParentNamespace()) {
            rows.add(Map.of("id", current.getID(), "name", current.getName(), "kind", current.getType().toString()));
        }
        return rows;
    }
    private Object variable(Variable v) {
        var row = new LinkedHashMap<String, Object>();
        row.put("name", v.getName()); row.put("type", v.getDataType().getPathName());
        row.put("firstUse", v.getFirstUseOffset()); row.put("storage", v.getVariableStorage().toString());
        row.put("source", v.getSource().toString()); row.put("symbolId", v.getSymbol() == null ? null : v.getSymbol().getID());
        row.put("owners", owners(v.getSymbol() == null ? null : v.getSymbol().getParentNamespace()));
        if (v instanceof Parameter p) row.put("autoKind", String.valueOf(p.getAutoParameterType()));
        return row;
    }
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("output-json");
        var result = new LinkedHashMap<String, Object>();
        result.put("program", currentProgram.getName()); result.put("language", currentProgram.getLanguageID().toString());
        result.put("javaVersion", System.getProperty("java.version"));
        var functions = new ArrayList<Object>();
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new AssertionError("openProgram");
            for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (!function.getName(true).contains("inspect_scope") && !function.getName().equals("main") && !function.getName().startsWith("FUN_")) continue;
                var row = new LinkedHashMap<String, Object>();
                row.put("name", function.getName(true)); row.put("entry", function.getEntryPoint().toString());
                row.put("symbolId", function.getSymbol().getID());
                row.put("owners", owners(function.getParentNamespace())); row.put("convention", function.getCallingConventionName());
                var variables = new ArrayList<Object>();
                for (var v : function.getAllVariables()) variables.add(variable(v));
                row.put("savedVariables", variables);
                var output = decompiler.decompileFunction(function, 30, monitor);
                row.put("decompiled", output.decompileCompleted()); row.put("error", output.getErrorMessage());
                var high = output.getHighFunction();
                var symbols = new ArrayList<Object>();
                if (high != null) {
                    var iterator = high.getLocalSymbolMap().getSymbols();
                    while (iterator.hasNext()) {
                        var symbol = iterator.next();
                        var s = new LinkedHashMap<String, Object>();
                        s.put("id", symbol.getId()); s.put("name", symbol.getName());
                        s.put("type", symbol.getDataType().getPathName()); s.put("storage", symbol.getStorage().toString());
                        s.put("firstMappingAddress", String.valueOf(symbol.getPCAddress()));
                        s.put("owners", owners(symbol.getNamespace()));
                        s.put("savedSymbol", symbol.getSymbol() != null);
                        symbols.add(s);
                    }
                }
                row.put("highSymbols", symbols);
                if (output.getDecompiledFunction() != null) row.put("syntheticC", output.getDecompiledFunction().getC());
                functions.add(row);
            }
        } finally { decompiler.dispose(); }
        result.put("functions", functions);
        var objects = new ArrayList<Object>();
        var symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbolIterator.hasNext()) {
            monitor.checkCancelled();
            var symbol = symbolIterator.next();
            if (!symbol.getName().equals("visits") && !symbol.getName().equals("first_object") && !symbol.getName().equals("second_object")) continue;
            var data = currentProgram.getListing().getDefinedDataAt(symbol.getAddress());
            objects.add(Map.of("name", symbol.getName(), "id", symbol.getID(),
                "address", symbol.getAddress().toString(), "owners", owners(symbol.getParentNamespace()),
                "type", data == null ? "" : data.getDataType().getPathName()));
        }
        result.put("objects", objects);
        var types = new ArrayList<Object>();
        var iterator = currentProgram.getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            var type = iterator.next();
            if (type.getName().equals("Same") || type.getName().equals("Counter")) types.add(Map.of("path", type.getPathName(), "size", type.getLength(), "kind", type.getClass().getName()));
        }
        result.put("types", types);
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("SCOPE_EVIDENCE_PROBE_PASS");
    }
}
