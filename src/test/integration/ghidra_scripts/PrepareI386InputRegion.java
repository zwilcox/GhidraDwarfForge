// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidradwarfforge.GhidraParameterAllocation;

public class PrepareI386InputRegion extends GhidraScript {
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        int count = Integer.parseInt(args[1]);
        var rows = new ArrayList<Object>();
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!Set.of("big", "ordinary").contains(function.getName())) continue;
            if (args[0].equals("curate")) {
                var manager = currentProgram.getDataTypeManager();
                boolean big = function.getName().equals("big");
                DataType returned = big ? new LongDoubleDataType(manager) : new IntegerDataType(manager);
                var parameters = new Parameter[big ? count : 0];
                for (int i = 0; i < parameters.length; i++) parameters[i] = new ParameterImpl("a" + i,
                    new IntegerDataType(manager), currentProgram);
                function.updateFunction("__cdecl", new ReturnParameterImpl(returned, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters);
            }
            rows.add(Map.of("name", function.getName(), "address", function.getEntryPoint().toString(),
                "prototype", function.getPrototypeString(false, false),
                "returnType", function.getReturn().getFormalDataType().getPathName(),
                "returnStorage", function.getReturn().getVariableStorage().toString(),
                "parameters", Arrays.stream(function.getParameters()).map(p -> Map.of("name", p.getName(),
                    "ordinal", p.getOrdinal(), "type", p.getFormalDataType().getPathName(),
                    "storage", p.getVariableStorage().toString())).toList()));
        }
        if (rows.size() != 2) throw new AssertionError("missing fixture functions");
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", rows, "origin", GhidraParameterAllocation.class.getProtectionDomain().getCodeSource().getLocation().toString())));
        println("i386-limit-model=PASS count=" + count);
    }
}
