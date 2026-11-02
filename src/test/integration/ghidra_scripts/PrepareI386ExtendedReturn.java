// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.nativeapi.DwarfTarget;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class PrepareI386ExtendedReturn extends GhidraScript {
    protected void run() throws Exception {
        boolean curate = getScriptArgs()[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var manager = currentProgram.getDataTypeManager();
        var types = Map.of("scalar_float", new FloatDataType(manager),
            "scalar_double", new DoubleDataType(manager), "scalar_extended", new LongDoubleDataType(manager));
        var rows = new ArrayList<Object>();
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[1]))) {
            monitor.checkCancelled();
            var fields = line.split(" ");
            var function = getFunctionAt(toAddr(Long.decode(fields[1]) + delta));
            if (function == null) throw new AssertionError("Missing fixture function " + fields[0]);
            DataType type = types.get(fields[0]);
            if (type == null) throw new AssertionError("Unexpected fixture name");
            if (curate) {
                function.setName(fields[0], SourceType.USER_DEFINED);
                function.updateFunction("__cdecl", new ReturnParameterImpl(type, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("a", type, currentProgram), new ParameterImpl("b", type, currentProgram));
            }
            rows.add(Map.of("name", function.getName(), "return", function.getReturn().getVariableStorage().toString(),
                "parameters", Arrays.stream(function.getParameters()).map(p -> Map.of("name", p.getName(),
                    "storage", p.getVariableStorage().toString(), "type", p.getFormalDataType().getPathName())).toList()));
        }
        if (rows.size() != 3) throw new AssertionError("Incomplete fixture");
        Files.writeString(Path.of(getScriptArgs()[2]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("functions", rows, "delta", delta,
                "origin", DwarfTarget.class.getProtectionDomain().getCodeSource().getLocation().toString())));
    }
}
