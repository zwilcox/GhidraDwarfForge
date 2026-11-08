// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmHfaLifetimes extends GhidraScript {
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "inspect").contains(args[0])) throw new IllegalArgumentException();
        var rows = new ArrayList<Object>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            var fields = line.split(" ");
            String name = fields[0];
            var function = getFunctionAt(toAddr(Long.decode(fields[1])));
            if (function == null) throw new AssertionError(name);
            DataType scalar = name.equals("sum_floats") ? FloatDataType.dataType : DoubleDataType.dataType;
            var type = new StructureDataType(name.equals("sum_floats") ? "FloatPair" : "DoublePair", 0,
                currentProgram.getDataTypeManager());
            type.add(scalar, "first", null);
            type.add(scalar, "second", null);
            if (args[0].equals("curate")) {
                function.setName(name, SourceType.USER_DEFINED);
                function.updateFunction("__stdcall", new ReturnParameterImpl(scalar, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
            }
            if (function.hasCustomVariableStorage() || !function.getCallingConventionName().equals("__stdcall") ||
                    function.getParameters().length != 1 ||
                    !function.getParameter(0).getFormalDataType().isEquivalent(type)) throw new AssertionError(name);
            rows.add(Map.of("name", name, "storage", function.getParameter(0).getVariableStorage().toString(),
                "signature", function.getPrototypeString(false, false)));
        }
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", rows, "language", currentProgram.getLanguageID().toString(),
            "origin", ghidradwarfforge.GhidraVariableStorage.class.getProtectionDomain()
                .getCodeSource().getLocation().toString())) + "\n");
        println("hfa-lifetime-preparation=PASS");
    }
}
