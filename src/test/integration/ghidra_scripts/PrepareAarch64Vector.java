// Preserve explicit analyst lane layouts and compiler-corroborated custom storage.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraTypeGraph;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.GsonBuilder;

public class PrepareAarch64Vector extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("curate|observe labels-file result-json");
        }
        boolean curate = args[0].equals("curate");
        var manager = currentProgram.getDataTypeManager();
        long delta = currentProgram.getImageBase().getOffset() -
            GhidraImageBase.originalImageBase(currentProgram);
        var types = new HashMap<Boolean, DataType>();
        for (boolean floating : List.of(false, true)) {
            String name = floating ? "AnalystFloatLanes4" : "AnalystIntLanes4";
            DataType type = manager.getDataType("/" + name);
            if (curate) {
                DataType element = floating ? FloatDataType.dataType : SignedDWordDataType.dataType;
                type = manager.addDataType(new TypedefDataType(CategoryPath.ROOT, name,
                    new ArrayDataType(element, 4, 4, manager), manager), DataTypeConflictHandler.REPLACE_HANDLER);
            }
            if (type == null || type.getLength() != 16) throw new AssertionError("lane layout missing");
            types.put(floating, type);
        }
        var records = new ArrayList<Object>();
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            String name = fields[0];
            long address = Long.decode(fields[1]);
            var entry = toAddr(Math.addExact(address, delta));
            var function = getFunctionAt(entry);
            if (function == null) throw new AssertionError("missing function " + name);
            DataType type = types.get(name.equals("vector_float"));
            if (curate) {
                var parameters = new ArrayList<Parameter>();
                if (name.equals("vector_stack_arg")) {
                    for (int index = 0; index < 8; index++) {
                        parameters.add(new ParameterImpl(Character.toString('a' + index), type,
                            new VariableStorage(currentProgram, currentProgram.getRegister("q" + index)), currentProgram));
                    }
                    parameters.add(new ParameterImpl("value", type, new VariableStorage(currentProgram, 0, 16), currentProgram));
                }
                else {
                    parameters.add(new ParameterImpl("value", type,
                        new VariableStorage(currentProgram, currentProgram.getRegister("q0")), currentProgram));
                }
                function.setName(name, SourceType.USER_DEFINED);
                function.updateFunction(convention, new ReturnParameterImpl(type,
                    new VariableStorage(currentProgram, currentProgram.getRegister("q0")), currentProgram),
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    parameters.toArray(Parameter[]::new));
            }
            if (!function.hasCustomVariableStorage() || function.getSignatureSource() != SourceType.USER_DEFINED ||
                    !function.getReturnType().isEquivalent(type) || !function.getName().equals(name)) {
                throw new AssertionError("saved signature changed");
            }
            var parameters = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                if (!parameter.getFormalDataType().isEquivalent(type) || parameter.getLength() != 16 ||
                        parameter.isAutoParameter() || parameter.getVariableStorage().isForcedIndirect()) {
                    throw new AssertionError("array view decayed to a pointer or lost storage");
                }
                parameters.add(Map.of("name", parameter.getName(), "type", parameter.getFormalDataType().getDisplayName(),
                    "storage", parameter.getVariableStorage().toString(), "bytes", parameter.getLength()));
            }
            records.add(Map.of("name",name,"address",address,"signature",function.getPrototypeString(false,false),
                "returnType",function.getReturnType().getDisplayName(),"returnStorage",function.getReturn().getVariableStorage().toString(),
                "parameters",parameters));
        }
        if (records.size() != 6) throw new AssertionError("fixture inventory changed");
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", records, "delta", delta, "language", currentProgram.getLanguageID().toString(),
            "compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "origin",GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
        println("aarch64-vector-preparation=PASS");
    }
}
