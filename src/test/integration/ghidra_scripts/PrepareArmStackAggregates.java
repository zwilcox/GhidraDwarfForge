// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmStackAggregates extends GhidraScript {
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "inspect").contains(args[0])) throw new IllegalArgumentException();
        boolean curate = args[0].equals("curate");
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            labels.put(fields[0], Long.decode(fields[1]));
        }
        var types = new LinkedHashMap<String, DataType>();
        types.put("pair", structure("Pair", IntegerDataType.dataType, IntegerDataType.dataType));
        types.put("aligned", structure("Aligned", UnsignedLongLongDataType.dataType, IntegerDataType.dataType));
        var packed = structure("Packed", UnsignedCharDataType.dataType, UnsignedIntegerDataType.dataType);
        packed.setExplicitPackingValue(1);
        types.put("packed", packed);
        types.put("bytes", structure("Bytes", UnsignedCharDataType.dataType, UnsignedCharDataType.dataType, UnsignedCharDataType.dataType));
        var words = new StructureDataType("Words", 0, currentProgram.getDataTypeManager());
        words.setPackingEnabled(true);
        words.add(new ArrayDataType(IntegerDataType.dataType, 3, 4), "items", null);
        types.put("words", words);
        types.put("mixed", structure("Mixed", FloatDataType.dataType, UnsignedLongLongDataType.dataType));
        types.put("floats", structure("Floats", FloatDataType.dataType, FloatDataType.dataType, FloatDataType.dataType));
        var sizes = Map.of("pair", 8, "aligned", 16, "packed", 5, "bytes", 3, "words", 12, "mixed", 16, "floats", 12);
        var rows = new ArrayList<Object>();
        for (String pcs : List.of("base", "vfp")) {
            for (var entry : types.entrySet()) {
                String kind = entry.getKey();
                String name = pcs + "_" + kind;
                DataType type = entry.getValue();
                if (type.getLength() != sizes.get(kind)) throw new AssertionError("layout size " + name);
                var parameters = new ArrayList<ParameterImpl>();
                boolean floating = kind.equals("floats");
                for (int index = 0; index < (floating ? 7 : 3); index++) {
                    parameters.add(new ParameterImpl(Character.toString('a' + index),
                        floating ? DoubleDataType.dataType : IntegerDataType.dataType, currentProgram, SourceType.USER_DEFINED));
                }
                parameters.add(new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
                parameters.add(new ParameterImpl("tail", floating ? FloatDataType.dataType : IntegerDataType.dataType,
                    currentProgram, SourceType.USER_DEFINED));
                String convention = pcs.equals("base") ? "__stdcall_softfp" : "__stdcall";
                var function = getFunctionAt(toAddr(labels.get(name)));
                if (function == null) throw new AssertionError("missing function " + name);
                if (curate) {
                    function.setName(name, SourceType.USER_DEFINED);
                    function.updateFunction(convention, new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                        parameters.toArray(ParameterImpl[]::new));
                    createLabel(toAddr(labels.get(name + "_observe")), name + "_observe", true, SourceType.USER_DEFINED);
                }
                if (function.hasCustomVariableStorage() || !function.getCallingConventionName().equals(convention) ||
                        function.getParameterCount() != parameters.size()) throw new AssertionError(name);
                rows.add(Map.of("name", name, "signature", function.getPrototypeString(false, false),
                    "parameters", Arrays.stream(function.getParameters()).map(p -> Map.of("name", p.getName(),
                        "type", p.getFormalDataType().getDisplayName(), "storage", p.getVariableStorage().toString())).toList()));
            }
        }
        if (curate) {
            for (var entry : types.entrySet()) {
                for (String prefix : List.of("input_", "seen_")) {
                    String name = prefix + entry.getKey();
                    var address = toAddr(labels.get(name));
                    DataUtilities.createData(currentProgram, address, entry.getValue(), entry.getValue().getLength(),
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    createLabel(address, name, true, SourceType.USER_DEFINED);
                }
            }
        }
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", rows, "language", currentProgram.getLanguageID().toString(), "origin",
            ghidradwarfforge.GhidraVariableStorage.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
        println("arm-stack-aggregates-preparation=PASS");
    }

    private StructureDataType structure(String name, DataType... members) {
        var result = new StructureDataType(name, 0, currentProgram.getDataTypeManager());
        result.setPackingEnabled(true);
        String[] fields = {"first", "second", "third"};
        for (int index = 0; index < members.length; index++) result.add(members[index], fields[index], null);
        return result;
    }
}
