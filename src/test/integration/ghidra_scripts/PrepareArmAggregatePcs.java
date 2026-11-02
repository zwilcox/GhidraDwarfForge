// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmAggregatePcs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "inspect").contains(args[0])) {
            throw new IllegalArgumentException("curate|inspect labels.txt observation.json");
        }
        boolean curate = args[0].equals("curate");
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            labels.put(fields[0], Long.decode(fields[1]));
        }
        var manager = currentProgram.getDataTypeManager();
        var types = Map.of(
            "pair", structure("Pair", IntegerDataType.dataType, IntegerDataType.dataType),
            "float3", structure("Float3", FloatDataType.dataType, FloatDataType.dataType, FloatDataType.dataType),
            "double2", structure("Double2", DoubleDataType.dataType, DoubleDataType.dataType),
            "mixed", structure("Mixed", IntegerDataType.dataType, FloatDataType.dataType));
        var records = new ArrayList<Object>();
        for (String pcs : List.of("base", "vfp")) {
            for (String kind : List.of("pair", "float3", "double2", "mixed", "split", "exhaust")) {
                String name = pcs + "_" + kind;
                var function = getFunctionAt(toAddr(labels.get(name)));
                if (function == null) throw new AssertionError("no function " + name);
                String convention = pcs.equals("base") ? "__stdcall_softfp" : "__stdcall";
                DataType result = kind.equals("split") ? IntegerDataType.dataType :
                    kind.equals("exhaust") ? DoubleDataType.dataType : types.get(kind);
                var parameters = new ArrayList<ParameterImpl>();
                int count = kind.equals("split") ? 3 : kind.equals("exhaust") ? 7 : 0;
                for (int index = 0; index < count; index++) {
                    parameters.add(new ParameterImpl(Character.toString('a' + index),
                        kind.equals("split") ? IntegerDataType.dataType : DoubleDataType.dataType, currentProgram));
                }
                parameters.add(new ParameterImpl("value", types.get(kind.equals("split") ? "pair" :
                    kind.equals("exhaust") ? "float3" : kind), currentProgram));
                if (curate) {
                    function.setName(name, SourceType.USER_DEFINED);
                    function.updateFunction(convention, new ReturnParameterImpl(result, currentProgram),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                        parameters.toArray(ParameterImpl[]::new));
                }
                var explicit = Arrays.stream(function.getParameters()).filter(p -> !p.isAutoParameter()).toList();
                if (function.hasCustomVariableStorage() || !function.getCallingConventionName().equals(convention) ||
                        explicit.size() != parameters.size() || !function.getReturn().getFormalDataType().isEquivalent(result)) {
                    throw new AssertionError("recorded PCS changed " + name);
                }
                for (int index = 0; index < explicit.size(); index++) {
                    if (!explicit.get(index).getName().equals(parameters.get(index).getName()) ||
                            !explicit.get(index).getFormalDataType().isEquivalent(parameters.get(index).getDataType())) {
                        throw new AssertionError("recorded parameter changed " + name);
                    }
                }
                var definition = new FunctionDefinitionDataType(name + "_type", manager);
                definition.setReturnType(result);
                definition.setCallingConvention(convention);
                definition.setArguments(parameters.stream().map(parameter -> new ParameterDefinitionImpl(
                    parameter.getName(), parameter.getDataType(), "")).toArray(ParameterDefinition[]::new));
                data(labels.get(name + "_pointer"), name + "_pointer", new PointerDataType(definition, manager), curate);
                records.add(Map.of("name", name, "convention", function.getCallingConventionName(),
                    "customStorage", function.hasCustomVariableStorage(), "signature", function.getPrototypeString(false, false),
                    "returnType", function.getReturn().getFormalDataType().getDisplayName(),
                    "returnStorage", function.getReturn().getVariableStorage().toString(), "parameters",
                    Arrays.stream(function.getParameters()).map(parameter -> Map.of("name", parameter.getName(),
                        "type", parameter.getFormalDataType().getDisplayName(), "storage", parameter.getVariableStorage().toString(),
                        "automatic", parameter.isAutoParameter(), "length", parameter.getLength())).toList()));
            }
        }
        for (var entry : types.entrySet()) {
            for (String prefix : List.of("input_", "seen_")) {
                String name = prefix + entry.getKey();
                data(labels.get(name), name, entry.getValue(), curate);
            }
        }
        data(labels.get("seen_ints"), "seen_ints", new ArrayDataType(IntegerDataType.dataType, 3, 4, manager), curate);
        data(labels.get("seen_doubles"), "seen_doubles", new ArrayDataType(DoubleDataType.dataType, 7, 8, manager), curate);
        data(labels.get("calls"), "calls", UnsignedIntegerDataType.dataType, curate);
        if (curate) getFunctionAt(toAddr(labels.get("marker"))).setName("marker", SourceType.USER_DEFINED);
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", records, "language", currentProgram.getLanguageID().toString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "origin", ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.class.getProtectionDomain()
                .getCodeSource().getLocation().toString())) + "\n");
        println("arm-aggregate-pcs-preparation=PASS");
    }

    private StructureDataType structure(String name, DataType... fields) {
        var result = new StructureDataType(name, 0, currentProgram.getDataTypeManager());
        result.setPackingEnabled(true);
        for (int index = 0; index < fields.length; index++) {
            result.add(fields[index], Character.toString('a' + index), "");
        }
        return result;
    }

    private void data(long address, String name, DataType type, boolean curate) throws Exception {
        if (curate) {
            DataUtilities.createData(currentProgram, toAddr(address), type, type.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            createLabel(toAddr(address), name, true, SourceType.USER_DEFINED);
        }
        if (!getDataAt(toAddr(address)).getDataType().isEquivalent(type)) throw new AssertionError("data changed " + name);
    }
}
