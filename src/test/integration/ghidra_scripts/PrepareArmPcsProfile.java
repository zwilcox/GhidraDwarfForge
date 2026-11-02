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

public class PrepareArmPcsProfile extends GhidraScript {
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
        var records = new ArrayList<Object>();
        for (String pcs : List.of("base", "vfp")) {
            for (String kind : List.of("float", "double", "wide", "many")) {
                String name = pcs + "_" + kind;
                var function = getFunctionAt(toAddr(labels.get(name)));
                if (function == null) throw new AssertionError("no function " + name);
                DataType type = kind.equals("float") ? FloatDataType.dataType : kind.equals("wide") ?
                    LongLongDataType.dataType : DoubleDataType.dataType;
                String convention = pcs.equals("base") ? "__stdcall_softfp" : "__stdcall";
                var parameters = new ArrayList<ParameterImpl>();
                int count = kind.equals("many") ? 10 : 2;
                for (int index = 0; index < count; index++) {
                    String parameter = count == 10 ? Character.toString('a' + index) : index == 0 ? "first" : "second";
                    parameters.add(new ParameterImpl(parameter, type, currentProgram));
                }
                if (curate) {
                    function.setName(name, SourceType.USER_DEFINED);
                    function.updateFunction(convention, new ReturnParameterImpl(type, currentProgram),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                        parameters.toArray(ParameterImpl[]::new));
                }
                if (function.hasCustomVariableStorage() || !function.getCallingConventionName().equals(convention) ||
                        function.getParameterCount() != count || !function.getReturnType().isEquivalent(type)) {
                    throw new AssertionError("recorded PCS changed " + name);
                }
                var definition = new FunctionDefinitionDataType(name + "_type", manager);
                definition.setReturnType(type);
                definition.setCallingConvention(convention);
                definition.setArguments(parameters.stream().map(parameter -> new ParameterDefinitionImpl(
                    parameter.getName(), parameter.getDataType(), "")).toArray(ParameterDefinition[]::new));
                data(labels.get(name + "_pointer"), name + "_pointer", new PointerDataType(definition, manager), curate);
                records.add(Map.of("name", name, "convention", convention, "signature", function.getPrototypeString(false, false),
                    "returnStorage", function.getReturn().getVariableStorage().toString(), "parameters",
                    Arrays.stream(function.getParameters()).map(parameter -> Map.of("name", parameter.getName(),
                        "type", parameter.getDataType().getDisplayName(), "storage", parameter.getVariableStorage().toString())).toList()));
            }
        }
        data(labels.get("seen_float"), "seen_float", new ArrayDataType(FloatDataType.dataType, 2, 4, manager), curate);
        data(labels.get("seen_double"), "seen_double", new ArrayDataType(DoubleDataType.dataType, 10, 8, manager), curate);
        data(labels.get("seen_wide"), "seen_wide", new ArrayDataType(LongLongDataType.dataType, 2, 8, manager), curate);
        data(labels.get("calls"), "calls", UnsignedIntegerDataType.dataType, curate);
        if (curate) getFunctionAt(toAddr(labels.get("marker"))).setName("marker", SourceType.USER_DEFINED);
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", records, "language", currentProgram.getLanguageID().toString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "origin", ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.class.getProtectionDomain()
                .getCodeSource().getLocation().toString())) + "\n");
        println("arm-pcs-profile-preparation=PASS");
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
