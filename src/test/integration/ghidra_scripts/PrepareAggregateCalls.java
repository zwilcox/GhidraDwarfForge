// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareAggregateCalls extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("Expected curate|observe labels output");
        }
        boolean curate = args[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("Invalid label");
            }
        }
        var manager = currentProgram.getDataTypeManager();
        DataType wide = new UnsignedLongLongDataType(manager);
        DataType word = new UnsignedIntegerDataType(manager);
        DataType signed = new IntegerDataType(manager);
        var triple = new StructureDataType("RecoveredTriple", 0, manager);
        for (String name : List.of("first", "second", "third")) triple.add(wide, name, null);
        var pair = new StructureDataType("RecoveredPair", 0, manager);
        for (String name : List.of("first", "second")) pair.add(word, name, null);
        var choice = new EnumDataType(CategoryPath.ROOT, "RecoveredChoice", 4, manager);
        choice.add("FIRST", 2);
        choice.add("SECOND", 5);
        var functions = new ArrayList<Map<String, Object>>();
        for (String name : List.of("triple64", "triple32", "pair64", "scalar64", "word_mix", "marker")) {
            Function function = getFunctionAt(toAddr(labels.get(name) + delta));
            if (function == null || function.isThunk()) throw new AssertionError("Missing ordinary function " + name);
            if (curate) {
                DataType result = switch (name) {
                    case "scalar64" -> wide;
                    case "pair64" -> pair;
                    case "marker" -> VoidDataType.dataType;
                    case "word_mix" -> new TypedefDataType(CategoryPath.ROOT, "RecoveredTripleAlias", triple, manager);
                    default -> triple;
                };
                var parameters = new ArrayList<Variable>();
                if (name.equals("word_mix")) {
                    parameters.add(new ParameterImpl("first", new SignedCharDataType(manager), currentProgram));
                    parameters.add(new ParameterImpl("second", new UnsignedShortDataType(manager), currentProgram));
                    parameters.add(new ParameterImpl("choice", choice, currentProgram));
                    parameters.add(new ParameterImpl("pointer", new PointerDataType(signed, manager), currentProgram));
                    parameters.add(new ParameterImpl("tail", word, currentProgram));
                }
                else if (!name.equals("marker")) {
                    parameters.add(new ParameterImpl("seed", name.equals("triple32") ? word : wide, currentProgram));
                    parameters.add(new ParameterImpl("delta", signed, currentProgram));
                }
                function.setName(name, SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(result, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, parameters.toArray(Variable[]::new));
            }
            var parameters = new ArrayList<Map<String, Object>>();
            for (Parameter parameter : function.getParameters()) {
                parameters.add(Map.of("name", parameter.getName(), "type", parameter.getFormalDataType().getName(),
                    "size", parameter.getFormalDataType().getLength(), "auto", parameter.isAutoParameter(),
                    "autoKind", parameter.getAutoParameterType() == null ? "" : parameter.getAutoParameterType().name()));
            }
            functions.add(Map.of("name", function.getName(), "entry", labels.get(name), "size", function.getBody().getNumAddresses(),
                "return", function.getReturn().getFormalDataType().getName(), "parameters", parameters));
        }
        if (curate) {
            for (String name : List.of("sink", "pointer_data", "triple64_calls", "triple32_calls", "pair64_calls", "scalar64_calls", "words_calls")) {
                var address = toAddr(labels.get(name) + delta);
                DataType type = name.equals("sink") ? wide : name.equals("pointer_data") ? signed : word;
                DataUtilities.createData(currentProgram, address, type, type.getLength(), DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
        }
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "functions", functions, "delta", delta, "origin", GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
    }
}
