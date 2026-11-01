// Curate owned wide-argument signatures with dynamic storage; preserve the saved model.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;
public class ProbeMipsWideArguments extends GhidraScript {
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("expected curate|observe labels-file output-json");
        }
        boolean curate = args[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() -
            ghidradwarfforge.GhidraImageBase.originalImageBase(currentProgram);
        var labels = new LinkedHashMap<String, Long>();
        for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid labels file");
            }
        }
        var manager = currentProgram.getDataTypeManager();
        var word = new LongLongDataType(manager);
        var real = new DoubleDataType(manager);
        var scalar = new FloatDataType(manager);
        var integer = new IntegerDataType(manager);
        var pair = new StructureDataType("Pair", 0, manager);
        pair.add(word,"first",null); pair.add(word,"second",null);
        var large = new StructureDataType("Large", 0, manager);
        large.add(word,"first",null); large.add(word,"second",null); large.add(word,"third",null);
        println("WIDE_LANGUAGE=" + currentProgram.getLanguageID() + " compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("pointerBytes", currentProgram.getDefaultPointerSize());
        result.put("delta", delta);
        result.put("exporterOrigin", ghidradwarfforge.GhidraTypeGraph.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI().toString());
        var functions = new ArrayList<Object>();
        for (String name : List.of("wide_words", "wide_pair", "wide_large", "wide_mixed")) {
            var function = getFunctionAt(toAddr(Math.addExact(labels.get(name), delta)));
            if (function == null) throw new IllegalStateException("missing function " + name);
            if (curate) function.setName(name, SourceType.USER_DEFINED);
            DataType[] types;
            String[] names;
            if (name.equals("wide_words")) {
                types = new DataType[]{word,word,word,word,word,word,word,word,word,word};
                names = new String[]{"a","b","c","d","e","f","g","h","i","j"};
            }
            else if (name.equals("wide_mixed")) {
                types = new DataType[]{word,real,integer,scalar,pair,word,real,word,integer};
                names = new String[]{"a","b","c","d","e","f","g","h","tail"};
            }
            else { types = new DataType[]{name.equals("wide_pair") ? pair : large}; names = new String[]{"value"}; }
            var parameters = new ArrayList<Parameter>();
            for (int i = 0; i < types.length; i++) parameters.add(new ParameterImpl(names[i],types[i],currentProgram,SourceType.USER_DEFINED));
            DataType returnType = name.equals("wide_pair") ? pair : name.equals("wide_large") ? large : word;
            if (curate) {
                function.setReturnType(returnType, SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(), function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
            }
            println("WIDE_FUNCTION="+name+" "+function.getEntryPoint()+" RETURN="+function.getReturn());
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("customStorage", function.hasCustomVariableStorage());
            var storage = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                storage.add(Map.of("name", parameter.getName(), "type", parameter.getDataType().getDisplayName(),
                    "bytes", parameter.getLength(), "storage", parameter.getVariableStorage().toString()));
            }
            row.put("parameters", storage);
            functions.add(row);
            String callbackName = name.substring("wide_".length()) + "_callback";
            var callbackAddress = toAddr(Math.addExact(labels.get(callbackName), delta));
            var prototype = new FunctionDefinitionDataType(name + "_prototype", manager);
            prototype.setReturnType(function.getReturn().getFormalDataType());
            prototype.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
            prototype.setArguments(Arrays.stream(function.getParameters()).filter(parameter -> !parameter.isAutoParameter())
                .map(parameter -> new ParameterDefinitionImpl(parameter.getName(), parameter.getFormalDataType(), null))
                .toArray(ParameterDefinition[]::new));
            var pointer = new PointerDataType(prototype, currentProgram.getDefaultPointerSize(), manager);
            if (curate) {
                clearListing(callbackAddress, callbackAddress.add(pointer.getLength() - 1));
                createData(callbackAddress, pointer);
                createLabel(callbackAddress, callbackName, true);
            }
            if (getDataAt(callbackAddress) == null || !getDataAt(callbackAddress).getDataType().isEquivalent(pointer)) {
                throw new IllegalStateException("missing saved callback " + callbackName);
            }
        }
        result.put("functions", functions);
        for (var global : Map.<String, DataType>of("integer_sink", word, "real_sink", real,
                "pair_sink", pair, "large_sink", large).entrySet()) {
            var address = toAddr(Math.addExact(labels.get(global.getKey()), delta));
            if (curate) {
                clearListing(address, address.add(global.getValue().getLength() - 1));
                createData(address, global.getValue());
                createLabel(address, global.getKey(), true);
            }
            var data = getDataAt(address);
            if (data == null || !data.getDataType().isEquivalent(global.getValue())) {
                throw new IllegalStateException("missing saved global " + global.getKey());
            }
        }
        java.nio.file.Files.writeString(java.nio.file.Path.of(args[2]),
            new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("MIPS_WIDE_ARGUMENTS_OBSERVATION_PASS");
    }
}
