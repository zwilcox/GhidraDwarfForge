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
        if (args.length != 1) throw new IllegalArgumentException("expected reference labels file");
        var labels = new LinkedHashMap<String, Long>();
        for (String line : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[0]))) {
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
        for (String name : List.of("wide_words", "wide_pair", "wide_large", "wide_mixed")) {
            var function = getFunctionAt(toAddr(labels.get(name)));
            if (function == null) throw new IllegalStateException("missing function " + name);
            function.setName(name, SourceType.USER_DEFINED);
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
            DataType result = name.equals("wide_pair") ? pair : name.equals("wide_large") ? large : word;
            function.setReturnType(result,SourceType.USER_DEFINED);
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(), function.getReturn(),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
            println("WIDE_FUNCTION="+name+" "+function.getEntryPoint()+" RETURN="+function.getReturn());
            for (var parameter:function.getParameters()) println("WIDE_PARAMETER="+name+" "+parameter+" STORAGE="+parameter.getVariableStorage());
        }
        println("WIDE_PROBE_PASS");
    }
}
