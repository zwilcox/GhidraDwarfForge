// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import ghidradwarfforge.GhidraImageBase;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.nativeapi.DwarfTarget;

public class PrepareI386Profile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3 || !List.of("curate", "observe").contains(getScriptArgs()[0])) {
            throw new IllegalArgumentException("expected curate|observe case-directory model-output");
        }
        boolean curate = getScriptArgs()[0].equals("curate");
        Path directory = Path.of(getScriptArgs()[1]);
        var symbols = JsonParser.parseString(Files.readString(directory.resolve("symbols.json"))).getAsJsonObject();
        var bindings = JsonParser.parseString(Files.readString(directory.resolve("compiler-gdb.json")))
            .getAsJsonObject().getAsJsonObject("bindings");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var rows = new ArrayList<Object>();
        var pair = new StructureDataType("i386_pair", 0);
        pair.add(IntegerDataType.dataType, "first", null);
        pair.add(IntegerDataType.dataType, "second", null);
        for (String name : List.of("scalar", "wide", "aggregate")) {
            String displayName = symbols.has("curatedNames")
                ? symbols.getAsJsonObject("curatedNames").get(name).getAsString() : name;
            var addresses = symbols.getAsJsonObject("functions").getAsJsonObject(name);
            var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(addresses.get("entry").getAsLong() + delta));
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    function.getBody().getMaxAddress().getOffset() + 1 != addresses.get("end").getAsLong() + delta) {
                throw new AssertionError("incomplete fixture function " + name);
            }
            if (curate) function.setName(displayName, SourceType.USER_DEFINED);
            if (!function.getName().equals(displayName)) throw new AssertionError("curated name lost");
            var integer = IntegerDataType.dataType;
            var wide = LongLongDataType.dataType;
            DataType result = name.equals("wide") ? wide : integer;
            if (curate) {
                var params = new ArrayList<Parameter>();
                if (name.equals("aggregate")) {
                    params.add(new ParameterImpl("value", pair, currentProgram));
                    params.add(new ParameterImpl("tail", integer, currentProgram));
                }
                else {
                    params.add(new ParameterImpl("first", integer, currentProgram));
                    params.add(new ParameterImpl("second", result, currentProgram));
                    if (name.equals("wide")) params.add(new ParameterImpl("third", integer, currentProgram));
                }
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(result, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, params.toArray(Parameter[]::new));
                var binding = bindings.getAsJsonObject(name);
                int offset = binding.get("firstUse").getAsInt();
                if (binding.get("bytes").getAsInt() != result.getLength() || offset <= 0) {
                    throw new AssertionError("invalid compiler local binding");
                }
                for (var local : function.getLocalVariables()) function.removeVariable(local);
                // Compiler GDB independently measures the local address relative to
                // the actual entry SP; no prologue or frame-width assumption is needed.
                // Their nonzero first-use remains unavailable under the existing stack policy.
                var held = new LocalVariableImpl("curated_held", result,
                    binding.get("stackOffset").getAsInt(), currentProgram, SourceType.USER_DEFINED);
                var attached = (LocalVariable) function.addLocalVariable(held, SourceType.USER_DEFINED);
                attached.setFirstUseOffset(offset);
            }
            var params = new ArrayList<Object>();
            for (var parameter : function.getParameters()) params.add(Map.of("name", parameter.getName(),
                "type", parameter.getDataType().getPathName(), "storage", parameter.getVariableStorage().toString(),
                "offset", parameter.getStackOffset(), "bytes", parameter.getLength()));
            var locals = java.util.Arrays.stream(function.getLocalVariables())
                .filter(variable -> variable.getName().equals("curated_held")).toList();
            if (locals.size() != 1) throw new AssertionError("curated local lost");
            var local = locals.get(0);
            rows.add(Map.of("name", name, "displayName", displayName, "entry", function.getEntryPoint().toString(), "parameters", params,
                "returnType", function.getReturnType().getPathName(), "customStorage", function.hasCustomVariableStorage(),
                "local", Map.of("name", local.getName(), "offset", local.getStackOffset(), "firstUse", local.getFirstUseOffset())));
        }
        if (curate) {
            var sink = toAddr(symbols.get("sink").getAsLong() + delta);
            createLabel(sink, "sink", true, SourceType.USER_DEFINED);
            if (symbols.has("start")) {
                var start = currentProgram.getFunctionManager().getFunctionAt(toAddr(symbols.get("start").getAsLong() + delta));
                if (start == null) throw new AssertionError("missing fixture entry");
                start.setName("_start", SourceType.USER_DEFINED);
                start.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                start.setNoReturn(true);
            }
            DataUtilities.createData(currentProgram, sink, IntegerDataType.dataType, 4,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        }
        Files.writeString(Path.of(getScriptArgs()[2]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("java", System.getProperty("java.version"), "imageBase", currentProgram.getImageBase().getOffset(),
                "originalImageBase", GhidraImageBase.originalImageBase(currentProgram),
                "language", currentProgram.getLanguageID().toString(), "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
                "origin", DwarfTarget.class.getProtectionDomain().getCodeSource().getLocation().toString(), "functions", rows)) + "\n");
    }
}
