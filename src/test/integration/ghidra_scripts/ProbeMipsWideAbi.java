// Curate scalar signatures using the selected N32/N64 model, without custom storage.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class ProbeMipsWideAbi extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("expected curate|observe labels-file output-json");
        }
        boolean curate = args[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() -
            ghidradwarfforge.GhidraImageBase.originalImageBase(currentProgram);
        var labels = new LinkedHashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.split(" ");
            if (fields.length != 2 || labels.put(fields[0], Long.decode(fields[1])) != null) {
                throw new IllegalArgumentException("invalid labels file");
            }
        }
        var manager = currentProgram.getDataTypeManager();
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("pointerBytes", currentProgram.getDefaultPointerSize());
        result.put("delta", delta);
        result.put("exporterOrigin", ghidradwarfforge.GhidraTypeGraph.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI().toString());
        String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        var functions = new ArrayList<Object>();
        for (String name : List.of("fp_float", "fp_double")) {
            DataType type = name.equals("fp_float") ? new FloatDataType(manager) : new DoubleDataType(manager);
            var address = toAddr(Math.addExact(labels.get(name), delta));
            Function function = getFunctionAt(address);
            if (function == null) throw new IllegalStateException("missing function " + name);
            if (curate) {
                function.setName("curated_" + name, SourceType.USER_DEFINED);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.updateFunction(convention, function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("first", type, currentProgram, SourceType.USER_DEFINED),
                    new ParameterImpl("second", type, currentProgram, SourceType.USER_DEFINED));
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("signature", function.getPrototypeString(false, false));
            row.put("customStorage", function.hasCustomVariableStorage());
            var parameters = new ArrayList<Object>();
            for (var parameter : function.getParameters()) {
                var item = new LinkedHashMap<String, Object>();
                item.put("name", parameter.getName());
                item.put("type", parameter.getDataType().getDisplayName());
                item.put("bytes", parameter.getLength());
                item.put("storage", parameter.getVariableStorage().toString());
                parameters.add(item);
            }
            row.put("parameters", parameters);
            functions.add(row);
            for (String suffix : List.of("first", "second")) {
                var globalAddress = toAddr(Math.addExact(labels.get(name + "_" + suffix), delta));
                if (curate) {
                    clearListing(globalAddress, globalAddress.add(type.getLength() - 1));
                    createData(globalAddress, type);
                    createLabel(globalAddress, "curated_" + name + "_" + suffix, true);
                }
                var data = getDataAt(globalAddress);
                if (data == null || !data.getDataType().isEquivalent(type)) {
                    throw new IllegalStateException("missing saved global " + name + "_" + suffix);
                }
            }
        }
        result.put("functions", functions);
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("MIPS_WIDE_ABI_OBSERVATION_PASS");
    }
}
