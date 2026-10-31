// Curate explicit per-function calling conventions; observe without changing the saved program.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraImageBase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;

public class PrepareCustomCallStorage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("<curate|observe> <output.json>");
        }
        var observations = new ArrayList<Object>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!function.getName().equals("sysv_function") && !function.getName().equals("microsoft_function") && !function.getName().equals("custom_return")) {
                continue;
            }
            String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
            if (args[0].equals("curate")) {
                var parameters = new Parameter[function.getName().equals("custom_return") ? 1 : 4];
                for (int i = 0; i < parameters.length; i++) {
                    String[] registers = function.getName().equals("microsoft_function")
                        ? new String[] { "ECX", "EDX", "R8D", "R9D" }
                        : new String[] { "EDI", "ESI", "EDX", "ECX" };
                    parameters[i] = new ParameterImpl("arg" + i, IntegerDataType.dataType,
                        currentProgram.getRegister(registers[i]), currentProgram);
                }
                function.updateFunction(convention, new ReturnParameterImpl(IntegerDataType.dataType,
                    new ghidra.program.model.listing.VariableStorage(currentProgram, currentProgram.getRegister(function.getName().equals("custom_return") ? "EDX" : "EAX")), currentProgram),
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED, parameters);
            }
            if (!function.getCallingConventionName().equals(convention) || !function.hasCustomVariableStorage() ||
                    function.getSignatureSource() != SourceType.USER_DEFINED || function.getParameterCount() != (function.getName().equals("custom_return") ? 1 : 4)) {
                throw new AssertionError("calling convention signature did not persist");
            }
            var record = new LinkedHashMap<String, Object>();
            record.put("name", function.getName());
            record.put("entry", function.getEntryPoint().getOffset());
            record.put("convention", function.getCallingConventionName());
            record.put("programDefault", currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
            record.put("compilerSpec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
            record.put("returnStorage", function.getReturn().getVariableStorage().toString());
            record.put("customStorage", function.hasCustomVariableStorage());
            record.put("storage", java.util.Arrays.stream(function.getParameters())
                .map(parameter -> parameter.getVariableStorage().toString()).toList());
            observations.add(record);
        }
        if (observations.size() != 3) {
            throw new AssertionError("missing calling convention function");
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("functions", observations);
        result.put("rebaseDelta", currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram));
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
