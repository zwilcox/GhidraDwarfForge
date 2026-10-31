// Curate explicit per-function calling conventions; observe without changing the saved program.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraImageBase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;

public class PreparePointerConventions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("<curate|observe> <output.json>");
        }
        boolean windows = currentProgram.getCompilerSpec().getCompilerSpecID().toString().equals("windows");
        var observations = new ArrayList<Object>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!function.getName().equals("sysv_function") && !function.getName().equals("microsoft_function")) {
                continue;
            }
            String convention = !windows && function.getName().equals("microsoft_function") ? "MSABI"
                : currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
            if (args[0].equals("curate")) {
                var parameters = new Parameter[4];
                for (int i = 0; i < parameters.length; i++) {
                    parameters[i] = windows ? new ParameterImpl("arg" + i, IntegerDataType.dataType,
                        currentProgram.getRegister((function.getName().equals("microsoft_function") ?
                            new String[] { "ECX", "EDX", "R8D", "R9D" } :
                            new String[] { "EDI", "ESI", "EDX", "ECX" })[i]), currentProgram) :
                        new ParameterImpl("arg" + i, IntegerDataType.dataType, currentProgram);
                }
                function.updateFunction(convention, new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                    windows ? Function.FunctionUpdateType.CUSTOM_STORAGE : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, parameters);
            }
            if (!function.getCallingConventionName().equals(convention) || function.hasCustomVariableStorage() != windows ||
                    function.getSignatureSource() != SourceType.USER_DEFINED || function.getParameterCount() != 4) {
                throw new AssertionError("calling convention signature did not persist");
            }
            var record = new LinkedHashMap<String, Object>();
            record.put("name", function.getName());
            record.put("entry", function.getEntryPoint().getOffset());
            record.put("convention", function.getCallingConventionName());
            record.put("programDefault", currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
            record.put("compilerSpec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
            record.put("storage", java.util.Arrays.stream(function.getParameters())
                .map(parameter -> parameter.getVariableStorage().toString()).toList());
            observations.add(record);
        }
        if (observations.size() != 2) {
            throw new AssertionError("missing calling convention function");
        }
        var pointerObservations = new ArrayList<Object>();
        for (String name : new String[] { "sysv_pointer", "microsoft_pointer" }) {
            var symbols = currentProgram.getSymbolTable().getGlobalSymbols(name);
            if (symbols.size() != 1) {
                throw new AssertionError("missing pointer " + name);
            }
            var address = symbols.get(0).getAddress();
            String convention = !windows && name.equals("microsoft_pointer") ? "MSABI" :
                currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
            if (args[0].equals("curate")) {
                var functionType = new FunctionDefinitionDataType(name + "_type", currentProgram.getDataTypeManager());
                functionType.setReturnType(IntegerDataType.dataType);
                var parameters = new ParameterDefinition[4];
                for (int i = 0; i < parameters.length; i++) {
                    parameters[i] = new ParameterDefinitionImpl("arg" + i, IntegerDataType.dataType, "");
                }
                functionType.setArguments(parameters);
                functionType.setCallingConvention(convention);
                clearListing(address, address.add(currentProgram.getDefaultPointerSize() - 1));
                createData(address, new PointerDataType(functionType, currentProgram.getDataTypeManager()));
                createLabel(address, name, true, SourceType.USER_DEFINED);
            }
            var pointer = (ghidra.program.model.data.Pointer) getDataAt(address).getDataType();
            var functionType = (ghidra.program.model.data.FunctionDefinition) pointer.getDataType();
            if (!convention.equals(functionType.getCallingConventionName())) {
                throw new AssertionError("lost pointer convention " + name);
            }
            pointerObservations.add(java.util.Map.of("name", name, "convention", functionType.getCallingConventionName(),
                "address", address.getOffset(), "prototype", functionType.getPrototypeString(true)));
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("pointers", pointerObservations);
        result.put("functions", observations);
        result.put("rebaseDelta", currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram));
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
