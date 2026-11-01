// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.SignedDWordDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;

public class PrepareAbiProfile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !java.util.List.of("curate", "observe").contains(args[0]) ||
                !java.util.List.of("float", "double").contains(args[1])) {
            throw new IllegalArgumentException("<curate|observe> <float|double> <output.json>");
        }
        // The source-built C oracle has four-byte int objects even when the
        // deliberately mismatched Go compiler model uses eight-byte native int.
        // Fixed-width analyst types preserve the oracle's actual object layout.
        DataType scalar = args[1].equals("float") ? FloatDataType.dataType : DoubleDataType.dataType;
        var records = new ArrayList<Object>();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        for (String name : new String[] { "fp_call", "integer_call" }) {
            var function = getGlobalFunctions(name).get(0);
            DataType type = name.equals("fp_call") ? scalar : SignedDWordDataType.dataType;
            var parameters = name.equals("fp_call") ? new ParameterImpl[] {
                new ParameterImpl("a", type, currentProgram), new ParameterImpl("b", type, currentProgram) } :
                new ParameterImpl[] { new ParameterImpl("value", type, currentProgram) };
            if (args[0].equals("curate")) {
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(type, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, parameters);
            }
            if (function.hasCustomVariableStorage() || function.getSignatureSource() != SourceType.USER_DEFINED ||
                    function.getParameterCount() != parameters.length || !function.getReturnType().isEquivalent(type)) {
                throw new AssertionError("signature or default storage changed");
            }
            var storage = new ArrayList<String>();
            for (int index = 0; index < parameters.length; index++) {
                var actual = function.getParameter(index);
                if (!actual.getName().equals(parameters[index].getName()) || !actual.getDataType().isEquivalent(type)) {
                    throw new AssertionError("parameter type/name changed");
                }
                storage.add(actual.getVariableStorage().toString());
            }
            records.add(Map.of("name", name, "entry", function.getEntryPoint().getOffset() - delta,
                "signature", function.getSignature().getPrototypeString(), "customStorage", function.hasCustomVariableStorage(),
                "storage", storage, "returnStorage", function.getReturn().getVariableStorage().toString(),
                "convention", function.getCallingConventionName()));
        }
        for (String name : new String[] { "fp_pointer", "integer_pointer" }) {
            var symbol = getSymbols(name, currentProgram.getGlobalNamespace()).get(0);
            var function = getGlobalFunctions(name.equals("fp_pointer") ? "fp_call" : "integer_call").get(0);
            var definition = new ghidra.program.model.data.FunctionDefinitionDataType(
                name + "_type", currentProgram.getDataTypeManager());
            definition.setReturnType(function.getReturnType());
            definition.setArguments(java.util.Arrays.stream(function.getParameters())
                .filter(parameter -> !parameter.isAutoParameter())
                .map(parameter -> new ghidra.program.model.data.ParameterDefinitionImpl(
                    parameter.getName(), parameter.getFormalDataType(), ""))
                .toArray(ghidra.program.model.data.ParameterDefinition[]::new));
            definition.setCallingConvention(function.getCallingConventionName());
            var pointer = new ghidra.program.model.data.PointerDataType(definition, currentProgram.getDataTypeManager());
            if (args[0].equals("curate")) {
                DataUtilities.createData(currentProgram, symbol.getAddress(), pointer, pointer.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                createLabel(symbol.getAddress(), name, true, SourceType.USER_DEFINED);
            }
            if (!getDataAt(symbol.getAddress()).getDataType().isEquivalent(pointer)) {
                throw new AssertionError("pointer type changed " + name);
            }
        }
        for (String name : new String[] { "seen_a", "seen_b", "floating_calls", "integer_calls", "seen_integer" }) {
            var symbol = getSymbols(name, currentProgram.getGlobalNamespace()).get(0);
            DataType type = name.startsWith("seen_") && !name.equals("seen_integer") ? scalar :
                name.equals("seen_integer") ? SignedDWordDataType.dataType : DWordDataType.dataType;
            if (args[0].equals("curate")) {
                DataUtilities.createData(currentProgram, symbol.getAddress(), type, type.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            }
            if (!getDataAt(symbol.getAddress()).getDataType().isEquivalent(type)) {
                throw new AssertionError("global type changed");
            }
        }
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "language", currentProgram.getLanguageID().toString(), "functions", records, "rebaseDelta", delta, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "origin", MinimalDwarfSidecarExporter.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
        println("abi-profile-preparation=PASS");
    }
}
