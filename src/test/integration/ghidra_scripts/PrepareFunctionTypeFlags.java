// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareFunctionTypeFlags extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("Expected curate|observe output.json");
        }
        var manager = currentProgram.getDataTypeManager();
        var records = new ArrayList<Object>();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        for (String kind : new String[] { "variadic", "noreturn" }) {
            boolean noReturn = kind.equals("noreturn");
            String name = "known_" + kind;
            var function = getGlobalFunctions(name).get(0);
            DataType resultType = noReturn ? VoidDataType.dataType : IntegerDataType.dataType;
            String argumentName = noReturn ? "code" : "count";
            String convention = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
            if (args[0].equals("curate")) {
                function.updateFunction(convention, new ReturnParameterImpl(resultType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl(argumentName, IntegerDataType.dataType, currentProgram));
                function.setNoReturn(noReturn);
                function.setVarArgs(!noReturn);
            }
            if (function.hasNoReturn() != noReturn || function.hasVarArgs() == noReturn ||
                    function.getParameterCount() != 1 || function.getSignatureSource() != SourceType.USER_DEFINED) {
                throw new AssertionError("Function flags changed " + name);
            }
            var definition = new FunctionDefinitionDataType(kind + "_type", manager);
            definition.setReturnType(resultType);
            definition.setArguments(new ParameterDefinitionImpl(argumentName, IntegerDataType.dataType, ""));
            definition.setCallingConvention(convention);
            definition.setNoReturn(noReturn);
            definition.setVarArgs(!noReturn);
            String pointerName = kind + "_pointer";
            var symbol = getSymbols(pointerName, currentProgram.getGlobalNamespace()).get(0);
            var address = symbol.getAddress();
            var pointer = new PointerDataType(definition, manager);
            if (args[0].equals("curate")) {
                DataUtilities.createData(currentProgram, address, pointer, pointer.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                createLabel(address, pointerName, true, SourceType.USER_DEFINED);
            }
            var actual = (FunctionDefinition) ((Pointer) getDataAt(address).getDataType()).getDataType();
            if (!actual.isEquivalent(definition) || actual.hasNoReturn() != noReturn ||
                    actual.hasVarArgs() == noReturn || !actual.getCallingConventionName().equals(convention)) {
                throw new AssertionError("Saved function-type flags changed " + pointerName);
            }
            records.add(Map.of("name", name, "pointer", pointerName, "type", actual.getPathName(),
                "noReturn", actual.hasNoReturn(), "variadic", actual.hasVarArgs(),
                "entry", function.getEntryPoint().getOffset() - delta,
                "pointerAddress", address.getOffset() - delta));
        }
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "records", records, "delta", delta,
            "origin", GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation().toString())) + "\n");
    }
}
