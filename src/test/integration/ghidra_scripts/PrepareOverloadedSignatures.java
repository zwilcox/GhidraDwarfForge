// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareOverloadedSignatures extends GhidraScript {
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("Expected curate|observe, output and two ELF entries");
        }
        boolean curate = args[0].equals("curate");
        var symbols = currentProgram.getSymbolTable();
        var owner = symbols.getNamespace("Recovered", currentProgram.getGlobalNamespace());
        if (owner == null && curate) owner = symbols.createClass(currentProgram.getGlobalNamespace(), "Recovered", SourceType.USER_DEFINED);
        var scope = symbols.getNamespace("nested", owner);
        if (scope == null && curate) scope = symbols.createNameSpace(owner, "nested", SourceType.USER_DEFINED);
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var results = new ArrayList<Map<String, Object>>();
        for (int i = 0; i < 2; i++) {
            long originalEntry = Long.decode(args[2 + i]);
            var function = getFunctionAt(toAddr(originalEntry + delta));
            if (function == null || function.isThunk()) throw new AssertionError("missing ordinary overload");
            DataType type = i == 0 ? IntegerDataType.dataType : DoubleDataType.dataType;
            String alias = i == 0 ? "combine_int" : "combine_double";
            if (curate) {
                function.setParentNamespace(scope);
                function.setName("combine", SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(type, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, new ParameterImpl("value", type, currentProgram));
                symbols.createLabel(function.getEntryPoint(), alias, scope, SourceType.USER_DEFINED);
                symbols.createLabel(function.getEntryPoint(), "ambiguous_alias", scope, SourceType.USER_DEFINED);
            }
            if (!function.getName(true).equals("Recovered::nested::combine")) throw new AssertionError("display identity");
            var label = symbols.getSymbol(alias, function.getEntryPoint(), scope);
            if (label == null || label.isPrimary()) throw new AssertionError("secondary identity");
            if (symbols.getSymbol("ambiguous_alias", function.getEntryPoint(), scope) == null) {
                throw new AssertionError("missing ambiguous-name control");
            }
            results.add(Map.of("entry", originalEntry, "name", function.getName(true), "alias", label.getName(true),
                "signature", function.getSignature().toString(), "parameter", function.getParameter(0).getDataType().getName(),
                "return", function.getReturn().getFormalDataType().getName(), "size", function.getBody().getNumAddresses(),
                "delta", delta, "origin", GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation().toString()));
        }
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(results) + "\n");
    }
}
