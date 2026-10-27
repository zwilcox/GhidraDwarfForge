// Preserve a curated thunk independently of its destination's decompiler body.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraImageBase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;

public class PrepareCuratedThunk extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("<curate|observe> <output.json>");
        }
        var implementation = getGlobalFunctions("implementation").get(0);
        Function gateway;
        if (args[0].equals("curate")) {
            gateway = getGlobalFunctions("gateway").get(0);
            implementation.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                new ParameterImpl("value", IntegerDataType.dataType, currentProgram));
            gateway.setThunkedFunction(implementation);
            gateway.setName("analyst_gateway", SourceType.USER_DEFINED);
        }
        else {
            gateway = getGlobalFunctions("analyst_gateway").get(0);
        }
        if (!implementation.getName().equals("implementation") || !gateway.isThunk() ||
                gateway.getSymbol().getSource() != SourceType.USER_DEFINED ||
                gateway.getSignatureSource() != SourceType.USER_DEFINED || gateway.getParameterCount() != 1) {
            throw new AssertionError("curated thunk identity/signature was not retained");
        }
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var diagnostics = new ArrayList<String>();
        var inventory = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor, diagnostics::add, delta);
        var row = new LinkedHashMap<String, Object>();
        row.put("entry", gateway.getEntryPoint().getOffset());
        var ranges = new ArrayList<Object>();
        for (var range : gateway.getBody().getAddressRanges(true)) {
            ranges.add(java.util.List.of(range.getMinAddress().getOffset() - delta,
                range.getMaxAddress().getOffset() - delta + 1));
        }
        row.put("ranges", ranges);
        row.put("target", implementation.getEntryPoint().getOffset());
        row.put("name", gateway.getName(true));
        row.put("source", gateway.getSymbol().getSource().name());
        row.put("signatureSource", gateway.getSignatureSource().name());
        row.put("signature", gateway.getSignature().getPrototypeString());
        row.put("selected", inventory.functions().stream().anyMatch(f -> f.address() == gateway.getEntryPoint().getOffset() - delta));
        row.put("rebaseDelta", delta);
        row.put("origin", GhidraFunctionSymbols.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(row) + "\n");
    }
}
