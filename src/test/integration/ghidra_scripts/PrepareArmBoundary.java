// @category DWARF.Tests
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

/** Curate a source-built Thumb tail; assert the importer retained its exact body. */
public class PrepareArmBoundary extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("curate") || args[0].equals("observe"))) {
            throw new IllegalArgumentException("Expected curate|observe and output path");
        }
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var entry = toAddr(0x101c + delta);
        var function = getFunctionAt(entry);
        if (function == null || function.getBody().getNumAddresses() != 4 ||
                !function.getBody().getMinAddress().equals(entry) ||
                !function.getBody().getMaxAddress().equals(entry.add(3))) {
            throw new AssertionError("boundary body");
        }
        if (!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
                currentProgram.getRegister("TMode"), entry, false))) {
            throw new AssertionError("boundary mode");
        }
        if (args[0].equals("curate")) {
            function.setName("recovered_boundary", SourceType.USER_DEFINED);
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                new ParameterImpl("value", IntegerDataType.dataType, currentProgram));
            currentProgram.getSymbolTable().createLabel(entry, "alternate_boundary", SourceType.USER_DEFINED);
        }
        var alias = currentProgram.getSymbolTable().getSymbol("alternate_boundary", entry,
            currentProgram.getGlobalNamespace());
        if (alias == null || alias.isPrimary() || !function.getName().equals("recovered_boundary")) {
            throw new AssertionError("alias identity");
        }
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "entry", 0x101c, "size", 4, "name", function.getName(), "alias", alias.getName(),
            "origin", GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation().toString(),
            "rebaseDelta", delta, "signature", function.getSignature().toString())) + "\n");
    }
}
