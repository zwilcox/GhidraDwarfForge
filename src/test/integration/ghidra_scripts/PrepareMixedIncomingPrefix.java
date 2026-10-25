// Owned ARM32 fixture: observe computed register/stack joins before extending support.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraVariableStorage;
import ghidradwarfforge.locations.TargetRegisterMap;

public class PrepareMixedIncomingPrefix extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !(args[2].equals("computed") || args[2].equals("custom"))) {
            throw new IllegalArgumentException("expected labels, observation path and computed|custom");
        }
        var labels = new LinkedHashMap<String, Long>();
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] fields = line.split(" ");
            labels.put(fields[0], Math.addExact(Long.decode(fields[1]), delta));
        }
        Function function = getFunctionAt(toAddr(labels.get("mixed")));
        if (function == null) {
            throw new IllegalStateException("fixture function absent");
        }
        var manager = currentProgram.getDataTypeManager();
        var integer = new IntegerDataType(manager);
        var structure = new StructureDataType(new CategoryPath("/Analyst"), "MixedPair", 0, manager);
        structure.add(integer, "low", "curated field");
        structure.add(integer, "high", "curated field");
        var pair = manager.resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
        function.setName("mixed", SourceType.USER_DEFINED);
        function.setReturnType(new VoidDataType(manager), SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
            SourceType.USER_DEFINED,
            new ParameterImpl("a", integer, currentProgram), new ParameterImpl("b", integer, currentProgram),
            new ParameterImpl("c", integer, currentProgram), new ParameterImpl("pair", pair, currentProgram));
        if (args[2].equals("custom")) {
            function.setCustomVariableStorage(true);
        }
        for (String name : new String[] { "mixed_low", "mixed_high" }) {
            var address = toAddr(labels.get(name));
            DataUtilities.createData(currentProgram, address, integer, 4, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("java", System.getProperty("java.version"));
        result.put("origin", GhidraVariableStorage.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("body", function.getBody().toString());
        result.put("rebaseDelta", delta);
        result.put("imageBase", currentProgram.getImageBase().getOffset());
        result.put("originalImageBase", GhidraImageBase.originalImageBase(currentProgram));
        var parameters = new ArrayList<Object>();
        for (var parameter : function.getParameters()) {
            var row = new LinkedHashMap<String, Object>();
            row.put("name", parameter.getName());
            row.put("type", parameter.getFormalDataType().getPathName());
            row.put("storage", parameter.getVariableStorage().toString());
            row.put("dynamic", !function.hasCustomVariableStorage());
            var nodes = new ArrayList<Object>();
            for (var node : parameter.getVariableStorage().getVarnodes()) {
                var piece = new LinkedHashMap<String, Object>();
                piece.put("address", node.getAddress().toString());
                piece.put("space", node.getAddress().getAddressSpace().getName());
                piece.put("offset", node.getOffset());
                piece.put("size", node.getSize());
                nodes.add(piece);
            }
            row.put("pieces", nodes);
            var storage = GhidraVariableStorage.stableParameter(currentProgram, function, parameter,
                TargetRegisterMap.forTarget("arm"), monitor);
            row.put("forgeStorage", storage.toString());
            row.put("forgePrefix", GhidraVariableStorage.parameterPrefix(currentProgram, function, parameter,
                TargetRegisterMap.forTarget("arm"), storage, monitor).toString());
            parameters.add(row);
        }
        result.put("parameters", parameters);
        var instructions = new ArrayList<Object>();
        var iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            var instruction = iterator.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("address", instruction.getAddress().toString());
            row.put("instruction", instruction.toString());
            row.put("length", instruction.getLength());
            row.put("depth", new ghidra.app.cmd.function.CallDepthChangeInfo(function, monitor).getSPDepth(instruction.getAddress()));
            row.put("pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList());
            instructions.add(row);
        }
        result.put("instructions", instructions);
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result),
            StandardOpenOption.CREATE_NEW);
        println("mixed-argument-observation=PASS");
    }
}
