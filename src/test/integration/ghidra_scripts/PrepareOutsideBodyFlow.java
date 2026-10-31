// Curate or observe the exact excluded-clobber reproduction without changing bytes.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraVariableStorage;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.locations.TargetRegisterMap;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.HexFormat;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;

public class PrepareOutsideBodyFlow extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 5) {
            throw new IllegalArgumentException("<curate|observe> <symbols.json> <complete|excluded> <target> <output.json>");
        }
        var symbols = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var function = getFunctionAt(toAddr(symbols.get("boundary").getAsLong() + delta));
        if (function == null) {
            throw new AssertionError("missing boundary function");
        }
        if (args[0].equals("curate")) {
            function.setName("boundary", SourceType.USER_DEFINED);
            function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                new Parameter[] { new ParameterImpl("unused", IntegerDataType.dataType, currentProgram),
                    new ParameterImpl("value", IntegerDataType.dataType, currentProgram) });
            if (args[2].equals("excluded")) {
                var body = new AddressSet(function.getBody());
                body.deleteRange(toAddr(symbols.get("probe_hidden").getAsLong() + delta),
                    toAddr(symbols.get("probe_after").getAsLong() + delta - 1));
                function.setBody(body);
            }
        }
        else if (!args[0].equals("observe")) {
            throw new IllegalArgumentException("unknown operation");
        }
        var parameter = function.getParameter(1);
        var registers = TargetRegisterMap.forTarget(args[3]);
        var storage = GhidraVariableStorage.stableParameter(currentProgram, function, parameter, registers, monitor);
        var result = new LinkedHashMap<String, Object>();
        result.put("mode", args[2]);
        result.put("body", function.getBody().toString());
        result.put("entry", function.getEntryPoint().getOffset());
        result.put("rebaseDelta", delta);
        result.put("register", parameter.getRegister().getName());
        result.put("storage", storage.toString());
        result.put("available", storage.available());
        result.put("firstUse", parameter.getFirstUseOffset());
        var instructions = new ArrayList<Object>();
        var cursor = function.getEntryPoint();
        var end = toAddr(symbols.get("end").getAsLong() + delta);
        while (cursor.compareTo(end) < 0) {
            monitor.checkCancelled();
            var instruction = getInstructionAt(cursor);
            if (instruction == null) throw new AssertionError("missing fixture instruction " + cursor);
            var next = cursor.add(instruction.getLength());
            instructions.add(Map.of("address", cursor.getOffset() - delta,
                "next", next.getOffset() - delta,
                "bytes", HexFormat.of().formatHex(instruction.getBytes()),
                "inBody", function.getBody().contains(cursor)));
            cursor = next;
        }
        if (!cursor.equals(end)) throw new AssertionError("fixture end is not an instruction boundary");
        result.put("instructions", instructions);
        result.put("java", System.getProperty("java.version"));
        result.put("origin", GhidraVariableStorage.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(args[4]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
