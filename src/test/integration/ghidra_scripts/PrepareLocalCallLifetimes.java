// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraTypeGraph;

public class PrepareLocalCallLifetimes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("expected curate|observe output-json boundaries-json");
        }
        var labels = JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        boolean x86 = currentProgram.getLanguageID().toString().startsWith("x86:");
        var register = currentProgram.getRegister(x86 ? "R12" : "x19");
        var rows = new ArrayList<Object>();
        for (var item : labels.entrySet()) {
            monitor.checkCancelled();
            String name = item.getKey();
            var label = item.getValue().getAsJsonObject();
            var entry = toAddr(label.get("entry").getAsLong() + delta);
            var end = toAddr(label.get("end").getAsLong() + delta);
            var body = new AddressSet(entry, end.previous());
            Function function = getFunctionAt(entry);
            if (function == null) throw new AssertionError("missing " + name);
            boolean caller = name.startsWith("local_call_");
            int firstUse = caller ? Math.toIntExact(label.get("definition").getAsLong() + delta - entry.getOffset()) : 0;
            if (args[0].equals("curate")) {
                var interior = new ArrayList<ghidra.program.model.address.Address>();
                for (Function other : currentProgram.getFunctionManager().getFunctions(body, true)) {
                    if (other == function) continue;
                    if (!body.contains(other.getBody())) throw new AssertionError("outside fixture tail");
                    interior.add(other.getEntryPoint());
                }
                for (var address : interior) currentProgram.getFunctionManager().removeFunction(address);
                function.setBody(body);
                function.setName(name, SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(LongLongDataType.dataType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("input", LongLongDataType.dataType, currentProgram));
                for (var variable : function.getLocalVariables()) function.removeVariable(variable);
                if (caller) function.addLocalVariable(new LocalVariableImpl("curated_held", firstUse,
                    LongLongDataType.dataType, register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
            if (!function.getBody().hasSameAddresses(body) || !function.getName().equals(name) ||
                    function.getCallingConvention() == null) throw new AssertionError("saved function changed");
            var locals = function.getLocalVariables();
            if (locals.length != (caller ? 1 : 0) || (caller &&
                    (!locals[0].getName().equals("curated_held") || locals[0].getFirstUseOffset() != firstUse ||
                    locals[0].getRegister() != register || locals[0].getSource() != SourceType.USER_DEFINED))) {
                throw new AssertionError("saved local changed");
            }
            var instructions = new ArrayList<Object>();
            var uncovered = new AddressSet(body);
            for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
                if (!uncovered.contains(instruction.getAddress(), instruction.getMaxAddress())) {
                    throw new AssertionError("instruction outside body");
                }
                uncovered.delete(instruction.getAddress(), instruction.getMaxAddress());
                instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().next().getOffset() - delta,
                    "text", instruction.toString(), "call", instruction.getFlowType().isCall(),
                    "writesHeld", java.util.Arrays.asList(instruction.getResultObjects()).contains(register),
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            if (!uncovered.isEmpty()) throw new AssertionError("incomplete body");
            rows.add(Map.of("name", name, "firstUse", firstUse, "instructions", instructions,
                "convention", function.getCallingConventionName()));
        }
        if (rows.size() != 3) throw new AssertionError("missing functions");
        var result = new LinkedHashMap<String, Object>();
        result.put("java", System.getProperty("java.version"));
        result.put("delta", delta);
        result.put("functions", rows);
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
