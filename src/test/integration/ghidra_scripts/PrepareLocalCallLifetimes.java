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
        if ((args.length != 3 && args.length != 4) || !List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("expected curate|observe output-json boundaries-json [stack-offsets-json]");
        }
        var offsets = args.length == 4 ? JsonParser.parseString(Files.readString(Path.of(args[3])))
            .getAsJsonObject().getAsJsonObject("functions") : null;
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
            if (name.equals("local_call_split")) {
                body.delete(toAddr(label.get("gap").getAsLong() + delta),
                    toAddr(label.get("resume").getAsLong() + delta - 1));
            }
            Function function = getFunctionAt(entry);
            if (function == null) throw new AssertionError("missing " + name);
            boolean caller = name.startsWith("local_call_");
            int firstUse = caller ? Math.toIntExact(label.get("definition").getAsLong() + delta - entry.getOffset()) : 0;
            int stackOffset = caller && offsets != null ? offsets.get(name).getAsInt() : 0;
            if (args[0].equals("curate")) {
                var interior = new ArrayList<ghidra.program.model.address.Address>();
                for (Function other : currentProgram.getFunctionManager().getFunctions(body, true)) {
                    if (other == function) continue;
                    if (!body.contains(other.getBody())) throw new AssertionError("outside fixture tail");
                    interior.add(other.getEntryPoint());
                }
                for (var address : interior) currentProgram.getFunctionManager().removeFunction(address);
                function.setBody(body);
                if (name.equals("local_call_split")) {
                    var jump = getInstructionAt(toAddr(label.get("jump").getAsLong() + delta));
                    var operations = jump.getPcode();
                    if (operations.length != 1 || operations[0].getOpcode() != ghidra.program.model.pcode.PcodeOp.BRANCH ||
                            !operations[0].getInput(0).getAddress().equals(toAddr(label.get("resume").getAsLong() + delta))) {
                        throw new AssertionError("fixture hole must use an ordinary machine branch");
                    }
                    jump.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
                }
                function.setName(name, SourceType.USER_DEFINED);
                var parameters = new ArrayList<ghidra.program.model.listing.Parameter>();
                if (name.equals("inspected_alias")) parameters.add(new ParameterImpl("destination",
                    new ghidra.program.model.data.PointerDataType(LongLongDataType.dataType), currentProgram));
                parameters.add(new ParameterImpl("input", LongLongDataType.dataType, currentProgram));
                if (!caller && labels.has("inspected_overlap")) {
                    for (int index = 1; index <= 7; index++) {
                        parameters.add(new ParameterImpl("p" + index, LongLongDataType.dataType, currentProgram));
                    }
                    parameters.add(new ParameterImpl("held", LongLongDataType.dataType, currentProgram));
                    parameters.add(new ParameterImpl("adjacent",
                        ghidra.program.model.data.UnsignedIntegerDataType.dataType, currentProgram));
                }
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(LongLongDataType.dataType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    parameters.toArray(ghidra.program.model.listing.Parameter[]::new));
                for (var variable : function.getLocalVariables()) function.removeVariable(variable);
                if (caller) {
                    if (offsets == null) function.addLocalVariable(new LocalVariableImpl("curated_held", firstUse,
                        LongLongDataType.dataType, register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    else {
                        var local = (ghidra.program.model.listing.LocalVariable) function.addLocalVariable(new LocalVariableImpl("curated_held", LongLongDataType.dataType,
                            stackOffset, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                        local.setFirstUseOffset(firstUse);
                    }
                }
            }
            if (!function.getBody().hasSameAddresses(body) || !function.getName().equals(name) ||
                    function.getCallingConvention() == null) throw new AssertionError("saved function changed");
            var locals = function.getLocalVariables();
            if (locals.length != (caller ? 1 : 0) || (caller &&
                    (!locals[0].getName().equals("curated_held") || locals[0].getFirstUseOffset() != firstUse ||
                    (offsets == null ? locals[0].getRegister() != register : locals[0].getStackOffset() != stackOffset) ||
                    locals[0].getSource() != SourceType.USER_DEFINED))) {
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
                    "writesSp", java.util.Arrays.asList(instruction.getResultObjects()).contains(currentProgram.getCompilerSpec().getStackPointer()),
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            if (!uncovered.isEmpty()) throw new AssertionError("incomplete body");
            if (caller && labels.has("inspected_overlap")) {
                var definition = getInstructionAt(entry.add(firstUse));
                var stores = java.util.Arrays.stream(definition.getPcode())
                    .filter(op -> op.getOpcode() == ghidra.program.model.pcode.PcodeOp.STORE).toList();
                if (stores.size() != 1 || stores.get(0).getInput(2).getSize() != 8 ||
                        definition.getFlowType().isCall() ||
                        java.util.Arrays.asList(definition.getResultObjects()).contains(
                            currentProgram.getCompilerSpec().getStackPointer()) ||
                        definition.getMaxAddress().next().getOffset() - delta != label.get("ready").getAsLong()) {
                    throw new AssertionError("compiler-calibrated copy must be one full non-SP-changing store");
                }
            }
            rows.add(Map.of("name", name, "firstUse", firstUse, "instructions", instructions,
                "convention", function.getCallingConventionName()));
        }
        if (rows.size() != labels.size()) throw new AssertionError("missing functions");
        var result = new LinkedHashMap<String, Object>();
        result.put("java", System.getProperty("java.version"));
        result.put("delta", delta);
        result.put("functions", rows);
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
