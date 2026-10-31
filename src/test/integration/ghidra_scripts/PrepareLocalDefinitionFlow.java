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
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraTypeGraph;

public class PrepareLocalDefinitionFlow extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3 || !List.of("curate", "observe").contains(getScriptArgs()[0])) {
            throw new IllegalArgumentException("expected curate|observe output-json compiler-boundaries-json");
        }
        var labels = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var rows = new ArrayList<Object>();
        for (var item : labels.entrySet()) {
            monitor.checkCancelled();
            String name = item.getKey();
            var label = item.getValue().getAsJsonObject();
            var entry = toAddr(label.get("entry").getAsLong() + delta);
            var end = toAddr(label.get("end").getAsLong() + delta);
            var definition = toAddr(label.get("definition").getAsLong() + delta);
            Function function = getFunctionAt(entry);
            if (function == null) throw new AssertionError("missing function " + name);
            boolean small = label.get("width").getAsInt() == 4;
            boolean x86 = currentProgram.getLanguageID().toString().startsWith("x86:");
            var register = currentProgram.getRegister(x86 ? (small ? "R10D" : "R10") : (small ? "w9" : "x9"));
            var type = small ? IntegerDataType.dataType : LongLongDataType.dataType;
            int firstUse = Math.toIntExact(definition.subtract(entry));
            var body = new AddressSet(entry, end.previous());
            if (name.startsWith("flow_split")) {
                body.delete(toAddr(label.get("gap").getAsLong() + delta),
                    toAddr(label.get("resume").getAsLong() + delta - 1));
            }
            if (getScriptArgs()[0].equals("curate")) {
                function.setName(name, SourceType.USER_DEFINED);
                // The source fixture intentionally exposes interior assembler labels.
                // Auto-analysis can turn a separately labeled tail into another
                // function. Reunite only functions wholly within this compiler's
                // independently recorded symbol bounds; never absorb outside code.
                var interior = new ArrayList<ghidra.program.model.address.Address>();
                for (Function other : currentProgram.getFunctionManager().getFunctions(body, true)) {
                    if (other.getEntryPoint().equals(entry)) continue;
                    if (!body.contains(other.getBody())) throw new AssertionError("outside fixture tail");
                    interior.add(other.getEntryPoint());
                }
                for (var address : interior) currentProgram.getFunctionManager().removeFunction(address);
                function.setBody(body);
                if (name.startsWith("flow_split")) {
                    var jump = getInstructionAt(toAddr(label.get("jump").getAsLong() + delta));
                    var operations = jump.getPcode();
                    var resume = toAddr(label.get("resume").getAsLong() + delta);
                    if (operations.length != 1 || operations[0].getOpcode() != ghidra.program.model.pcode.PcodeOp.BRANCH ||
                            !operations[0].getInput(0).getAddress().equals(resume)) {
                        throw new AssertionError("fixture gap must use an ordinary machine branch");
                    }
                    println("Fixture internal branch " + jump.getAddress() + " inferred override=" + jump.getFlowOverride());
                    jump.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
                }
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(type, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, new ParameterImpl("input", type, currentProgram),
                    new ParameterImpl("choose", IntegerDataType.dataType, currentProgram));
                for (var variable : function.getLocalVariables()) function.removeVariable(variable);
                function.addLocalVariable(new LocalVariableImpl("curated_held", firstUse, type,
                    register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
            var locals = function.getLocalVariables();
            if (!function.getBody().hasSameAddresses(body) || !function.getName().equals(name) ||
                    locals.length != 1 || !locals[0].getName().equals("curated_held") ||
                    locals[0].getFirstUseOffset() != firstUse || locals[0].getSource() != SourceType.USER_DEFINED ||
                    locals[0].getRegister() != register || locals[0].getLength() != type.getLength()) {
                throw new AssertionError("curated storage/body did not persist: " + name + " " + function.getBody() + " locals=" + java.util.Arrays.toString(locals));
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", name);
            row.put("entry", entry.toString());
            row.put("end", end.toString());
            row.put("firstUse", firstUse);
            row.put("width", type.getLength());
            row.put("source", locals[0].getSource().name());
            row.put("storage", locals[0].getVariableStorage().toString());
            var ranges = new ArrayList<Object>();
            for (var range : body.getAddressRanges()) {
                ranges.add(List.of(range.getMinAddress().toString(), range.getMaxAddress().next().toString()));
            }
            row.put("bodyRanges", ranges);
            var instructions = new ArrayList<Object>();
            var uncovered = new AddressSet(body);
            for (var instruction : currentProgram.getListing().getInstructions(body, true)) {
                if (!uncovered.contains(instruction.getAddress(), instruction.getMaxAddress())) {
                    throw new AssertionError("instruction crosses body boundary");
                }
                uncovered.delete(instruction.getAddress(), instruction.getMaxAddress());
                instructions.add(Map.of("address", instruction.getAddress().toString(),
                    "next", instruction.getMaxAddress().next().toString(), "text", instruction.toString(),
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "flowOverride", instruction.getFlowOverride().name(), "flowType", instruction.getFlowType().toString(),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            if (!uncovered.isEmpty() || getInstructionAt(definition) == null || firstUse <= 0) {
                throw new AssertionError("fixture body/definition is not completely decoded");
            }
            row.put("instructions", instructions);
            rows.add(row);
        }
        if (rows.size() != 12) throw new AssertionError("missing fixture functions");
        var result = new LinkedHashMap<String, Object>();
        result.put("java", System.getProperty("java.version"));
        result.put("imageBase", currentProgram.getImageBase().getOffset());
        result.put("originalImageBase", GhidraImageBase.originalImageBase(currentProgram));
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("functions", rows);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
