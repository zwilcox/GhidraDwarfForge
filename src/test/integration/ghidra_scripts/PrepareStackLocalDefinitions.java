// Saves distinct function-owned locals at compiler-correlated stack definitions.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareStackLocalDefinitions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3 && getScriptArgs().length != 4) {
            throw new IllegalArgumentException("labels storage output-json [observe]");
        }
        boolean observe = getScriptArgs().length == 4 && getScriptArgs()[3].equals("observe");
        if (getScriptArgs().length == 4 && !observe) throw new IllegalArgumentException("expected observe");
        var labels = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        var storage = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[1]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var records = new LinkedHashMap<String, Object>();
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        for (String name : new String[] { "stack_scope", "zero_stack" }) {
            var row = labels.getAsJsonObject(name);
            var entry = toAddr(row.get("entry").getAsLong() + delta);
            var end = toAddr(row.get("end").getAsLong() + delta);
            var function = getFunctionAt(entry);
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(entry) ||
                    !function.getBody().getMaxAddress().next().equals(end)) throw new AssertionError("compiler body mismatch");
            if (!observe) {
                function.setName(name, SourceType.USER_DEFINED);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, new Parameter[0]);
                for (var local : function.getLocalVariables()) function.removeVariable(local);
            }
            if (!function.getName().equals(name) || function.getParameterCount() != 0 ||
                    function.getSignatureSource() != SourceType.USER_DEFINED) throw new AssertionError("saved function changed");
            var locals = new ArrayList<Object>();
            for (String localName : name.equals("stack_scope") ? new String[] { "first", "second" } : new String[] { "zero" }) {
                var live = toAddr(row.get(localName + "_live").getAsLong() + delta);
                var definition = getInstructionBefore(live);
                if (definition == null || !definition.getMaxAddress().next().equals(live) ||
                        java.util.Arrays.stream(definition.getPcode()).filter(op -> op.getOpcode() == PcodeOp.STORE).count() != 1) {
                    throw new AssertionError("marker must immediately follow one raw STORE: " + localName);
                }
                int offset = storage.get(name.equals("stack_scope") ? "scope_offset" : "zero_offset").getAsInt();
                int firstUse = name.equals("stack_scope") ? Math.toIntExact(definition.getAddress().subtract(entry)) : 0;
                LocalVariable local;
                if (observe) {
                    local = (LocalVariable) java.util.Arrays.stream(function.getLocalVariables())
                        .filter(value -> value.getName().equals(localName)).findFirst().orElseThrow();
                }
                else {
                    local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(localName,
                        type, offset, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    local.setFirstUseOffset(firstUse);
                }
                if (local.getFirstUseOffset() != firstUse || local.getStackOffset() != offset ||
                        local.getLength() != 4 || local.getSource() != SourceType.USER_DEFINED ||
                        !local.getDataType().isEquivalent(type)) throw new AssertionError("saved local changed");
                locals.add(Map.of("name", localName, "symbolId", local.getSymbol().getID(), "firstUse", firstUse,
                    "stackOffset", offset, "definition", definition.getAddress().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(definition.getBytes()),
                    "pcode", java.util.Arrays.stream(definition.getPcode()).map(Object::toString).toList()));
            }
            if (function.getLocalVariables().length != locals.size()) throw new AssertionError("local identity replaced");
            records.put(name, locals);
            var instructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().next().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "text", instruction.toString(), "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            records.put(name + "_instructions", instructions);
        }
        for (String name : new String[] { "scope_sink", "zero_sink" }) {
            var address = toAddr(labels.get(name).getAsLong() + delta);
            if (!observe) {
                DataUtilities.createData(currentProgram, address, type, type.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
            if (getDataAt(address) == null || !getDataAt(address).getDataType().isEquivalent(type) ||
                    !currentProgram.getSymbolTable().getPrimarySymbol(address).getName().equals(name)) {
                throw new AssertionError("saved global changed");
            }
        }
        Files.writeString(Path.of(getScriptArgs()[2]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
        println("stack-local-definitions-preparation=PASS");
    }
}
