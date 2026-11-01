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
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareMutableStackMappings extends GhidraScript {
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
        int width = labels.get("width").getAsInt();
        if (width != 4 && width != 8) throw new IllegalArgumentException("unsupported local width");
        DataType type = width == 4 ? new IntegerDataType(currentProgram.getDataTypeManager()) :
            new LongLongDataType(currentProgram.getDataTypeManager());
        if (labels.has("helper")) {
            var helper = labels.getAsJsonObject("helper");
            var entry = toAddr(helper.get("entry").getAsLong() + delta);
            var end = toAddr(helper.get("end").getAsLong() + delta);
            var function = getFunctionAt(entry);
            if (function == null || !function.getBody().hasSameAddresses(
                    new ghidra.program.model.address.AddressSet(entry, end.previous()))) {
                throw new AssertionError("inspected helper body mismatch");
            }
            if (!observe) {
                function.setName("inspected_mutable", SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ghidra.program.model.listing.ReturnParameterImpl(VoidDataType.dataType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ghidra.program.model.listing.ParameterImpl("input", type, currentProgram));
            }
            if (!function.getName().equals("inspected_mutable") || function.getParameterCount() != 1 ||
                    function.getCallingConvention() == null) throw new AssertionError("helper contract changed");
            var helperInstructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                helperInstructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().next().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "text", instruction.toString(),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            records.put("inspected_mutable_instructions", helperInstructions);
        }
        for (String name : labels.getAsJsonObject("functions").keySet()) {
            var row = labels.getAsJsonObject("functions").getAsJsonObject(name);
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
            for (String localName : name.equals("navigation_control") ? new String[0] : new String[] { "value" }) {
                var live = toAddr(row.get("live").getAsLong() + delta);
                var definition = getInstructionBefore(live);
                if (definition == null || !definition.getMaxAddress().next().equals(live) ||
                        java.util.Arrays.stream(definition.getPcode()).filter(op -> op.getOpcode() == PcodeOp.STORE).count() != 1) {
                    throw new AssertionError("marker must immediately follow one raw STORE: " + localName);
                }
                int offset = storage.getAsJsonObject(name).get("offset").getAsInt();
                int firstUse = Math.toIntExact(definition.getAddress().subtract(entry));
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
                if (firstUse <= 0 || local.getFirstUseOffset() != firstUse || local.getStackOffset() != offset ||
                        local.getLength() != width || local.getSource() != SourceType.USER_DEFINED ||
                        !local.getDataType().isEquivalent(type)) throw new AssertionError("saved local changed");
                locals.add(Map.of("name", localName, "symbolId", local.getSymbol().getID(), "firstUse", firstUse,
                    "stackOffset", offset, "definition", definition.getAddress().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(definition.getBytes()),
                    "pcode", java.util.Arrays.stream(definition.getPcode()).map(Object::toString).toList()));
            }
            if (!name.equals("navigation_control")) {
                boolean x86 = currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86");
                var register = currentProgram.getRegister(x86 ? (width == 4 ? "R10D" : "R10") : (width == 4 ? "w9" : "x9"));
                if (register == null || register.getMinimumByteSize() != width) throw new AssertionError("carrier");
                int ordinal = 0;
                for (String marker : new String[] { "load", "update" }) {
                    ordinal++;
                    String localName = "value$" + ordinal;
                    var definition = toAddr(row.get(marker).getAsLong() + delta);
                    int firstUse = Math.toIntExact(definition.subtract(entry));
                    var instruction = getInstructionAt(definition);
                    if (instruction == null || !function.getBody().contains(definition)) throw new AssertionError("assignment boundary");
                    LocalVariable local;
                    if (observe) local = (LocalVariable) java.util.Arrays.stream(function.getLocalVariables())
                        .filter(value -> value.getName().equals(localName)).findFirst().orElseThrow();
                    else local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(localName, firstUse,
                        type, register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    if (local.getFirstUseOffset() != firstUse || local.getRegister() != register ||
                            local.getLength() != width || local.getSource() != SourceType.USER_DEFINED ||
                            !local.getDataType().isEquivalent(type)) throw new AssertionError("saved assignment changed");
                    locals.add(Map.of("name", localName, "symbolId", local.getSymbol().getID(), "firstUse", firstUse,
                        "register", register.getName(), "definition", definition.getOffset() - delta,
                        "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                        "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
                }
            }
            if (name.equals("mutable_conflict")) {
                var definition = getInstructionBefore(toAddr(row.get("lost").getAsLong() + delta));
                int firstUse = Math.toIntExact(definition.getAddress().subtract(entry));
                int offset = storage.getAsJsonObject(name).get("offset").getAsInt();
                LocalVariable other;
                if (observe) other = (LocalVariable) java.util.Arrays.stream(function.getLocalVariables())
                    .filter(value -> value.getName().equals("other")).findFirst().orElseThrow();
                else {
                    other = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("other", type, offset,
                        currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    other.setFirstUseOffset(firstUse);
                }
                if (other.getFirstUseOffset() != firstUse || other.getStackOffset() != offset ||
                        other.getSource() != SourceType.USER_DEFINED || !other.getDataType().isEquivalent(type)) {
                    throw new AssertionError("conflicting owner changed");
                }
                locals.add(Map.of("name", "other", "symbolId", other.getSymbol().getID(), "firstUse", firstUse,
                    "stackOffset", offset, "definition", definition.getAddress().getOffset() - delta));
            }
            if (function.getLocalVariables().length != locals.size()) throw new AssertionError("local identity replaced");
            records.put(name, locals);
            var instructions = new ArrayList<Object>();
            int callCount = 0;
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                if (labels.has("helper") && instruction.getFlowType().isCall()) {
                    callCount++;
                    var helper = labels.getAsJsonObject("helper");
                    if (name.equals("navigation_control") || instruction.getFlows().length != 1 ||
                            instruction.getFlows()[0].getOffset() - delta != helper.get("entry").getAsLong() ||
                            instruction.getMaxAddress().next().getOffset() - delta != row.get("returned").getAsLong()) {
                        throw new AssertionError("unexpected call or return boundary");
                    }
                }
                instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().next().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "text", instruction.toString(), "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            records.put(name + "_instructions", instructions);
            if (labels.has("helper") && callCount != (name.equals("navigation_control") ? 0 : 1)) {
                throw new AssertionError("missing fixture call");
            }
        }
        for (String name : new String[] { "effect_sink", "backup_sink", "path_choice" }) {
            DataType globalType = name.equals("path_choice") ? new IntegerDataType(currentProgram.getDataTypeManager()) : type;
            var address = toAddr(labels.get(name).getAsLong() + delta);
            if (!observe) {
                DataUtilities.createData(currentProgram, address, globalType, globalType.getLength(),
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
            }
            if (getDataAt(address) == null || !getDataAt(address).getDataType().isEquivalent(globalType) ||
                    !currentProgram.getSymbolTable().getPrimarySymbol(address).getName().equals(name)) {
                throw new AssertionError("saved global changed");
            }
        }
        Files.writeString(Path.of(getScriptArgs()[2]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
        println("mutable-stack-mappings-origin=" + GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation());
        println("mutable-stack-mappings-java=" + System.getProperty("java.version"));
        println("mutable-stack-mappings-preparation=PASS");
    }
}
