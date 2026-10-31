// Groups compiler-observed scalar arguments into an explicit analyst Pair.
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
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareCompositeValueFlow extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3 && getScriptArgs().length != 4) {
            throw new IllegalArgumentException("labels compiler-storage output-json [observe]");
        }
        boolean observe = getScriptArgs().length == 4 && getScriptArgs()[3].equals("observe");
        if (getScriptArgs().length == 4 && !observe) throw new IllegalArgumentException("expected observe");
        var labels = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        var compiler = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[1]))).getAsJsonObject();
        boolean x86 = labels.get("target").getAsString().equals("x86_64");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var records = new LinkedHashMap<String, Object>();
        var integer = new UnsignedLongLongDataType(currentProgram.getDataTypeManager());
        var pair = new StructureDataType("AnalystPair", 0, currentProgram.getDataTypeManager());
        pair.add(integer, "first", null);
        pair.add(integer, "second", null);
        for (String name : labels.getAsJsonObject("functions").keySet()) {
            var row = labels.getAsJsonObject("functions").getAsJsonObject(name);
            var entry = toAddr(row.get("entry").getAsLong() + delta);
            var end = toAddr(row.get("end").getAsLong() + delta);
            var function = getFunctionAt(entry);
            if (function == null || !function.getBody().getMinAddress().equals(entry) ||
                    !function.getBody().getMaxAddress().next().equals(end)) throw new AssertionError("compiler body mismatch: " + name);
            if (name.equals("pieces_split") && (function.getBody().getNumAddressRanges() != 2 ||
                    function.getBody().intersects(toAddr(row.get("hole").getAsLong() + delta),
                        toAddr(row.get("afterhole").getAsLong() + delta - 1)))) {
                throw new AssertionError("the compiler body hole was included");
            }
            boolean navigation = name.equals("navigation_control") || name.equals("pieces_leaf");
            VariableStorage joined = null;
            if (!navigation) {
                var first = currentProgram.getRegister(x86 ? "RDI" : "x0");
                var second = currentProgram.getRegister(x86 ? "RSI" : "x1");
                var secondNode = name.endsWith("mixed") ?
                    new Varnode(currentProgram.getAddressFactory().getStackSpace().getAddress(
                        compiler.getAsJsonObject(name).get("incomingSecond").getAsLong()), 8) :
                    new Varnode(second.getAddress(), 8);
                joined = new VariableStorage(currentProgram, secondNode, new Varnode(first.getAddress(), 8));
            }
            if (!observe) {
                function.setName(name, SourceType.USER_DEFINED);
                if (name.equals("pieces_leaf")) {
                    // The separately compiled no-argument C leaf uses this
                    // compiler ABI; custom analyst aggregates make no such claim.
                    function.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
                }
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    navigation ? new Parameter[0] : new Parameter[] {
                        new ParameterImpl("value", pair, joined, currentProgram, SourceType.USER_DEFINED) });
                for (var local : function.getLocalVariables()) function.removeVariable(local);
            }
            if (!function.getName().equals(name) || function.getParameterCount() != (navigation ? 0 : 1) ||
                    function.getSignatureSource() != SourceType.USER_DEFINED || function.getLocalVariables().length != 0) {
                throw new AssertionError("saved analyst signature changed");
            }
            if (name.equals("pieces_leaf") && function.getCallingConvention() !=
                    currentProgram.getCompilerSpec().getDefaultCallingConvention()) {
                throw new AssertionError("the compiler leaf ABI was not retained");
            }
            if (!navigation) {
                Parameter parameter = function.getParameter(0);
                if (!parameter.getName().equals("value") || !parameter.getFormalDataType().isEquivalent(pair) ||
                        !parameter.getVariableStorage().equals(joined) || parameter.getLength() != 16 ||
                        parameter.getSource() != SourceType.USER_DEFINED || parameter.getFirstUseOffset() != 0 ||
                        parameter.getFunction() != function || parameter.getOrdinal() != 0) {
                    throw new AssertionError("complete saved aggregate changed");
                }
                var pieces = new ArrayList<Object>();
                for (Varnode node : parameter.getVariableStorage().getVarnodes()) {
                    pieces.add(Map.of("space", node.getAddress().getAddressSpace().getName(),
                        "offset", node.getOffset(), "bytes", node.getSize(),
                        "register", node.isRegister() ? currentProgram.getRegister(node).getName() : ""));
                }
                records.put(name + "_storage", pieces);
            }
            var body = new ArrayList<Object>();
            for (var range : function.getBody()) body.add(List.of(
                range.getMinAddress().getOffset() - delta, range.getMaxAddress().getOffset() - delta + 1));
            records.put(name + "_body", body);
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
        var sink = toAddr(labels.get("effect_sink").getAsLong() + delta);
        if (!observe) {
            DataUtilities.createData(currentProgram, sink, integer, integer.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(sink, "effect_sink", SourceType.USER_DEFINED).setPrimary();
        }
        var output = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(records);
        Files.writeString(Path.of(getScriptArgs()[2]), output + "\n");
        println("composite-value-flow-origin=" + ghidradwarfforge.GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation());
        println("composite-value-flow-java=" + System.getProperty("java.version"));
        println("composite-value-flow-preparation=PASS");
    }
}
