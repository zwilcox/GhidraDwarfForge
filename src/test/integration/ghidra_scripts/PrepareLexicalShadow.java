// Persist explicit lexical ownership independently of saved stack definitions.
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraLexicalScopes;

public class PrepareLexicalShadow extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("labels storage observation");
        var labels = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        var storage = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var entry = toAddr(labels.get("scoped").getAsLong() + delta);
        var function = getFunctionAt(entry);
        if (function == null) throw new AssertionError("missing function");
        function.setName("scoped", SourceType.USER_DEFINED);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED, new Parameter[0]);
        for (var variable : function.getLocalVariables()) function.removeVariable(variable);
        var bindings = new ArrayList<GhidraLexicalScopes.Local>();
        var records = new LinkedHashMap<String, Object>();
        for (String block : List.of("outer", "inner")) {
            var live = toAddr(labels.get(block + "_live").getAsLong() + delta);
            var definition = getInstructionBefore(live);
            if (definition == null || !definition.getMaxAddress().next().equals(live) ||
                    java.util.Arrays.stream(definition.getPcode()).filter(op -> op.getOpcode() == PcodeOp.STORE).count() != 1) {
                throw new AssertionError("expected initialization STORE before " + block);
            }
            String name = block.equals("outer") ? "shadow" : "shadow_1";
            int offset = storage.get(block).getAsInt();
            var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(name,
                new IntegerDataType(currentProgram.getDataTypeManager()), offset, currentProgram,
                SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            local.setFirstUseOffset(Math.toIntExact(definition.getAddress().subtract(entry)));
            bindings.add(new GhidraLexicalScopes.Local(local, block, "shadow"));
            records.put(block, Map.of("savedName", name, "symbolId", local.getSymbol().getID(),
                "firstUse", local.getFirstUseOffset(), "stackOffset", offset));
        }
        var blocks = new ArrayList<GhidraLexicalScopes.Block>();
        for (String block : List.of("outer", "inner")) {
            var body = new AddressSet(toAddr(labels.get(block + "_begin").getAsLong() + delta),
                toAddr(labels.get(block + "_end").getAsLong() + delta - 1));
            if (block.equals("inner") && labels.has("inner_gap_begin")) {
                var gap = toAddr(labels.get("inner_gap_begin").getAsLong() + delta);
                var afterGap = toAddr(labels.get("inner_gap_end").getAsLong() + delta);
                var instruction = getInstructionAt(gap);
                if (instruction == null || !instruction.getMaxAddress().next().equals(afterGap) ||
                        instruction.getPcode().length != 0) throw new AssertionError("gap must be one effect-free instruction");
                body.deleteRange(gap, afterGap.previous());
            }
            blocks.add(new GhidraLexicalScopes.Block(block, block.equals("outer") ? "" : "outer", body));
        }
        GhidraLexicalScopes.save(function, "Analyst assertion correlated to source-built lexical fixture markers",
            blocks, bindings, monitor);
        if (GhidraLexicalScopes.read(function, monitor, this::println).isEmpty()) throw new AssertionError("missing saved scopes");
        if (labels.has("lexical_leaf")) {
            var leafEntry = toAddr(labels.get("lexical_leaf").getAsLong() + delta);
            var leafEnd = toAddr(labels.get("leaf_end").getAsLong() + delta);
            var leaf = getFunctionAt(leafEntry);
            if (leaf == null || !leaf.getBody().hasSameAddresses(new AddressSet(leafEntry, leafEnd.previous()))) {
                throw new AssertionError("callee body mismatch");
            }
            leaf.setName("lexical_leaf", SourceType.USER_DEFINED);
            leaf.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
            leaf.setReturnType(ghidra.program.model.data.VoidDataType.dataType, SourceType.USER_DEFINED);
            leaf.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED, new Parameter[0]);
            for (var variable : leaf.getLocalVariables()) leaf.removeVariable(variable);
            var leafInstructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(leaf.getBody(), true)) {
                leafInstructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().next().getOffset() - delta,
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes())));
            }
            records.put("calleeInstructions", leafInstructions);
        }
        int calls = 0;
        var instructions = new ArrayList<Object>();
        for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            if (instruction.getFlowType().isCall()) {
                String block = calls++ == 0 ? "outer" : "inner";
                if (!labels.has("lexical_leaf") || instruction.getFlows().length != 1 ||
                        instruction.getFlows()[0].getOffset() - delta != labels.get("lexical_leaf").getAsLong() ||
                        instruction.getMaxAddress().next().getOffset() - delta != labels.get(block + "_returned").getAsLong()) {
                    throw new AssertionError("unexpected call contract");
                }
            }
            instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                "next", instruction.getMaxAddress().next().getOffset() - delta,
                "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                "call", instruction.getFlowType().isCall()));
        }
        if (calls != (labels.has("lexical_leaf") ? 2 : 0)) throw new AssertionError("missing lexical calls");
        records.put("instructions", instructions);
        records.put("javaVersion", System.getProperty("java.version"));
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
        println("lexical-shadow-preparation=PASS");
    }
}
