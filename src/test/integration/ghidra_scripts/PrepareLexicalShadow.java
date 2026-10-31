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
            blocks.add(new GhidraLexicalScopes.Block(block, block.equals("outer") ? "" : "outer",
                new AddressSet(toAddr(labels.get(block + "_begin").getAsLong() + delta),
                    toAddr(labels.get(block + "_end").getAsLong() + delta - 1))));
        }
        GhidraLexicalScopes.save(function, "Analyst assertion correlated to source-built lexical fixture markers",
            blocks, bindings, monitor);
        if (GhidraLexicalScopes.read(function, monitor, this::println).isEmpty()) throw new AssertionError("missing saved scopes");
        var instructions = new ArrayList<Object>();
        for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                "next", instruction.getMaxAddress().next().getOffset() - delta,
                "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes())));
        }
        records.put("instructions", instructions);
        records.put("javaVersion", System.getProperty("java.version"));
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
        println("lexical-shadow-preparation=PASS");
    }
}
