// Preserve explicit static object identity without rewriting imported namespace ownership.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraLexicalScopes;
import ghidradwarfforge.GhidraStaticBindings;

public class PrepareLexicalStatics extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("labels objects observation");
        JsonObject labels = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonObject objects = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var owner = function(labels, "scoped_statics", delta);
        var other = function(labels, "other_statics", delta);
        function(labels, "main", delta);
        var blocks = new ArrayList<GhidraLexicalScopes.Block>();
        for (String name : List.of("outer", "inner", "sibling")) {
            blocks.add(new GhidraLexicalScopes.Block(name, name.equals("inner") ? "outer" : "",
                new AddressSet(toAddr(labels.get(name + "_begin").getAsLong() + delta),
                    toAddr(labels.get(name + "_end").getAsLong() + delta - 1))));
        }
        GhidraLexicalScopes.save(owner, "Analyst records source-built static scope boundaries", blocks, List.of(), monitor);
        var namespace = currentProgram.getSymbolTable().createNameSpace(currentProgram.getGlobalNamespace(),
            "scoped_statics", SourceType.IMPORTED);
        if (namespace.getID() == owner.getID()) throw new AssertionError("plain namespace must remain distinct");
        var records = new ArrayList<Object>();
        for (String name : List.of("root", "outer", "inner", "sibling", "other", "global")) {
            var address = toAddr(objects.get(name).getAsLong() + delta);
            clearListing(address, address.add(3));
            createData(address, new IntegerDataType(currentProgram.getDataTypeManager()));
            var parent = name.equals("other") ? other : name.equals("global") ? currentProgram.getGlobalNamespace() : namespace;
            var symbol = currentProgram.getSymbolTable().createLabel(address,
                name.equals("global") ? "shadow" : "saved_" + name, parent, SourceType.USER_DEFINED);
            symbol.setPrimary();
            if (!name.equals("global")) {
                GhidraStaticBindings.save(currentProgram, symbol, name.equals("other") ? other : owner,
                    List.of("root", "other").contains(name) ? "" : name, "shadow",
                    "Analyst associates compiler-correlated static object " + name, monitor);
                var result = GhidraStaticBindings.read(currentProgram, symbol.getID(), monitor, this::println);
                if (result.status() != GhidraStaticBindings.Status.VALID) throw new AssertionError("binding did not persist");
            }
            records.add(Map.of("scope", name, "symbolId", symbol.getID(), "address", objects.get(name).getAsLong()));
        }
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create()
            .toJson(Map.of("javaVersion", System.getProperty("java.version"), "objects", records)) + "\n");
        println("lexical-statics-preparation=PASS");
    }

    private Function function(JsonObject labels, String name, long delta) throws Exception {
        var function = getFunctionAt(toAddr(labels.get(name).getAsLong() + delta));
        if (function == null) throw new AssertionError("missing " + name);
        function.setName(name, SourceType.USER_DEFINED);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED, new Parameter[0]);
        for (var local : function.getLocalVariables()) function.removeVariable(local);
        return function;
    }
}
