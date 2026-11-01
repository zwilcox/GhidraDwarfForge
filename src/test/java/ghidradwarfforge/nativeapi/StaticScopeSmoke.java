package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonParser;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Isolated producer exercised with independently observed compiler addresses. */
public final class StaticScopeSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 6) throw new IllegalArgumentException("consumer producer original output labels objects");
        var labels = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var objects = JsonParser.parseString(Files.readString(Path.of(args[5]))).getAsJsonObject();
        var functions = new ArrayList<FunctionSymbol>();
        var signatures = new ArrayList<ProgramTypeModel.FunctionSignature>();
        var type = new TypeGraph.TypeRef("int");
        var graph = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        for (String name : List.of("scoped_statics", "other_statics", "main")) {
            long address = labels.get(name).getAsLong();
            functions.add(new FunctionSymbol(name, address, labels.get(name + "_size").getAsLong()));
            signatures.add(new ProgramTypeModel.FunctionSignature(name, address, type, List.of(), List.of(),
                false, false, "default", "USER_DEFINED"));
        }
        long owner = labels.get("scoped_statics").getAsLong();
        var blocks = new ArrayList<LexicalScopeModel.Block>();
        for (String name : List.of("outer", "inner", "sibling")) {
            long start = labels.get(name + "_begin").getAsLong();
            long end = labels.get(name + "_end").getAsLong();
            blocks.add(new LexicalScopeModel.Block(name, name.equals("inner") ? "outer" : "",
                List.of(new FunctionRange(start, end - start))));
        }
        var scopes = new LexicalScopeModel(owner, functions.getFirst().ranges(), blocks, List.of(), "compiler fixture boundaries");
        var statics = new ArrayList<ProgramTypeModel.FunctionStaticVariable>();
        for (String name : List.of("root", "outer", "inner", "sibling", "other")) {
            statics.add(new ProgramTypeModel.FunctionStaticVariable("shadow", objects.get(name).getAsLong(), 4, type,
                name.equals("other") ? labels.get("other_statics").getAsLong() : owner, "compiler fixture object identity",
                List.of("root", "other").contains(name) ? "" : name));
        }
        var model = new ProgramTypeModel(graph, signatures,
            List.of(new ProgramTypeModel.GlobalVariable("shadow", objects.get("global").getAsLong(), 4, type, false, "USER_DEFINED")),
            new VariableStorageModel(List.of()), statics, List.of(), List.of(scopes));
        new MinimalDwarfSidecarExporter().export(Path.of(args[2]), Path.of(args[3]), Path.of(args[0]), Path.of(args[1]), functions, null, model);
        System.out.println("static-scope-native=PASS");
    }
}
