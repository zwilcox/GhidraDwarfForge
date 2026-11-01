package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;
import com.google.gson.JsonParser;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Isolated real-producer lookup and collision controls. No replacement production classes. */
public final class NamespaceGlobalLookupSmoke {
    public static void main(String[] args) throws Exception {
        var symbols = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var integer = new TypeGraph.TypeRef("int");
        String variant = args[5];
        var nodes = new ArrayList<TypeGraph.TypeNode>();
        nodes.add(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED));
        String collision = variant.endsWith("full") ? "left::item" : "unique_value";
        if (variant.startsWith("type-")) nodes.add(new TypeGraph.TypedefType("alias", collision, 4, integer));
        if (variant.startsWith("enum-")) nodes.add(new TypeGraph.EnumType("mode", "Mode", 4, true,
            List.of(new TypeGraph.Enumerator(collision, 73))));
        var types = new TypeGraph(nodes);
        var globals = new ArrayList<>(List.of(
            new ProgramTypeModel.GlobalVariable("missing", 0, 4, integer, true, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("left::item").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("right::item").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("right")),
            new ProgramTypeModel.GlobalVariable("unique_value", symbols.get("left::unique_value").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("item").getAsLong(), 4, integer, false, "USER_DEFINED")));
        if (variant.equals("global-full")) globals.add(new ProgramTypeModel.GlobalVariable(
            "left::item", symbols.get("left::unique_value").getAsLong(), 4, integer, false, "USER_DEFINED"));
        var function = new MinimalDwarfSidecarExporter.FunctionSymbol(variant.startsWith("function-") ? collision : "marker", symbols.get("marker").getAsLong(), symbols.get("marker.size").getAsLong());
        var model = new ProgramTypeModel(types, List.of(), globals);
        new MinimalDwarfSidecarExporter().export(Path.of(args[2]), Path.of(args[3]), Path.of(args[0]), Path.of(args[1]),
            List.of(function), null, model, "fixture.dbg.c", () -> false, List.of(), System.out::println);
        System.out.println("producer-origin=" + MinimalDwarfSidecarExporter.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.println("namespace-global-producer=PASS java=" + System.getProperty("java.version"));
    }
}
