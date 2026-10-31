package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import com.google.gson.JsonParser;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Research fixture; the driver isolates each alternate producer class from production. */
public final class NamespaceGlobalProducer {
    public static void main(String[] args) throws Exception {
        var symbols = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var integer = new TypeGraph.TypeRef("int");
        var types = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var globals = List.of(
            new ProgramTypeModel.GlobalVariable("missing", 0, 4, integer, true, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("left::item").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("right::item").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("right")),
            new ProgramTypeModel.GlobalVariable("unique_value", symbols.get("left::unique_value").getAsLong(), 4, integer, false, "USER_DEFINED", List.of("left")),
            new ProgramTypeModel.GlobalVariable("item", symbols.get("item").getAsLong(), 4, integer, false, "USER_DEFINED"));
        var function = new MinimalDwarfSidecarExporter.FunctionSymbol("marker", symbols.get("marker").getAsLong(), symbols.get("marker.size").getAsLong());
        var model = new ProgramTypeModel(types, List.of(), globals);
        new MinimalDwarfSidecarExporter().export(Path.of(args[2]), Path.of(args[3]), Path.of(args[0]), Path.of(args[1]), List.of(function), null, model);
        System.out.println("producer-origin=" + MinimalDwarfSidecarExporter.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.println("namespace-global-producer=PASS java=" + System.getProperty("java.version"));
    }
}
