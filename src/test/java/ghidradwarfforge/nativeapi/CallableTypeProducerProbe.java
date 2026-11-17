package ghidradwarfforge.nativeapi;

import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Explicit C fixture signatures; tests native serialization, not decompiler recovery. */
public final class CallableTypeProducerProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("consumer producer input directory request");
        Path input = Path.of(args[2]), directory = Path.of(args[3]);
        var request = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var symbols = new java.util.ArrayList<MinimalDwarfSidecarExporter.FunctionSymbol>();
        var texts = new java.util.ArrayList<SyntheticSourceFile.FunctionText>();
        for (String name : List.of("forge_probe", "forge_variadic")) {
            var symbol = request.getAsJsonObject(name);
            long address = symbol.get("address").getAsLong();
            symbols.add(new MinimalDwarfSidecarExporter.FunctionSymbol(name, address, symbol.get("size").getAsLong()));
            texts.add(new SyntheticSourceFile.FunctionText(name, address,
                name.equals("forge_probe") ? "int forge_probe(void) { return forge_callback(37, 9); }\n"
                    : "int forge_variadic(int first, ...) { return first; }\n", null));
        }
        var source = SyntheticSourceFile.build("callable-fixture", "test", texts);
        var integer = new TypeGraph.TypeRef("int");
        var nothing = new TypeGraph.TypeRef("void");
        var unnamed = List.of(new TypeGraph.Parameter("", integer, false));
        byte[] original = Files.readAllBytes(input);
        for (String mode : List.of("normal", "unknown", "blocked")) {
            String convention = mode.equals("normal") ? "default" : mode.equals("unknown") ? "unknown" : "";
            String restriction = mode.equals("blocked") ? "fixture has no proven injected-call ABI" : "";
            var graph = new TypeGraph(List.of(new TypeGraph.VoidType("void"),
                new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED),
                new TypeGraph.SubroutineType("callable", "ForgeCallback", 0, integer, unnamed,
                    true, convention, restriction),
                new TypeGraph.IndirectionType("pointer", "ForgeCallback *", 8,
                    TypeGraph.IndirectionKind.POINTER, new TypeGraph.TypeRef("callable"))));
            var signatures = symbols.stream().map(symbol -> new ProgramTypeModel.FunctionSignature(
                symbol.name(), symbol.address(), integer,
                symbol.name().equals("forge_variadic") ? unnamed : List.of(), List.of(),
                symbol.name().equals("forge_variadic"), false, convention, "EXPLICIT_C_FIXTURE",
                false, restriction)).toList();
            var global = request.getAsJsonObject("forge_callback");
            if (global.get("size").getAsLong() != 8) throw new AssertionError("fixture pointer width differs");
            var model = new ProgramTypeModel(graph, signatures, List.of(new ProgramTypeModel.GlobalVariable(
                "forge_callback", global.get("address").getAsLong(), 8, new TypeGraph.TypeRef("pointer"),
                false, "EXPLICIT_C_FIXTURE")), new VariableStorageModel(List.of()), List.of(),
                List.of(new ProgramTypeModel.FunctionDeclaration("external:declared_only", "declared_only", nothing,
                    unnamed, true, true, convention, "EXPLICIT_C_FIXTURE", false, restriction)));
            Path output = directory.resolve(mode + ".dbg");
            Path sourcePath = Path.of(output + ".c");
            Files.write(sourcePath, source.utf8());
            var exporter = new MinimalDwarfSidecarExporter();
            byte[] first = null;
            for (int iteration = 0; iteration < 2; iteration++) {
                exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), symbols, source, model);
                byte[] actual = Files.readAllBytes(output);
                if (first == null) first = actual;
                else if (!Arrays.equals(first, actual)) throw new AssertionError("callable export changed across lifetimes");
                if (!Arrays.equals(original, Files.readAllBytes(input)) ||
                        !Arrays.equals(source.utf8(), Files.readAllBytes(sourcePath))) {
                    throw new AssertionError("callable export changed original or source");
                }
            }
        }
        System.out.println("callable-type-producer=PASS modes=3 deterministic=true preserved=true");
    }
}
