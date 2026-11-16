package ghidradwarfforge.nativeapi;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Explicit fixture type model through the production serializer; not a Ghidra extraction claim. */
public final class QualifiedTypeProducerProbe {
    private record Symbol(String name, long address, long size) { }
    private record Request(Symbol function, List<Symbol> globals) { }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("consumer producer input output request");
        Path input = Path.of(args[2]), output = Path.of(args[3]);
        var json = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var requestedGlobals = new ArrayList<Symbol>();
        for (var item : json.getAsJsonArray("globals")) requestedGlobals.add(symbol(item.getAsJsonObject()));
        Request request = new Request(symbol(json.getAsJsonObject("function")), List.copyOf(requestedGlobals));
        var nodes = new ArrayList<TypeGraph.TypeNode>();
        nodes.add(new TypeGraph.VoidType("void"));
        nodes.add(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED));
        nodes.add(new TypeGraph.BaseType("schar", "signed char", 1, TypeGraph.BaseEncoding.SIGNED_CHAR));
        nodes.add(new TypeGraph.BaseType("uchar", "unsigned char", 1, TypeGraph.BaseEncoding.UNSIGNED_CHAR));
        nodes.add(new TypeGraph.BaseType("bool", "_Bool", 1, TypeGraph.BaseEncoding.BOOLEAN));
        nodes.add(new TypeGraph.BaseType("utf16", "char16_t", 2, TypeGraph.BaseEncoding.UTF));
        nodes.add(new TypeGraph.BaseType("utf32", "char32_t", 4, TypeGraph.BaseEncoding.UTF));
        nodes.add(new TypeGraph.BaseType("float", "float", 4, TypeGraph.BaseEncoding.FLOAT));
        nodes.add(new TypeGraph.BaseType("double", "double", 8, TypeGraph.BaseEncoding.FLOAT));
        nodes.add(new TypeGraph.BaseType("u64", "unsigned long long", 8, TypeGraph.BaseEncoding.UNSIGNED));
        nodes.add(new TypeGraph.QualifiedType("atomic", "_Atomic int", 4,
            List.of(TypeGraph.Qualifier.ATOMIC), ref("int")));
        nodes.add(new TypeGraph.QualifiedType("cv", "const volatile int", 4,
            List.of(TypeGraph.Qualifier.CONST, TypeGraph.Qualifier.VOLATILE), ref("int")));
        nodes.add(new TypeGraph.IndirectionType("pointer", "int *", 8,
            TypeGraph.IndirectionKind.POINTER, ref("int")));
        nodes.add(new TypeGraph.QualifiedType("restrict", "int *restrict", 8,
            List.of(TypeGraph.Qualifier.RESTRICT), ref("pointer")));
        nodes.add(new TypeGraph.QualifiedType("constvoid", "const void", 0,
            List.of(TypeGraph.Qualifier.CONST), ref("void")));
        nodes.add(new TypeGraph.IndirectionType("voidpointer", "const void *", 8,
            TypeGraph.IndirectionKind.POINTER, ref("constvoid")));
        var graph = new TypeGraph(nodes);
        Map<String, String> types = Map.ofEntries(
            Map.entry("forge_base", "int"), Map.entry("forge_atomic", "atomic"),
            Map.entry("forge_cv", "cv"), Map.entry("forge_restrict", "restrict"),
            Map.entry("forge_void", "voidpointer"), Map.entry("forge_schar", "schar"),
            Map.entry("forge_uchar", "uchar"), Map.entry("forge_bool", "bool"),
            Map.entry("forge_utf16", "utf16"), Map.entry("forge_utf32", "utf32"),
            Map.entry("forge_float", "float"), Map.entry("forge_double", "double"),
            Map.entry("forge_u64", "u64"));
        require(request.globals().stream().map(Symbol::name).collect(java.util.stream.Collectors.toSet()).equals(types.keySet()),
            "fixture globals differ");
        var globals = new ArrayList<ProgramTypeModel.GlobalVariable>();
        for (Symbol symbol : request.globals()) {
            var type = ref(types.get(symbol.name()));
            require(graph.byKey().get(type.key()).byteSize() == symbol.size(), "compiler object size differs");
            globals.add(new ProgramTypeModel.GlobalVariable(symbol.name(), symbol.address(), symbol.size(), type,
                false, "EXPLICIT_COMPILER_FIXTURE_MODEL"));
        }
        var function = request.function();
        var signature = new ProgramTypeModel.FunctionSignature(function.name(), function.address(), ref("int"),
            List.of(), List.of(), false, false, "default", "EXPLICIT_COMPILER_FIXTURE_MODEL");
        var model = new ProgramTypeModel(graph, List.of(signature), globals);
        var text = SyntheticSourceFile.build("qualified-type-fixture", "test",
            List.of(new SyntheticSourceFile.FunctionText(function.name(), function.address(),
                "int forge_types_probe(void)\n{\n    return forge_base + forge_atomic;\n}\n", null,
                List.of(new SyntheticSourceFile.RelativeLine(3, List.of(function.address()))))));
        Path source = Path.of(output + ".c");
        Files.write(source, text.utf8());
        byte[] original = Files.readAllBytes(input);
        var exporter = new MinimalDwarfSidecarExporter();
        var functions = List.of(new MinimalDwarfSidecarExporter.FunctionSymbol(function.name(), function.address(), function.size()));
        exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, text, model);
        byte[] first = Files.readAllBytes(output);
        exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, text, model);
        require(Arrays.equals(first, Files.readAllBytes(output)), "type export is not deterministic");
        require(Arrays.equals(original, Files.readAllBytes(input)), "original changed");
        require(Arrays.equals(text.utf8(), Files.readAllBytes(source)), "source changed");
        System.out.println("qualified-type-producer=PASS globals=13 deterministic=true original-preserved=true");
    }

    private static TypeGraph.TypeRef ref(String key) { return new TypeGraph.TypeRef(key); }
    private static Symbol symbol(JsonObject value) {
        return new Symbol(value.get("name").getAsString(), value.get("address").getAsLong(), value.get("size").getAsLong());
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
}
