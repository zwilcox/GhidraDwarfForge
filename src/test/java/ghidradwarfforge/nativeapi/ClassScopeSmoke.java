package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Isolated producer: class declarations, exact specifications and independent names. */
public final class ClassScopeSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 0 && args.length != 6) throw new IllegalArgumentException("consumer producer input output entry size");
        long entry = args.length == 0 ? 0x401106 : Long.decode(args[4]);
        long size = args.length == 0 ? 0x4f : Long.decode(args[5]);
        long half = size / 2;
        var integer = new TypeRef("int");
        var object = new TypeRef("object");
        var pointer = new TypeRef("pointer");
        var graph = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED),
            new AggregateType("object", "StoredCounter", 4, AggregateKind.STRUCTURE,
                List.of(new Member("value", integer, 0))),
            new IndirectionType("pointer", "StoredCounter *", 8, IndirectionKind.POINTER, object)));
        var receiver = new Parameter("receiver", pointer, true, false, true);
        var argument = new Parameter("amount", integer, false);
        String method = "outer::Counter::method";
        String nested = "outer::Counter::Nested::static_method";
        String external = "outer::Counter::external";
        var signatures = List.of(
            new ProgramTypeModel.FunctionSignature(method, entry, integer, List.of(receiver, argument),
                List.of(), false, false, "default", "USER_DEFINED"),
            new ProgramTypeModel.FunctionSignature(nested, entry + half, integer, List.of(argument),
                List.of(), false, false, "default", "USER_DEFINED"));
        var declarations = List.of(new ProgramTypeModel.FunctionDeclaration("external:103", external,
            integer, List.of(receiver), false, false, "default", "USER_DEFINED"));
        var classes = new ClassScopeModel(List.of(new Scope(1, 0, "outer", Kind.NAMESPACE),
            new Scope(2, 1, "Counter", Kind.CLASS), new Scope(3, 2, "Nested", Kind.CLASS)),
            List.of(new Binding(2, object, BindingSource.EXPLICIT_SAVED, "analyst binding with different type name")),
            List.of(new Method(101, 2, "method", FunctionReference.definition(method, entry)),
                new Method(102, 3, "static_method", FunctionReference.definition(nested, entry + half)),
                new Method(103, 2, "external", FunctionReference.declaration(external, "external:103"))));
        var model = new ProgramTypeModel(graph, signatures, List.of(),
            new VariableStorageModel(List.of()), List.of(), declarations, List.of(), classes);
        var functions = List.of(new FunctionSymbol(method, entry, half),
            new FunctionSymbol(nested, entry + half, size - half));
        if (args.length == 0) {
            System.out.println("class-scope-fixture-model=PASS");
            return;
        }
        Path input = Path.of(args[2]);
        Path output = Path.of(args[3]);
        byte[] original = Files.readAllBytes(input);
        var exporter = new MinimalDwarfSidecarExporter();
        byte[] first = null;
        for (int iteration = 0; iteration < 2; iteration++) {
            exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, null, model);
            byte[] bytes = Files.readAllBytes(output);
            if (first != null && !Arrays.equals(first, bytes)) throw new AssertionError("nondeterministic class emission");
            first = bytes;
        }
        var failure = SyntheticSourceFile.build("fixture", "fixture", List.of(
            new SyntheticSourceFile.FunctionText(method, entry, null, "controlled failure")));
        exporter.export(input, Path.of(args[3] + ".failed"), Path.of(args[0]), Path.of(args[1]), functions, failure, model);
        var extendedTypes = new java.util.ArrayList<TypeGraph.TypeNode>(graph.nodes());
        extendedTypes.add(new AggregateType("unrelated", "Counter", 8, AggregateKind.STRUCTURE,
            List.of(new Member("first", integer, 0), new Member("second", integer, 4))));
        var collision = new ProgramTypeModel(new TypeGraph(extendedTypes), signatures, List.of(),
            new VariableStorageModel(List.of()), List.of(), declarations, List.of(), classes);
        exporter.export(input, Path.of(args[3] + ".collision"), Path.of(args[0]), Path.of(args[1]), functions, null, collision);
        extendedTypes.set(extendedTypes.size() - 1, new AggregateType("unrelated", "OtherLayout", 8,
            AggregateKind.STRUCTURE, List.of(new Member("first", integer, 0), new Member("second", integer, 4))));
        var extendedScopes = new java.util.ArrayList<ClassScopeModel.Scope>(classes.scopes());
        extendedScopes.add(new Scope(4, 0, "other", Kind.NAMESPACE));
        extendedScopes.add(new Scope(5, 4, "Counter", Kind.CLASS));
        var extendedBindings = new java.util.ArrayList<ClassScopeModel.Binding>(classes.bindings());
        extendedBindings.add(new Binding(5, new TypeRef("unrelated"), BindingSource.EXPLICIT_SAVED, "distinct same-name class"));
        var ambiguous = new ProgramTypeModel(new TypeGraph(extendedTypes), signatures, List.of(),
            new VariableStorageModel(List.of()), List.of(), declarations, List.of(),
            new ClassScopeModel(extendedScopes, extendedBindings, classes.methods()));
        exporter.export(input, Path.of(args[3] + ".ambiguous"), Path.of(args[0]), Path.of(args[1]), functions, null, ambiguous);
        if (!Arrays.equals(original, Files.readAllBytes(input))) throw new AssertionError("input modified");
        System.out.println("class-scope-native=PASS");
    }
}
